# ------------------------------------------------------------------------------- #
# cloudscraper/async_scraper.py — Minimal async wrapper
#
# Provides AsyncCloudScraper backed by curl_cffi.requests.AsyncSession.
# Challenge **detection** is supported; solving raises CloudflareChallengeError
# (full async solving is planned for a future release).
# ------------------------------------------------------------------------------- #

import asyncio
import logging
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Optional

from curl_cffi.requests import AsyncSession

from .config import ScraperConfig, parse_config
from .exceptions import CloudflareChallengeError
from .fingerprint import resolve_profile
from .proxy_manager import ProxyManager
from .stealth import StealthMode
from .transport_curl import apply_profile_headers, apply_curl_options
from .user_agent import User_Agent

from .cloudflare import Cloudflare
from .cloudflare_v2 import CloudflareV2
from .cloudflare_v3 import CloudflareV3
from .turnstile import CloudflareTurnstile

# ------------------------------------------------------------------------------- #


@dataclass
class _AsyncRequestChain:
    depth: int = 0


_async_chain: ContextVar[Optional[_AsyncRequestChain]] = ContextVar(
    '_async_chain', default=None
)

# ------------------------------------------------------------------------------- #


class AsyncCloudScraper(AsyncSession):
    """Async counterpart of CloudScraper.

    Reuses the same config / fingerprint / header pipeline.  Challenge
    detection is supported — if a Cloudflare challenge is found the
    response raises ``CloudflareChallengeError`` rather than attempting
    to solve it (async solving is not yet implemented).
    """

    def __init__(self, *args, **kwargs):
        # ---- Step 1: Parse config ----
        self._config = parse_config(kwargs)
        cfg = self._config

        # ---- Step 2: Build User_Agent ----
        self.user_agent = User_Agent(
            allow_brotli=cfg.allow_brotli,
            browser=cfg.browser_arg_raw,
        )

        # ---- Step 3: Resolve fingerprint profile ----
        self._profile = resolve_profile(cfg, self.user_agent)

        # ---- Step 4: Initialize AsyncSession ----
        max_clients = kwargs.pop('max_clients', None)
        init_kwargs = {}
        if max_clients is not None:
            init_kwargs['max_clients'] = max_clients

        super().__init__(
            impersonate=self._profile.impersonate,
            *args,
            **{**kwargs, **init_kwargs},
        )

        # ---- Step 5: Apply profile headers + curl options ----
        apply_profile_headers(self, self._profile, cfg.caller_headers)
        apply_curl_options(self, self._profile)

        # ---- Step 6: Expose config attributes ----
        self.impersonate = self._profile.impersonate
        self.debug = cfg.debug
        self.delay = cfg.delay
        self.captcha = cfg.captcha
        self.allow_brotli = cfg.allow_brotli
        self.enable_stealth = cfg.enable_stealth

        self.disableCloudflareV1 = cfg.disableCloudflareV1
        self.disableCloudflareV2 = cfg.disableCloudflareV2
        self.disableCloudflareV3 = cfg.disableCloudflareV3
        self.disableTurnstile = cfg.disableTurnstile

        # ---- Step 7: Async concurrency primitives ----
        self._sem = asyncio.Semaphore(cfg.max_concurrent_requests)
        self._throttle_lock = asyncio.Lock()
        self.last_request_time = 0
        self.min_request_interval = cfg.min_request_interval

        # ---- Step 8: Proxy manager (shared, thread-safe) ----
        self.proxy_manager = ProxyManager(
            proxies=cfg.rotating_proxies,
            proxy_rotation_strategy=cfg.proxy_options.get('rotation_strategy', 'sequential'),
            ban_time=cfg.proxy_options.get('ban_time', 300),
        )

        # ---- Step 9: Stealth mode ----
        self.stealth_mode = StealthMode(self)
        stealth_options = cfg.stealth_options
        if stealth_options:
            if 'min_delay' in stealth_options and 'max_delay' in stealth_options:
                self.stealth_mode.set_delay_range(
                    stealth_options['min_delay'],
                    stealth_options['max_delay'],
                )
            self.stealth_mode.enable_human_like_delays(stealth_options.get('human_like_delays', True))
            self.stealth_mode.enable_randomize_headers(stealth_options.get('randomize_headers', True))
            self.stealth_mode.enable_browser_quirks(stealth_options.get('browser_quirks', True))

        # ---- Step 10: hooks dict (requests compat) ----
        self.hooks = {'response': []}

    # ------------------------------------------------------------------------------- #
    # Sleep helpers
    # ------------------------------------------------------------------------------- #

    def _sleep(self, seconds):
        """Sync sleep — used by StealthMode (runs in the calling thread)."""
        time.sleep(seconds)

    async def _async_sleep(self, seconds):
        """Async-friendly sleep for internal async paths."""
        await asyncio.sleep(seconds)

    # ------------------------------------------------------------------------------- #
    # Challenge detection (no I/O)
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def _is_challenge(response):
        """Return True if the response looks like any Cloudflare challenge."""
        if CloudflareTurnstile.is_Turnstile_Challenge(response):
            return True
        if CloudflareV3.is_V3_Challenge(response):
            return True
        if CloudflareV2.is_V2_Challenge(response):
            return True
        if CloudflareV2.is_V2_Captcha_Challenge(response):
            return True
        if Cloudflare.is_Any_V1_Challenge(response):
            return True
        return False

    # ------------------------------------------------------------------------------- #
    # Core request path
    # ------------------------------------------------------------------------------- #

    async def perform_request(self, method, url, *args, **kwargs):
        """Execute the actual HTTP request via AsyncSession."""
        return await super().request(method, url, *args, **kwargs)

    async def _apply_request_throttling(self):
        """Async request throttling."""
        async with self._throttle_lock:
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            if elapsed < self.min_request_interval:
                sleep_time = self.min_request_interval - elapsed
                if self.debug:
                    logging.debug(f'Async throttling: sleeping {sleep_time:.2f}s')
                await self._async_sleep(sleep_time)
            self.last_request_time = time.time()

    async def request(self, method, url, *args, **kwargs):
        """Async request with throttling, stealth, proxy rotation, and challenge detection."""
        request_hooks = kwargs.pop('hooks', None)

        chain = _async_chain.get(None)
        is_root = chain is None
        if is_root:
            chain = _AsyncRequestChain()
            token = _async_chain.set(chain)
            await self._sem.acquire()

        chain.depth += 1
        try:
            response = await self._request_core(method, url, *args, **kwargs)
        finally:
            chain.depth -= 1
            if is_root:
                self._sem.release()
                _async_chain.reset(token)

        return response

    async def _request_core(self, method, url, *args, **kwargs):
        """Core async request: throttling → stealth → proxy → request → challenge detect."""
        await self._apply_request_throttling()

        # Proxy rotation
        if not kwargs.get('proxies') and self.proxy_manager.proxies:
            kwargs['proxies'] = self.proxy_manager.get_proxy()

        # Stealth — compute delay asynchronously, then apply header-only stealth
        if self.enable_stealth:
            delay = self.stealth_mode.compute_human_like_delay()
            if delay >= 0.1:
                await self._async_sleep(delay)
            kwargs = self.stealth_mode.apply_stealth_techniques(method, url, apply_delay=False, **kwargs)

        # Perform request
        response = await self.perform_request(method, url, *args, **kwargs)

        # Challenge detection — raise instead of solving
        if self._is_challenge(response):
            raise CloudflareChallengeError(
                "Cloudflare challenge detected. Async challenge solving is not "
                "yet supported — use the synchronous CloudScraper for challenge "
                "bypass, or handle the challenge externally."
            )

        return response


# ------------------------------------------------------------------------------- #
# Factory
# ------------------------------------------------------------------------------- #

def create_async_scraper(**kwargs):
    """Create an AsyncCloudScraper instance."""
    return AsyncCloudScraper(**kwargs)
