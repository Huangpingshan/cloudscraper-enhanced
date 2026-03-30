# ------------------------------------------------------------------------------- #
# cloudscraper/__init__.py — Assembly-only entry point
#
# CloudScraper delegates parameter parsing, fingerprint resolution,
# transport setup, and session state management to dedicated modules:
#   config.py        — ScraperConfig dataclass + parse_config()
#   fingerprint.py   — FingerprintProfile + resolve_profile()
#   transport_curl.py — curl_cffi session setup + header application
#   session_state.py  — clone / pickle / restore
# ------------------------------------------------------------------------------- #

import logging
import ssl
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Optional, Dict, Any

from curl_cffi import requests as curl_requests
from curl_cffi.requests import Session

# ------------------------------------------------------------------------------- #

from urllib.parse import urlparse

# ------------------------------------------------------------------------------- #

from .exceptions import (
    CloudflareLoopProtection,
    CloudflareIUAMError,
    CloudflareChallengeError,
    CloudflareTurnstileError,
    CloudflareV3Error
)

from .cloudflare import Cloudflare
from .cloudflare_v2 import CloudflareV2
from .cloudflare_v3 import CloudflareV3
from .turnstile import CloudflareTurnstile
from .user_agent import User_Agent
from .proxy_manager import ProxyManager
from .stealth import StealthMode

from .config import ScraperConfig, parse_config
from .fingerprint import (
    FingerprintProfile, resolve_profile,
    FINGERPRINT_HEADER_KEYS, _IMPERSONATE_UA_MAP,
)
from .transport_curl import apply_profile_headers, apply_curl_options
from .session_state import (
    clone_session_attrs, get_picklable_state, restore_from_state,
)

# ------------------------------------------------------------------------------- #

__version__ = '3.0.0'

# ------------------------------------------------------------------------------- #


@dataclass
class _RequestChain:
    """Per-request-chain state, isolated via ContextVar.

    Each top-level request() creates one of these.  Recursive calls
    (challenge handlers, 403 retries) share the same chain instance,
    incrementing depth so only the root dispatches hooks.
    """
    depth: int = 0
    solve_depth_cnt: int = 0
    retry_403_count: int = 0
    in_403_retry: bool = False


_current_chain: ContextVar[Optional[_RequestChain]] = ContextVar(
    '_current_chain', default=None
)


class CloudScraper(Session):

    _browsers_data_cache = None
    _browsers_data_lock = threading.Lock()

    @classmethod
    def _get_browsers_data(cls):
        if cls._browsers_data_cache is None:
            with cls._browsers_data_lock:
                if cls._browsers_data_cache is None:
                    import json
                    import os
                    browsers_file = os.path.join(
                        os.path.dirname(__file__), 'user_agent', 'browsers.json'
                    )
                    with open(browsers_file, 'r') as f:
                        cls._browsers_data_cache = json.load(f)
        return cls._browsers_data_cache

    def __init__(self, *args, **kwargs):
        # ---- Step 1: Parse config (modifies kwargs in-place) ----
        self._config = parse_config(kwargs)
        cfg = self._config

        # ---- Step 2: Build User_Agent for custom UA / cipher data ----
        self.user_agent = User_Agent(
            allow_brotli=cfg.allow_brotli,
            browser=cfg.browser_arg_raw,
        )

        # ---- Step 3: Resolve fingerprint profile ----
        self._profile = resolve_profile(cfg, self.user_agent)

        # ---- Step 4: Initialize curl_cffi Session with impersonate ----
        super(CloudScraper, self).__init__(
            impersonate=self._profile.impersonate,
            *args,
            **kwargs
        )

        # ---- Step 5: Apply profile headers + curl_options ----
        apply_profile_headers(self, self._profile, cfg.caller_headers)
        apply_curl_options(self, self._profile)

        # ---- Step 6: Expose config attributes on self ----
        # (challenge handlers read self.debug, self.captcha, etc.)
        self.impersonate = self._profile.impersonate
        self.debug = cfg.debug
        self.delay = cfg.delay
        self.captcha = cfg.captcha
        self.doubleDown = cfg.doubleDown
        self.interpreter = cfg.interpreter
        self.solveDepth = cfg.solveDepth
        self.requestPreHook = cfg.requestPreHook
        self.requestPostHook = cfg.requestPostHook
        self.disableCloudflareV1 = cfg.disableCloudflareV1
        self.disableCloudflareV2 = cfg.disableCloudflareV2
        self.disableCloudflareV3 = cfg.disableCloudflareV3
        self.disableTurnstile = cfg.disableTurnstile
        self.allow_brotli = cfg.allow_brotli
        self.enable_stealth = cfg.enable_stealth

        # TLS state (for cipher rotation)
        self.cipherSuite = cfg.cipherSuite
        self.ecdhCurve = cfg.ecdhCurve
        self._explicit_cipherSuite = cfg.explicit_cipherSuite
        self._custom_ua = self._profile.is_custom_ua

        # Populate cipherSuite from User_Agent for rotation feature
        if not self.cipherSuite:
            self.cipherSuite = self.user_agent.cipherSuite
        if isinstance(self.cipherSuite, list):
            self.cipherSuite = ':'.join(self.cipherSuite)

        # Kept for backward compat — always None with curl_cffi
        self.ssl_context = None

        # ---- Step 7: Initialize subsystems ----
        # Per-request-chain state (solve depth, 403 retry) is managed via
        # ContextVar (_current_chain) — not stored on self.  This makes
        # concurrent requests (threads AND asyncio tasks) fully isolated.

        # Session health monitoring — shared across all requests, guarded by lock
        self._state_lock = threading.Lock()
        self._in_refresh = False  # guard against recursive refresh
        self.session_start_time = time.time()
        self.request_count = 0
        self.last_403_time = 0
        self.session_refresh_interval = cfg.session_refresh_interval
        self.auto_refresh_on_403 = cfg.auto_refresh_on_403
        self.max_403_retries = cfg.max_403_retries

        # Request throttling — semaphore replaces busy-wait loop
        self.last_request_time = 0
        self.min_request_interval = cfg.min_request_interval
        self.max_concurrent_requests = cfg.max_concurrent_requests
        self._concurrent_sem = threading.BoundedSemaphore(cfg.max_concurrent_requests)
        self.rotate_tls_ciphers = cfg.rotate_tls_ciphers
        self._cipher_rotation_count = 0

        # Proxy management
        self.proxy_manager = ProxyManager(
            proxies=cfg.rotating_proxies,
            proxy_rotation_strategy=cfg.proxy_options.get('rotation_strategy', 'sequential'),
            ban_time=cfg.proxy_options.get('ban_time', 300),
        )

        # Stealth mode
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

        # ---- Step 8: Initialize requests-style hooks dict ----
        # curl_cffi Session doesn't provide this; we set it so that
        # scraper.hooks['response'].append(fn) works out of the box.
        self.hooks = {'response': []}

        # ---- Step 9: Initialize Cloudflare handlers ----
        self.cloudflare_v1 = Cloudflare(self)
        self.cloudflare_v2 = CloudflareV2(self)
        self.cloudflare_v3 = CloudflareV3(self)
        self.turnstile = CloudflareTurnstile(self)

    # ------------------------------------------------------------------------------- #
    # Pickle support via session_state module
    # ------------------------------------------------------------------------------- #

    def __getstate__(self):
        return get_picklable_state(self)

    def __setstate__(self, state):
        restored = restore_from_state(state)
        self.__dict__.update(restored.__dict__)

    # ------------------------------------------------------------------------------- #
    # Allow replacing actual web request call via subclassing
    # ------------------------------------------------------------------------------- #

    def perform_request(self, method, url, *args, **kwargs):
        return super(CloudScraper, self).request(method, url, *args, **kwargs)

    # ------------------------------------------------------------------------------- #
    # Sleeps — override in async subclass with `await asyncio.sleep()`
    # ------------------------------------------------------------------------------- #

    def _sleep(self, seconds):
        """Sleep for the given number of seconds.

        Override this in an async subclass to use ``await asyncio.sleep(seconds)``
        instead of the blocking ``time.sleep()``.  All internal sleep calls
        (throttling, stealth delays, challenge delays) route through here.
        """
        time.sleep(seconds)

    # ------------------------------------------------------------------------------- #

    def simpleException(self, exception, msg):
        chain = _current_chain.get(None)
        if chain is not None:
            chain.solve_depth_cnt = 0
        raise exception(msg)

    # ------------------------------------------------------------------------------- #

    @staticmethod
    def debugRequest(req):
        try:
            print(f"--- Debug Request ---")
            print(f"URL: {req.url}")
            print(f"Status: {req.status_code}")
            print(f"Headers: {dict(req.headers)}")
            print(f"--- End Debug ---")
        except Exception as e:
            print(f"Debug Error: {getattr(e, 'message', e)}")

    # ------------------------------------------------------------------------------- #

    def decodeBrotli(self, resp):
        return resp

    @staticmethod
    def _adapt_response(resp):
        """Patch requests-compatible properties onto a curl_cffi Response.

        curl_cffi.Response lacks some properties that the original
        requests.Response exposes (e.g. is_redirect).  Challenge handlers
        and user code may rely on them, so we add them here once rather
        than scattering compat checks across every consumer.
        """
        if not hasattr(resp, 'is_redirect'):
            resp.is_redirect = (
                resp.status_code in (301, 302, 303, 307, 308)
                and 'Location' in resp.headers
            )

        if not hasattr(resp, 'apparent_encoding'):
            resp.apparent_encoding = getattr(resp, 'charset', None) or 'utf-8'

        if not hasattr(resp, 'links'):
            links = {}
            link_header = resp.headers.get('Link', '')
            if link_header:
                for part in link_header.split(','):
                    part = part.strip()
                    if '<' in part and '>' in part:
                        url_part = part[part.index('<') + 1:part.index('>')]
                        params = {}
                        for param in part[part.index('>') + 1:].split(';'):
                            param = param.strip()
                            if '=' in param:
                                key, val = param.split('=', 1)
                                params[key.strip()] = val.strip().strip('"')
                        rel = params.get('rel', url_part)
                        params['url'] = url_part
                        links[rel] = params
            resp.links = links

        return resp

    # ------------------------------------------------------------------------------- #
    # Request hijacker
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def _normalize_hooks(value):
        """Normalize a hooks 'response' value to a flat list of callables.

        Accepts the same forms as the requests library:
        - None                  → []
        - single callable       → [callable]
        - list/tuple of callables → list(...)
        """
        if value is None:
            return []
        if callable(value):
            return [value]
        if isinstance(value, (list, tuple)):
            return list(value)
        raise TypeError(
            f"hooks 'response' value must be callable or a list of callables, "
            f"got {type(value).__name__}"
        )

    def _dispatch_hooks(self, response, request_hooks=None, **hook_kwargs):
        """Dispatch requests-style response hooks (session-level + per-request).

        Each hook receives (response, **kwargs) and may return a replacement
        response.  This mirrors the requests library convention where hooks
        are called as ``hook(response, **kwargs)``.
        """
        all_hooks = []
        session_hooks = self.hooks
        if session_hooks and isinstance(session_hooks, dict):
            all_hooks.extend(self._normalize_hooks(session_hooks.get('response')))
        if request_hooks and isinstance(request_hooks, dict):
            all_hooks.extend(self._normalize_hooks(request_hooks.get('response')))

        for hook in all_hooks:
            result = hook(response, **hook_kwargs)
            if result is not None:
                response = result

        return response

    def request(self, method, url, *args, **kwargs):
        """Thin wrapper that owns hook dispatch.

        Only the outermost request() dispatches response hooks (both
        session-level self.hooks and per-request hooks= kwarg).  Challenge
        handlers and 403-retry paths recurse through this method, but the
        depth counter ensures hooks fire exactly once on the final response.

        The request chain is stored in a ContextVar so that concurrent
        requests from different threads AND different asyncio tasks each
        get independent dispatch ownership.
        """
        request_hooks = kwargs.pop('hooks', None)
        chain = _current_chain.get(None)
        is_root = chain is None
        if is_root:
            chain = _RequestChain()
            token = _current_chain.set(chain)
            self._concurrent_sem.acquire()
        chain.depth += 1
        try:
            response = self._request_core(method, url, *args, **kwargs)
        finally:
            chain.depth -= 1
            if is_root:
                self._concurrent_sem.release()
                _current_chain.reset(token)

        if is_root:
            response = self._dispatch_hooks(
                response, request_hooks, method=method, url=url,
            )

        return response

    def _request_core(self, method, url, *args, **kwargs):
        """Core request logic: throttling, network call, challenge handling.

        Contains zero _dispatch_hooks() calls — hook dispatch is owned
        exclusively by the outermost request() wrapper.

        Per-request-chain state (solve depth, 403 retries) lives in the
        ContextVar-backed _RequestChain, not on self.
        """
        chain = _current_chain.get()

        # Apply request throttling
        self._apply_request_throttling()

        # TLS cipher rotation — requires both profile capability AND user toggle
        if self.rotate_tls_ciphers and self._profile.can_rotate_tls:
            self._rotate_tls_cipher_suite()

        # Check if session needs refresh
        if self._should_refresh_session():
            self._refresh_session(url)

        # Proxy rotation
        if not kwargs.get('proxies') and hasattr(self, 'proxy_manager') and self.proxy_manager.proxies:
            kwargs['proxies'] = self.proxy_manager.get_proxy()
        elif kwargs.get('proxies') and kwargs.get('proxies') != self.proxies:
            self.proxies = kwargs.get('proxies')

        # Stealth
        if self.enable_stealth:
            kwargs = self.stealth_mode.apply_stealth_techniques(method, url, **kwargs)

        with self._state_lock:
            self.request_count += 1

        # Pre-Hook (cloudscraper-specific)
        if self.requestPreHook:
            (method, url, args, kwargs) = self.requestPreHook(
                self, method, url, *args, **kwargs
            )

        # Perform the request
        try:
            response = self._adapt_response(self.decodeBrotli(
                self.perform_request(method, url, *args, **kwargs)
            ))
            if kwargs.get('proxies') and hasattr(self, 'proxy_manager'):
                self.proxy_manager.report_success(kwargs['proxies'])
        except curl_requests.errors.RequestsError as e:
            if kwargs.get('proxies') and hasattr(self, 'proxy_manager'):
                self.proxy_manager.report_failure(kwargs['proxies'])
            raise

        if self.debug:
            self.debugRequest(response)

        # Post-Hook (cloudscraper-specific)
        if self.requestPostHook:
            newResponse = self.requestPostHook(self, response)
            if response != newResponse:
                response = newResponse
                if self.debug:
                    print('==== requestPostHook Debug ====')
                    self.debugRequest(response)

        # ------------------------------------------------------------------------------- #
        # Cloudflare challenge handling
        #
        # Challenge handlers call self.cloudscraper.request() internally,
        # which re-enters request() (the wrapper).  The depth counter in
        # the wrapper ensures hooks are NOT dispatched on those inner calls.
        # Only the outermost wrapper dispatches hooks on whatever response
        # ultimately bubbles up.
        # ------------------------------------------------------------------------------- #

        if chain.solve_depth_cnt >= self.solveDepth:
            cnt = chain.solve_depth_cnt
            self.simpleException(
                CloudflareLoopProtection,
                f"!!Loop Protection!! We have tried to solve {cnt} time(s) in a row."
            )

        if not self.disableTurnstile:
            if self.turnstile.is_Turnstile_Challenge(response):
                if self.debug:
                    print('Detected a Cloudflare Turnstile challenge.')
                chain.solve_depth_cnt += 1
                return self.turnstile.handle_Turnstile_Challenge(response, **kwargs)

        if not self.disableCloudflareV3:
            if self.cloudflare_v3.is_V3_Challenge(response):
                if self.debug:
                    print('Detected a Cloudflare v3 JavaScript VM challenge.')
                chain.solve_depth_cnt += 1
                return self.cloudflare_v3.handle_V3_Challenge(response, **kwargs)

        if not self.disableCloudflareV2:
            if self.cloudflare_v2.is_V2_Captcha_Challenge(response):
                chain.solve_depth_cnt += 1
                return self.cloudflare_v2.handle_V2_Captcha_Challenge(response, **kwargs)
            if self.cloudflare_v2.is_V2_Challenge(response):
                chain.solve_depth_cnt += 1
                return self.cloudflare_v2.handle_V2_Challenge(response, **kwargs)

        if not self.disableCloudflareV1:
            if self.cloudflare_v1.is_Challenge_Request(response):
                chain.solve_depth_cnt += 1
                return self.cloudflare_v1.Challenge_Response(response, **kwargs)

        # Reset solve depth
        is_redirect = response.is_redirect
        if not is_redirect and response.status_code not in [429, 503]:
            chain.solve_depth_cnt = 0
            if response.status_code == 200 and not chain.in_403_retry:
                chain.retry_403_count = 0

        # Handle 403 — the retry calls self.request() (the wrapper), which
        # increments depth.  The inner call won't dispatch hooks; the
        # outermost wrapper dispatches once when the final response arrives.
        if response.status_code == 403 and self.auto_refresh_on_403:
            if chain.retry_403_count < self.max_403_retries:
                chain.retry_403_count += 1
                with self._state_lock:
                    self.last_403_time = time.time()

                if self.debug:
                    print(f'Received 403 error, attempting session refresh (attempt {chain.retry_403_count}/{self.max_403_retries})')

                if self._refresh_session(url):
                    if self.debug:
                        print(f'Session refreshed successfully, retrying original request...')

                    chain.in_403_retry = True
                    try:
                        retry_response = self.request(method, url, *args, **kwargs)
                        if retry_response.status_code == 200:
                            chain.retry_403_count = 0
                            with self._state_lock:
                                self.last_403_time = 0
                            if self.debug:
                                print('403 retry successful, request completed')
                        return retry_response
                    finally:
                        chain.in_403_retry = False
                else:
                    if self.debug:
                        print('Session refresh failed, returning 403 response')
            else:
                with self._state_lock:
                    self.last_403_time = 0
                if self.debug:
                    print(f'Max 403 retries ({self.max_403_retries}) exceeded, returning 403 response')

        return response

    # ------------------------------------------------------------------------------- #
    # Session health monitoring
    # ------------------------------------------------------------------------------- #

    def _should_refresh_session(self):
        with self._state_lock:
            if self._in_refresh:
                return False
            current_time = time.time()
            session_age = current_time - self.session_start_time
            if session_age > self.session_refresh_interval:
                return True
            if self.last_403_time > 0 and (current_time - self.last_403_time) < 60:
                return True
            return False

    def _refresh_session(self, url):
        with self._state_lock:
            if self._in_refresh:
                return False
            self._in_refresh = True

        try:
            if self.debug:
                print('Refreshing session due to staleness or 403 errors...')
            self._clear_cloudflare_cookies()
            with self._state_lock:
                self.session_start_time = time.time()
                self.request_count = 0

            # Re-apply the immutable profile headers instead of regenerating
            # User_Agent. This preserves the exact fingerprint (including
            # custom UAs) across refreshes.
            apply_profile_headers(self, self._profile, self._config.caller_headers)
            try:
                parsed_url = urlparse(url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                # Use self.get() so challenge handling is active during refresh.
                # _in_refresh prevents recursive refresh calls.
                test_response = self.get(base_url, timeout=30)
                if self.debug:
                    print(f'Session refresh request status: {test_response.status_code}')
                success = test_response.status_code in [200, 301, 302, 304]
                if success and self.debug:
                    print('Session refresh successful')
                elif not success and self.debug:
                    print(f'Session refresh failed with status: {test_response.status_code}')
                return success
            except Exception as e:
                if self.debug:
                    print(f'Session refresh failed: {e}')
                return False
        except Exception as e:
            if self.debug:
                print(f'Error during session refresh: {e}')
            return False
        finally:
            with self._state_lock:
                self._in_refresh = False

    def _clear_cloudflare_cookies(self):
        cf_cookie_names = ['cf_clearance', 'cf_chl_2', 'cf_chl_prog', 'cf_chl_rc_ni', 'cf_turnstile', '__cf_bm']
        remove_list = []
        for cookie in self.cookies.jar:
            if cookie.name in cf_cookie_names:
                remove_list.append(cookie)
        for cookie in remove_list:
            self.cookies.jar.clear(cookie.domain, cookie.path, cookie.name)
        if self.debug:
            print('Cleared Cloudflare cookies for session refresh')

    def _apply_request_throttling(self):
        with self._state_lock:
            current_time = time.time()
            time_since_last_request = current_time - self.last_request_time
            if time_since_last_request < self.min_request_interval:
                sleep_time = self.min_request_interval - time_since_last_request
            else:
                sleep_time = 0
            # Claim the slot immediately so other threads see the updated time
            # and compute their own sleep accordingly, even before we actually sleep.
            self.last_request_time = current_time + sleep_time

        if sleep_time > 0:
            if self.debug:
                print(f'Request throttling: sleeping {sleep_time:.2f}s')
            self._sleep(sleep_time)

    def _rotate_tls_cipher_suite(self):
        """Rotate TLS cipher suites (only when caller explicitly set cipherSuite=
        AND rotate_tls_ciphers is enabled)."""
        if not self._explicit_cipherSuite:
            return
        if not self.rotate_tls_ciphers:
            return
        if not hasattr(self, 'user_agent') or not hasattr(self.user_agent, 'cipherSuite'):
            return
        browser_name = getattr(self.user_agent, 'browser', 'chrome')
        try:
            browsers_data = self._get_browsers_data()
            available_ciphers = browsers_data.get('cipherSuite', {}).get(browser_name, [])
            if available_ciphers and len(available_ciphers) > 1:
                with self._state_lock:
                    self._cipher_rotation_count += 1
                    cipher_index = self._cipher_rotation_count % len(available_ciphers)
                    num_ciphers = min(8, len(available_ciphers))
                    start_index = cipher_index % (len(available_ciphers) - num_ciphers + 1)
                    selected_ciphers = available_ciphers[start_index:start_index + num_ciphers]
                    new_cipher_suite = ':'.join(selected_ciphers)
                    if new_cipher_suite != self.cipherSuite:
                        self.cipherSuite = new_cipher_suite
                        self._explicit_cipherSuite = True
                        try:
                            from curl_cffi.const import CurlOpt
                            self.curl_options[CurlOpt.SSL_CIPHER_LIST] = self.cipherSuite
                            if self.ecdhCurve:
                                self.curl_options[CurlOpt.SSL_EC_CURVES] = self.ecdhCurve
                        except (ImportError, AttributeError):
                            pass
                        if self.debug:
                            print(f'Rotated TLS cipher suite (rotation #{self._cipher_rotation_count})')
                            print(f'    Using {len(selected_ciphers)} ciphers starting from index {start_index}')
        except Exception as e:
            if self.debug:
                print(f'TLS cipher rotation failed: {e}')

    # ------------------------------------------------------------------------------- #
    # Factory methods
    # ------------------------------------------------------------------------------- #

    @classmethod
    def create_scraper(cls, sess=None, **kwargs):
        scraper = cls(**kwargs)
        if sess:
            clone_session_attrs(sess, scraper, FINGERPRINT_HEADER_KEYS)
        return scraper

    # ------------------------------------------------------------------------------- #

    @classmethod
    def get_tokens(cls, url, **kwargs):
        scraper = cls.create_scraper(
            **{
                field: kwargs.pop(field, None) for field in [
                    'allow_brotli', 'browser', 'debug', 'delay',
                    'doubleDown', 'captcha', 'interpreter', 'source_address',
                    'requestPreHook', 'requestPostHook',
                    'rotating_proxies', 'proxy_options',
                    'enable_stealth', 'stealth_options',
                    'session_refresh_interval', 'auto_refresh_on_403',
                    'max_403_retries', 'disableCloudflareV3',
                    'disableTurnstile', 'impersonate',
                ] if field in kwargs
            }
        )

        try:
            resp = scraper.get(url, **kwargs)
            resp.raise_for_status()
        except Exception as e:
            logging.error(f'"{url}" returned an error. Could not collect tokens. Error: {str(e)}')
            raise

        domain = urlparse(resp.url).netloc
        cookie_domain = None

        cookie_domains = set()
        for cookie in scraper.cookies.jar:
            cookie_domains.add(cookie.domain)

        for d in cookie_domains:
            if d.startswith('.') and d == f'.{domain}':
                cookie_domain = d
                break
        else:
            for d in cookie_domains:
                if d == domain:
                    cookie_domain = d
                    break
            else:
                cls.simpleException(
                    cls,
                    CloudflareIUAMError,
                    "Unable to find Cloudflare cookies. Does the site actually "
                    "have Cloudflare IUAM (I'm Under Attack Mode) enabled?"
                )

        cf_cookies = {}
        for cookie_name in ['cf_clearance', 'cf_chl_2', 'cf_chl_prog', 'cf_chl_rc_ni', 'cf_turnstile']:
            cookie_value = scraper.cookies.get(cookie_name, '', domain=cookie_domain)
            if cookie_value:
                cf_cookies[cookie_name] = cookie_value

        return (cf_cookies, scraper.headers['User-Agent'])

    # ------------------------------------------------------------------------------- #

    @classmethod
    def get_cookie_string(cls, url, **kwargs):
        tokens, user_agent = cls.get_tokens(url, **kwargs)
        return '; '.join('='.join(pair) for pair in tokens.items()), user_agent


# ------------------------------------------------------------------------------- #

if ssl.OPENSSL_VERSION_INFO < (1, 1, 1):
    print(
        f"DEPRECATION: The OpenSSL being used by this python install ({ssl.OPENSSL_VERSION}) does not meet the minimum supported "
        "version (>= OpenSSL 1.1.1) in order to support TLS 1.3 required by Cloudflare, "
        "You may encounter an unexpected Captcha or cloudflare 1020 blocks."
    )

# ------------------------------------------------------------------------------- #

create_scraper = CloudScraper.create_scraper
session = CloudScraper.create_scraper
get_tokens = CloudScraper.get_tokens
get_cookie_string = CloudScraper.get_cookie_string


def create_async_scraper(**kwargs):
    """Lazy-loaded factory for AsyncCloudScraper."""
    from .async_scraper import create_async_scraper as _create
    return _create(**kwargs)
