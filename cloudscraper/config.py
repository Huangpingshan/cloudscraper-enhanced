# ------------------------------------------------------------------------------- #
# config.py — Parameter normalization for CloudScraper
#
# All kwargs are parsed into a ScraperConfig dataclass. After construction,
# all code reads config instead of directly parsing kwargs.
# ------------------------------------------------------------------------------- #

from dataclasses import dataclass, field
from typing import Optional, Callable, List, Dict, Any


@dataclass
class ScraperConfig:
    """Normalized configuration for CloudScraper.

    Created once during __init__ from user kwargs; read-only afterwards.
    """

    # Fingerprint inputs (normalized)
    browser_name: Optional[str] = None        # 'chrome' | 'firefox' | None (custom UA)
    platform: Optional[str] = None            # 'windows'|'linux'|'darwin'|'android'|'ios'|None
    custom_ua: Optional[str] = None           # browser={'custom': ...}
    impersonate: Optional[str] = None         # direct impersonate= value
    explicit_cipherSuite: bool = False
    cipherSuite: Optional[str] = None
    ecdhCurve: str = 'prime256v1'
    source_address: Optional[str] = None
    allow_brotli: bool = True

    # Challenge / hook / debug
    debug: bool = False
    delay: Optional[float] = None
    captcha: dict = field(default_factory=dict)
    doubleDown: bool = True
    interpreter: str = 'js2py'
    solveDepth: int = 3
    requestPreHook: Optional[Callable] = None
    requestPostHook: Optional[Callable] = None
    disableCloudflareV1: bool = False
    disableCloudflareV2: bool = False
    disableCloudflareV3: bool = False
    disableTurnstile: bool = False

    # Session health & throttling
    session_refresh_interval: int = 3600
    auto_refresh_on_403: bool = True
    max_403_retries: int = 3
    min_request_interval: float = 0.0
    max_concurrent_requests: int = 10
    rotate_tls_ciphers: bool = True

    # Proxy / stealth
    rotating_proxies: Optional[list] = None
    proxy_options: dict = field(default_factory=dict)
    enable_stealth: bool = False
    stealth_options: dict = field(default_factory=dict)

    # Caller's explicit headers (preserved as-is)
    caller_headers: dict = field(default_factory=dict)

    # Raw browser arg for User_Agent compatibility
    browser_arg_raw: Any = None


def parse_config(kwargs: dict) -> ScraperConfig:
    """Parse all CloudScraper kwargs into a ScraperConfig.

    IMPORTANT: This function modifies kwargs in-place by popping known keys,
    so that only curl_cffi-compatible kwargs remain for Session.__init__.

    Raises NotImplementedError for unsupported TLS parameters.
    """
    # Fail fast on unsupported parameters
    if kwargs.get('server_hostname'):
        raise NotImplementedError(
            "server_hostname is not supported with the curl_cffi backend. "
            "libcurl does not allow setting TLS SNI independently of the "
            "request URL hostname. Use CurlOpt.CONNECT_TO or "
            "CurlOpt.RESOLVE with an explicit IP mapping instead."
        )
    if kwargs.get('ssl_context'):
        raise NotImplementedError(
            "ssl_context is not supported with the curl_cffi backend. "
            "libcurl uses its own TLS implementation and cannot accept "
            "a Python ssl.SSLContext. To set a custom CA bundle, pass "
            "verify='/path/to/ca-bundle.crt' to request methods or set "
            "CurlOpt.CAINFO via curl_options. To disable verification, "
            "pass verify=False."
        )

    # Pop known keys so they don't leak into curl_cffi Session.__init__
    browser_arg = kwargs.pop('browser', None)
    impersonate = kwargs.pop('impersonate', None)

    # Normalize browser arg
    browser_name = None
    platform = None
    custom_ua = None

    if browser_arg:
        if isinstance(browser_arg, dict):
            custom_ua = browser_arg.get('custom')
            if not custom_ua:
                browser_name = browser_arg.get('browser', 'chrome')
                platform = browser_arg.get('platform')
        elif isinstance(browser_arg, str):
            browser_name = browser_arg
    if not custom_ua and not impersonate and browser_name is None:
        browser_name = 'chrome'

    # Cipher suite
    cipher_suite_raw = kwargs.pop('cipherSuite', None)
    explicit_cipher = cipher_suite_raw is not None

    # Source address normalization
    source_addr = kwargs.pop('source_address', None)
    if isinstance(source_addr, tuple):
        source_addr = source_addr[0]

    # Pop remaining known keys
    # Remove unsupported keys silently (already raised above if truthy)
    kwargs.pop('server_hostname', None)
    kwargs.pop('ssl_context', None)

    # Caller headers
    caller_headers = {}
    if 'headers' in kwargs:
        # Don't pop — let it pass through to Session.__init__
        # But record what the caller explicitly set
        h = kwargs.get('headers', {})
        if h:
            caller_headers = dict(h)

    config = ScraperConfig(
        browser_name=browser_name,
        platform=platform,
        custom_ua=custom_ua,
        impersonate=impersonate,
        explicit_cipherSuite=explicit_cipher,
        cipherSuite=cipher_suite_raw,
        ecdhCurve=kwargs.pop('ecdhCurve', 'prime256v1'),
        source_address=source_addr,
        allow_brotli=kwargs.pop('allow_brotli', True),
        debug=kwargs.pop('debug', False),
        delay=kwargs.pop('delay', None),
        captcha=kwargs.pop('captcha', {}),
        doubleDown=kwargs.pop('doubleDown', True),
        interpreter=kwargs.pop('interpreter', 'js2py'),
        solveDepth=kwargs.pop('solveDepth', 3),
        requestPreHook=kwargs.pop('requestPreHook', None),
        requestPostHook=kwargs.pop('requestPostHook', None),
        disableCloudflareV1=kwargs.pop('disableCloudflareV1', False),
        disableCloudflareV2=kwargs.pop('disableCloudflareV2', False),
        disableCloudflareV3=kwargs.pop('disableCloudflareV3', False),
        disableTurnstile=kwargs.pop('disableTurnstile', False),
        session_refresh_interval=kwargs.pop('session_refresh_interval', 3600),
        auto_refresh_on_403=kwargs.pop('auto_refresh_on_403', True),
        max_403_retries=kwargs.pop('max_403_retries', 3),
        min_request_interval=kwargs.pop('min_request_interval', 0.0),
        max_concurrent_requests=kwargs.pop('max_concurrent_requests', 10),
        rotate_tls_ciphers=kwargs.pop('rotate_tls_ciphers', True),
        rotating_proxies=kwargs.pop('rotating_proxies', None),
        proxy_options=kwargs.pop('proxy_options', {}),
        enable_stealth=kwargs.pop('enable_stealth', False),
        stealth_options=kwargs.pop('stealth_options', {}),
        caller_headers=caller_headers,
        browser_arg_raw=browser_arg,
    )

    return config
