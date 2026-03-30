# ------------------------------------------------------------------------------- #
# session_state.py — Session cloning and serialization for CloudScraper
#
# Handles sess= cloning (preserving business state, filtering fingerprint state)
# and pickle serialization (whitelist approach, no curl_cffi internals).
# ------------------------------------------------------------------------------- #

from .fingerprint import FINGERPRINT_HEADER_KEYS


def clone_session_attrs(source, target, fingerprint_keys=FINGERPRINT_HEADER_KEYS):
    """Copy business-relevant session attributes from source to target.

    Copies: auth, cert, cookies, hooks, params, proxies
    Copies non-fingerprint headers (e.g. Authorization, X-CSRF-Token)
    Filters: User-Agent, Accept, Accept-Language, Accept-Encoding
    """
    for attr in ('auth', 'cert', 'cookies', 'hooks', 'params', 'proxies'):
        val = getattr(source, attr, None)
        if val is not None:
            setattr(target, attr, val)

    # Copy non-fingerprint headers from source
    source_headers = getattr(source, 'headers', None)
    if source_headers:
        for key in source_headers:
            if key.lower() not in fingerprint_keys:
                target.headers[key] = source_headers[key]


def get_picklable_state(scraper) -> dict:
    """Extract a picklable state dict from a CloudScraper instance.

    Uses a whitelist approach — only known-safe attributes are serialized.
    curl_cffi Session internals (RLock, _local, ssl_context) are excluded.

    State categories:
    - Config layer: _config, _profile → rebuilt via _config_to_kwargs()
    - Session layer: cert, cookies, auth, params, proxies, counters
    - Optional session state: hooks (best-effort, skipped if unpicklable)
    - Transport layer: never serialized
    """
    import pickle as _pickle
    from dataclasses import replace as _dc_replace

    state = {}

    # Config and profile (both are plain dataclasses).
    # requestPreHook / requestPostHook may be unpicklable (lambdas, closures).
    # We strip them from the config copy and serialize them separately with
    # best-effort, mirroring the strategy used for session.hooks.
    config = scraper._config
    pre_hook = config.requestPreHook
    post_hook = config.requestPostHook

    # Always store a config copy with hooks cleared — guaranteed picklable.
    safe_config = _dc_replace(config, requestPreHook=None, requestPostHook=None)
    state['_config'] = safe_config
    state['_profile'] = scraper._profile

    # Best-effort: serialize each request hook individually.
    for key, hook in (('_requestPreHook', pre_hook), ('_requestPostHook', post_hook)):
        if hook is not None:
            try:
                _pickle.dumps(hook)
            except Exception:
                pass
            else:
                state[key] = hook

    # Cookies as serializable list — preserve full metadata so that
    # secure, expires, domain rules etc. survive the round-trip.
    cookies_list = []
    try:
        for cookie in scraper.cookies.jar:
            cookies_list.append({
                'name': cookie.name,
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': getattr(cookie, 'secure', False),
                'expires': getattr(cookie, 'expires', None),
                'discard': getattr(cookie, 'discard', True),
                'version': getattr(cookie, 'version', 0),
                'port': getattr(cookie, 'port', None),
                'port_specified': getattr(cookie, 'port_specified', False),
                'path_specified': getattr(cookie, 'path_specified', True),
                'domain_specified': getattr(cookie, 'domain_specified', False),
                'domain_initial_dot': getattr(cookie, 'domain_initial_dot', False),
                'rest': getattr(cookie, '_rest', {}),
                'comment': getattr(cookie, 'comment', None),
                'comment_url': getattr(cookie, 'comment_url', None),
                'rfc2109': getattr(cookie, 'rfc2109', False),
            })
    except Exception:
        pass
    state['_cookies_list'] = cookies_list

    # Simple attributes (always serializable).
    # Per-request-chain state (_solveDepthCnt, _403_retry_count) now lives in
    # ContextVar, not on the instance.  Locks, semaphores, and ContextVars are
    # not serializable and are re-created in __init__.
    for attr in (
        'auth', 'cert', 'params', 'proxies',
        # Counters (shared instance state)
        'request_count', 'last_403_time',
        'session_start_time', 'last_request_time',
        '_cipher_rotation_count',
    ):
        if hasattr(scraper, attr):
            state[attr] = getattr(scraper, attr)

    # Hooks — best-effort: only serialize if picklable, otherwise skip
    # so that lambdas/closures don't break the entire serialization.
    hooks = getattr(scraper, 'hooks', None)
    if hooks is not None:
        try:
            _pickle.dumps(hooks)
        except Exception:
            pass
        else:
            state['hooks'] = hooks

    # Non-fingerprint runtime headers (e.g. Authorization, X-CSRF-Token)
    # Caller-supplied fingerprint headers are restored from _config.caller_headers
    # via _config_to_kwargs(), so we only need business headers here.
    headers_dict = {}
    try:
        for key in scraper.headers:
            if key.lower() not in FINGERPRINT_HEADER_KEYS:
                headers_dict[key] = scraper.headers[key]
    except Exception:
        pass
    state['_headers_dict'] = headers_dict

    return state


def restore_from_state(state: dict):
    """Restore a CloudScraper instance from a pickled state dict.

    Rebuilds the curl_cffi transport from _config, then restores
    cookies, counters, and non-fingerprint headers.
    """
    # Import here to avoid circular imports
    from cloudscraper import CloudScraper
    from .config import ScraperConfig

    config = state.get('_config')
    if not isinstance(config, ScraperConfig):
        # Fallback: create with defaults
        return CloudScraper()

    # Re-inject request hooks that were serialized separately.
    from dataclasses import replace as _dc_replace
    pre_hook = state.get('_requestPreHook')
    post_hook = state.get('_requestPostHook')
    if pre_hook is not None or post_hook is not None:
        config = _dc_replace(
            config,
            requestPreHook=pre_hook,
            requestPostHook=post_hook,
        )

    # Rebuild kwargs from config for CloudScraper.__init__
    kwargs = _config_to_kwargs(config)
    scraper = CloudScraper(**kwargs)

    # Restore cookies with full metadata (secure, expires, etc.)
    from http.cookiejar import Cookie
    for cd in state.get('_cookies_list', []):
        try:
            cookie = Cookie(
                version=cd.get('version', 0),
                name=cd['name'],
                value=cd['value'],
                port=cd.get('port'),
                port_specified=cd.get('port_specified', False),
                domain=cd.get('domain', ''),
                domain_specified=cd.get('domain_specified', False),
                domain_initial_dot=cd.get('domain_initial_dot', False),
                path=cd.get('path', '/'),
                path_specified=cd.get('path_specified', True),
                secure=cd.get('secure', False),
                expires=cd.get('expires'),
                discard=cd.get('discard', True),
                comment=cd.get('comment'),
                comment_url=cd.get('comment_url'),
                rest=cd.get('rest', {}),
                rfc2109=cd.get('rfc2109', False),
            )
            scraper.cookies.jar.set_cookie(cookie)
        except Exception:
            pass

    # Restore counters (shared instance state only — per-request-chain state
    # lives in ContextVar and is not serialized)
    for attr in (
        'request_count', 'last_403_time',
        'session_start_time', 'last_request_time',
        '_cipher_rotation_count',
    ):
        if attr in state:
            setattr(scraper, attr, state[attr])

    # Restore non-fingerprint runtime headers (e.g. Authorization, X-CSRF-Token)
    for key, val in state.get('_headers_dict', {}).items():
        scraper.headers[key] = val

    # Restore session-layer attributes
    for attr in ('auth', 'cert', 'params', 'proxies', 'hooks'):
        if attr in state:
            setattr(scraper, attr, state[attr])

    return scraper


def _config_to_kwargs(config) -> dict:
    """Convert a ScraperConfig back to kwargs for CloudScraper.__init__."""
    kwargs = {}

    # Reconstruct browser arg
    if config.custom_ua:
        kwargs['browser'] = {'custom': config.custom_ua}
    elif config.browser_name:
        browser_dict = {'browser': config.browser_name}
        if config.platform:
            browser_dict['platform'] = config.platform
        kwargs['browser'] = browser_dict

    if config.impersonate:
        kwargs['impersonate'] = config.impersonate
    if config.explicit_cipherSuite and config.cipherSuite:
        kwargs['cipherSuite'] = config.cipherSuite
    if config.ecdhCurve != 'prime256v1':
        kwargs['ecdhCurve'] = config.ecdhCurve
    if config.source_address:
        kwargs['source_address'] = config.source_address

    kwargs['allow_brotli'] = config.allow_brotli
    kwargs['debug'] = config.debug
    kwargs['delay'] = config.delay
    kwargs['captcha'] = config.captcha
    kwargs['doubleDown'] = config.doubleDown
    kwargs['interpreter'] = config.interpreter
    kwargs['solveDepth'] = config.solveDepth
    if config.requestPreHook is not None:
        kwargs['requestPreHook'] = config.requestPreHook
    if config.requestPostHook is not None:
        kwargs['requestPostHook'] = config.requestPostHook
    kwargs['disableCloudflareV1'] = config.disableCloudflareV1
    kwargs['disableCloudflareV2'] = config.disableCloudflareV2
    kwargs['disableCloudflareV3'] = config.disableCloudflareV3
    kwargs['disableTurnstile'] = config.disableTurnstile
    kwargs['session_refresh_interval'] = config.session_refresh_interval
    kwargs['auto_refresh_on_403'] = config.auto_refresh_on_403
    kwargs['max_403_retries'] = config.max_403_retries
    kwargs['min_request_interval'] = config.min_request_interval
    kwargs['max_concurrent_requests'] = config.max_concurrent_requests
    kwargs['rotate_tls_ciphers'] = config.rotate_tls_ciphers
    kwargs['enable_stealth'] = config.enable_stealth

    if config.rotating_proxies:
        kwargs['rotating_proxies'] = config.rotating_proxies
    if config.proxy_options:
        kwargs['proxy_options'] = config.proxy_options
    if config.stealth_options:
        kwargs['stealth_options'] = config.stealth_options

    # Rebuild headers= from caller_headers so that caller-supplied
    # fingerprint headers (e.g. explicit User-Agent, Accept) flow through
    # apply_profile_headers() with proper priority on reconstruction.
    if config.caller_headers:
        kwargs['headers'] = dict(config.caller_headers)

    return kwargs
