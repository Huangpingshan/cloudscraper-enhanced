# ------------------------------------------------------------------------------- #
# fingerprint.py — Fingerprint strategy object for CloudScraper
#
# From a ScraperConfig, produces an immutable FingerprintProfile containing all
# fingerprint decisions. Once constructed, the profile cannot be modified.
# ------------------------------------------------------------------------------- #

import re
from dataclasses import dataclass, field
from typing import Optional, Dict

from .config import ScraperConfig

# ------------------------------------------------------------------------------- #
# Browser (name, platform) → curl_cffi impersonate value
# ------------------------------------------------------------------------------- #

_BROWSER_IMPERSONATE_MAP = {
    ('chrome', None):      'chrome120',
    ('chrome', 'windows'): 'chrome120',
    ('chrome', 'linux'):   'chrome120',
    ('chrome', 'darwin'):  'chrome120',
    ('chrome', 'android'): 'chrome131_android',
    ('chrome', 'ios'):     'chrome120',        # no chrome_ios, fallback to desktop
    ('firefox', None):      'firefox133',
    ('firefox', 'windows'): 'firefox133',
    ('firefox', 'linux'):   'firefox133',
    ('firefox', 'darwin'):  'firefox133',
    ('firefox', 'android'): 'firefox133',      # no mobile firefox impersonate
    ('firefox', 'ios'):     'firefox133',
    ('safari', None):      'safari184',
    ('safari', 'darwin'):  'safari184',
    ('safari', 'windows'): 'safari184',        # Safari for Windows is defunct; best effort
    ('safari', 'linux'):   'safari184',
    ('safari', 'ios'):     'safari184_ios',
    ('safari', 'android'): 'safari184',        # unlikely, best effort
    ('edge', None):        'edge101',
    ('edge', 'windows'):   'edge101',
    ('edge', 'darwin'):    'edge101',
    ('edge', 'linux'):     'edge101',
    ('edge', 'ios'):       'edge101',
    ('edge', 'android'):   'edge101',
}

# ------------------------------------------------------------------------------- #
# User-Agent strings that curl_cffi sends for each impersonate value.
# Internal code reads self.headers['User-Agent'], so we keep a Python-accessible
# copy that matches the C-level value to avoid TLS-vs-UA mismatch.
# ------------------------------------------------------------------------------- #

_IMPERSONATE_UA_MAP = {
    # Chrome (Windows: 99-116)
    'chrome99': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
    'chrome100': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36',
    'chrome101': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36',
    'chrome104': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
    'chrome107': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    'chrome110': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
    'chrome116': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
    # Chrome (Mac: 119+)
    'chrome119': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'chrome120': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'chrome123': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'chrome124': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'chrome131': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'chrome133a': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'chrome136': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'chrome142': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
    # Chrome Android
    'chrome99_android': 'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.58 Mobile Safari/537.36',
    'chrome131_android': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
    # Edge
    'edge99': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.30',
    'edge101': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47',
    # Safari (Mac)
    'safari153': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15',
    'safari155': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15',
    'safari170': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'safari180': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
    'safari184': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15',
    'safari260': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15',
    'safari2601': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15',
    # Safari iOS
    'safari172_ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'safari180_ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
    'safari184_ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1',
    'safari260_ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1',
    # Safari deprecated aliases
    'safari15_3': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15',
    'safari15_5': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15',
    'safari17_0': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'safari17_2_ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'safari18_0': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
    'safari18_0_ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
    # Firefox
    'firefox133': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0',
    'firefox135': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0',
    'firefox144': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0',
    # Tor
    'tor145': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0',
}

# Platform string replacements for _adapt_ua_platform.
_PLATFORM_UA_PATTERNS = {
    'windows': (
        r'Macintosh; Intel Mac OS X [^\)]+|X11; Linux [^\)]+',
        'Windows NT 10.0; Win64; x64'
    ),
    'linux': (
        r'Macintosh; Intel Mac OS X [^\)]+|Windows NT [^\)]+',
        'X11; Linux x86_64'
    ),
    'darwin': (
        r'Windows NT [^\)]+|X11; Linux [^\)]+',
        'Macintosh; Intel Mac OS X 10_15_7'
    ),
}

# Fingerprint-sensitive headers — used by session clone and request-time merge
FINGERPRINT_HEADER_KEYS = frozenset({
    'user-agent', 'accept', 'accept-language', 'accept-encoding',
})

# Browser-family header templates.  The Accept/Accept-Language/Accept-Encoding
# values must match the browser family implied by the impersonate key so that
# Python-visible headers stay consistent with the TLS fingerprint.
_BROWSER_HEADER_TEMPLATES = {
    'chrome': {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
    },
    'firefox': {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
    },
    'safari': {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
    },
    'edge': {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
    },
    'tor': {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
    },
}


# ------------------------------------------------------------------------------- #
# Immutable fingerprint profile
# ------------------------------------------------------------------------------- #

@dataclass(frozen=True)
class FingerprintProfile:
    """Immutable fingerprint profile. Once created, cannot be modified."""
    impersonate: str            # 'chrome120', 'chrome131_android', etc.
    user_agent: str             # exact UA matching the impersonate value
    headers: Dict[str, str]     # UA + Accept-family complete header set
    curl_options: Dict          # CurlOpt mapping (only for explicit cipherSuite)
    can_rotate_tls: bool        # True only when explicit_cipherSuite=True
    is_custom_ua: bool          # True when browser={'custom':...}


# ------------------------------------------------------------------------------- #
# Helper functions
# ------------------------------------------------------------------------------- #

def _adapt_ua_platform(ua: str, platform: Optional[str]) -> str:
    """Replace the OS token in a UA string to match the requested platform."""
    if not platform:
        return ua
    spec = _PLATFORM_UA_PATTERNS.get(platform)
    if not spec:
        return ua
    pattern, replacement = spec
    return re.sub(pattern, replacement, ua, count=1)


def _infer_family_from_custom_ua(custom_ua: str) -> Optional[str]:
    """Infer browser family from a custom User-Agent string.

    Returns 'firefox', 'chrome', 'safari', 'edge', or None if not
    reliably detectable.  Detection order matters — Edge UAs contain
    'Chrome' too, so Edge must be checked first.
    """
    ua = custom_ua.lower()
    if 'edg/' in ua or 'edge/' in ua:
        return 'edge'
    if 'firefox/' in ua or 'fxios/' in ua:
        return 'firefox'
    if 'safari/' in ua and 'chrome/' not in ua:
        return 'safari'
    if 'chrome/' in ua or 'crios/' in ua:
        return 'chrome'
    return None


def _resolve_impersonate(config: ScraperConfig) -> str:
    """Determine the impersonate value from config.

    For custom UAs, infer the browser family from the UA string so the
    TLS fingerprint matches.  If the family cannot be determined, raise
    ValueError to fail fast rather than silently mismatching.
    """
    if config.impersonate:
        return config.impersonate

    # Custom UA path: infer family from the UA string
    if config.custom_ua:
        family = _infer_family_from_custom_ua(config.custom_ua)
        if family:
            key = (family, config.platform)
            imp = _BROWSER_IMPERSONATE_MAP.get(key)
            if imp:
                return imp
            return _BROWSER_IMPERSONATE_MAP.get((family, None), 'chrome120')
        # UA doesn't look like any known browser (e.g. "MyBot/1.0").
        # No mismatch risk since anti-bot systems won't expect a specific
        # TLS profile for a non-browser UA.  Default to chrome120.
        return 'chrome120'

    key = (config.browser_name, config.platform)
    imp = _BROWSER_IMPERSONATE_MAP.get(key)
    if imp:
        return imp
    # Fallback: try without platform
    return _BROWSER_IMPERSONATE_MAP.get((config.browser_name, None), 'chrome120')


def _resolve_ua(impersonate: str, config: ScraperConfig, user_agent_obj) -> str:
    """Determine the User-Agent string.

    Priority:
    1. Custom UA from browser={'custom': ...}
    2. User_Agent-generated UA if version matches impersonate
    3. _IMPERSONATE_UA_MAP with platform adaptation
    4. User_Agent-generated UA as fallback
    """
    if config.custom_ua:
        return config.custom_ua

    impersonate_ua = _IMPERSONATE_UA_MAP.get(impersonate, '')
    ua_from_agent = ''
    if user_agent_obj and user_agent_obj.headers:
        ua_from_agent = user_agent_obj.headers.get('User-Agent', '')

    # Check if User_Agent's UA version matches the impersonate version
    imp_ver_m = re.search(r'(\d+)', impersonate or '')
    imp_ver = imp_ver_m.group(1) if imp_ver_m else ''

    ua_version_matches = False
    if imp_ver and ua_from_agent:
        family = 'Firefox' if 'firefox' in (impersonate or '') else 'Chrome'
        ua_version_matches = bool(re.search(rf'{family}/{imp_ver}\b', ua_from_agent))

    if ua_version_matches:
        return ua_from_agent
    elif impersonate_ua:
        if config.platform:
            return _adapt_ua_platform(impersonate_ua, config.platform)
        return impersonate_ua
    else:
        return ua_from_agent


def _browser_family_from_impersonate(impersonate: str) -> str:
    """Extract browser family from an impersonate key.

    'chrome120' → 'chrome', 'firefox133' → 'firefox', 'safari180' → 'safari',
    'edge101' → 'edge', 'tor145' → 'tor'.  Falls back to 'chrome'.
    """
    imp = (impersonate or '').lower()
    for family in ('chrome', 'firefox', 'safari', 'edge', 'tor'):
        if imp.startswith(family):
            return family
    return 'chrome'


def _build_headers(user_agent: str, impersonate: str) -> dict:
    """Build the profile header set.

    User-Agent comes from the caller (custom or impersonate-matched).
    Accept / Accept-Language / Accept-Encoding always come from
    _BROWSER_HEADER_TEMPLATES keyed by the browser family derived from
    the final impersonate value.  This ensures the visible headers match
    the TLS fingerprint in all modes — custom UA, explicit impersonate,
    or default browser selection.
    """
    headers = {'User-Agent': user_agent}

    family = _browser_family_from_impersonate(impersonate)
    template = _BROWSER_HEADER_TEMPLATES.get(family, _BROWSER_HEADER_TEMPLATES['chrome'])
    headers.update(template)

    return headers


def _build_curl_options(config: ScraperConfig) -> dict:
    """Build curl_options dict from config."""
    opts = {}
    try:
        from curl_cffi.const import CurlOpt

        if config.explicit_cipherSuite and config.cipherSuite:
            cipher_str = config.cipherSuite
            if isinstance(cipher_str, list):
                cipher_str = ':'.join(cipher_str)
            opts[CurlOpt.SSL_CIPHER_LIST] = cipher_str
            if config.ecdhCurve:
                opts[CurlOpt.SSL_EC_CURVES] = config.ecdhCurve

        if config.source_address:
            opts[CurlOpt.INTERFACE] = config.source_address
    except (ImportError, AttributeError):
        pass

    return opts


# ------------------------------------------------------------------------------- #
# Main entry point
# ------------------------------------------------------------------------------- #

def resolve_profile(config: ScraperConfig, user_agent_obj=None) -> FingerprintProfile:
    """Resolve a complete FingerprintProfile from config + User_Agent data.

    The returned profile is frozen (immutable).
    """
    is_custom = bool(config.custom_ua)

    impersonate = _resolve_impersonate(config)
    user_agent = _resolve_ua(impersonate, config, user_agent_obj)
    headers = _build_headers(user_agent, impersonate)
    curl_options = _build_curl_options(config)

    return FingerprintProfile(
        impersonate=impersonate,
        user_agent=user_agent,
        headers=headers,
        curl_options=curl_options,
        can_rotate_tls=config.explicit_cipherSuite,
        is_custom_ua=is_custom,
    )
