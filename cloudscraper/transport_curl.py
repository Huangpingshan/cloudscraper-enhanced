# ------------------------------------------------------------------------------- #
# transport_curl.py — curl_cffi transport layer for CloudScraper
#
# Isolates all curl_cffi-specific session creation and configuration.
# __init__.py does not directly import curl_cffi internals (except Session base).
# ------------------------------------------------------------------------------- #

from curl_cffi.requests import Session

from .fingerprint import FingerprintProfile, FINGERPRINT_HEADER_KEYS


def apply_profile_headers(session, profile: FingerprintProfile, caller_headers: dict):
    """Write profile headers into session, respecting caller's explicit headers.

    Priority: caller_headers > profile.headers > curl_cffi impersonate defaults
    """
    caller_keys = {k.lower() for k in caller_headers}

    for key, val in profile.headers.items():
        if key.lower() not in caller_keys:
            session.headers[key] = val

    # Caller's explicit headers always win
    for key, val in caller_headers.items():
        session.headers[key] = val


def apply_curl_options(session, profile: FingerprintProfile):
    """Merge profile curl_options into session, preserving caller's existing entries.

    Priority: caller-set curl_options (from Session.__init__) > profile defaults.
    """
    existing = getattr(session, 'curl_options', None) or {}
    merged = dict(existing)
    for key, val in profile.curl_options.items():
        merged.setdefault(key, val)
    session.curl_options = merged
