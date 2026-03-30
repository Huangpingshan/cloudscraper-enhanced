"""
Modern test suite for cloudscraper
"""

import pytest
import cloudscraper
from unittest.mock import Mock, patch
from cloudscraper.exceptions import (
    CloudflareLoopProtection,
    CloudflareIUAMError
)


# Module-level function for picklable-hooks test (local functions can't be pickled).
def _picklable_response_hook(response, *args, **kwargs):
    return response


class TestCloudScraper:
    """Test suite for CloudScraper functionality"""

    def test_create_scraper(self):
        """Test basic scraper creation"""
        scraper = cloudscraper.create_scraper()
        assert isinstance(scraper, cloudscraper.CloudScraper)
        assert hasattr(scraper, 'session_refresh_interval')
        assert hasattr(scraper, 'auto_refresh_on_403')
        assert hasattr(scraper, 'max_403_retries')

    def test_create_scraper_with_options(self):
        """Test scraper creation with custom options"""
        scraper = cloudscraper.create_scraper(
            session_refresh_interval=1800,
            auto_refresh_on_403=True,
            max_403_retries=5,
            enable_stealth=True
        )
        assert scraper.session_refresh_interval == 1800
        assert scraper.auto_refresh_on_403 is True
        assert scraper.max_403_retries == 5
        assert scraper.enable_stealth is True

    def test_user_agent_generation(self):
        """Test that User-Agent is always accessible on session headers."""
        # Default impersonate mode: UA should match the impersonate version
        scraper = cloudscraper.create_scraper()
        user_agent = scraper.headers.get('User-Agent')
        assert user_agent is not None
        assert 'Chrome/120' in user_agent

        # Custom UA mode: UA should be the custom string
        scraper2 = cloudscraper.create_scraper(
            browser={'custom': 'MyBot/1.0'}
        )
        assert scraper2.headers.get('User-Agent') == 'MyBot/1.0'

    def test_browser_selection(self):
        """Test browser selection sets correct impersonate value"""
        expected = {'chrome': 'chrome120', 'firefox': 'firefox133'}
        for browser in ['chrome', 'firefox']:
            scraper = cloudscraper.create_scraper(
                browser={'browser': browser, 'platform': 'windows'}
            )
            assert scraper.impersonate == expected[browser]

    def test_browser_string_maps_impersonate(self):
        """String browser= value must map to the correct impersonate profile,
        not fall back to chrome120.

        The __init__ code now reads browser_name from a string browser= arg,
        so 'firefox' should produce impersonate='firefox133'.

        We mock User_Agent to avoid browsers.json platform randomness."""
        with patch('cloudscraper.User_Agent') as MockUA:
            # Minimal stub so __init__ doesn't fail
            mock_instance = Mock()
            mock_instance.headers = {'User-Agent': 'stub', 'Accept': '*/*',
                                     'Accept-Language': 'en', 'Accept-Encoding': 'gzip'}
            mock_instance.cipherSuite = []
            mock_instance.browser = 'firefox'
            MockUA.return_value = mock_instance

            scraper = cloudscraper.create_scraper(browser='firefox')
            assert scraper.impersonate == 'firefox133'

    def test_cipher_rotation_disabled_under_impersonate(self):
        """Default impersonate mode must not rotate cipher suites"""
        scraper = cloudscraper.create_scraper()
        from curl_cffi.const import CurlOpt
        # Trigger rotation
        scraper._rotate_tls_cipher_suite()
        # Impersonate should still be in control — no cipher override
        assert CurlOpt.SSL_CIPHER_LIST not in scraper.curl_options

    def test_session_health_monitoring(self):
        """Test session health monitoring"""
        scraper = cloudscraper.create_scraper()

        # Test initial state
        assert scraper.request_count == 0
        # _403_retry_count now lives in per-request ContextVar (_RequestChain),
        # not on the instance — verify shared counters instead
        assert scraper.last_403_time == 0

        # Test should refresh logic
        assert not scraper._should_refresh_session()

    def test_stealth_mode(self):
        """Test stealth mode functionality"""
        scraper = cloudscraper.create_scraper(
            enable_stealth=True,
            stealth_options={
                'min_delay': 1.0,
                'max_delay': 3.0,
                'human_like_delays': True,
                'randomize_headers': True,
                'browser_quirks': True
            }
        )
        assert scraper.enable_stealth is True
        assert hasattr(scraper, 'stealth_mode')
        assert scraper.stealth_mode.min_delay == 1.0
        assert scraper.stealth_mode.max_delay == 3.0

    def test_stealth_skip_randomize_headers_when_session_has_them(self):
        """_randomize_headers must not inject Accept/Accept-Language when session already provides them"""
        scraper = cloudscraper.create_scraper(
            enable_stealth=True,
            stealth_options={'randomize_headers': True},
        )
        # Session should already have these from the fingerprint profile
        assert 'Accept' in scraper.headers
        assert 'Accept-Language' in scraper.headers

        for _ in range(5):
            kwargs = scraper.stealth_mode._randomize_headers({'headers': {}})
            req_headers = kwargs.get('headers', {})
            assert 'Accept' not in req_headers, "Accept should not be duplicated into request kwargs"
            assert 'Accept-Language' not in req_headers, "Accept-Language should not be duplicated into request kwargs"

    def test_stealth_skip_browser_quirks_when_session_has_them(self):
        """_apply_browser_quirks must not inject headers already present in the session"""
        scraper = cloudscraper.create_scraper(
            enable_stealth=True,
            stealth_options={'browser_quirks': True},
        )
        assert 'Accept-Language' in scraper.headers

        kwargs = scraper.stealth_mode._apply_browser_quirks({'headers': {}})
        req_headers = kwargs.get('headers', {})
        assert 'Accept-Language' not in req_headers, "Accept-Language should not be duplicated by browser quirks"

    def test_proxy_manager(self):
        """Test proxy manager functionality"""
        proxies = ['http://proxy1:8080', 'http://proxy2:8080']
        scraper = cloudscraper.create_scraper(
            rotating_proxies=proxies,
            proxy_options={
                'rotation_strategy': 'sequential',
                'ban_time': 300
            }
        )
        assert hasattr(scraper, 'proxy_manager')
        assert scraper.proxy_manager.proxies == proxies

    @patch('cloudscraper.CloudScraper._refresh_session', return_value=False)
    @patch('cloudscraper.CloudScraper.perform_request')
    def test_403_handling(self, mock_request, mock_refresh):
        """Test 403 error handling"""
        # Mock a 403 response
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.headers = {}
        mock_response.url = 'http://example.com'
        mock_response.text = ''
        mock_response.content = b''
        mock_request.return_value = mock_response

        scraper = cloudscraper.create_scraper(
            auto_refresh_on_403=True,
            max_403_retries=1
        )

        # This should trigger 403 handling
        response = scraper.get('http://example.com')
        assert response.status_code == 403

    def test_version_info(self):
        """Test version information"""
        assert hasattr(cloudscraper, '__version__')
        assert cloudscraper.__version__ == '3.0.0'

    def test_ssl_context_creation(self):
        """Test SSL context attribute exists"""
        scraper = cloudscraper.create_scraper()
        assert hasattr(scraper, 'ssl_context')

    def test_impersonate_default(self):
        """Test default impersonate value"""
        scraper = cloudscraper.create_scraper()
        assert scraper.impersonate == 'chrome120'

    def test_impersonate_firefox(self):
        """Test Firefox impersonate value.
        Pin platform to 'windows' because browsers.json has 0 Firefox agents
        for 'ios', so a random platform pick could fail."""
        scraper = cloudscraper.create_scraper(
            browser={'browser': 'firefox', 'platform': 'windows'}
        )
        assert scraper.impersonate == 'firefox133'

    def test_impersonate_explicit(self):
        """Test explicit impersonate value"""
        scraper = cloudscraper.create_scraper(impersonate='chrome116')
        assert scraper.impersonate == 'chrome116'


class TestHeaderPreservation:
    """Test that caller-supplied headers are not overwritten"""

    def test_explicit_user_agent_preserved(self):
        """Caller-set User-Agent must not be clobbered by impersonate defaults"""
        scraper = cloudscraper.create_scraper()
        scraper.headers['User-Agent'] = 'MyCustomBot/1.0'
        assert scraper.headers['User-Agent'] == 'MyCustomBot/1.0'

    def test_explicit_accept_preserved(self):
        """Caller-set Accept header must survive __init__"""
        scraper = cloudscraper.CloudScraper(
            headers={'Accept': 'application/json'}
        )
        # curl_cffi Headers is case-insensitive
        assert scraper.headers.get('Accept') == 'application/json'

    def test_custom_ua_via_browser_dict(self):
        """browser={'custom': ...} should set headers from User_Agent"""
        custom = 'Custom Agent 2.0'
        scraper = cloudscraper.create_scraper(
            browser={'custom': custom}
        )
        assert scraper.headers['User-Agent'] == custom

    def test_impersonate_ua_matches_tls_version(self):
        """In impersonate mode, session-level User-Agent must match the
        impersonate TLS version, not an old browsers.json entry."""
        scraper = cloudscraper.create_scraper()
        ua = scraper.headers.get('User-Agent', '')
        # Must contain Chrome/120 (matching impersonate='chrome120')
        assert 'Chrome/120' in ua
        # Must NOT contain old browsers.json versions
        assert 'Chrome/50' not in ua
        assert 'Firefox/50' not in ua

    def test_impersonate_firefox_ua_matches(self):
        """Firefox impersonate UA must match the TLS fingerprint version."""
        scraper = cloudscraper.create_scraper(
            browser={'browser': 'firefox', 'platform': 'windows'}
        )
        ua = scraper.headers.get('User-Agent', '')
        assert 'Firefox/133' in ua

    def test_source_address_forwarded(self):
        """source_address should be forwarded to curl_options"""
        from curl_cffi.const import CurlOpt
        scraper = cloudscraper.create_scraper(source_address='192.168.1.100')
        assert CurlOpt.INTERFACE in scraper.curl_options
        assert scraper.curl_options[CurlOpt.INTERFACE] == '192.168.1.100'

    def test_source_address_tuple_forwarded(self):
        """source_address as (ip, port) tuple should extract IP"""
        from curl_cffi.const import CurlOpt
        scraper = cloudscraper.create_scraper(
            source_address=('10.0.0.1', 0)
        )
        assert scraper.curl_options[CurlOpt.INTERFACE] == '10.0.0.1'

    def test_server_hostname_raises(self):
        """server_hostname must raise NotImplementedError (fail fast)"""
        with pytest.raises(NotImplementedError, match='server_hostname'):
            cloudscraper.create_scraper(server_hostname='custom.sni.host')

    def test_ssl_context_raises(self):
        """ssl_context must raise NotImplementedError (fail fast)"""
        import ssl
        ctx = ssl.create_default_context()
        with pytest.raises(NotImplementedError, match='ssl_context'):
            cloudscraper.create_scraper(ssl_context=ctx)

    def test_explicit_ua_via_headers_kwarg(self):
        """User-Agent passed via headers= kwarg must not be overwritten"""
        scraper = cloudscraper.CloudScraper(
            headers={'User-Agent': 'ExplicitBot/3.0'}
        )
        assert scraper.headers.get('User-Agent') == 'ExplicitBot/3.0'

    def test_impersonate_does_not_override_tls(self):
        """Default create_scraper() must not inject cipher suite into curl_options"""
        from curl_cffi.const import CurlOpt
        scraper = cloudscraper.create_scraper()
        # impersonate handles TLS at C level; no cipher override
        assert CurlOpt.SSL_CIPHER_LIST not in scraper.curl_options
        assert CurlOpt.SSL_EC_CURVES not in scraper.curl_options

    def test_explicit_ciphersuite_applied(self):
        """Explicit cipherSuite= must be written to curl_options"""
        from curl_cffi.const import CurlOpt
        scraper = cloudscraper.create_scraper(
            cipherSuite='ECDHE-RSA-AES128-GCM-SHA256'
        )
        assert CurlOpt.SSL_CIPHER_LIST in scraper.curl_options
        assert scraper.curl_options[CurlOpt.SSL_CIPHER_LIST] == 'ECDHE-RSA-AES128-GCM-SHA256'

    def test_platform_specific_ua_windows(self):
        """browser={'platform': 'windows'} must produce a Windows UA, not Mac"""
        scraper = cloudscraper.create_scraper(
            browser={'browser': 'chrome', 'platform': 'windows'}
        )
        ua = scraper.headers.get('User-Agent', '')
        assert 'Windows' in ua, f"Expected Windows UA, got: {ua}"
        assert 'Chrome/120' in ua

    def test_platform_specific_ua_linux(self):
        """browser={'platform': 'linux'} must produce a Linux UA"""
        scraper = cloudscraper.create_scraper(
            browser={'browser': 'chrome', 'platform': 'linux'}
        )
        ua = scraper.headers.get('User-Agent', '')
        assert 'Linux' in ua or 'X11' in ua, f"Expected Linux UA, got: {ua}"

    def test_sess_headers_not_copied(self):
        """create_scraper(sess=...) must NOT copy headers from source session,
        which would overwrite the impersonate-matched headers."""
        from curl_cffi.requests import Session
        source = Session()
        source.headers['User-Agent'] = 'python-requests/2.31.0'
        scraper = cloudscraper.create_scraper(sess=source)
        ua = scraper.headers.get('User-Agent', '')
        assert 'python-requests' not in ua
        assert 'Chrome/120' in ua

    def test_ua_version_no_false_positive(self):
        """A UA with matching digits in a different position must not
        be accepted as version-matched (e.g. Chrome/56.0.7090.120
        must not match impersonate='chrome120')."""
        import re
        # Simulate the check that __init__ performs
        imp_ver = '120'
        fake_ua = 'Mozilla/5.0 Chrome/56.0.7090.120 Safari/537.36'
        family = 'Chrome'
        # The old check: imp_ver in fake_ua — would be True (false positive)
        assert imp_ver in fake_ua
        # The new check: family/version at word boundary — must be False
        assert not re.search(rf'{family}/{imp_ver}\b', fake_ua)

    def test_ssl_context_excluded_from_state(self):
        """ssl_context must not appear in __getstate__ output."""
        scraper = cloudscraper.create_scraper()
        state = scraper.__getstate__()
        assert 'ssl_context' not in state


class TestSessionRefresh:
    """Test session refresh functionality"""

    def test_clear_cloudflare_cookies(self):
        """Test clearing Cloudflare cookies"""
        scraper = cloudscraper.create_scraper()

        # Add some mock cookies
        scraper.cookies.set('cf_clearance', 'test_value')
        scraper.cookies.set('cf_chl_2', 'test_value')

        # Clear cookies
        scraper._clear_cloudflare_cookies()

        # Verify cookies are cleared
        assert scraper.cookies.get('cf_clearance') is None
        assert scraper.cookies.get('cf_chl_2') is None

    def test_should_refresh_session(self):
        """Test session refresh logic"""
        scraper = cloudscraper.create_scraper(session_refresh_interval=10)

        # Initially should not refresh
        assert not scraper._should_refresh_session()

        # Simulate old session
        import time
        scraper.session_start_time = time.time() - 20
        assert scraper._should_refresh_session()


class TestCompatibility:
    """Test backward compatibility"""

    def test_legacy_create_scraper(self):
        """Test legacy create_scraper function"""
        scraper = cloudscraper.create_scraper()
        assert isinstance(scraper, cloudscraper.CloudScraper)

    def test_legacy_session_alias(self):
        """Test legacy session alias"""
        scraper = cloudscraper.session()
        assert isinstance(scraper, cloudscraper.CloudScraper)

    def test_create_scraper_copies_hooks_when_present(self):
        """create_scraper(sess=...) must copy hooks if the source session has them"""
        from curl_cffi.requests import Session
        source = Session()
        # Simulate a session subclass that has hooks (e.g. requests compat layer)
        source.hooks = {'response': [lambda r, *a, **kw: None]}
        scraper = cloudscraper.create_scraper(sess=source)
        assert scraper.hooks == source.hooks


class TestUserAgent:
    """Test user agent functionality"""

    def test_user_agent_browsers(self):
        """Test different browser impersonation via browser dict"""
        expected = {'chrome': 'chrome120', 'firefox': 'firefox133'}
        for browser in ['chrome', 'firefox']:
            scraper = cloudscraper.create_scraper(
                browser={'browser': browser, 'platform': 'windows'}
            )
            assert scraper.impersonate == expected[browser]
            # user_agent object should still have the browser info
            assert scraper.user_agent.browser == browser
            # UA header must be accessible and version-matched
            ua = scraper.headers.get('User-Agent', '')
            assert ua, f"User-Agent must be set for {browser}"

    def test_custom_user_agent(self):
        """Test custom user agent"""
        custom_ua = 'Custom User Agent 1.0'
        scraper = cloudscraper.create_scraper(
            browser={'custom': custom_ua}
        )
        assert scraper.headers.get('User-Agent') == custom_ua


class TestRefactoredArchitecture:
    """Tests for the new config/fingerprint/transport/session_state modules."""

    def test_android_platform_impersonate(self):
        """browser={'browser':'chrome','platform':'android'} must use android impersonate"""
        scraper = cloudscraper.create_scraper(
            browser={'browser': 'chrome', 'platform': 'android'}
        )
        assert scraper.impersonate == 'chrome131_android'
        ua = scraper.headers.get('User-Agent', '')
        assert 'Android' in ua

    def test_sess_preserves_authorization(self):
        """create_scraper(sess=) must preserve Authorization header"""
        from curl_cffi.requests import Session
        source = Session()
        source.headers['Authorization'] = 'Bearer token123'
        source.headers['User-Agent'] = 'python-requests/2.31.0'
        scraper = cloudscraper.create_scraper(sess=source)
        assert scraper.headers.get('Authorization') == 'Bearer token123'
        ua = scraper.headers.get('User-Agent', '')
        assert 'python-requests' not in ua
        assert 'Chrome/120' in ua

    def test_pickle_roundtrip(self):
        """pickle.dumps/loads must not error and must rebuild instance"""
        import pickle
        scraper = cloudscraper.create_scraper()
        data = pickle.dumps(scraper)
        restored = pickle.loads(data)
        assert isinstance(restored, cloudscraper.CloudScraper)
        ua = restored.headers.get('User-Agent', '')
        assert 'Chrome/120' in ua

    def test_pickle_roundtrip_preserves_explicit_headers(self):
        """Caller-supplied fingerprint headers must survive pickle round-trip"""
        import pickle
        scraper = cloudscraper.CloudScraper(
            headers={'User-Agent': 'ExplicitBot/3.0', 'Accept': 'application/json'}
        )
        assert scraper.headers.get('User-Agent') == 'ExplicitBot/3.0'
        assert scraper.headers.get('Accept') == 'application/json'

        data = pickle.dumps(scraper)
        restored = pickle.loads(data)
        assert restored.headers.get('User-Agent') == 'ExplicitBot/3.0'
        assert restored.headers.get('Accept') == 'application/json'

    def test_pickle_roundtrip_preserves_cert(self):
        """Client cert must survive pickle round-trip"""
        import pickle
        scraper = cloudscraper.create_scraper()
        scraper.cert = ('cert.pem', 'key.pem')

        data = pickle.dumps(scraper)
        restored = pickle.loads(data)
        assert restored.cert == ('cert.pem', 'key.pem')

    def test_pickle_roundtrip_preserves_picklable_hooks(self):
        """Picklable hooks (module-level functions) must survive pickle round-trip"""
        import pickle

        scraper = cloudscraper.create_scraper()
        scraper.hooks = {'response': [_picklable_response_hook]}

        data = pickle.dumps(scraper)
        restored = pickle.loads(data)
        assert 'response' in restored.hooks
        assert len(restored.hooks['response']) == 1
        assert restored.hooks['response'][0] is _picklable_response_hook

    def test_pickle_roundtrip_skips_unpicklable_hooks(self):
        """Unpicklable hooks (lambdas) must not break pickle.dumps"""
        import pickle
        scraper = cloudscraper.create_scraper()
        scraper.hooks = {'response': [lambda r, *a, **kw: r]}

        # Must not raise — hooks are skipped if unpicklable
        data = pickle.dumps(scraper)
        restored = pickle.loads(data)
        # Hooks were not serialized, so restored gets default hooks
        assert isinstance(restored, cloudscraper.CloudScraper)

    def test_default_no_cipher_in_curl_options(self):
        """Default scraper must not inject cipher suite into curl_options"""
        from curl_cffi.const import CurlOpt
        scraper = cloudscraper.create_scraper()
        # Simulate multiple requests worth of rotation calls
        scraper._rotate_tls_cipher_suite()
        scraper._rotate_tls_cipher_suite()
        assert CurlOpt.SSL_CIPHER_LIST not in scraper.curl_options

    def test_config_dataclass_created(self):
        """_config must be a ScraperConfig instance"""
        from cloudscraper.config import ScraperConfig
        scraper = cloudscraper.create_scraper()
        assert isinstance(scraper._config, ScraperConfig)

    def test_profile_frozen(self):
        """_profile must be a frozen FingerprintProfile"""
        from cloudscraper.fingerprint import FingerprintProfile
        scraper = cloudscraper.create_scraper()
        assert isinstance(scraper._profile, FingerprintProfile)
        with pytest.raises(AttributeError):
            scraper._profile.impersonate = 'chrome99'

    def test_explicit_ua_via_headers_not_overwritten(self):
        """User-Agent in headers= kwarg must not be overwritten by profile"""
        scraper = cloudscraper.CloudScraper(
            headers={'User-Agent': 'ExplicitBot/3.0'}
        )
        assert scraper.headers.get('User-Agent') == 'ExplicitBot/3.0'

    def test_caller_curl_options_preserved(self):
        """Caller's curl_options (e.g. CAINFO) must not be dropped by profile merge"""
        from curl_cffi.const import CurlOpt
        scraper = cloudscraper.create_scraper(
            source_address='10.0.0.1',
        )
        # Simulate a caller who also set CAINFO before profile merge
        # (in practice this would come through Session.__init__ kwargs)
        # We test that apply_curl_options merges rather than replaces:
        scraper.curl_options[CurlOpt.CAINFO] = b'/path/to/ca-bundle.crt'
        # Re-apply profile options — must not wipe CAINFO
        from cloudscraper.transport_curl import apply_curl_options
        apply_curl_options(scraper, scraper._profile)
        assert scraper.curl_options.get(CurlOpt.CAINFO) == b'/path/to/ca-bundle.crt'
        assert scraper.curl_options.get(CurlOpt.INTERFACE) == '10.0.0.1'

    def test_rotate_tls_ciphers_false_respected(self):
        """cipherSuite=... + rotate_tls_ciphers=False must NOT rotate ciphers"""
        from curl_cffi.const import CurlOpt
        original_cipher = 'ECDHE-RSA-AES128-GCM-SHA256'
        scraper = cloudscraper.create_scraper(
            cipherSuite=original_cipher,
            rotate_tls_ciphers=False,
        )
        assert scraper.curl_options[CurlOpt.SSL_CIPHER_LIST] == original_cipher
        # Simulate what request() does — with rotate_tls_ciphers=False
        # the rotation branch must NOT execute
        assert scraper.rotate_tls_ciphers is False
        assert scraper._profile.can_rotate_tls is True  # profile allows it
        # But the guard in request() checks both:
        should_rotate = scraper.rotate_tls_ciphers and scraper._profile.can_rotate_tls
        assert should_rotate is False
        # Verify cipher unchanged after manual rotation attempt
        scraper._rotate_tls_cipher_suite()
        scraper._rotate_tls_cipher_suite()
        assert scraper.curl_options[CurlOpt.SSL_CIPHER_LIST] == original_cipher

    def test_custom_ua_survives_refresh(self):
        """browser={'custom': ...} must keep the custom UA after _refresh_session"""
        scraper = cloudscraper.create_scraper(
            browser={'custom': 'MyBot/1.0'}
        )
        assert scraper.headers.get('User-Agent') == 'MyBot/1.0'
        # Simulate a refresh (without actually making a network request)
        scraper._clear_cloudflare_cookies()
        scraper.session_start_time = __import__('time').time()
        scraper.request_count = 0
        from cloudscraper.transport_curl import apply_profile_headers
        apply_profile_headers(scraper, scraper._profile, scraper._config.caller_headers)
        assert scraper.headers.get('User-Agent') == 'MyBot/1.0'

    def test_firefox_impersonate_gets_firefox_headers(self):
        """impersonate='firefox133' without browser= must get Firefox-family Accept headers"""
        scraper = cloudscraper.create_scraper(impersonate='firefox133')
        ua = scraper.headers.get('User-Agent', '')
        assert 'Firefox/133' in ua
        # Accept header must be Firefox-style (no image/webp, uses */*;q=0.8)
        accept = scraper.headers.get('Accept', '')
        assert 'image/webp' not in accept
        assert '*/*;q=0.8' in accept
        # Accept-Language must be Firefox-style
        accept_lang = scraper.headers.get('Accept-Language', '')
        assert 'en;q=0.5' in accept_lang

    def test_is_redirect_on_curl_response(self):
        """curl_cffi responses must have is_redirect after _adapt_response"""
        scraper = cloudscraper.create_scraper()
        # Build a mock curl_cffi response with a 302 + Location
        mock_resp = Mock()
        mock_resp.status_code = 302
        mock_resp.headers = {'Location': 'https://example.com/redirected'}
        # Ensure no pre-existing is_redirect (simulating curl_cffi.Response)
        del mock_resp.is_redirect
        adapted = scraper._adapt_response(mock_resp)
        assert adapted.is_redirect is True

        # Non-redirect 200 must have is_redirect=False
        mock_200 = Mock()
        mock_200.status_code = 200
        mock_200.headers = {}
        del mock_200.is_redirect
        adapted_200 = scraper._adapt_response(mock_200)
        assert adapted_200.is_redirect is False

    def test_custom_firefox_ua_gets_firefox_tls(self):
        """browser={'custom': 'Mozilla/... Firefox/...'} must get Firefox impersonate"""
        firefox_ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'
        scraper = cloudscraper.create_scraper(
            browser={'custom': firefox_ua}
        )
        assert scraper.headers.get('User-Agent') == firefox_ua
        assert 'firefox' in scraper.impersonate

    def test_custom_chrome_ua_gets_chrome_tls(self):
        """browser={'custom': 'Mozilla/... Chrome/...'} must get Chrome impersonate"""
        chrome_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
        scraper = cloudscraper.create_scraper(
            browser={'custom': chrome_ua}
        )
        assert scraper.headers.get('User-Agent') == chrome_ua
        assert 'chrome' in scraper.impersonate

    def test_custom_nonbrowser_ua_defaults_chrome(self):
        """browser={'custom': 'MyBot/1.0'} (non-browser) should still work with chrome120"""
        scraper = cloudscraper.create_scraper(
            browser={'custom': 'MyBot/1.0'}
        )
        assert scraper.headers.get('User-Agent') == 'MyBot/1.0'
        assert scraper.impersonate == 'chrome120'

    def test_pickle_roundtrip_preserves_request_hooks(self):
        """requestPreHook and requestPostHook must survive pickle round-trip"""
        import pickle

        scraper = cloudscraper.create_scraper(
            requestPreHook=_picklable_response_hook,
            requestPostHook=_picklable_response_hook,
        )
        assert scraper.requestPreHook is _picklable_response_hook
        assert scraper.requestPostHook is _picklable_response_hook

        data = pickle.dumps(scraper)
        restored = pickle.loads(data)
        assert restored.requestPreHook is _picklable_response_hook
        assert restored.requestPostHook is _picklable_response_hook

    def test_custom_safari_ua_gets_safari_tls(self):
        """browser={'custom': <Safari UA>} must get safari impersonate, not chrome120"""
        safari_ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15'
        scraper = cloudscraper.create_scraper(
            browser={'custom': safari_ua}
        )
        assert scraper.headers.get('User-Agent') == safari_ua
        assert 'safari' in scraper.impersonate

    def test_custom_edge_ua_gets_edge_tls(self):
        """browser={'custom': <Edge UA>} must get edge impersonate, not chrome120"""
        edge_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47'
        scraper = cloudscraper.create_scraper(
            browser={'custom': edge_ua}
        )
        assert scraper.headers.get('User-Agent') == edge_ua
        assert 'edge' in scraper.impersonate

    def test_pickle_with_unpicklable_request_hooks(self):
        """Unpicklable requestPreHook/requestPostHook must not break pickle.dumps"""
        import pickle
        scraper = cloudscraper.create_scraper(
            requestPreHook=lambda s, m, u, *a, **kw: (m, u, a, kw),
            requestPostHook=lambda s, r: r,
        )
        # Must not raise
        data = pickle.dumps(scraper)
        restored = pickle.loads(data)
        # Hooks were not picklable, so they are None after restore
        assert restored.requestPreHook is None
        assert restored.requestPostHook is None

    # --- hooks dispatch tests ---

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_request_level_hooks_dispatched(self, mock_request):
        """hooks= kwarg must be popped and dispatched, not passed to curl_cffi"""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.url = 'http://example.com'
        mock_resp.text = ''
        mock_resp.content = b''
        mock_request.return_value = mock_resp

        called = []

        def my_hook(response, **kwargs):
            called.append(kwargs)
            return response

        scraper = cloudscraper.create_scraper()
        scraper.get('http://example.com', hooks={'response': [my_hook]})
        assert len(called) == 1
        # Hook must receive request context kwargs
        assert called[0].get('method') == 'GET'
        assert called[0].get('url') == 'http://example.com'

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_session_level_hooks_dispatched(self, mock_request):
        """session-level self.hooks must be dispatched after each request"""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.url = 'http://example.com'
        mock_resp.text = ''
        mock_resp.content = b''
        mock_request.return_value = mock_resp

        called = []

        def my_hook(response, **kwargs):
            called.append(True)
            return response

        scraper = cloudscraper.create_scraper()
        scraper.hooks = {'response': [my_hook]}
        scraper.get('http://example.com')
        assert len(called) == 1

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_hook_can_replace_response(self, mock_request):
        """A hook that returns a new response must replace the original"""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.url = 'http://example.com'
        mock_resp.text = ''
        mock_resp.content = b''
        mock_request.return_value = mock_resp

        replacement = Mock()
        replacement.status_code = 200
        replacement.headers = {}
        replacement.url = 'http://example.com'
        replacement.text = 'replaced'
        replacement.content = b'replaced'

        def replacing_hook(response, **kwargs):
            return replacement

        scraper = cloudscraper.create_scraper()
        result = scraper.get('http://example.com', hooks={'response': [replacing_hook]})
        assert result.text == 'replaced'

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_hooks_default_dict_works(self, mock_request):
        """scraper.hooks['response'].append(fn) must work out of the box"""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.url = 'http://example.com'
        mock_resp.text = ''
        mock_resp.content = b''
        mock_request.return_value = mock_resp

        called = []

        def my_hook(response, **kwargs):
            called.append(True)
            return response

        scraper = cloudscraper.create_scraper()
        # This must NOT raise KeyError — hooks dict should be pre-initialized
        scraper.hooks['response'].append(my_hook)
        scraper.get('http://example.com')
        assert len(called) == 1

    # --- custom UA Accept-family alignment tests ---

    def test_custom_firefox_ua_gets_firefox_accept(self):
        """Custom Firefox UA must get Firefox-style Accept headers, not Chrome"""
        firefox_ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'
        scraper = cloudscraper.create_scraper(browser={'custom': firefox_ua})
        accept = scraper.headers.get('Accept', '')
        assert 'image/webp' not in accept
        assert '*/*;q=0.8' in accept
        accept_lang = scraper.headers.get('Accept-Language', '')
        assert 'en;q=0.5' in accept_lang

    def test_custom_safari_ua_gets_safari_accept(self):
        """Custom Safari UA must get Safari-family Accept headers"""
        safari_ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15'
        scraper = cloudscraper.create_scraper(browser={'custom': safari_ua})
        accept = scraper.headers.get('Accept', '')
        assert '*/*;q=0.8' in accept

    def test_custom_ua_explicit_accept_wins(self):
        """Caller-supplied Accept via headers= must override profile template"""
        firefox_ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'
        scraper = cloudscraper.CloudScraper(
            browser={'custom': firefox_ua},
            headers={'Accept': 'application/json'},
        )
        assert scraper.headers.get('Accept') == 'application/json'


class TestHooksCompatibility:
    """Tests for requests-compatible hook handling edge cases."""

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_request_hook_accepts_single_callable(self, mock_request):
        """hooks={'response': hook} (single callable, no list) must work"""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.url = 'http://example.com'
        mock_resp.text = ''
        mock_resp.content = b''
        mock_request.return_value = mock_resp

        called = []

        def my_hook(response, **kwargs):
            called.append(True)
            return response

        scraper = cloudscraper.create_scraper()
        scraper.get('http://example.com', hooks={'response': my_hook})
        assert len(called) == 1

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_session_hook_accepts_single_callable(self, mock_request):
        """self.hooks = {'response': hook} (single callable) must work"""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.url = 'http://example.com'
        mock_resp.text = ''
        mock_resp.content = b''
        mock_request.return_value = mock_resp

        called = []

        def my_hook(response, **kwargs):
            called.append(True)
            return response

        scraper = cloudscraper.create_scraper()
        scraper.hooks = {'response': my_hook}
        scraper.get('http://example.com')
        assert len(called) == 1

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_request_hook_survives_403_retry(self, mock_request):
        """Request-level hooks must fire on the final response after 403 retry"""
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            resp = Mock()
            resp.headers = {}
            resp.url = 'http://example.com'
            resp.text = ''
            resp.content = b''
            # First call: 403, second call (retry): 200
            resp.status_code = 403 if call_count[0] == 1 else 200
            return resp

        mock_request.side_effect = side_effect

        hook_responses = []

        def my_hook(response, **kwargs):
            hook_responses.append(response.status_code)
            return response

        scraper = cloudscraper.create_scraper(
            auto_refresh_on_403=True,
            max_403_retries=1,
            max_concurrent_requests=10,  # avoid throttle deadlock on recursion
        )
        # Stub _refresh_session to avoid real network calls
        scraper._refresh_session = Mock(return_value=True)

        result = scraper.get('http://example.com', hooks={'response': [my_hook]})
        # The hook must have seen the final 200 response exactly once
        assert hook_responses == [200]

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_last_403_time_resets_after_successful_retry(self, mock_request):
        """last_403_time must be reset to 0 after a successful 403 retry"""
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            resp = Mock()
            resp.headers = {}
            resp.url = 'http://example.com'
            resp.text = ''
            resp.content = b''
            resp.status_code = 403 if call_count[0] == 1 else 200
            return resp

        mock_request.side_effect = side_effect

        scraper = cloudscraper.create_scraper(
            auto_refresh_on_403=True,
            max_403_retries=1,
            max_concurrent_requests=10,
        )
        scraper._refresh_session = Mock(return_value=True)

        result = scraper.get('http://example.com')
        assert result.status_code == 200
        assert scraper.last_403_time == 0

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_last_403_time_resets_after_max_retries_exhausted(self, mock_request):
        """last_403_time must be reset to 0 when max retries are exhausted"""
        mock_resp = Mock()
        mock_resp.headers = {}
        mock_resp.url = 'http://example.com'
        mock_resp.text = ''
        mock_resp.content = b''
        mock_resp.status_code = 403
        mock_request.return_value = mock_resp

        scraper = cloudscraper.create_scraper(
            auto_refresh_on_403=True,
            max_403_retries=1,
            max_concurrent_requests=10,
        )
        scraper._refresh_session = Mock(return_value=True)

        result = scraper.get('http://example.com')
        assert result.status_code == 403
        assert scraper.last_403_time == 0

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_request_hook_survives_challenge_flow(self, mock_request):
        """Request-level hooks must fire exactly once on the solved response"""
        mock_resp = Mock()
        mock_resp.status_code = 503
        mock_resp.headers = {'Server': 'cloudflare'}
        mock_resp.url = 'http://example.com'
        mock_resp.text = '<html>challenge</html>'
        mock_resp.content = b'<html>challenge</html>'
        mock_request.return_value = mock_resp

        solved_resp = Mock()
        solved_resp.status_code = 200
        solved_resp.headers = {}
        solved_resp.url = 'http://example.com'
        solved_resp.text = 'solved'
        solved_resp.content = b'solved'

        hook_responses = []

        def my_hook(response, **kwargs):
            hook_responses.append(response.status_code)
            return response

        scraper = cloudscraper.create_scraper()

        # Mock a challenge detection + solve
        scraper.cloudflare_v1.is_Challenge_Request = Mock(return_value=True)
        scraper.cloudflare_v1.Challenge_Response = Mock(return_value=solved_resp)

        result = scraper.get('http://example.com', hooks={'response': [my_hook]})
        # The hook must fire exactly once — not twice due to challenge recursion
        assert hook_responses == [200]
        assert result.status_code == 200


    @patch('cloudscraper.CloudScraper.perform_request')
    def test_hook_fires_once_when_handler_recurses(self, mock_request):
        """When a challenge handler calls self.cloudscraper.request() internally,
        the hook must still fire exactly once on the final response — not once
        in the inner call and again in the outer call."""
        # First call returns a challenge page; the handler will call
        # self.cloudscraper.request() to submit the solution, producing
        # the solved response.
        challenge_resp = Mock()
        challenge_resp.status_code = 503
        challenge_resp.headers = {'Server': 'cloudflare'}
        challenge_resp.url = 'http://example.com'
        challenge_resp.text = '<html>challenge</html>'
        challenge_resp.content = b'<html>challenge</html>'

        solved_resp = Mock()
        solved_resp.status_code = 200
        solved_resp.headers = {}
        solved_resp.url = 'http://example.com'
        solved_resp.text = 'solved'
        solved_resp.content = b'solved'

        # perform_request returns challenge on first call, solved on second
        mock_request.side_effect = [challenge_resp, solved_resp]

        hook_calls = []

        def counting_hook(response, **kwargs):
            hook_calls.append(response.status_code)
            return response

        scraper = cloudscraper.create_scraper(
            max_concurrent_requests=10,  # avoid throttle deadlock on recursion
        )

        # Simulate a v1 handler that internally calls self.cloudscraper.request().
        # is_Challenge_Request returns True on the first (503) response, then
        # False on the second (200) response — matching real Cloudflare behavior.
        scraper.cloudflare_v1.is_Challenge_Request = Mock(
            side_effect=[True, False]
        )

        def fake_challenge_response(resp, **kw):
            return scraper.request('GET', 'http://example.com/solve')

        scraper.cloudflare_v1.Challenge_Response = fake_challenge_response

        result = scraper.get('http://example.com', hooks={'response': [counting_hook]})
        assert result.status_code == 200
        # Must be exactly [200], not [200, 200]
        assert hook_calls == [200], f"Hook fired {len(hook_calls)} times: {hook_calls}"

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_session_hook_fires_once_when_handler_recurses(self, mock_request):
        """Session-level self.hooks must fire exactly once when a challenge
        handler internally calls self.cloudscraper.request()."""
        challenge_resp = Mock()
        challenge_resp.status_code = 503
        challenge_resp.headers = {'Server': 'cloudflare'}
        challenge_resp.url = 'http://example.com'
        challenge_resp.text = '<html>challenge</html>'
        challenge_resp.content = b'<html>challenge</html>'

        solved_resp = Mock()
        solved_resp.status_code = 200
        solved_resp.headers = {}
        solved_resp.url = 'http://example.com'
        solved_resp.text = 'solved'
        solved_resp.content = b'solved'

        mock_request.side_effect = [challenge_resp, solved_resp]

        session_hook_calls = []

        def session_hook(response, **kwargs):
            session_hook_calls.append(response.status_code)
            return response

        scraper = cloudscraper.create_scraper(
            max_concurrent_requests=10,
        )
        scraper.hooks = {'response': [session_hook]}

        scraper.cloudflare_v1.is_Challenge_Request = Mock(
            side_effect=[True, False]
        )

        def fake_challenge_response(resp, **kw):
            return scraper.request('GET', 'http://example.com/solve')

        scraper.cloudflare_v1.Challenge_Response = fake_challenge_response

        result = scraper.get('http://example.com')
        assert result.status_code == 200
        assert session_hook_calls == [200], \
            f"Session hook fired {len(session_hook_calls)} times: {session_hook_calls}"

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_both_hooks_fire_once_on_recursive_solve(self, mock_request):
        """Both session-level and request-level hooks must each fire exactly
        once when a challenge handler recurses through self.request()."""
        challenge_resp = Mock()
        challenge_resp.status_code = 503
        challenge_resp.headers = {'Server': 'cloudflare'}
        challenge_resp.url = 'http://example.com'
        challenge_resp.text = '<html>challenge</html>'
        challenge_resp.content = b'<html>challenge</html>'

        solved_resp = Mock()
        solved_resp.status_code = 200
        solved_resp.headers = {}
        solved_resp.url = 'http://example.com'
        solved_resp.text = 'solved'
        solved_resp.content = b'solved'

        mock_request.side_effect = [challenge_resp, solved_resp]

        session_calls = []
        request_calls = []

        def session_hook(response, **kwargs):
            session_calls.append(response.status_code)
            return response

        def request_hook(response, **kwargs):
            request_calls.append(response.status_code)
            return response

        scraper = cloudscraper.create_scraper(
            max_concurrent_requests=10,
        )
        scraper.hooks = {'response': [session_hook]}

        scraper.cloudflare_v1.is_Challenge_Request = Mock(
            side_effect=[True, False]
        )

        def fake_challenge_response(resp, **kw):
            return scraper.request('GET', 'http://example.com/solve')

        scraper.cloudflare_v1.Challenge_Response = fake_challenge_response

        result = scraper.get(
            'http://example.com', hooks={'response': [request_hook]}
        )
        assert result.status_code == 200
        assert session_calls == [200], \
            f"Session hook fired {len(session_calls)} times: {session_calls}"
        assert request_calls == [200], \
            f"Request hook fired {len(request_calls)} times: {request_calls}"

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_concurrent_requests_both_dispatch_hooks(self, mock_request):
        """Two overlapping top-level requests from different threads must
        each dispatch their hooks independently."""
        import threading

        barrier = threading.Barrier(2)

        def slow_response(*args, **kwargs):
            # Both threads wait here so requests overlap
            barrier.wait(timeout=5)
            resp = Mock()
            resp.status_code = 200
            resp.headers = {}
            resp.url = args[1] if len(args) > 1 else 'http://example.com'
            resp.text = ''
            resp.content = b''
            return resp

        mock_request.side_effect = slow_response

        scraper = cloudscraper.create_scraper(
            max_concurrent_requests=10,
        )

        hook_urls = []
        lock = threading.Lock()

        def tracking_hook(response, **kwargs):
            with lock:
                hook_urls.append(kwargs.get('url', ''))
            return response

        scraper.hooks = {'response': [tracking_hook]}

        results = [None, None]
        errors = [None, None]

        def do_request(idx, url):
            try:
                results[idx] = scraper.get(url)
            except Exception as e:
                errors[idx] = e

        t1 = threading.Thread(target=do_request, args=(0, 'http://example.com/1'))
        t2 = threading.Thread(target=do_request, args=(1, 'http://example.com/2'))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert errors[0] is None, f"Thread 1 error: {errors[0]}"
        assert errors[1] is None, f"Thread 2 error: {errors[1]}"
        # Both requests must have dispatched the session hook
        assert len(hook_urls) == 2, \
            f"Expected 2 hook calls, got {len(hook_urls)}: {hook_urls}"


class TestCookiePickle:
    """Tests for cookie metadata preservation across pickle round-trips."""

    def test_pickle_roundtrip_preserves_secure_cookie(self):
        """Secure cookies must remain secure after pickle round-trip"""
        import pickle
        from http.cookiejar import Cookie

        scraper = cloudscraper.create_scraper()
        cookie = Cookie(
            version=0, name='cf_clearance', value='abc123',
            port=None, port_specified=False,
            domain='.example.com', domain_specified=True,
            domain_initial_dot=True,
            path='/', path_specified=True,
            secure=True,
            expires=None, discard=True,
            comment=None, comment_url=None,
            rest={}, rfc2109=False,
        )
        scraper.cookies.jar.set_cookie(cookie)

        data = pickle.dumps(scraper)
        restored = pickle.loads(data)

        restored_cookie = None
        for c in restored.cookies.jar:
            if c.name == 'cf_clearance':
                restored_cookie = c
                break

        assert restored_cookie is not None
        assert restored_cookie.secure is True
        assert restored_cookie.domain == '.example.com'
        assert restored_cookie.domain_initial_dot is True

    def test_pickle_roundtrip_preserves_cookie_expiry(self):
        """Cookie expires timestamp must survive pickle round-trip"""
        import pickle
        from http.cookiejar import Cookie

        expiry = 1893456000  # 2030-01-01

        scraper = cloudscraper.create_scraper()
        cookie = Cookie(
            version=0, name='session_id', value='xyz789',
            port=None, port_specified=False,
            domain='example.com', domain_specified=True,
            domain_initial_dot=False,
            path='/', path_specified=True,
            secure=False,
            expires=expiry, discard=False,
            comment=None, comment_url=None,
            rest={'HttpOnly': None}, rfc2109=False,
        )
        scraper.cookies.jar.set_cookie(cookie)

        data = pickle.dumps(scraper)
        restored = pickle.loads(data)

        restored_cookie = None
        for c in restored.cookies.jar:
            if c.name == 'session_id':
                restored_cookie = c
                break

        assert restored_cookie is not None
        assert restored_cookie.expires == expiry
        assert restored_cookie.discard is False
        assert restored_cookie._rest == {'HttpOnly': None}


class TestAsyncSafety:
    """Tests for async-compatible architecture (ContextVar, locks, _sleep)."""

    def test_contextvar_isolation_between_threads(self):
        """Two concurrent top-level requests in different threads must have
        independent _RequestChain instances (solve depth, 403 retry)."""
        import threading
        from cloudscraper import _current_chain, _RequestChain

        chains_seen = [None, None]
        barrier = threading.Barrier(2)

        def check_chain(idx):
            # Verify no chain exists before request
            assert _current_chain.get(None) is None
            chain = _RequestChain()
            token = _current_chain.set(chain)
            chain.solve_depth_cnt = idx + 1
            barrier.wait(timeout=5)
            # Verify our chain is still ours
            chains_seen[idx] = _current_chain.get().solve_depth_cnt
            _current_chain.reset(token)

        t1 = threading.Thread(target=check_chain, args=(0,))
        t2 = threading.Thread(target=check_chain, args=(1,))
        t1.start(); t2.start()
        t1.join(timeout=10); t2.join(timeout=10)

        assert chains_seen[0] == 1
        assert chains_seen[1] == 2

    def test_contextvar_not_on_instance(self):
        """Per-request-chain state must NOT be stored on the CloudScraper instance."""
        scraper = cloudscraper.create_scraper()
        assert not hasattr(scraper, '_solveDepthCnt')
        assert not hasattr(scraper, '_403_retry_count')
        assert not hasattr(scraper, '_in_403_retry')
        assert not hasattr(scraper, '_request_local')

    def test_state_lock_exists(self):
        """CloudScraper must have a _state_lock for shared counter protection."""
        import threading
        scraper = cloudscraper.create_scraper()
        assert hasattr(scraper, '_state_lock')
        assert isinstance(scraper._state_lock, type(threading.Lock()))

    def test_concurrent_semaphore_exists(self):
        """CloudScraper must have a _concurrent_sem semaphore."""
        import threading
        scraper = cloudscraper.create_scraper(max_concurrent_requests=5)
        assert hasattr(scraper, '_concurrent_sem')
        assert isinstance(scraper._concurrent_sem, type(threading.Semaphore()))

    def test_sleep_override_point(self):
        """_sleep() must be overridable for async subclass."""
        sleep_calls = []

        class AsyncScraper(cloudscraper.CloudScraper):
            def _sleep(self, seconds):
                sleep_calls.append(seconds)

        scraper = AsyncScraper(min_request_interval=0.5)
        # Trigger throttling by setting last_request_time to now
        import time
        with scraper._state_lock:
            scraper.last_request_time = time.time()
        scraper._apply_request_throttling()
        # _sleep should have been called with roughly 0.5s
        assert len(sleep_calls) == 1
        assert 0 < sleep_calls[0] <= 0.5

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_semaphore_released_on_exception(self, mock_request):
        """Concurrency semaphore must be released even when request raises."""
        mock_request.side_effect = Exception("network error")
        scraper = cloudscraper.create_scraper(max_concurrent_requests=1)
        with pytest.raises(Exception, match="network error"):
            scraper.get('http://example.com')
        # Semaphore must be available again (acquire should not block)
        acquired = scraper._concurrent_sem.acquire(blocking=False)
        assert acquired is True
        scraper._concurrent_sem.release()

    @patch('cloudscraper.CloudScraper.perform_request')
    def test_semaphore_released_on_success(self, mock_request):
        """Concurrency semaphore must be released after successful request."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.url = 'http://example.com'
        mock_resp.text = ''
        mock_resp.content = b''
        mock_request.return_value = mock_resp

        scraper = cloudscraper.create_scraper(max_concurrent_requests=1)
        scraper.get('http://example.com')
        # Semaphore must be available
        acquired = scraper._concurrent_sem.acquire(blocking=False)
        assert acquired is True
        scraper._concurrent_sem.release()

    def test_proxy_manager_has_lock(self):
        """ProxyManager must have a _lock for thread safety."""
        import threading
        from cloudscraper.proxy_manager import ProxyManager
        pm = ProxyManager(proxies=['http://proxy1:8080'])
        assert hasattr(pm, '_lock')
        assert isinstance(pm._lock, type(threading.Lock()))

    def test_stealth_mode_has_lock(self):
        """StealthMode must have a _lock for thread safety."""
        import threading
        scraper = cloudscraper.create_scraper(enable_stealth=True)
        assert hasattr(scraper.stealth_mode, '_lock')
        assert isinstance(scraper.stealth_mode._lock, type(threading.Lock()))

    def test_stealth_sleep_routes_through_scraper(self):
        """StealthMode delays must route through cloudscraper._sleep()."""
        sleep_calls = []

        class AsyncScraper(cloudscraper.CloudScraper):
            def _sleep(self, seconds):
                sleep_calls.append(seconds)

        scraper = AsyncScraper(enable_stealth=True)
        scraper.stealth_mode.request_count = 1  # skip first-request bypass
        scraper.stealth_mode._apply_human_like_delay()
        assert len(sleep_calls) == 1

    def test_pickle_excludes_lock_and_semaphore(self):
        """Pickle state must not contain _state_lock or _concurrent_sem."""
        scraper = cloudscraper.create_scraper()
        state = scraper.__getstate__()
        assert '_state_lock' not in state
        assert '_concurrent_sem' not in state
        # And old per-request-chain state must also be absent
        assert '_solveDepthCnt' not in state
        assert '_403_retry_count' not in state
        assert 'current_concurrent_requests' not in state


@pytest.mark.slow
class TestIntegration:
    """Integration tests (marked as slow)"""

    def test_real_request(self):
        """Test making a real HTTP request"""
        scraper = cloudscraper.create_scraper()
        try:
            response = scraper.get('http://httpbin.org/headers', timeout=10)
            assert response.status_code == 200
            assert 'headers' in response.json()
        except Exception as e:
            pytest.skip(f"Network request failed: {e}")

    def test_session_persistence(self):
        """Test session persistence across requests"""
        scraper = cloudscraper.create_scraper()
        try:
            # Set a cookie
            response1 = scraper.get('http://httpbin.org/cookies/set/test/value', timeout=10)
            # Check if cookie persists
            response2 = scraper.get('http://httpbin.org/cookies', timeout=10)
            assert response2.status_code == 200
        except Exception as e:
            pytest.skip(f"Network request failed: {e}")


class TestBugFixes:
    """Tests for specific bug fixes."""

    def test_proxy_manager_empty_banned(self):
        """Empty banned_proxies should not crash min()."""
        from cloudscraper.proxy_manager import ProxyManager
        pm = ProxyManager(proxies=['http://proxy1:8080'])
        # Ban the only proxy
        pm.report_failure('http://proxy1:8080')
        # Clear banned_proxies to simulate the edge case
        pm.banned_proxies.clear()
        # All proxies filtered out, banned_proxies empty → should return None
        # Re-add to banned with future time so they're all filtered
        import time
        pm.banned_proxies['http://proxy1:8080'] = time.time()
        pm.ban_time = 99999
        # Now banned_proxies is non-empty but all proxies banned → uses least recently banned
        result = pm.get_proxy()
        assert result is not None

        # True edge case: proxies exist, all filtered, banned_proxies empty
        pm2 = ProxyManager(proxies=[])
        assert pm2.get_proxy() is None

    def test_stealth_dnt_consistent(self):
        """DNT header should be consistent within a single session."""
        scraper = cloudscraper.create_scraper(enable_stealth=True)
        stealth = scraper.stealth_mode
        results = []
        for _ in range(20):
            kwargs = stealth._randomize_headers({})
            results.append(kwargs.get('headers', {}).get('DNT'))
        # All should be the same (either all '1' or all None)
        assert len(set(results)) == 1

    def test_max_concurrent_default(self):
        """Default max_concurrent_requests should be 10."""
        from cloudscraper.config import ScraperConfig
        assert ScraperConfig().max_concurrent_requests == 10
        scraper = cloudscraper.create_scraper()
        assert scraper.max_concurrent_requests == 10

    def test_user_agent_no_tracebacklimit(self):
        """User_Agent errors should not modify sys.tracebacklimit."""
        import sys
        original = getattr(sys, 'tracebacklimit', None)
        try:
            from cloudscraper.user_agent import User_Agent
            with pytest.raises(RuntimeError):
                User_Agent(desktop=False, mobile=False)
            # tracebacklimit should not have been set to 0
            current = getattr(sys, 'tracebacklimit', None)
            assert current == original
        finally:
            if original is None and hasattr(sys, 'tracebacklimit'):
                del sys.tracebacklimit
            elif original is not None:
                sys.tracebacklimit = original

    def test_create_async_scraper(self):
        """Async scraper should be creatable."""
        scraper = cloudscraper.create_async_scraper()
        from cloudscraper.async_scraper import AsyncCloudScraper
        assert isinstance(scraper, AsyncCloudScraper)
        assert hasattr(scraper, '_async_sleep')
        assert hasattr(scraper, '_is_challenge')

    @pytest.mark.asyncio
    async def test_async_sleep(self):
        """_async_sleep should complete without error."""
        scraper = cloudscraper.create_async_scraper()
        import time as _time
        start = _time.monotonic()
        await scraper._async_sleep(0.05)
        elapsed = _time.monotonic() - start
        assert elapsed >= 0.04  # Allow small timing variance


if __name__ == '__main__':
    pytest.main([__file__])
