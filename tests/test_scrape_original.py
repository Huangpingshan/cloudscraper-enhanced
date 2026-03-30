#!/usr/bin/env python3
"""
Original cloudscraper (requests-based) scrape test — for comparison.

Requires the original cloudscraper to be installed in a separate venv:
    pip install cloudscraper==1.2.71

If running from the repo venv (which has the modified curl_cffi version),
this script will detect the conflict and exit with instructions.

Usage:
    python tests/test_scrape_original.py --url https://example.com
    python tests/test_scrape_original.py --url https://example.com --proxy http://user:pass@host:port
"""

import argparse
import sys
import time


def check_original_cloudscraper():
    """Verify we have the original requests-based cloudscraper, not the modified one."""
    try:
        import cloudscraper
    except ImportError:
        print("[ERROR] cloudscraper is not installed.")
        print("        pip install cloudscraper==1.2.71")
        sys.exit(1)

    # The modified version inherits from curl_cffi.requests.Session
    # The original inherits from requests.Session
    try:
        from requests import Session as RequestsSession
        if issubclass(cloudscraper.CloudScraper, RequestsSession):
            return  # Good — this is the original
    except ImportError:
        pass

    try:
        from curl_cffi.requests import Session as CurlSession
        if issubclass(cloudscraper.CloudScraper, CurlSession):
            print("[ERROR] Detected the MODIFIED cloudscraper (curl_cffi backend).")
            print("        This script tests the ORIGINAL requests-based version.")
            print()
            print("  To compare, create a separate venv:")
            print("    python -m venv /tmp/venv_original")
            print("    source /tmp/venv_original/bin/activate")
            print("    pip install cloudscraper==1.2.71")
            print("    python tests/test_scrape_original.py --url https://example.com")
            sys.exit(1)
    except ImportError:
        pass

    # Can't tell — proceed anyway
    return


def print_summary(resp, elapsed_ms):
    print(f"\n{'=' * 60}")
    print(f"  Status     : {resp.status_code}")
    print(f"  URL        : {resp.url}")
    print(f"  Elapsed    : {elapsed_ms:.0f} ms")
    print(f"  Body size  : {len(resp.content):,} bytes")
    print(f"{'=' * 60}")

    print(f"\n--- Response Headers ---")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")

    if resp.cookies:
        print(f"\n--- Cookies ---")
        for k, v in resp.cookies.items():
            print(f"  {k}={v}")

    text = resp.text[:2000] if resp.text else ''
    print(f"\n--- Body (first 2000 chars) ---")
    print(text)
    if len(resp.text) > 2000:
        print(f"\n  ... ({len(resp.text) - 2000:,} more chars)")


def main():
    parser = argparse.ArgumentParser(
        description='Original cloudscraper (requests-based) scrape test',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--proxy', default=None, help='Proxy URL, e.g. http://user:pass@host:port')
    parser.add_argument('--method', default='GET', choices=['GET', 'POST', 'PUT', 'DELETE', 'HEAD'])
    parser.add_argument('--browser', default='chrome',
                        choices=['chrome', 'firefox'],
                        help='Browser to emulate (default: chrome)')
    parser.add_argument('--header', '-H', dest='headers', action='append', default=[],
                        help='Extra header, e.g. -H "Accept:text/html"')
    parser.add_argument('--data', '-d', default=None, help='Request body (for POST)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--output', '-o', default=None, help='Save response body to file')

    args = parser.parse_args()

    check_original_cloudscraper()

    import cloudscraper

    # --- Build scraper ---
    scraper = cloudscraper.create_scraper(
        browser={
            'browser': args.browser,
            'platform': 'darwin',
            'mobile': False,
        },
        debug=args.debug,
    )

    print(f"--- Original cloudscraper Config ---")
    print(f"  version      : {cloudscraper.__version__}")
    print(f"  backend      : requests (urllib3)")
    print(f"  browser      : {args.browser}")
    print(f"  User-Agent   : {scraper.headers.get('User-Agent', 'N/A')}")
    print(f"  proxy        : {args.proxy or 'None'}")
    print()

    # --- Build request kwargs ---
    req_kwargs = {
        'timeout': args.timeout,
        'allow_redirects': True,
    }
    if args.proxy:
        scraper.proxies = {'http': args.proxy, 'https': args.proxy}
    if args.headers:
        req_kwargs['headers'] = dict(h.split(':', 1) for h in args.headers)
    if args.data:
        req_kwargs['data'] = args.data

    # --- Send request ---
    print(f">>> {args.method} {args.url}")
    t0 = time.time()

    try:
        resp = scraper.request(args.method, args.url, **req_kwargs)
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}")
        sys.exit(1)

    elapsed_ms = (time.time() - t0) * 1000
    print_summary(resp, elapsed_ms)

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(resp.content)
        print(f"\nSaved {len(resp.content):,} bytes to {args.output}")


if __name__ == '__main__':
    main()
