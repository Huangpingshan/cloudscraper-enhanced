#!/usr/bin/env python3
"""
Raw curl_cffi scrape test — baseline for comparison.

Usage:
    python tests/test_scrape_curl.py --url https://example.com
    python tests/test_scrape_curl.py --url https://example.com --proxy http://user:pass@host:port
    python tests/test_scrape_curl.py --url https://nowsecure.nl --proxy http://... --impersonate chrome120
"""

import argparse
import sys
import time

from curl_cffi import requests as curl_requests
from curl_cffi.requests import Session


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
        description='Raw curl_cffi scrape test (baseline)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--proxy', default=None, help='Proxy URL, e.g. http://user:pass@host:port')
    parser.add_argument('--method', default='GET', choices=['GET', 'POST', 'PUT', 'DELETE', 'HEAD'])
    parser.add_argument('--impersonate', default='chrome120',
                        help='curl_cffi impersonate value (default: chrome120)')
    parser.add_argument('--header', '-H', dest='headers', action='append', default=[],
                        help='Extra header, e.g. -H "Accept:text/html"')
    parser.add_argument('--data', '-d', default=None, help='Request body (for POST)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--output', '-o', default=None, help='Save response body to file')

    args = parser.parse_args()

    # --- Build session ---
    session = Session(impersonate=args.impersonate)

    print(f"--- curl_cffi Config ---")
    print(f"  impersonate  : {args.impersonate}")
    print(f"  User-Agent   : (managed by curl_cffi impersonate)")
    print(f"  proxy        : {args.proxy or 'None'}")
    print()

    # --- Build request kwargs ---
    req_kwargs = {
        'timeout': args.timeout,
        'allow_redirects': True,
    }
    if args.proxy:
        req_kwargs['proxies'] = {'http': args.proxy, 'https': args.proxy}
    if args.headers:
        req_kwargs['headers'] = dict(h.split(':', 1) for h in args.headers)
    if args.data:
        req_kwargs['data'] = args.data

    # --- Send request ---
    print(f">>> {args.method} {args.url}")
    t0 = time.time()

    try:
        resp = session.request(args.method, args.url, **req_kwargs)
    except curl_requests.errors.RequestsError as e:
        print(f"\n[ERROR] curl_cffi RequestsError: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}")
        sys.exit(1)

    elapsed_ms = (time.time() - t0) * 1000
    print_summary(resp, elapsed_ms)

    # --- Cloudflare detection (informational only, no solving) ---
    is_cf = resp.headers.get('Server', '').startswith('cloudflare')
    if is_cf and resp.status_code in (403, 429, 503):
        print(f"\n[INFO] Cloudflare challenge/block detected (status={resp.status_code}).")
        print(f"       curl_cffi alone cannot solve Cloudflare challenges.")

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(resp.content)
        print(f"\nSaved {len(resp.content):,} bytes to {args.output}")


if __name__ == '__main__':
    main()
