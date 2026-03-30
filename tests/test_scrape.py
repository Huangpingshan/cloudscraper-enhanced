#!/usr/bin/env python3
"""
Quick scrape test for cloudscraper with curl_cffi backend.

Usage:
    # Basic (no proxy)
    python tests/test_scrape.py --url https://example.com

    # With proxy
    python tests/test_scrape.py --url https://example.com --proxy http://user:pass@host:port

    # Full options
    python tests/test_scrape.py \
        --url https://nowsecure.nl \
        --proxy http://user:pass@host:port \
        --impersonate chrome120 \
        --method GET \
        --debug \
        --stealth \
        --output response.html
"""

import argparse
import json
import sys
import time
import os

# Ensure the repo root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import cloudscraper
from cloudscraper.exceptions import (
    CloudflareCaptchaProvider,
    CloudflareChallengeError,
    CloudflareCode1020,
    CloudflareIUAMError,
    CloudflareLoopProtection,
    CloudflareSolveError,
    CloudflareTurnstileError,
)


def build_scraper(args):
    kwargs = {
        'debug': args.debug,
        'enable_stealth': args.stealth,
        'min_request_interval': 0.0,
        'auto_refresh_on_403': True,
        'max_403_retries': args.max_retries,
    }
    if args.impersonate:
        kwargs['impersonate'] = args.impersonate
    else:
        kwargs['browser'] = {'browser': 'chrome', 'platform': 'darwin'}

    if args.captcha_provider and args.captcha_key:
        kwargs['captcha'] = {
            'provider': args.captcha_provider,
            'api_key': args.captcha_key,
        }

    return cloudscraper.create_scraper(**kwargs)


def do_request(scraper, args):
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

    return scraper.request(args.method, args.url, **req_kwargs)


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

    # Show a snippet of body
    text = resp.text[:2000] if resp.text else ''
    print(f"\n--- Body (first 2000 chars) ---")
    print(text)
    if len(resp.text) > 2000:
        print(f"\n  ... ({len(resp.text) - 2000:,} more chars)")


def print_scraper_info(scraper, args):
    print(f"--- Scraper Config ---")
    print(f"  impersonate  : {scraper.impersonate}")
    print(f"  User-Agent   : {scraper.headers.get('User-Agent', 'N/A')}")
    print(f"  stealth      : {scraper.enable_stealth}")
    print(f"  proxy        : {args.proxy or 'None'}")
    if scraper.captcha:
        print(f"  captcha      : {scraper.captcha.get('provider', 'None')}")
    else:
        print(f"  captcha      : None")
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Test cloudscraper against a target URL',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--proxy', default=None, help='Proxy URL, e.g. http://user:pass@host:port')
    parser.add_argument('--method', default='GET', choices=['GET', 'POST', 'PUT', 'DELETE', 'HEAD'])
    parser.add_argument('--impersonate', default=None,
                        help='curl_cffi impersonate value, e.g. chrome120, firefox133, safari184')
    parser.add_argument('--header', '-H', dest='headers', action='append', default=[],
                        help='Extra header, e.g. -H "Accept:text/html"')
    parser.add_argument('--data', '-d', default=None, help='Request body (for POST)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--max-retries', type=int, default=3, help='Max 403 retries (default: 3)')
    parser.add_argument('--debug', action='store_true', help='Enable cloudscraper debug output')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--output', '-o', default=None, help='Save response body to file')
    parser.add_argument('--captcha-provider', default=None, help='Captcha provider: capsolver, 2captcha, etc.')
    parser.add_argument('--captcha-key', default=None, help='Captcha provider API key')

    args = parser.parse_args()

    scraper = build_scraper(args)
    print_scraper_info(scraper, args)

    print(f">>> {args.method} {args.url}")
    t0 = time.time()

    try:
        resp = do_request(scraper, args)
    except CloudflareCode1020 as e:
        print(f"\n[BLOCKED] Cloudflare 1020 — IP is firewall-blocked. Change proxy.\n  {e}")
        sys.exit(1)
    except CloudflareCaptchaProvider as e:
        print(f"\n[CAPTCHA] Challenge requires a captcha provider (Turnstile / hCaptcha)."
              f"\n  Use --captcha-provider and --captcha-key to configure.\n  {e}")
        sys.exit(1)
    except CloudflareTurnstileError as e:
        print(f"\n[TURNSTILE] Turnstile challenge failed.\n  {e}")
        sys.exit(1)
    except CloudflareChallengeError as e:
        print(f"\n[CHALLENGE] Cloudflare challenge failed.\n  {e}")
        sys.exit(1)
    except CloudflareSolveError as e:
        print(f"\n[SOLVE_FAIL] Challenge answer rejected by Cloudflare.\n  {e}")
        sys.exit(1)
    except CloudflareLoopProtection as e:
        print(f"\n[LOOP] Too many solve attempts, giving up.\n  {e}")
        sys.exit(1)
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
