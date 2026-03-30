# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cloudscraper is a Python library (v3.0.0) that bypasses Cloudflare's anti-bot protection (IUAM). It extends `requests.Session` to automatically detect and solve Cloudflare JavaScript challenges (v1/v2/v3), Turnstile CAPTCHAs, and traditional CAPTCHAs. Supports Python 3.8–3.13.

## Common Commands

```bash
# Install with dev/test dependencies
pip install -e .[dev,test]

# Run all tests
pytest tests/ -v

# Run a single test
pytest tests/test_modern.py -v -k "test_create_scraper"

# Run tests with coverage
pytest tests/ --cov=cloudscraper --cov-report=term-missing

# Linting
flake8 cloudscraper
black --check cloudscraper
isort --check-only cloudscraper
mypy cloudscraper
```

## Architecture

**Entry point**: `cloudscraper/__init__.py` — contains `CloudScraper(requests.Session)` and the `create_scraper()` factory function. All HTTP methods auto-detect and solve Cloudflare challenges via request hooks.

**Challenge handlers** (each is a separate module):
- `cloudflare.py` — v1 JavaScript challenge
- `cloudflare_v2.py` — v2 JS + CAPTCHA challenge
- `cloudflare_v3.py` — v3 JavaScript VM challenge (most advanced)
- `turnstile.py` — Cloudflare Turnstile handler

**JavaScript interpreters** (`interpreters/`): Pluggable backends for executing Cloudflare's JS challenges. Default is `js2py`. Also supports Node.js (`nodejs.py`), V8 (`v8.py`), and ChakraCore (`chakracore.py`). Selected via `interpreter` param in `create_scraper()`.

**CAPTCHA providers** (`captcha/`): Integrations with third-party solving services (2captcha, anticaptcha, capsolver, etc.). Selected via `captcha` param.

**Other key modules**:
- `stealth.py` — Human-like delays, header randomization, browser quirk simulation
- `proxy_manager.py` — Proxy rotation with ban tracking
- `user_agent/` — User-Agent generation from `browsers.json` fingerprint database
- `exceptions.py` — Custom exception hierarchy

## Code Style

- **black** with line-length 88
- **isort** with black-compatible profile
- Test markers: `@pytest.mark.slow`, `@pytest.mark.integration`, `@pytest.mark.unit`
