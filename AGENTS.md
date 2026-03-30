# Repository Guidelines

## Project Structure & Module Organization
`cloudscraper/` contains the published package. Core challenge handlers live in files such as `cloudflare.py`, `cloudflare_v2.py`, `cloudflare_v3.py`, and `turnstile.py`. Supporting modules are grouped under `cloudscraper/interpreters/`, `cloudscraper/captcha/`, and `cloudscraper/user_agent/` (`browsers.json` is packaged data). Tests live in `tests/`, with HTML fixtures under `tests/fixtures/`. Keep runnable examples in `examples/`, such as `examples/turnstile_example.py`.

## Build, Test, and Development Commands
Set up a contributor environment with:

```bash
python -m pip install --upgrade pip
pip install -e .[dev,test]
```

Run the local quality gate with:

```bash
pytest tests/ -v --cov=cloudscraper --cov-report=term-missing
black --check cloudscraper
isort --check-only cloudscraper
flake8 cloudscraper
mypy cloudscraper
```

Build the distributable package with `python -m build`, then validate it with `twine check dist/*`.

## Coding Style & Naming Conventions
Use 4-space indentation and keep Python code Black-compatible with the repository’s 88-character line length. Sort imports with `isort` using the Black profile. Prefer `snake_case` for modules, functions, variables, and test names; use `CapWords` for classes such as `CloudScraper` and `TestCloudScraper`. Follow existing public API naming when preserving backward compatibility.

## Testing Guidelines
Pytest is the standard test runner. Add tests under `tests/` using `test_*.py` or `*_test.py`; name test classes `Test*` and functions `test_*`. Reuse fixture HTML files when covering Cloudflare challenge parsing. Mark long-running or network-sensitive cases with existing markers like `@pytest.mark.slow` or `@pytest.mark.integration`. CI runs coverage, but no hard threshold is declared, so new changes should include focused tests for the affected code path.

## Commit & Pull Request Guidelines
Recent history favors short, imperative commit subjects such as `Fix owner`, `Refactor code structure...`, and `Add comprehensive and advanced tests...`. Keep commits narrowly scoped and descriptive. Pull requests should summarize behavioral changes, link the related issue when applicable, and include the exact validation commands you ran. For changes affecting challenge handling, proxies, or packaging, call out compatibility impact explicitly.

## Security & Configuration Tips
Do not commit real proxy credentials, CAPTCHA solver secrets, or private endpoints. Keep reproducible test data in `tests/fixtures/` and avoid embedding live targets in tests.
