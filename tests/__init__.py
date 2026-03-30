# -*- coding: utf-8 -*-
import hashlib

from os import path
from io import open

try:
    from urlparse import parse_qsl
except ImportError:
    from urllib.parse import parse_qsl

# Fake URL, network requests are not allowed by default when using the decorator
url = 'http://www.evildomain.com'

# These kwargs will be passed to tests by the decorator
cloudscraper_kwargs = dict(delay=0.01, debug=False)

# Cloudflare challenge fixtures are only read from the FS once
cache = {}

# ------------------------------------------------------------------------------- #


def fixtures(filename):
    """
    Read and cache a challenge fixture

    Returns: HTML (bytes): The HTML challenge fixture
    """
    if not cache.get(filename):
        print('reading...')
        with open(path.join(path.dirname(__file__), 'fixtures', filename), 'r') as fp:
            cache[filename] = fp.read()
    return cache[filename]
