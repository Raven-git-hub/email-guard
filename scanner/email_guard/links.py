"""Link de-fanging, re-fanging, and host comparison.

De-fanging is a *presentation* concern: the normalised message and the verdict
carry ``h_ttps://www[.]example[.]com`` so nothing downstream can render a
clickable link to a hostile site. It is not meant to change what the detection
rules can see.

The prototype conflated the two: links were de-fanged before the rules pack ran,
so every link rule compared a mangled string against a real domain and could
never match. Alignment always failed and shortener detection never fired. The
fix is here -- :func:`refang` and :func:`link_host` recover the real host for
comparison, while the de-fanged form remains the only thing ever emitted.

Never return a re-fanged URL to a caller that emits output; re-fanging exists
solely for internal comparison.
"""

from __future__ import annotations

import re

# A URL scheme per RFC 3986: a letter followed by letters/digits/+/-/.
_URL_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://([^/?#]*)")
_HTTP_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# Multi-label public suffixes we care about, so `registrable_domain` keeps the
# right number of labels for them.
#
# TODO(suffixes): this is a pragmatic hardcoded set, not the real thing. Adopt
# the Public Suffix List (e.g. a vendored snapshot refreshed in CI) when link
# analysis matters more; until then an unlisted multi-label suffix just makes
# alignment stricter, never looser.
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "com.hk",
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "gov.au",
        "co.nz",
        "co.jp",
        "com.sg",
        "com.cn",
    }
)


def defang(url: str) -> str:
    """Render a URL unclickable: ``http`` -> ``h_ttp`` and ``.`` -> ``[.]``."""
    return url.replace("http", "h_ttp").replace(".", "[.]")


def refang(url: str) -> str:
    """Inverse of :func:`defang`. For internal comparison only -- never emit this."""
    return (url or "").replace("[.]", ".").replace("h_ttp", "http")


def extract_links(text: str) -> list[str]:
    """Unique http(s) URLs in document order, still fanged."""
    seen: list[str] = []
    for url in _HTTP_URL_RE.findall(text or ""):
        if url not in seen:
            seen.append(url)
    return seen


def link_host(url: str) -> str:
    """Lower-cased host of a link, de-fanged or not. ``""`` if it will not parse."""
    match = _URL_RE.match(refang(str(url or "")).strip())
    if not match:
        return ""
    authority = match.group(2)
    host = authority.rsplit("@", 1)[-1]  # drop any userinfo
    if host.startswith("["):  # IPv6 literal
        return host.lower()
    return host.rsplit(":", 1)[0].lower().rstrip(".")


def registrable_domain(host: str) -> str:
    """The registrable ("organisational") domain of a host.

    ``www.example-bank.test`` -> ``example-bank.test``;
    ``mail.example.com.hk`` -> ``example.com.hk`` via
    :data:`MULTI_LABEL_SUFFIXES`.
    """
    cleaned = (host or "").strip().lower().rstrip(".")
    if not cleaned:
        return ""
    labels = cleaned.split(".")
    if len(labels) <= 2:
        return cleaned
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def hosts_aligned(host: str, domain: str) -> bool:
    """Do a link host and a sender domain share a registrable domain?

    Subdomain-aware in both directions, so a link on
    ``www.example-bank.test`` aligns with a sender at
    ``notify.example-bank.test``.
    """
    left = registrable_domain(host)
    right = registrable_domain(domain)
    return bool(left) and bool(right) and left == right


def link_aligned_with(url: str, domain: str) -> bool:
    """Convenience: does this (possibly de-fanged) link sit on ``domain``?"""
    return hosts_aligned(link_host(url), domain)
