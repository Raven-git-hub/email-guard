"""Level 4 rule functions.

Ported from ``reference/n8n/level4.json``. Signature: ``(value, message, context) -> status``.
"""

from __future__ import annotations

from typing import Any

from email_guard.links import link_host, registrable_domain

MAJOR_PROVIDERS = ("live.com", "outlook.com", "gmail.com")

# URL shorteners and dynamic-DNS hosts: a link that hides its real destination
# has no business in mail that has reached the cleared tier.
SHORTENER_HOSTS = frozenset({"bit.ly", "t.co"})
SHORTENER_LABELS = frozenset({"tinyurl", "duckdns"})


def major_provider_sender(value: Any, message: dict, context: dict) -> str:
    """Pass senders on a major consumer provider, fail everything else.

    TODO(tuning): this is the prototype's rule verbatim, and it is too narrow.
    A legitimate greylisted institution -- a bank, an airline, a utility --
    is not one of these three consumer providers, so it returns ``fail`` here,
    the level-4 assessment reads that as "suspicious", and the message is
    downgraded to level 3 (flagged for review). Anything reaching level 4 has
    already matched a greylist entry, so the sender check arguably wants to
    compare against the *matched list entry* rather than a hardcoded provider
    list. Left as-is pending a regression corpus to tune against.

    This is currently the dominant reason legitimate greylisted mail lands on
    ``flagged`` rather than ``cleared``.
    """
    text = str(value or "")
    domain = text.split("@")[1] if "@" in text else ""
    is_major = any(domain.endswith(provider) for provider in MAJOR_PROVIDERS)
    return "pass" if is_major else "fail"


def shortener_links(value: Any, message: dict, context: dict) -> str:
    """Fail if any link resolves to a URL shortener or dynamic-DNS host.

    Links arrive de-fanged, so each is re-fanged internally to recover its real
    host. The prototype substring-matched ``bit.ly`` against the de-fanged
    ``h_ttps://bit[.]ly/x``, which never matched -- the check could not fire.
    """
    if not isinstance(value, list):
        return "pass"
    return "fail" if any(_is_shortener(link_host(str(link))) for link in value) else "pass"


def _is_shortener(host: str) -> bool:
    if not host:
        return False
    if host in SHORTENER_HOSTS or registrable_domain(host) in SHORTENER_HOSTS:
        return True
    return any(label in SHORTENER_LABELS for label in host.split("."))
