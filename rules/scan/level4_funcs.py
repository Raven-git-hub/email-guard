"""Level 4 rule functions.

Ported from ``reference/n8n/level4.json``. Signature: ``(value, message, context) -> status``.
"""

from __future__ import annotations

from typing import Any

from email_guard.links import link_host, registrable_domain

# URL shorteners and dynamic-DNS hosts: a link that hides its real destination
# has no business in mail that has reached the cleared tier.
SHORTENER_HOSTS = frozenset({"bit.ly", "t.co"})
SHORTENER_LABELS = frozenset({"tinyurl", "duckdns"})


def sender_on_trusted_list(value: Any, message: dict, context: dict) -> str:
    """Confirm the sender is on a trusted list.

    Replaces the prototype's ``major_provider_sender``, which passed only
    ``live.com`` / ``outlook.com`` / ``gmail.com`` senders. Every greylisted
    institution -- a bank, an airline, a utility -- failed that check, the
    level-4 assessment read the failure as "suspicious", and the message was
    downgraded to 3. Nothing from a real service could ever reach ``cleared``.

    Reaching level 4 already means a trusted list matched: triage rule 4
    (greylist structure recognised) or rule 7 (whitelisted sender with
    attachments). So the right question at this depth is whether that list
    membership still holds, not which consumer provider hosts the mailbox.

    Failing when neither flag is set is deliberate and defensive: a message that
    somehow arrives at level 4 off-list has not earned the cleared tier.
    """
    return "pass" if (message.get("whitelist_hit") or message.get("greylist_hit")) else "fail"


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
