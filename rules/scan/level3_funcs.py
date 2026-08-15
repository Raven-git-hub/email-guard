"""Level 3 rule functions.

Ported from ``reference/n8n/level3.json``. Signature: ``(value, message, context) -> status``.
"""

from __future__ import annotations

import re
from typing import Any

from email_guard.links import link_aligned_with

_SIGNING_DOMAIN_RE = re.compile(r"header\.d=([a-z0-9.-]+)", re.IGNORECASE)


def _return_path(message: dict, context: dict) -> str:
    report = context.get("report") or {}
    content = report.get("messageContent") or message or {}
    return str((((content.get("metadata") or {}).get("path") or {}).get("return_path")) or "")


def capture_sender_domain(value: Any, message: dict, context: dict) -> str:
    text = str(value or "")
    parts = text.split("@")
    context["senderDomain"] = parts[1].lower() if len(parts) > 1 else ""
    return "pass"


def dkim_domain_alignment(value: Any, message: dict, context: dict) -> str:
    """The DKIM signing domain should line up with the return path.

    Note the empty-signing-domain case: the prototype tested
    ``returnPath.includes(signingDomain)`` with ``signingDomain === ''``, which
    JavaScript answers ``true``. Python's ``"" in text`` agrees, so a message
    with no ``header.d=`` passes here exactly as it did before.
    """
    match = _SIGNING_DOMAIN_RE.search(str(value or ""))
    signing_domain = match.group(1).lower() if match else ""
    return_path = _return_path(message, context)

    aligned = (
        signing_domain in return_path
        or signing_domain.endswith(".com")
        or signing_domain.endswith(".net")
    )
    return "pass_service" if aligned else "fail_critical"


def hop_count_with_srs(value: Any, message: dict, context: dict) -> str:
    """Many hops are fine for a forward (SRS), suspicious otherwise."""
    return_path = _return_path(message, context)
    is_srs = "SRS=" in return_path
    try:
        hops = float(value)
    except (TypeError, ValueError):
        return "pass"
    return "fail_critical" if (hops > 5 and not is_srs) else "pass"


def header_count_high(value: Any, message: dict, context: dict) -> str:
    """A very rich header set indicates real service infrastructure."""
    try:
        count = float(value)
    except (TypeError, ValueError):
        return "pass"
    return "pass_service" if count > 35 else "pass"


def links_aligned_with_sender(value: Any, message: dict, context: dict) -> str:
    """Every link's host should share the sender's registrable domain.

    Two changes from the prototype, both required for this rule to mean
    anything in this deployment:

    1. Links arrive de-fanged, so each is re-fanged internally to recover its
       real host. The prototype fed ``h_ttps://...`` to ``new URL()``, which
       threw on the invalid scheme, so every host came out empty and any
       message carrying links failed.
    2. The comparison domain is the *sender's*, not the return path's. All mail
       here arrives forwarded, so the return path is always the forwarder's SRS
       address (``owner+SRS=...=bank.example=notices@forwarder.test``) and its
       first ``@`` yields the forwarder's domain -- never the bank's. Comparing
       links against that could only ever fail for legitimate service mail.
    """
    if not isinstance(value, list) or not value:
        return "pass"

    sender_domain = context.get("senderDomain") or _sender_domain(message, context)
    if not sender_domain:
        return "fail_critical"

    aligned = all(link_aligned_with(str(link), sender_domain) for link in value)
    return "pass_service" if aligned else "fail_critical"


def _sender_domain(message: dict, context: dict) -> str:
    """Sender domain, falling back to the report when the scan order changed."""
    report = context.get("report") or {}
    content = report.get("messageContent") or message or {}
    sender = str(content.get("original_sender") or "")
    return sender.split("@")[1].lower() if "@" in sender else ""
