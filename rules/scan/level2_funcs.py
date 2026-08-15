"""Level 2 rule functions.

The declarative rules in ``level2.json`` cover the per-field pattern checks;
these are the ones that derive a value or compare across fields. Ported from
``reference/n8n/level2.json`` (the ``logic`` JS strings).

Every function has the same signature::

    (value, message, context) -> status

``value``   the scan point's value
``message`` the whole normalised message
``context`` per-iteration scratch space, shared across rules in one scan;
            also carries ``context["report"]``
"""

from __future__ import annotations

from typing import Any

from email_guard.links import link_aligned_with


def capture_sender_domain(value: Any, message: dict, context: dict) -> str:
    """Record the sender domain for the rules that follow. Always passes."""
    text = str(value or "")
    parts = text.split("@")
    context["senderDomain"] = parts[1].lower() if len(parts) > 1 else ""
    context["originalSender"] = text
    context.setdefault("results", {})
    return "pass"


def return_path_alignment(value: Any, message: dict, context: dict) -> str:
    """Return-path must mention the sender's domain, or it is a forgery signal."""
    sender_domain = context.get("senderDomain") or ""
    return_path = str(value or "")
    if not sender_domain or sender_domain in return_path:
        return "pass"
    return "fail_critical"


def header_count_band(value: Any, message: dict, context: dict) -> str:
    """Too few headers is suspicious; many headers means real infrastructure.

    The prototype's two ``if`` statements run in sequence, so the bands cannot
    both apply: under 15 fails, over 25 earns a downgrade, in between passes.
    """
    status = "pass"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < 15:
            status = "fail_pass"
        if value > 25:
            status = "pass_downgrade"
    return status


def links_aligned_with_sender(value: Any, message: dict, context: dict) -> str:
    """Every link should sit on the sender's own registrable domain.

    ``value`` holds de-fanged links, so each is re-fanged internally to recover
    its real host before comparison -- the prototype substring-matched the
    de-fanged string and could never align. Matching is subdomain-aware in both
    directions: a link on ``www.example-bank.test`` aligns with a sender at
    ``notify.example-bank.test``.
    """
    if not isinstance(value, list) or not value:
        return "pass"
    sender_domain = context.get("senderDomain") or ""
    if not sender_domain:
        aligned = False
    else:
        aligned = all(link_aligned_with(str(link), sender_domain) for link in value)
    return "pass_downgrade" if aligned else "fail_pass"
