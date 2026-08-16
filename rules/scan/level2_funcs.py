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

from email_guard.links import link_aligned_with, registrable_domain


def capture_sender_domain(value: Any, message: dict, context: dict) -> str:
    """Record the sender domain for the rules that follow. Always passes."""
    text = str(value or "")
    parts = text.split("@")
    context["senderDomain"] = parts[1].lower() if len(parts) > 1 else ""
    context["originalSender"] = text
    context.setdefault("results", {})
    return "pass"


def return_path_alignment(value: Any, message: dict, context: dict) -> str:
    """Return-path should account for the sender's domain; if not, note it.

    A weak, supporting signal -- ``fail_pass`` -- never grounds to reject on its
    own. Every message here arrives forwarded through the bridge, so the
    envelope return path belongs to the *forwarder* rather than the sender, and
    misalignment is the normal case rather than the exception:

        <owner+SRS=hash=DM=notify.bank.example=notices@forwarder.test>

    This check previously returned ``fail_critical``, which the level-2
    assessment reads as grounds to reject, so a forwarding quirk could sink
    legitimate mail by itself. It is now defense-in-depth: it contributes to a
    picture built from several signals instead of deciding the verdict. The
    same reasoning removed the return-path check from triage entirely -- see
    ``scanner/email_guard/triage.py`` on content vs technical vs identity.

    SRS-aware, which the prototype's plain substring test was not. Level 3 was
    already SRS-aware; this brings level 2 into line.

    When the return path carries an ``SRS=`` token the original domain is
    embedded in it, so the test is whether the sender's registrable domain
    appears there -- subdomain-tolerant, since the envelope may name the parent
    domain where the header names a subdomain, or the reverse. Without an
    ``SRS=`` token nothing has been rewritten and the original direct-delivery
    check stands.

    TODO(srs): this looks for the domain anywhere in the SRS address rather than
    decoding the token properly (SRS0/SRS1, hash, timestamp, then the original
    domain and local part). Parsing it would let the check reject an address
    that merely mentions the domain in the wrong field.
    """
    sender_domain = context.get("senderDomain") or ""
    return_path = str(value or "")

    if not sender_domain:
        return "pass"

    if "SRS=" in return_path:
        registrable = registrable_domain(sender_domain)
        return "pass" if registrable and registrable in return_path else "fail_pass"

    return "pass" if sender_domain in return_path else "fail_pass"


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
