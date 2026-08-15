"""Shared normalisation: everything the three cleaners used to duplicate.

This is the fix for the root README's "Known issues" -> "Cleaner contract
mismatch". In the prototype the Proton cleaner built the whole normalised object
while the Outlook and Gmail cleaners returned only ``{metadata, integrity}``, so
the three sources emitted different shapes.

Here the split is inverted and made explicit: this module owns *all* shared work
(sender identity, friendly name, list hits, obfuscation flags, link de-fanging,
clean_text, attachments, content block), and each source module supplies only
its ``metadata`` pillars + ``integrity`` -- the Outlook/Gmail contract, now
applied to Proton too. Every source therefore emits the identical normalised
shape documented in the root README.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from .. import links as links_module
from .. import lists as lists_module
from ..parse import header_text

CLEAN_TEXT_LIMIT = 2000

# VISUAL obfuscation: characters in the subject that fall outside the "expected"
# set. The job of this heuristic is homoglyph / lookalike detection -- a Cyrillic
# "a" standing in for a Latin "a" -- NOT typography. Ordinary punctuation that a
# real sender types must not flag.
#
# Allowed: ASCII, Latin-1 Supplement, CJK, kana, halfwidth katakana/hangul,
# fullwidth *punctuation*, emoji and dingbats (as ported from the prototype's
# Proton cleaner), PLUS most of General Punctuation (U+2000-U+206F): curly
# quotes, en/em dashes, the ellipsis, the various spaces. Those were missing, so
# one curly apostrophe in a subject read as "obfuscation" and triage rejected the
# message at level 1.
#
# Deliberately NOT allowed, so genuine lookalike attacks still flag:
#   * Cyrillic (U+0400-U+04FF), Greek (U+0370-U+03FF) and Mathematical
#     Alphanumeric Symbols (U+1D400-U+1D7FF) -- all outside every range below.
#   * fullwidth Latin letters and digits (U+FF10-U+FF19, U+FF21-U+FF3A,
#     U+FF41-U+FF5A). The prototype allowed the whole U+FF00-U+FFEF block for CJK
#     compatibility, which let "\uff21ccount" masquerade as "Account"; the block
#     is now admitted in pieces so its punctuation stays usable and its Latin
#     lookalikes do not.
#   * the invisible members of General Punctuation, which are not typography:
#     zero-width and bidi marks (U+200B-U+200F), bidi embedding/override
#     (U+202A-U+202E) and the invisible operators / deprecated format characters
#     (U+2060-U+206F).
_SAFE_SUBJECT_CHARS = re.compile(
    r"[\u0000-\u007F\u00A0-\u00FF"
    r"\u2000-\u200A\u2010-\u2029\u202F-\u205F"
    r"\u2600-\u26FF\u2700-\u27BF"
    r"\u3040-\u30FF\u4E00-\u9FA5"
    r"\uFF01-\uFF0F\uFF1A-\uFF20\uFF3B-\uFF40\uFF5B-\uFFEF"
    r"\U0001F300-\U0001F9FF\U0001F600-\U0001F64F\U0001F680-\U0001F6FF]"
)

# TACTICAL obfuscation: high-pressure urgency language in the subject.
_TACTICAL_SUBJECT = re.compile(
    r"(deleted|action|detected|declined|suspended|urgent|verify|immediately)", re.IGNORECASE
)

_STYLE_RE = re.compile(r"<style[\s\S]*?</style>", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_FORWARD_PREFIX_RE = re.compile(r"(Fw:\s*|FW:\s*|Fwd:\s*)", re.IGNORECASE)
_ANGLE_ADDR_RE = re.compile(r"<([^>]*)>")


def normalise(
    parsed: dict[str, Any],
    source,
    lists: lists_module.Lists,
    job_id: str | None = None,
) -> dict[str, Any]:
    """Build the normalised message from a parsed message + a source module.

    ``source`` is one of :mod:`~email_guard.clean.outlook`,
    :mod:`~email_guard.clean.gmail`, :mod:`~email_guard.clean.proton`; it must
    expose ``SOURCE_PIPE``, ``FRIENDLY_PREFIX`` and ``pillars(parsed)``.
    """
    metadata = parsed.get("metadata") or {}
    subject_raw = parsed.get("subject") or ""

    sender = _sender_address(parsed, metadata)
    sender_domain = sender.split("@")[1] if "@" in sender else ""

    html = parsed.get("textHtml") or ""
    # The prototype only ever read textHtml. Falling back to textPlain keeps
    # plain-text messages (common in raw .eml input) from cleaning to nothing.
    body_source = html or (parsed.get("textPlain") or "")

    links = defang_links(html or body_source)
    clean_text = strip_html(body_source)[:CLEAN_TEXT_LIMIT]
    title = _FORWARD_PREFIX_RE.sub("", subject_raw)
    attachments = collect_attachments(parsed)

    white_entry = lists_module.find_entry(lists.whitelist, sender, sender_domain)
    grey_entry = lists_module.find_entry(lists.greylist, sender, sender_domain)
    black_entry = lists_module.find_entry(lists.blacklist, sender, sender_domain)

    friendly_name = _friendly_name(
        sender, source.FRIENDLY_PREFIX, black_entry, grey_entry, white_entry
    )

    pillars = source.pillars(parsed)

    timestamp = metadata.get("x-pm-date") or parsed.get("date") or ""
    message_id = metadata.get("message-id") or parsed.get("messageID") or "N/A"

    content = {
        "links": links,
        "attachments": attachments,
        "text": clean_text,
        "timestamp": timestamp,
    }

    return {
        "messageID": header_text(message_id) or "N/A",
        "timestamp": header_text(timestamp),
        "job_id": job_id or uuid.uuid4().hex,
        "uid": parsed.get("uid"),
        "mailbox": header_text(
            metadata.get("x-original-to") or metadata.get("delivered-to") or ""
        ),
        "original_sender": sender,
        "friendly_name": friendly_name,
        "whitelist_hit": white_entry is not None,
        "greylist_hit": grey_entry is not None,
        "blacklist_hit": black_entry is not None,
        "obfuscation_flags": obfuscation_flags(subject_raw),
        "title": title,
        "clean_text": clean_text,
        "attachments": attachments,
        "links": links,
        "metadata": pillars["metadata"],
        "integrity": pillars["integrity"],
        "content": content,
    }


def _sender_address(parsed: dict[str, Any], metadata: dict[str, Any]) -> str:
    raw_from = header_text(parsed.get("from") or metadata.get("from") or "")
    match = _ANGLE_ADDR_RE.search(raw_from)
    if match:
        return match.group(1).lower().strip()
    return raw_from.replace("<", "").replace(">", "").lower().strip() or "unknown"


def _friendly_name(sender, prefix, black_entry, grey_entry, white_entry) -> str:
    """Default ``<source>-<localpart>``, overridden by list entries.

    Order matches the prototype: blacklist, then greylist, then whitelist, so the
    most-trusted list wins. Unlike the prototype an entry without a
    ``friendly_name`` (every greylist entry in the live schema) no longer
    clobbers the name with ``undefined``.
    """
    friendly = "Unknown"
    if sender != "unknown" and sender.count("@") == 1:
        friendly = f"{prefix}-{sender.split('@')[0]}"

    for entry in (black_entry, grey_entry, white_entry):
        if entry and entry.get("friendly_name"):
            friendly = entry["friendly_name"]
    return friendly


def obfuscation_flags(subject_raw: str) -> dict[str, bool]:
    stripped = _SAFE_SUBJECT_CHARS.sub("", subject_raw or "")
    return {
        "visual": len(stripped) > 0,
        "tactical": bool(_TACTICAL_SUBJECT.search(subject_raw or "")),
    }


def defang_links(html: str) -> list[str]:
    """Unique links, rendered unclickable.

    This is the only form that ever reaches the normalised message or the
    verdict. Rules that need to reason about a link's real host re-fang it
    internally via :mod:`email_guard.links`.
    """
    return [links_module.defang(url) for url in links_module.extract_links(html)]


def strip_html(html: str) -> str:
    text = _STYLE_RE.sub("", html or "")
    text = _TAG_RE.sub(" ", text)
    text = text.replace("&nbsp;", " ")
    return re.sub(r"\s+", " ", text).strip()


def collect_attachments(parsed: dict[str, Any]) -> list[dict[str, str]]:
    """Attachments from the parsed message plus the Proton ``x-attached`` header."""
    metadata = parsed.get("metadata") or {}
    found: list[dict[str, str]] = []

    attached_header = metadata.get("x-attached")
    if attached_header:
        for name in (
            attached_header if isinstance(attached_header, list) else [attached_header]
        ):
            found.append({"filename": str(name), "contentType": "image/png"})

    for item in parsed.get("attachments") or []:
        found.append(
            {
                "filename": item.get("filename") or item.get("fileName") or "unnamed",
                "contentType": item.get("contentType") or item.get("mimeType") or "unknown",
            }
        )

    unique: list[dict[str, str]] = []
    names: set[str] = set()
    for item in found:
        if item["filename"] in names:
            continue
        names.add(item["filename"])
        unique.append(item)
    return unique


# --- helpers shared by the source pillar modules -------------------------------

_DKIM_RE = re.compile(r"dkim=([a-zA-Z]+)")
_DMARC_RE = re.compile(r"dmarc=([a-zA-Z]+)")
_SPF_RE = re.compile(r"spf=([a-zA-Z]+)")
_RECEIVED_IP_RE = re.compile(r"\[([0-9.]+)\]")


def auth_results(metadata: dict[str, Any]) -> tuple[str, str, str, str]:
    """``(auth_string, dkim, dmarc, spf)`` from ``Authentication-Results``."""
    auth_string = header_text(metadata.get("authentication-results") or "")
    dkim_results = [m.lower() for m in _DKIM_RE.findall(auth_string)]
    dkim = "pass" if "pass" in dkim_results else (dkim_results[0] if dkim_results else "none")
    dmarc_match = _DMARC_RE.search(auth_string)
    spf_match = _SPF_RE.search(auth_string)
    return (
        auth_string,
        dkim,
        dmarc_match.group(1).lower() if dmarc_match else "none",
        spf_match.group(1).lower() if spf_match else "none",
    )


def sender_ip(metadata: dict[str, Any]) -> str:
    explicit = header_text(metadata.get("x-sender-ip") or "")
    if explicit:
        return explicit
    match = _RECEIVED_IP_RE.search(header_text(metadata.get("received") or ""))
    return match.group(1) if match else "unknown"
