"""Triage: assign the initial threat level from list hits and obvious signals.

Adapted from the prototype's "Triage Direction" node to the current greylist
schema (``known_structures`` / ``key_phrases``) -- see the root README, "Known
issues" -> "Greylist schema drift".

Priority ladder, first match wins:

    1. blacklist hit                                            -> 1
    2. not whitelisted AND (visual obfuscation OR injection)    -> 1
    3. not whitelisted AND greylist "none" AND
       (tactical OR not dkim_verified OR not multipart)         -> 2
    4. greylist "known"                                         -> 4
    5. greylist "new_structure"                                 -> 3
    6. greylist "none" AND not whitelisted                      -> 3
    7. whitelist hit  (overrides everything above)              -> 4 with
                                                                   attachments,
                                                                   else 5
"""

from __future__ import annotations

import re
from typing import Any

from .lists import GREYLIST_KNOWN, GREYLIST_NEW_STRUCTURE, GREYLIST_NONE

# Roleplay / instruction framing, e.g. "system:", "### Instruction:", "[INST]:".
_ROLEPLAY_RE = re.compile(r"(system|user|assistant|instruction|###|\[INST\])\s*:", re.IGNORECASE)
# Zero-width and BOM characters used to smuggle text past a human reader.
# Escape form deliberately -- these are invisible when pasted literally.
_HIDDEN_UNICODE_RE = re.compile(r"[\u200B-\u200D\uFEFF]")
_FENCE_RE = re.compile(r"```")


def injection_markers(clean_text: str) -> list[str]:
    """Which prompt-injection markers appear in the cleaned body."""
    text = clean_text or ""
    found: list[str] = []
    if _ROLEPLAY_RE.search(text):
        found.append("roleplay_tag")
    if _HIDDEN_UNICODE_RE.search(text):
        found.append("hidden_unicode")
    if len(_FENCE_RE.findall(text)) >= 2:
        found.append("code_fences")
    return found


def initial_level(message: dict[str, Any], greylist_classification: str) -> tuple[int, list[str]]:
    """Return ``(level, reasons)`` for a normalised message."""
    reasons: list[str] = []

    whitelisted = bool(message.get("whitelist_hit"))
    obfuscation = message.get("obfuscation_flags") or {}
    integrity = message.get("integrity") or {}
    technical = (message.get("metadata") or {}).get("technical") or {}

    if message.get("blacklist_hit"):
        return 1, ["blacklist_hit"]

    markers = injection_markers(message.get("clean_text", ""))
    if not whitelisted and (obfuscation.get("visual") or markers):
        if obfuscation.get("visual"):
            reasons.append("obfuscation_visual")
        reasons.extend(f"injection_marker:{marker}" for marker in markers)
        level = 1
    elif (
        not whitelisted
        and greylist_classification == GREYLIST_NONE
        and (
            obfuscation.get("tactical")
            or not integrity.get("dkim_verified")
            or not technical.get("is_multipart")
        )
    ):
        if obfuscation.get("tactical"):
            reasons.append("obfuscation_tactical")
        if not integrity.get("dkim_verified"):
            reasons.append("dkim_unverified")
        if not technical.get("is_multipart"):
            reasons.append("not_multipart")
        level = 2
    elif greylist_classification == GREYLIST_KNOWN:
        reasons.append("greylist_known_structure")
        level = 4
    elif greylist_classification == GREYLIST_NEW_STRUCTURE:
        reasons.append("greylist_new_structure")
        level = 3
    elif greylist_classification == GREYLIST_NONE and not whitelisted:
        reasons.append("unknown_domain")
        level = 3
    else:
        # Whitelisted and nothing above tripped; rule 7 sets the level below.
        level = 5

    # Rule 7 -- the whitelist overrides every outcome above.
    if whitelisted:
        if message.get("attachments"):
            return 4, ["whitelist_hit", "attachments_present"]
        return 5, ["whitelist_hit"]

    return level, reasons
