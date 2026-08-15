"""Classify unfamiliar senders and uncatalogued message structures.

This build *classifies only*. It deliberately writes nothing: no daily-brief
files, no touching the live lists.

>>> FUTURE INTEGRATION POINT <<<

TODO(propose): the candidate -> daily-brief -> UI review -> applier loop is out
of scope here. When it lands, this module gains a writer that stages a candidate
entry into ``data/daily-brief-{date}/`` using the classification computed below.
Nothing may ever edit the live lists without approval -- root README,
"The learning loop".
"""

from __future__ import annotations

from typing import Any

from .lists import GREYLIST_NEW_STRUCTURE, GREYLIST_NONE

UNKNOWN_DOMAIN = "unknown_domain"
NEW_STRUCTURE = "new_structure"
SKIP = "skip"


def classify(message: dict[str, Any], greylist_classification: str) -> dict[str, Any]:
    """Return ``{classification, reason}`` for the daily-review queue."""
    sender = message.get("original_sender", "unknown")

    if message.get("blacklist_hit"):
        return {"classification": SKIP, "reason": "sender is already blacklisted"}
    if message.get("whitelist_hit"):
        return {"classification": SKIP, "reason": "sender is already whitelisted"}

    if greylist_classification == GREYLIST_NEW_STRUCTURE:
        return {
            "classification": NEW_STRUCTURE,
            "reason": f"{sender} is on the greylist but this message matches no known structure",
        }
    if greylist_classification == GREYLIST_NONE:
        return {
            "classification": UNKNOWN_DOMAIN,
            "reason": f"{sender} is on no list",
        }
    return {"classification": SKIP, "reason": "message matches a catalogued structure"}
