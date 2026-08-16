"""The bridge from a review card to the applier.

The decisions document is the contract between this UI and
:mod:`email_guard.apply` (root README, "The decisions document"), and it is the
only way a live list changes. Everything here builds that document; nothing
here decides whether it is valid. Validation belongs to the applier, which owns
the rules and reports *every* error rather than the first -- duplicating any of
it on this side would give a reviewer two sources of truth that could disagree.

Each Confirm is its own one-item document applied immediately. Batching a day's
answers would mean one bad card blocking every other decision, since the
applier is all-or-nothing by design.

``reviewed`` is the injected day, never ``date.today()`` read down here -- the
same discipline :mod:`email_guard.propose` follows for the brief folder, and
what makes an applied decision reproducible in a test.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from email_guard.apply import DECISIONS_VERSION

# The fields a decision's `entry` may carry from the browser. `known_structures`
# is deliberately absent: the applier fills a white/black entry with a match-all
# shape, and a greylist shape arrives as the decision's `structure`.
ENTRY_FIELDS = ("email", "domain", "friendly_name", "tags")
STRUCTURE_FIELDS = ("name", "key_phrases", "disposition", "tags")


def build_document(decision: dict[str, Any], *, today: date) -> dict[str, Any]:
    """Wrap one decision as the document the applier consumes."""
    return {
        "decisions_version": DECISIONS_VERSION,
        "reviewed": today.isoformat(),
        "decisions": [decision],
    }


def build_decision(
    candidate: str,
    action: str,
    entry: dict[str, Any] | None = None,
    structure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One decision, with empty optional fields dropped.

    Absent is not the same as empty here: an ``entry`` of ``{}`` reaches the
    applier as "a decision with no subject", whose error names the candidate.
    An entry omitted entirely gets the same treatment. What must *not* happen is
    a stray key surviving into a list file, so the shape is rebuilt field by
    field rather than passed through.
    """
    decision: dict[str, Any] = {"candidate": candidate, "action": action}
    if entry is not None:
        decision["entry"] = _prune(entry, ENTRY_FIELDS)
    if structure is not None:
        decision["structure"] = _prune(structure, STRUCTURE_FIELDS)
    return decision


def _prune(source: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    pruned: dict[str, Any] = {}
    for name in fields:
        value = source.get(name)
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
        if isinstance(value, list):
            value = [item.strip() if isinstance(item, str) else item for item in value]
            value = [item for item in value if item != ""]
            if not value:
                continue
        pruned[name] = value
    return pruned
