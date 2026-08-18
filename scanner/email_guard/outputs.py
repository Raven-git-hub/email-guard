"""Build the structured verdict emitted to stdout.

This is the scanner's whole output surface. Later components (dispatcher webhook
delivery, consolidated-inbox delivery, the quarantine browser) consume this
object, so keys are added rather than renamed.
"""

from __future__ import annotations

from typing import Any

from .route import bucket_for


def build_verdict(
    message: dict[str, Any],
    report: dict[str, Any],
    greylist_classification: str,
    canary_result: dict[str, Any],
    proposal: dict[str, Any],
    tags: list[str] | None = None,
) -> dict[str, Any]:
    initial_level = report["header"]["initialLevel"]
    final_level = report["finalLevel"]

    return {
        "message_id": message.get("messageID"),
        "source_pipe": (message.get("integrity") or {}).get("source_pipe"),
        "sender": message.get("original_sender"),
        "friendly_name": message.get("friendly_name"),
        "initial_level": initial_level,
        "final_level": final_level,
        "bucket": bucket_for(final_level),
        "list_hits": {
            "whitelist": bool(message.get("whitelist_hit")),
            "greylist": bool(message.get("greylist_hit")),
            "blacklist": bool(message.get("blacklist_hit")),
        },
        "greylist_classification": greylist_classification,
        # Routing labels from the greylist structure this message matched, for
        # the downstream webhook to dispatch on. Tags never affect the level --
        # they say what a message *is*, not how dangerous it is.
        "tags": list(tags or []),
        "forensic_log": list(report.get("forensicLog") or []),
        "links": list(message.get("links") or []),
        "attachments": list(message.get("attachments") or []),
        "canary": canary_result,
        # The attachments actually written to the job directory, filled in by
        # the output stage: one entry per file, with the sender's original
        # name, the sanitised name it was stored under, its type, size and
        # SHA-256. Empty for a quarantined message (nothing is materialised)
        # and for a `--dry-run` (nothing is written at all). Distinct from
        # `attachments` above, which is what the MESSAGE claims -- this is what
        # is on disk. See `email_guard.attachments`.
        "extracted_attachments": [],
        # TODO(actions): `cleared` mail carries an action (finance,
        # personal_assistant, work, calendar, summarise) for the downstream
        # webhook. Not yet in the greylist schema -- root README, "Actions".
        "proposed_action": None,
        "proposal": proposal,
        # Filled in by the output stage with the paths it created; stays null
        # for a pure verdict (`--dry-run`, or a caller using the library form).
        "written": None,
    }
