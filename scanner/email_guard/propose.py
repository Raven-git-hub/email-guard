"""Classify unfamiliar senders and uncatalogued message structures, and stage
the resulting candidate for the daily review.

Two steps, deliberately separate:

* :func:`classify` decides whether this message is worth a human's attention --
  ``unknown_domain`` (sender on no list), ``new_structure`` (greylisted domain,
  message shape not catalogued) or ``skip``.
* :func:`build_candidate` / :func:`write_candidate` stage a *proposal* under
  ``<daily_brief_dir>/daily-brief-<YYYY-MM-DD>/<job>/candidate.json``.

**Nothing here ever touches the live lists.** A candidate is a suggestion: the
UI reviews the batch, the reviewer picks a list (or discards it), and only the
applier writes ``data/lists/*.json`` -- root README, "The learning loop".

The date in the folder name is injected, never read from the clock down here,
so a run is reproducible and testable (``--now``).
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Any

from .lists import GREYLIST_NEW_STRUCTURE, GREYLIST_NONE
from .route import write_json

UNKNOWN_DOMAIN = "unknown_domain"
NEW_STRUCTURE = "new_structure"
SKIP = "skip"

CANDIDATE_NAME = "candidate.json"
# Bumped when the on-disk shape changes, so the applier and the UI can tell
# which contract a staged candidate was written against.
CANDIDATE_VERSION = 1

MATCH_ALL_NAME = "ALL EMAILS"
SUBJECT_PREFIX = "Subject: "

# Enough of the body for a reviewer to recognise the message in the UI without
# copying the whole thing into a second store.
EXCERPT_LIMIT = 500
STRUCTURE_NAME_LIMIT = 80

_WHITESPACE_RE = re.compile(r"\s+")


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


def wants_candidate(proposal: dict[str, Any]) -> bool:
    """Only the two reviewable classifications are staged; ``skip`` writes nothing."""
    return proposal.get("classification") in {UNKNOWN_DOMAIN, NEW_STRUCTURE}


def brief_dir_name(day: date) -> str:
    return f"daily-brief-{day.isoformat()}"


def candidate_path(daily_brief_dir: str | Path, day: date, job: str) -> Path:
    """``<daily_brief_dir>/daily-brief-<YYYY-MM-DD>/<job>/candidate.json``."""
    return Path(daily_brief_dir) / brief_dir_name(day) / job / CANDIDATE_NAME


def build_candidate(
    message: dict[str, Any],
    verdict: dict[str, Any],
    proposal: dict[str, Any],
    *,
    job: str,
    day: date,
    greylist_entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the staged proposal for one message.

    ``proposed_entries`` is the part the applier consumes: each is a complete,
    schema-shaped list entry plus the ``list`` it would join and the
    ``operation`` needed. They are alternatives, not a batch -- the reviewer
    picks at most one.
    """
    sender = message.get("original_sender") or "unknown"
    sender_domain = sender.split("@")[1] if "@" in sender else ""
    classification = proposal.get("classification")
    structure = propose_structure(message)

    return {
        "candidate_version": CANDIDATE_VERSION,
        "job": job,
        "date": day.isoformat(),
        "classification": classification,
        "reason": proposal.get("reason"),
        "sender": {
            "email": sender,
            "domain": sender_domain,
            "friendly_name": message.get("friendly_name"),
        },
        # Where the scanned message itself is parked, so the UI can show the
        # full report and the original beside the proposal.
        "outbound": {"bucket": verdict.get("bucket"), "job": job},
        "evidence": _evidence(message, verdict),
        "proposed_structure": structure,
        "proposed_entries": _proposed_entries(
            classification, sender, sender_domain, message, structure, greylist_entry
        ),
    }


def write_candidate(candidate: dict[str, Any], path: str | Path) -> Path:
    """Stage one candidate. Creates the daily-brief folders as needed."""
    destination = Path(path)
    write_json(destination, candidate)
    return destination


def propose_structure(message: dict[str, Any]) -> dict[str, Any]:
    """A first-draft ``known_structure`` for this message's shape.

    Keyed on the subject, because that is the field a machine can propose
    honestly from one sample. It is deliberately over-specific -- a subject with
    a per-message reference in it will match only this message -- and the review
    UI is where a human generalises it before it reaches a list. That is the
    whole point of the approval step.
    """
    title = _collapse(message.get("title") or "")
    if not title:
        return {"name": MATCH_ALL_NAME, "key_phrases": []}
    return {
        "name": title[:STRUCTURE_NAME_LIMIT],
        "key_phrases": [f"{SUBJECT_PREFIX}{title}"],
    }


def _proposed_entries(
    classification: str | None,
    sender: str,
    sender_domain: str,
    message: dict[str, Any],
    structure: dict[str, Any],
    greylist_entry: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if classification == NEW_STRUCTURE:
        # The domain is already listed; only the shape is new. Key on the
        # *listed* domain, not the sending subdomain -- a greylist entry for
        # `bank.example` already covers `notify.bank.example`, so proposing the
        # subdomain would add a redundant second entry.
        domain = (greylist_entry or {}).get("domain") or sender_domain
        return [
            {
                "list": "greylist",
                "operation": "add_structure",
                "match": {"domain": domain},
                "entry": {"domain": domain, "known_structures": [structure]},
            }
        ]

    if classification == UNKNOWN_DOMAIN:
        # Sender is on no list at all, so every list is a legitimate answer and
        # the reviewer chooses. Whitelist/blacklist key on the address, the
        # greylist on the domain -- root README, "List schemas".
        friendly_name = message.get("friendly_name")
        match_all = {"name": MATCH_ALL_NAME, "key_phrases": []}
        return [
            {
                "list": "whitelist",
                "operation": "add_entry",
                "match": {"email": sender},
                "entry": {
                    "email": sender,
                    "friendly_name": friendly_name,
                    "known_structures": [match_all],
                },
            },
            {
                "list": "greylist",
                "operation": "add_entry",
                "match": {"domain": sender_domain},
                "entry": {"domain": sender_domain, "known_structures": [structure]},
            },
            {
                "list": "blacklist",
                "operation": "add_entry",
                "match": {"email": sender},
                "entry": {
                    "email": sender,
                    "friendly_name": friendly_name,
                    "known_structures": [match_all],
                },
            },
        ]

    return []


def _evidence(message: dict[str, Any], verdict: dict[str, Any]) -> dict[str, Any]:
    authenticity = (message.get("metadata") or {}).get("authenticity") or {}
    return {
        "message_id": verdict.get("message_id"),
        "subject": message.get("title"),
        "timestamp": message.get("timestamp"),
        "source_pipe": verdict.get("source_pipe"),
        "initial_level": verdict.get("initial_level"),
        "final_level": verdict.get("final_level"),
        "greylist_classification": verdict.get("greylist_classification"),
        "excerpt": (message.get("clean_text") or "")[:EXCERPT_LIMIT],
        # Links are carried in their de-fanged form, the only form that ever
        # leaves the scanner (root README, the Canary security note).
        "links": list(message.get("links") or []),
        "attachments": list(message.get("attachments") or []),
        "authenticity": {
            "dkim": authenticity.get("dkim"),
            "dmarc": authenticity.get("dmarc"),
            "spf": authenticity.get("spf"),
        },
    }


def _collapse(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text).strip()
