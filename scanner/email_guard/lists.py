"""Whitelist / greylist / blacklist loading and structure matching.

Rebuilt against the *current* list schema. The prototype's Triage node still
matched an older ``greyEntry.pass.subject`` / ``block.keywords`` shape that the
live data no longer has -- see the root README, "Known issues" -> "Greylist
schema drift". The schema implemented here is the one in the README:

    whitelist: [ { email, friendly_name, known_structures: [ {name, key_phrases} ] } ]
    blacklist: [ { email, friendly_name?, known_structures: [ ... ] } ]
    greylist:  [ { domain,               known_structures: [ {name, key_phrases} ] } ]

Live lists are personal data and are never committed; they are read from a
configurable directory (see :mod:`email_guard.config` and the README section
"Storage & privacy"). A missing file yields an empty list rather than an error,
so a clean clone runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GREYLIST_KNOWN = "known"
GREYLIST_NEW_STRUCTURE = "new_structure"
GREYLIST_NONE = "none"

MATCH_ALL_NAME = "ALL EMAILS"
SUBJECT_PREFIX = "subject:"


@dataclass
class Lists:
    whitelist: list[dict[str, Any]] = field(default_factory=list)
    greylist: list[dict[str, Any]] = field(default_factory=list)
    blacklist: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, lists_dir: str | Path) -> "Lists":
        base = Path(lists_dir)
        return cls(
            whitelist=_load_one(base / "whitelist.json", "whitelist"),
            greylist=_load_one(base / "greylist.json", "greylist"),
            blacklist=_load_one(base / "blacklist.json", "blacklist"),
        )

    def find(self, list_name: str, sender: str, sender_domain: str) -> dict[str, Any] | None:
        entries = getattr(self, list_name)
        return find_entry(entries, sender, sender_domain)


def _load_one(path: Path, key: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    entries = data.get(key, []) if isinstance(data, dict) else data
    return dedupe(entries or [])


def dedupe(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop repeated entries, keeping the first.

    The live blacklist ships at least one address twice -- see the root README,
    "Known issues" -> "Data hygiene: dedupe on load".
    """
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = (entry.get("email") or entry.get("domain") or "").strip().lower()
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        unique.append(entry)
    return unique


def entry_matches(entry: dict[str, Any], sender: str, sender_domain: str) -> bool:
    """Does this list entry cover this sender?

    Keys on ``email`` (exact) or ``domain``. Domain matching includes
    subdomains, so an ``example-bank.test`` entry covers
    ``notify.example-bank.test`` -- see the root README, "List schemas".
    """
    email = (entry.get("email") or "").strip().lower()
    if email and email == sender:
        return True
    domain = (entry.get("domain") or "").strip().lower()
    if domain and sender_domain:
        if sender_domain == domain or sender_domain.endswith("." + domain):
            return True
    return False


def find_entry(
    entries: list[dict[str, Any]], sender: str, sender_domain: str
) -> dict[str, Any] | None:
    for entry in entries:
        if entry_matches(entry, sender, sender_domain):
            return entry
    return None


def structure_matches(structure: dict[str, Any], subject: str, body: str) -> bool:
    """Does one ``known_structure`` match this message?

    A structure with no ``key_phrases``, or one named ``"ALL EMAILS"``, means
    *match every message from this sender*. The prototype used ``.some()`` over
    the phrase list, which is ``false`` for an empty list, so "trust everything"
    entries never matched -- see the root README, "Known issues" ->
    ``"ALL EMAILS"`` / empty ``key_phrases`` not handled.

    Otherwise the structure matches if ANY phrase hits: ``"Subject: ..."``
    phrases are tested against the subject, every other phrase against the body.
    Case-insensitive throughout.
    """
    phrases = structure.get("key_phrases") or []
    name = (structure.get("name") or "").strip().upper()
    if not phrases or name == MATCH_ALL_NAME:
        return True

    subject_lower = (subject or "").lower()
    body_lower = (body or "").lower()

    for phrase in phrases:
        if not isinstance(phrase, str) or not phrase.strip():
            continue
        lowered = phrase.strip().lower()
        if lowered.startswith(SUBJECT_PREFIX):
            needle = lowered[len(SUBJECT_PREFIX):].strip()
            if needle and needle in subject_lower:
                return True
        elif lowered in body_lower:
            return True
    return False


def matched_structure(
    entry: dict[str, Any] | None, subject: str, body: str
) -> dict[str, Any] | None:
    """First ``known_structure`` of ``entry`` that matches, if any."""
    if not entry:
        return None
    for structure in entry.get("known_structures") or []:
        if isinstance(structure, dict) and structure_matches(structure, subject, body):
            return structure
    return None


def classify_greylist(
    greylist: list[dict[str, Any]], sender: str, sender_domain: str, subject: str, body: str
) -> tuple[str, dict[str, Any] | None, dict[str, Any] | None]:
    """Classify a message against the greylist.

    Returns ``(classification, entry, structure)`` where classification is one
    of ``known`` (a structure matched), ``new_structure`` (the domain is listed
    but nothing matched) or ``none`` (the domain is absent).
    """
    entry = find_entry(greylist, sender, sender_domain)
    if entry is None:
        return GREYLIST_NONE, None, None
    structure = matched_structure(entry, subject, body)
    if structure is not None:
        return GREYLIST_KNOWN, entry, structure
    return GREYLIST_NEW_STRUCTURE, entry, None
