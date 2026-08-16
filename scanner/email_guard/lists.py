"""Whitelist / greylist / blacklist loading, structure matching and validation.

Rebuilt against the *current* list schema. The prototype's Triage node still
matched an older ``greyEntry.pass.subject`` / ``block.keywords`` shape that the
live data no longer has -- see the root README, "Known issues" -> "Greylist
schema drift". The schema implemented here is the one in the README:

    whitelist: [ { email|domain, friendly_name, tags: [],
                   known_structures: [ {name, key_phrases} ] } ]
    blacklist: [ { email|domain, friendly_name?,
                   known_structures: [ ... ] } ]
    greylist:  [ { domain, tags: [],
                   known_structures: [ {name, key_phrases, disposition, tags: []} ] } ]

A greylist structure carries a ``disposition``: ``allowed`` (the default when
absent, so lists written before dispositions existed keep working) clears the
shape, ``denied`` rejects it. ``tags`` are routing labels carried through to the
verdict for the downstream webhook; they never affect the level.

**A domain lives on exactly one list.** :func:`validate_lists` enforces that
invariant and :meth:`Lists.load` fails closed on it, the same way the rules pack
does -- a hand-edit that puts a domain on two lists is a contradiction the
matcher would resolve silently, so it is surfaced at load instead. Only the
applier (:mod:`email_guard.apply`) writes lists, and it maintains the invariant.

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
GREYLIST_DENIED = "denied"
GREYLIST_NEW_STRUCTURE = "new_structure"
GREYLIST_NONE = "none"

DISPOSITION_ALLOWED = "allowed"
DISPOSITION_DENIED = "denied"
DISPOSITIONS = (DISPOSITION_ALLOWED, DISPOSITION_DENIED)

LIST_NAMES = ("whitelist", "greylist", "blacklist")

MATCH_ALL_NAME = "ALL EMAILS"
SUBJECT_PREFIX = "subject:"


class InvalidLists(Exception):
    """Raised when the live lists break a schema rule or the exclusivity invariant.

    Mirrors :class:`email_guard.rulespack.InvalidRulesPack`: the engine refuses
    to run on lists it cannot trust, rather than guessing which of two
    contradictory entries the reviewer meant.
    """

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass
class Lists:
    whitelist: list[dict[str, Any]] = field(default_factory=list)
    greylist: list[dict[str, Any]] = field(default_factory=list)
    blacklist: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, lists_dir: str | Path, validate: bool = True) -> "Lists":
        base = Path(lists_dir)
        lists = cls(
            whitelist=_load_one(base / "whitelist.json", "whitelist"),
            greylist=_load_one(base / "greylist.json", "greylist"),
            blacklist=_load_one(base / "blacklist.json", "blacklist"),
        )
        # After dedupe, never before: a repeated entry *within* one list is a
        # hygiene problem the loader already fixes, not a cross-list conflict.
        if validate:
            errors = validate_lists(lists.whitelist, lists.greylist, lists.blacklist)
            if errors:
                raise InvalidLists(errors)
        return lists

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


def find_entries(
    entries: list[dict[str, Any]], sender: str, sender_domain: str
) -> list[dict[str, Any]]:
    """Every entry covering this sender, in list order.

    More than one can cover it: domain matching includes subdomains, so a
    ``bank.example`` entry and a ``notify.bank.example`` entry both claim a
    sender at the subdomain. :func:`classify_greylist` has to see all of them,
    or a denied shape could hide behind whichever entry happens to be listed
    first.
    """
    return [entry for entry in entries if entry_matches(entry, sender, sender_domain)]


def find_entry(
    entries: list[dict[str, Any]], sender: str, sender_domain: str
) -> dict[str, Any] | None:
    """The first entry covering this sender, if any."""
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


def matched_structures(
    entry: dict[str, Any] | None, subject: str, body: str
) -> list[dict[str, Any]]:
    """Every ``known_structure`` of ``entry`` that matches, in list order.

    All of them, not the first: a message can match an allowed shape and a
    denied one at once, and the denied verdict has to win, so the whole list is
    scanned before anything is trusted (see :func:`classify_greylist`).
    """
    if not entry:
        return []
    return [
        structure
        for structure in entry.get("known_structures") or []
        if isinstance(structure, dict) and structure_matches(structure, subject, body)
    ]


def matched_structure(
    entry: dict[str, Any] | None, subject: str, body: str
) -> dict[str, Any] | None:
    """First ``known_structure`` of ``entry`` that matches, if any."""
    matches = matched_structures(entry, subject, body)
    return matches[0] if matches else None


def disposition(structure: dict[str, Any]) -> str:
    """Is this structure ``allowed`` or ``denied``?

    Absent means ``allowed``: dispositions were added after the schema shipped,
    and every list written before then means "catalogued, therefore fine".

    Present but unrecognised means ``denied``. That asymmetry is deliberate --
    an unreadable disposition must not buy trust, and :func:`validate_lists`
    rejects the value separately so the typo surfaces rather than silently
    rejecting a correspondent's mail forever.
    """
    value = structure.get("disposition")
    if value is None:
        return DISPOSITION_ALLOWED
    normalised = str(value).strip().lower()
    return normalised if normalised in DISPOSITIONS else DISPOSITION_DENIED


def tags_of(obj: dict[str, Any] | None) -> list[str]:
    """Normalise a ``tags`` field: strings only, stripped, deduped, order kept."""
    tags: list[str] = []
    for tag in (obj or {}).get("tags") or []:
        if not isinstance(tag, str):
            continue
        cleaned = tag.strip()
        if cleaned and cleaned not in tags:
            tags.append(cleaned)
    return tags


def classify_greylist(
    greylist: list[dict[str, Any]], sender: str, sender_domain: str, subject: str, body: str
) -> tuple[str, dict[str, Any] | None, dict[str, Any] | None]:
    """Classify a message against the greylist.

    Returns ``(classification, entry, structure)`` where classification is one
    of ``known`` (an *allowed* structure matched), ``denied`` (a denied
    structure matched), ``new_structure`` (the domain is listed but nothing
    matched) or ``none`` (the domain is absent).

    **Denied wins.** A message matching both an allowed and a denied structure
    is denied: the reviewer catalogued the denied shape precisely to reject it,
    and a broad match-all entry must not override that. So neither loop here
    short-circuits -- every covering entry, and every structure on it, is
    scanned before an allowed match is trusted.
    """
    entries = find_entries(greylist, sender, sender_domain)
    if not entries:
        return GREYLIST_NONE, None, None

    allowed_hit: tuple[dict[str, Any], dict[str, Any]] | None = None
    for entry in entries:
        for structure in matched_structures(entry, subject, body):
            if disposition(structure) == DISPOSITION_DENIED:
                return GREYLIST_DENIED, entry, structure
            if allowed_hit is None:
                allowed_hit = (entry, structure)

    if allowed_hit is not None:
        return GREYLIST_KNOWN, *allowed_hit
    return GREYLIST_NEW_STRUCTURE, entries[0], None


# --- validation ----------------------------------------------------------------


def entry_key(entry: dict[str, Any]) -> str:
    """The address or domain an entry is keyed on, lower-cased. ``""`` if keyless."""
    return (entry.get("email") or entry.get("domain") or "").strip().lower()


def claimed_domain(entry: dict[str, Any]) -> str:
    """The domain an entry claims -- its ``domain``, or its address's domain part.

    Exclusivity is a *domain* rule, so an ``a@shopfast.example`` whitelist entry
    claims ``shopfast.example`` just as a greylist ``domain`` entry does.
    Claims compare by exact equality, never by the subdomain-inclusive rule
    :func:`entry_matches` uses for senders: a decision about
    ``notify.bank.example`` must not silently delete a far broader
    ``bank.example`` entry from another list.
    """
    domain = (entry.get("domain") or "").strip().lower()
    if domain:
        return domain
    email = (entry.get("email") or "").strip().lower()
    return email.split("@", 1)[1] if "@" in email else ""


def validate_lists(
    whitelist: list[dict[str, Any]],
    greylist: list[dict[str, Any]],
    blacklist: list[dict[str, Any]],
) -> list[str]:
    """Validate the three lists. Returns error strings; empty means valid.

    Two kinds of check: each entry is schema-shaped, and no address or domain is
    represented on more than one list.
    """
    errors: list[str] = []
    by_list = {"whitelist": whitelist, "greylist": greylist, "blacklist": blacklist}

    for name, entries in by_list.items():
        for index, entry in enumerate(entries):
            errors.extend(_validate_entry(name, index, entry))

    errors.extend(_validate_exclusivity(by_list))
    return errors


def _validate_entry(list_name: str, index: int, entry: Any) -> list[str]:
    where = f"{list_name}[{index}]"
    if not isinstance(entry, dict):
        return [f"{where}: expected an object"]

    key = entry_key(entry)
    if not key:
        return [f"{where}: needs an 'email' or a 'domain'"]
    where = f"{list_name}[{key}]"

    errors: list[str] = []
    if list_name == "greylist" and not (entry.get("domain") or "").strip():
        errors.append(f"{where}: greylist entries key on 'domain', not 'email'")
    if "@" in key and not claimed_domain(entry):
        errors.append(f"{where}: 'email' has no domain part")

    errors.extend(_validate_tags(where, entry))

    structures = entry.get("known_structures")
    if structures is None:
        structures = []
    if not isinstance(structures, list):
        return errors + [f"{where}: 'known_structures' must be a list"]

    for position, structure in enumerate(structures):
        label = f"{where}.known_structures[{position}]"
        if not isinstance(structure, dict):
            errors.append(f"{label}: expected an object")
            continue
        name = structure.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{label}: needs a non-empty 'name'")
        phrases = structure.get("key_phrases")
        if phrases is not None and not isinstance(phrases, list):
            errors.append(f"{label}: 'key_phrases' must be a list")
        elif isinstance(phrases, list):
            for phrase in phrases:
                if not isinstance(phrase, str):
                    errors.append(f"{label}: key phrase {phrase!r} is not a string")
        value = structure.get("disposition")
        if value is not None and str(value).strip().lower() not in DISPOSITIONS:
            errors.append(
                f"{label}: 'disposition' is {value!r}, "
                f"not one of {', '.join(DISPOSITIONS)}"
            )
        errors.extend(_validate_tags(label, structure))

    return errors


def _validate_tags(where: str, obj: dict[str, Any]) -> list[str]:
    tags = obj.get("tags")
    if tags is None:
        return []
    if not isinstance(tags, list):
        return [f"{where}: 'tags' must be a list"]
    return [f"{where}: tag {tag!r} is not a string" for tag in tags if not isinstance(tag, str)]


def _validate_exclusivity(by_list: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Flag any address or domain represented on more than one list.

    The lists answer one question -- who is this sender? -- and the matcher
    consults them in a fixed order, so a sender on two lists gets a verdict
    decided by precedence rather than by the reviewer. That is a data bug, and
    it fails the load rather than being silently resolved.
    """
    addresses: dict[str, str] = {}
    domains: dict[str, tuple[str, str]] = {}
    errors: list[str] = []

    for name in LIST_NAMES:
        for entry in by_list[name]:
            if not isinstance(entry, dict):
                continue
            key = entry_key(entry)
            if not key:
                continue

            reported = False
            if "@" in key:
                owner = addresses.get(key)
                if owner is not None and owner != name:
                    errors.append(
                        f"{owner}[{key}] / {name}[{key}]: "
                        f"address '{key}' is on more than one list"
                    )
                    reported = True
                addresses.setdefault(key, name)

            domain = claimed_domain(entry)
            if not domain:
                continue
            held = domains.get(domain)
            # One error per conflicting entry: an address on two lists already
            # said everything the domain-level message would repeat.
            if held is not None and held[0] != name and not reported:
                errors.append(
                    f"{held[0]}[{held[1]}] / {name}[{key}]: "
                    f"domain '{domain}' is on more than one list"
                )
            domains.setdefault(domain, (name, key))

    return errors
