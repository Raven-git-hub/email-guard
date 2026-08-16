"""Apply a reviewer's decisions to the live lists.

The other half of the learning loop (root README, "The learning loop").
:mod:`email_guard.propose` stages candidates and is forbidden from touching a
list; this module is the only thing in the scanner that writes one, and it does
so only from an approved decisions document:

    { "decisions_version": 1, "reviewed": "<YYYY-MM-DD>",
      "decisions": [
        { "candidate": "<job-or-domain>",
          "action": "whitelist" | "greylist" | "blacklist" | "discard",
          "entry":     { "email"|"domain", "friendly_name"?, "tags": [] },
          "structure": { "name", "key_phrases": [], "disposition", "tags": [] } } ] }

``entry`` names the *subject* of a decision and is required for all three list
actions -- a greylist decision needs a target domain like any other. ``structure``
says what to catalogue and is greylist-only; a greylist decision without one just
creates the entry, whose shapes then all come back ``new_structure`` for review.
``discard`` drops the candidate and touches nothing.

Four guarantees, in the order they matter:

* **Mutual exclusivity.** A domain lives on exactly one list. Applying a
  decision first removes every entry claiming that domain from the other two
  lists -- including address-keyed ones, since an address claims its domain --
  and logs each removal. The new decision wins; that is what approving it meant.
* **All-or-nothing.** The whole document is validated before anything is
  applied, and the resulting lists are validated in memory before anything is
  written. One bad decision leaves every file exactly as it was.
* **Idempotent.** Re-applying a document changes nothing: a structure is
  appended only when its name is not already on the entry. A structure of the
  same name whose *content* differs is replaced in place rather than silently
  dropped -- flipping a shape from ``allowed`` to ``denied`` is the operation a
  reviewer most needs after a domain starts sending something nasty.
* **Atomic.** Each file is written via a temp sibling and ``os.replace``, so a
  crash mid-write cannot truncate a live list.

Atomicity is per file; three replaces are not atomic together. Files that only
*lost* entries are written first, so a crash between them leaves a domain on
zero lists -- re-reviewed at level 3 -- rather than on two, which the loader
would now refuse outright.

Live lists are personal data and are never committed (root README, "Storage &
privacy"). Nothing here reads or writes anything but the list directory it is
given.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .lists import (
    DISPOSITIONS,
    LIST_NAMES,
    MATCH_ALL_NAME,
    claimed_domain,
    entry_key,
    tags_of,
    validate_lists,
)

DECISIONS_VERSION = 1

ACTION_WHITELIST = "whitelist"
ACTION_GREYLIST = "greylist"
ACTION_BLACKLIST = "blacklist"
ACTION_DISCARD = "discard"
LIST_ACTIONS = (ACTION_WHITELIST, ACTION_GREYLIST, ACTION_BLACKLIST)
ACTIONS = LIST_ACTIONS + (ACTION_DISCARD,)

LIST_FILES = {name: f"{name}.json" for name in LIST_NAMES}

OP_ADD_ENTRY = "add_entry"
OP_UPDATE_ENTRY = "update_entry"
OP_ADD_STRUCTURE = "add_structure"
OP_UPDATE_STRUCTURE = "update_structure"
OP_REMOVE_ENTRY = "remove_entry"
OP_DISCARD = "discard"
OP_NO_OP = "no_op"

MATCH_ALL_STRUCTURE = {"name": MATCH_ALL_NAME, "key_phrases": []}


class InvalidDecisions(Exception):
    """Raised when a decisions document cannot be applied.

    Carries *every* error, not the first: a reviewer fixing a document wants
    the whole list, the same way :class:`email_guard.rulespack.InvalidRulesPack`
    reports a whole pack.
    """

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


# --- the list files ------------------------------------------------------------


@dataclass
class ListFile:
    """One list file, read to be written back without losing anything.

    Deliberately not read through :class:`email_guard.lists.Lists`: that dedupes,
    unwraps ``{"greylist": [...]}`` and drops sibling keys such as the fixtures'
    ``_note``. Rewriting an operator's file from it would silently rewrite parts
    of the file nobody asked to change.
    """

    path: Path
    key: str
    document: dict[str, Any] | None
    entries: list[dict[str, Any]]
    dirty: bool = False
    gained: bool = False

    @classmethod
    def read(cls, lists_dir: str | Path, list_name: str) -> "ListFile":
        path = Path(lists_dir) / LIST_FILES[list_name]
        if not path.is_file():
            # A list that does not exist yet is created in the canonical
            # wrapped form, matching every shipped sample.
            return cls(path=path, key=list_name, document={}, entries=[])

        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            entries = data.get(list_name) or []
            return cls(path=path, key=list_name, document=dict(data), entries=list(entries))
        # A bare top-level array is a shape the loader accepts, so it round-trips.
        return cls(path=path, key=list_name, document=None, entries=list(data or []))

    def payload(self) -> dict[str, Any] | list[dict[str, Any]]:
        if self.document is None:
            return self.entries
        payload = dict(self.document)
        payload[self.key] = self.entries
        return payload

    def find(self, key: str) -> dict[str, Any] | None:
        """The entry keyed exactly on ``key``.

        Exact, never the subdomain-inclusive rule
        :func:`email_guard.lists.entry_matches` uses: this locates the entry a
        decision names, it does not decide which entry covers a sender.
        """
        for entry in self.entries:
            if isinstance(entry, dict) and entry_key(entry) == key:
                return entry
        return None


def write_json_atomic(path: Path, payload: Any) -> None:
    """Write one list file, or leave the previous one untouched.

    Temp sibling, ``fsync``, ``os.replace``. The dispatcher does the same for
    its state file (``dispatcher/email_guard_dispatcher/state.py``); scanner and
    dispatcher share no code by design, so this is a deliberate second copy
    rather than an import across that boundary.

    Formatting matches :func:`email_guard.route.write_json` exactly, so a
    hand-edited list and an applied one are indistinguishable in a diff.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n"

    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=path.name + ".",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(handle.name)
        raise


# --- validation ----------------------------------------------------------------


def load_decisions(path: str | Path) -> dict[str, Any]:
    """Read a decisions document. Malformed JSON is an invalid document."""
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidDecisions([f"{source}: invalid JSON ({exc})"]) from exc
    if not isinstance(payload, dict):
        raise InvalidDecisions([f"{source}: expected a JSON object at the top level"])
    return payload


def validate_decisions(document: dict[str, Any]) -> list[str]:
    """Validate a whole decisions document. Returns errors; empty means valid.

    Errors never raise here and always name the candidate they came from, so a
    reviewer can find the card that produced the bad decision.
    """
    if not isinstance(document, dict):
        return ["expected a JSON object at the top level"]

    errors: list[str] = []

    version = document.get("decisions_version")
    if version != DECISIONS_VERSION:
        errors.append(
            f"unsupported decisions_version: {version!r} (expected {DECISIONS_VERSION})"
        )

    reviewed = document.get("reviewed")
    if not isinstance(reviewed, str) or not reviewed.strip():
        errors.append("'reviewed' must be a YYYY-MM-DD date string")
    else:
        try:
            date.fromisoformat(reviewed)
        except ValueError:
            errors.append(f"'reviewed' is {reviewed!r}, not a YYYY-MM-DD date")

    decisions = document.get("decisions")
    if not isinstance(decisions, list):
        return errors + ["'decisions' must be a list"]

    # An empty review -- everything discarded -- is a legitimate document.
    claims: dict[str, tuple[int, str, str]] = {}
    for index, decision in enumerate(decisions):
        errors.extend(_validate_decision(index, decision, claims))

    return errors


def _validate_decision(
    index: int, decision: Any, claims: dict[str, tuple[int, str, str]]
) -> list[str]:
    where = f"decisions[{index}]"
    if not isinstance(decision, dict):
        return [f"{where}: expected an object"]

    candidate = decision.get("candidate")
    if not isinstance(candidate, str) or not candidate.strip():
        return [f"{where}: needs a non-empty 'candidate'"]
    where = f"{where} (candidate {candidate!r})"

    action = decision.get("action")
    if action not in ACTIONS:
        return [f"{where}: unknown action {action!r} (expected one of {', '.join(ACTIONS)})"]
    if action == ACTION_DISCARD:
        return []

    entry = decision.get("entry")
    if not isinstance(entry, dict):
        return [f"{where}: a {action} decision needs an 'entry' object"]

    errors: list[str] = []
    email = (entry.get("email") or "").strip()
    domain = (entry.get("domain") or "").strip()
    if bool(email) == bool(domain):
        errors.append(f"{where}: 'entry' needs exactly one of 'email' or 'domain'")
    elif email and "@" not in email:
        errors.append(f"{where}: entry email {email!r} has no domain part")
    if action == ACTION_GREYLIST and email:
        errors.append(f"{where}: greylist entries key on 'domain', not 'email'")

    friendly_name = entry.get("friendly_name")
    if friendly_name is not None and not isinstance(friendly_name, str):
        errors.append(f"{where}: 'friendly_name' must be a string")
    errors.extend(_validate_tag_list(where, "entry", entry))

    structure = decision.get("structure")
    if structure is not None:
        if action != ACTION_GREYLIST:
            errors.append(f"{where}: only a greylist decision carries a 'structure'")
        else:
            errors.extend(_validate_structure(where, structure))

    # Two decisions sending one domain to two different lists would be resolved
    # by document order, which is not a decision anybody made.
    if not errors:
        claim = claimed_domain(entry)
        held = claims.get(claim)
        if held is not None and held[2] != action:
            errors.append(
                f"{where}: claims '{claim}' for the {action}, but decisions[{held[0]}] "
                f"(candidate {held[1]!r}) claims it for the {held[2]}"
            )
        claims.setdefault(claim, (index, candidate, action))

    return errors


def _validate_structure(where: str, structure: Any) -> list[str]:
    if not isinstance(structure, dict):
        return [f"{where}: 'structure' must be an object"]

    errors: list[str] = []
    name = structure.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append(f"{where}: 'structure' needs a non-empty 'name'")

    phrases = structure.get("key_phrases")
    if phrases is not None:
        if not isinstance(phrases, list):
            errors.append(f"{where}: 'key_phrases' must be a list")
        else:
            errors.extend(
                f"{where}: key phrase {phrase!r} is not a string"
                for phrase in phrases
                if not isinstance(phrase, str)
            )

    value = structure.get("disposition")
    if value is not None and (
        not isinstance(value, str) or value.strip().lower() not in DISPOSITIONS
    ):
        errors.append(
            f"{where}: 'disposition' is {value!r}, not one of {', '.join(DISPOSITIONS)}"
        )

    errors.extend(_validate_tag_list(where, "structure", structure))
    return errors


def _validate_tag_list(where: str, label: str, obj: dict[str, Any]) -> list[str]:
    tags = obj.get("tags")
    if tags is None:
        return []
    if not isinstance(tags, list):
        return [f"{where}: {label} 'tags' must be a list"]
    return [
        f"{where}: {label} tag {tag!r} is not a string"
        for tag in tags
        if not isinstance(tag, str)
    ]


# --- applying ------------------------------------------------------------------


@dataclass
class _Report:
    changes: list[dict[str, str]] = field(default_factory=list)

    def record(
        self, candidate: str, list_name: str, operation: str, key: str, detail: str
    ) -> None:
        self.changes.append(
            {
                # "list", not "list_name": the same key propose.py uses in a
                # candidate's proposed_entries.
                "candidate": candidate,
                "list": list_name,
                "operation": operation,
                "key": key,
                "detail": detail,
            }
        )


def apply_decisions(
    document: dict[str, Any], lists_dir: str | Path, *, dry_run: bool = False
) -> dict[str, Any]:
    """Apply a decisions document to the lists in ``lists_dir``.

    Returns the report. Raises :class:`InvalidDecisions` -- before touching
    disk -- if the document is malformed, or if applying it would produce lists
    the loader would then refuse.
    """
    errors = validate_decisions(document)
    if errors:
        raise InvalidDecisions(errors)

    files = {name: ListFile.read(lists_dir, name) for name in LIST_NAMES}
    report = _Report()

    for decision in document["decisions"]:
        _apply_one(files, decision, report)

    # The applier must never hand the scanner a state the scanner rejects.
    # Checked in memory, so a failure costs nothing.
    residual = validate_lists(
        files[ACTION_WHITELIST].entries,
        files[ACTION_GREYLIST].entries,
        files[ACTION_BLACKLIST].entries,
    )
    if residual:
        raise InvalidDecisions(
            [f"applying these decisions would leave the lists invalid: {error}" for error in residual]
        )

    written: list[str] = []
    if not dry_run:
        for name in _write_order(files):
            list_file = files[name]
            if list_file.dirty:
                write_json_atomic(list_file.path, list_file.payload())
                written.append(str(list_file.path))

    counts: dict[str, int] = {"decisions": len(document["decisions"])}
    for change in report.changes:
        counts[change["operation"]] = counts.get(change["operation"], 0) + 1

    return {
        "decisions_version": document["decisions_version"],
        "reviewed": document["reviewed"],
        "lists_dir": str(lists_dir),
        "dry_run": dry_run,
        "counts": counts,
        "changes": report.changes,
        "written": written,
    }


def _write_order(files: dict[str, ListFile]) -> list[str]:
    """Files that only lost entries first -- see this module's docstring."""
    return sorted(LIST_NAMES, key=lambda name: files[name].gained)


def _apply_one(files: dict[str, ListFile], decision: dict[str, Any], report: _Report) -> None:
    candidate = decision["candidate"]
    action = decision["action"]

    if action == ACTION_DISCARD:
        report.record(candidate, "", OP_DISCARD, candidate, "candidate discarded")
        return

    spec = decision["entry"]
    key = entry_key(spec)
    domain = claimed_domain(spec)

    _remove_conflicts(files, candidate, action, domain, report)

    if action == ACTION_GREYLIST:
        _apply_greylist(files[action], candidate, spec, decision.get("structure"), report)
    else:
        _apply_address_list(files[action], candidate, action, spec, key, report)


def _remove_conflicts(
    files: dict[str, ListFile], candidate: str, action: str, domain: str, report: _Report
) -> None:
    """Take the domain off the other two lists, logging every removal.

    An address-keyed entry conflicts when its domain is the one being claimed:
    exclusivity is a domain rule, so ``a@shopfast.example`` on the whitelist
    loses to a greylist decision about ``shopfast.example``.
    """
    if not domain:
        return

    for name in LIST_NAMES:
        if name == action:
            continue
        other = files[name]
        kept: list[dict[str, Any]] = []
        for existing in other.entries:
            if isinstance(existing, dict) and claimed_domain(existing) == domain:
                report.record(
                    candidate,
                    name,
                    OP_REMOVE_ENTRY,
                    entry_key(existing),
                    f"'{domain}' now lives on the {action}",
                )
                other.dirty = True
                continue
            kept.append(existing)
        other.entries = kept


def _apply_address_list(
    target: ListFile,
    candidate: str,
    action: str,
    spec: dict[str, Any],
    key: str,
    report: _Report,
) -> None:
    """Whitelist / blacklist: one match-all entry for the address or domain."""
    field_name = "email" if "email" in spec and (spec.get("email") or "").strip() else "domain"
    friendly_name = spec.get("friendly_name")
    tags = tags_of(spec)
    structures = spec.get("known_structures") or [dict(MATCH_ALL_STRUCTURE)]

    existing = target.find(key)
    if existing is None:
        entry: dict[str, Any] = {field_name: key}
        if friendly_name:
            entry["friendly_name"] = friendly_name
        entry["tags"] = tags
        entry["known_structures"] = [dict(structure) for structure in structures]
        target.entries.append(entry)
        target.dirty = True
        target.gained = True
        report.record(candidate, action, OP_ADD_ENTRY, key, f"added to the {action}")
        return

    detail = _merge_entry(existing, friendly_name, tags)
    if detail:
        target.dirty = True
        target.gained = True
        report.record(candidate, action, OP_UPDATE_ENTRY, key, detail)
    else:
        report.record(candidate, action, OP_NO_OP, key, f"already on the {action}")


def _apply_greylist(
    target: ListFile,
    candidate: str,
    spec: dict[str, Any],
    structure: dict[str, Any] | None,
    report: _Report,
) -> None:
    """Greylist: the domain entry, then the structure appended to it."""
    key = entry_key(spec)
    tags = tags_of(spec)

    entry = target.find(key)
    if entry is None:
        entry = {"domain": key, "tags": tags, "known_structures": []}
        target.entries.append(entry)
        target.dirty = True
        target.gained = True
        report.record(candidate, ACTION_GREYLIST, OP_ADD_ENTRY, key, "added to the greylist")
    else:
        detail = _merge_entry(entry, spec.get("friendly_name"), tags)
        if detail:
            target.dirty = True
            target.gained = True
            report.record(candidate, ACTION_GREYLIST, OP_UPDATE_ENTRY, key, detail)

    if structure is None:
        return

    wanted = _normalise_structure(structure)
    structures = entry.setdefault("known_structures", [])
    name = wanted["name"].strip().casefold()

    for position, existing in enumerate(structures):
        if not isinstance(existing, dict):
            continue
        if (existing.get("name") or "").strip().casefold() != name:
            continue
        if existing == wanted:
            report.record(
                candidate,
                ACTION_GREYLIST,
                OP_NO_OP,
                key,
                f"structure {wanted['name']!r} is already catalogued",
            )
            return
        # Same name, different content: replaced rather than dropped, so a
        # reviewer can flip a shape from allowed to denied.
        structures[position] = wanted
        target.dirty = True
        target.gained = True
        report.record(
            candidate,
            ACTION_GREYLIST,
            OP_UPDATE_STRUCTURE,
            key,
            f"structure {wanted['name']!r} updated ({wanted['disposition']})",
        )
        return

    structures.append(wanted)
    target.dirty = True
    target.gained = True
    report.record(
        candidate,
        ACTION_GREYLIST,
        OP_ADD_STRUCTURE,
        key,
        f"structure {wanted['name']!r} catalogued ({wanted['disposition']})",
    )


def _merge_entry(
    entry: dict[str, Any], friendly_name: Any, tags: list[str]
) -> str:
    """Fold a decision into an entry already on the list. Returns what changed."""
    changed: list[str] = []

    if isinstance(friendly_name, str) and friendly_name and entry.get("friendly_name") != friendly_name:
        entry["friendly_name"] = friendly_name
        changed.append("friendly_name")

    if tags:
        merged = tags_of(entry)
        added = [tag for tag in tags if tag not in merged]
        if added:
            entry["tags"] = merged + added
            changed.append(f"tags +{', '.join(added)}")

    return "; ".join(changed)


def _normalise_structure(structure: dict[str, Any]) -> dict[str, Any]:
    """The on-disk form of a decided structure.

    ``disposition`` is written out even when it is ``allowed``. The default
    exists so lists predating the field keep working, not so that new entries
    stay ambiguous -- a list is read by a human, and "allowed" should say so.
    """
    value = structure.get("disposition")
    disposition = str(value).strip().lower() if isinstance(value, str) and value.strip() else "allowed"
    return {
        "name": structure["name"].strip(),
        "key_phrases": [
            phrase for phrase in (structure.get("key_phrases") or []) if isinstance(phrase, str)
        ],
        "disposition": disposition,
        "tags": tags_of(structure),
    }
