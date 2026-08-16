"""The review queue: staged candidates in, review cards out.

The scanner stages one proposal per unfamiliar sender at
``<daily_brief_dir>/daily-brief-<YYYY-MM-DD>/<job>/candidate.json``
(:mod:`email_guard.propose`). This module reads that tree, turns each candidate
into the small object the review card needs, and -- once a decision has been
applied -- consumes it so it does not come back on reload.

Three rules the rest of the component depends on:

* **A card carries plain text only.** ``body`` is the candidate's ``excerpt``
  and nothing else: the scanner's ``clean_text``, HTML already stripped and
  links already de-fanged, truncated at :data:`email_guard.propose.EXCERPT_LIMIT`.
  No raw HTML body exists on this side of the wall to leak by accident.
* **An id is a path, so it is validated like one.** A candidate id is
  ``<brief-dir>/<job>``, the two path segments that locate it. It arrives back
  from the browser in a decision, so :func:`resolve` rebuilds the path from
  strictly-validated segments rather than joining user input onto a directory.
* **Consuming is a move, not a delete.** A reviewed candidate goes to a
  ``reviewed/`` sibling. The proposal that produced a list change is evidence,
  and the daily-brief tree is already git-ignored personal data, so keeping it
  costs nothing and losing it costs the audit trail.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from email_guard.clean.common import obfuscation_flags
from email_guard.lists import LIST_NAMES, Lists, entry_key, find_entry
from email_guard.propose import CANDIDATE_NAME

LOGGER = logging.getLogger(__name__)

# Where a candidate goes once its decision has been applied.
REVIEWED_DIR = "reviewed"

# Everything the scanner puts in a path segment: `daily-brief-<date>` and a job
# slug. Anything else is not a segment this component wrote.
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")

_AUTHENTICITY_PASS = frozenset({"pass", "ok", "true", "none"})


@dataclass(frozen=True)
class Candidate:
    """One staged proposal, with the path it came from."""

    id: str
    path: Path
    document: dict[str, Any]


def queue(daily_brief_dir: str | Path) -> list[Candidate]:
    """Every unreviewed candidate, oldest brief first.

    A candidate that will not parse is skipped with a warning rather than
    failing the whole queue: one corrupt file must not hide the rest of the
    day's review behind a 500.
    """
    base = Path(daily_brief_dir)
    if not base.is_dir():
        return []

    candidates: list[Candidate] = []
    # Depth is exact -- `daily-brief-*/<job>/candidate.json` -- so a consumed
    # candidate under `<job>/reviewed/` no longer matches.
    for path in sorted(base.glob(f"daily-brief-*/*/{CANDIDATE_NAME}")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("skipping unreadable candidate %s: %s", path, exc)
            continue
        if not isinstance(document, dict):
            LOGGER.warning("skipping candidate %s: expected a JSON object", path)
            continue
        candidates.append(
            Candidate(id=f"{path.parent.parent.name}/{path.parent.name}", path=path, document=document)
        )
    return candidates


def resolve(daily_brief_dir: str | Path, candidate_id: str) -> Path | None:
    """The candidate file for an id, or ``None`` if there is no live one.

    The id comes back from the browser, so it is rebuilt segment by segment and
    the result is checked to be inside ``daily_brief_dir``. A ``..`` never gets
    as far as the join; the containment check is the second lock on the same
    door.
    """
    parts = str(candidate_id or "").split("/")
    if len(parts) != 2 or not all(_SEGMENT_RE.match(part) for part in parts):
        return None

    base = Path(daily_brief_dir).resolve()
    path = (base / parts[0] / parts[1] / CANDIDATE_NAME).resolve()
    if base not in path.parents:
        return None
    return path if path.is_file() else None


def mark_reviewed(path: str | Path) -> Path:
    """Consume one candidate by moving it into its ``reviewed/`` sibling.

    ``os.replace`` so the move is atomic and a re-review overwrites rather than
    failing: applying the same decision twice must be as harmless here as it is
    in the applier.
    """
    source = Path(path)
    destination = source.parent / REVIEWED_DIR / source.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(source, destination)
    return destination


def card(candidate: Candidate, lists: Lists) -> dict[str, Any]:
    """The review card for one candidate: id, sender, flags, body, membership.

    Deliberately narrow. The staged candidate holds more than this -- message
    ids, links, the proposed entries -- and none of it belongs on a screen that
    only has to answer "who is this, and which list should they be on?".
    """
    document = candidate.document
    sender = _section(document, "sender")
    email = str(sender.get("email") or "").strip().lower()
    domain = str(sender.get("domain") or "").strip().lower()

    return {
        "id": candidate.id,
        "sender": {"email": email, "domain": domain},
        "flags": flags(document),
        "body": body(document),
        "membership": membership(lists, email, domain),
    }


def body(document: dict[str, Any]) -> str:
    """The candidate's excerpt, and only ever the excerpt.

    ``propose`` fills this from the scanner's ``clean_text``: HTML stripped,
    links de-fanged, whitespace collapsed. There is no other body field on a
    candidate, and this function is the only place the web UI reads message
    text -- so "the server never sends a raw HTML body" is a property of one
    line rather than a convention spread over the handlers.
    """
    excerpt = _section(document, "evidence").get("excerpt")
    return excerpt if isinstance(excerpt, str) else ""


def _section(document: dict[str, Any], name: str) -> dict[str, Any]:
    """One nested object of a candidate, or an empty one.

    A candidate is a file on disk that a human may have opened, so every read of
    it treats a missing or wrong-shaped section as absent rather than as a
    reason to fail the whole queue.
    """
    section = document.get(name)
    return section if isinstance(section, dict) else {}


def flags(document: dict[str, Any]) -> list[str]:
    """Why this candidate is in the queue, as short labels for the card.

    Built from what the scanner already decided -- the candidate's
    ``classification``, its greylist classification, the authenticity pillar --
    plus the obfuscation heuristic, recomputed from the stored subject with the
    scanner's own :func:`email_guard.clean.common.obfuscation_flags`. That last
    one is a *reuse*, not a second opinion: the function is pure, and the
    candidate does not carry the flags the scanner computed at scan time. If
    that becomes untidy the fix is to add them to the candidate schema, which is
    a scanner change and therefore not this phase's to make.
    """
    found: list[str] = []

    def add(label: str) -> None:
        if label and label not in found:
            found.append(label)

    classification = document.get("classification")
    add(classification.strip() if isinstance(classification, str) else "")

    evidence = _section(document, "evidence")
    subject = evidence.get("subject")
    for name, present in obfuscation_flags(subject if isinstance(subject, str) else "").items():
        if present:
            add(f"obfuscation_{name}")

    authenticity = _section(evidence, "authenticity")
    for check in ("dkim", "dmarc", "spf"):
        value = authenticity.get(check)
        if value is None:
            continue
        if str(value).strip().lower() not in _AUTHENTICITY_PASS:
            add(f"{check}_fail")

    if evidence.get("attachments"):
        add("attachments_present")

    return found


def membership(lists: Lists, email: str, domain: str) -> dict[str, str] | None:
    """Which list already covers this sender, if any.

    Matched with :func:`email_guard.lists.find_entry`, so the answer uses the
    same subdomain-inclusive rule the scanner uses -- a card must not claim a
    sender is unlisted when the engine would find them on the greylist via a
    parent domain. Lists are mutually exclusive, so the first hit is the answer.
    """
    if not email and not domain:
        return None
    for name in LIST_NAMES:
        entry = find_entry(getattr(lists, name), email, domain)
        if entry is not None:
            key = entry_key(entry)
            return {"list": name, "key": key, "scope": "address" if "@" in key else "domain"}
    return None
