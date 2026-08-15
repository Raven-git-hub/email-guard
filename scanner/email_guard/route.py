"""Routing: final level -> bucket, and the bucket -> disk write.

    1     -> rejected   (quarantine)
    2, 3  -> flagged    (quarantine)
    4, 5  -> cleared    (consolidated inbox, tagged with an action)

Root README, "Threat level model".

Every scanned message lands in::

    <outbound_dir>/<bucket>/<job>/report.json    # the full verdict
    <outbound_dir>/<bucket>/<job>/message.eml    # the original, verbatim
                              ... /message.json  # ... or the --from-json input

The original is copied byte for byte and never re-serialised: quarantine is
forensic storage, so what the scanner saw must be what a reviewer later reads.
``<job>`` is a filesystem-safe slug of the message id -- see :func:`job_slug`.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REJECTED = "rejected"
FLAGGED = "flagged"
CLEARED = "cleared"

BUCKETS = (CLEARED, FLAGGED, REJECTED)

REPORT_NAME = "report.json"

# A message id may legally contain almost anything between the angle brackets,
# including `/` and `..`, and it arrives from a hostile source -- so it is
# never used as a path component untreated. Only this set survives; everything
# else collapses to a single "-".
_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_TRIM_CHARS = "-._"
# Keep well inside the 255-byte limit every common filesystem imposes, leaving
# room for the disambiguating hash suffix a truncated slug carries.
_SLUG_MAX = 100
_ABSENT_IDS = {"", "n/a", "none", "null", "unknown"}


def bucket_for(level: int) -> str:
    if level <= 1:
        return REJECTED
    if level in (2, 3):
        return FLAGGED
    return CLEARED


@dataclass(frozen=True)
class SourceMessage:
    """The message exactly as it arrived, plus which front door it came in by.

    ``kind`` is ``"eml"`` (raw RFC822) or ``"json"`` (a pre-parsed n8n IMAP
    item), which decides the filename the copy is stored under.
    """

    kind: str
    raw: bytes

    EML = "eml"
    JSON = "json"

    @classmethod
    def from_eml(cls, raw: bytes) -> "SourceMessage":
        return cls(kind=cls.EML, raw=raw)

    @classmethod
    def from_json(cls, raw: bytes) -> "SourceMessage":
        return cls(kind=cls.JSON, raw=raw)

    @property
    def filename(self) -> str:
        return "message.eml" if self.kind == self.EML else "message.json"


def job_slug(message_id: Any, fallback: bytes = b"") -> str:
    """A filesystem-safe directory name for one scanned message.

    The message id with its angle brackets stripped and every unsafe character
    replaced, e.g. ``<a1b2@bank.example>`` -> ``a1b2@bank.example`` ->
    ``a1b2-bank.example``. A message with no usable id (the normalised message
    carries ``"N/A"``) falls back to a short content hash, so two id-less
    messages still get separate directories and the same message always gets
    the same one.
    """
    raw = (message_id or "").strip() if isinstance(message_id, str) else ""
    stripped = raw.strip("<>").strip()

    if stripped.lower() in _ABSENT_IDS:
        return _content_slug(fallback)

    slug = _UNSAFE_CHARS.sub("-", stripped).strip(_TRIM_CHARS)
    # A slug of only unsafe characters, or one that sanitises to "." / "..",
    # would escape or collide with the job directory: hash it instead.
    if not slug or set(slug) <= {"."}:
        return _content_slug(fallback)

    if len(slug) > _SLUG_MAX:
        digest = hashlib.sha256(stripped.encode("utf-8")).hexdigest()[:8]
        slug = f"{slug[:_SLUG_MAX].rstrip(_TRIM_CHARS)}-{digest}"
    return slug


def _content_slug(fallback: bytes) -> str:
    return f"msg-{hashlib.sha256(fallback).hexdigest()[:16]}"


def job_dir(outbound_dir: str | Path, bucket: str, job: str) -> Path:
    return Path(outbound_dir) / bucket / job


def plan_paths(outbound_dir: str | Path, bucket: str, job: str, source: SourceMessage) -> dict:
    """Where this message's outputs will go -- computed before anything is written.

    Planning first is what lets ``report.json`` describe its own location: the
    verdict's ``written`` section is filled in from this, then the whole verdict
    is serialised.
    """
    directory = job_dir(outbound_dir, bucket, job)
    return {
        "dir": directory,
        "report": directory / REPORT_NAME,
        "message": directory / source.filename,
    }


def write_outbound(verdict: dict[str, Any], source: SourceMessage, paths: dict) -> None:
    """Write ``report.json`` + the verbatim message copy into the job directory."""
    directory: Path = paths["dir"]
    directory.mkdir(parents=True, exist_ok=True)
    write_json(paths["report"], verdict)
    paths["message"].write_bytes(source.raw)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Serialise one output file.

    Fixed formatting, no timestamps, no dict re-ordering: re-scanning the same
    message must produce byte-identical files (see ``tests/test_write.py``).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)
    path.write_text(text + "\n", encoding="utf-8")


# TODO(delivery): `cleared` mail is later tagged with an action (finance,
# personal_assistant, work, calendar, summarise) taken from the greylist entry,
# and handed to the dispatcher for webhook delivery + consolidated-inbox
# delivery. The action field is not yet in the greylist schema; the verdict
# carries `proposed_action: null` as the placeholder.
#
# TODO(links): a `links.json` per job -- downloaded attachments and resolved
# link targets -- belongs beside `report.json`, but resolving either needs the
# IMAP fetch the dispatcher owns. Out of scope here; the job directory is the
# seam it will slot into.
