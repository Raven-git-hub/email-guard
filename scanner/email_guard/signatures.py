"""Signature reference feeds: the one part of the pack that fails OPEN.

Two feeds live under ``rules/reference/``:

* ``injection_signatures.json`` -- prompt-injection phrasing. A hit is a
  level-1 signal: no legitimate sender embeds injection.
* ``phishing_signatures.json`` -- phishing language. A hit is a level-2 signal
  for a sender who is not whitelisted.

Both are *reference data*, not logic. They are expected to be updated far more
often than the engine or the scan rules -- which is what the ``rules_sync``
auto-updater now does, pulling this repository on an interval (README,
"Auto-updating the pack") -- so they are read defensively.

TWO OPPOSITE FAILURE MODES, ON PURPOSE. DO NOT UNIFY THEM.
=========================================================

* The **scan rules** (``rules/scan/``, ``rules/assess/``) fail **CLOSED**.
  ``rules/validate.py`` rejects a malformed pack, :class:`InvalidRulesPack` is
  raised and the scanner refuses to score anything. A broken scan rule could
  silently mis-score every message, so not running at all is the safer
  outcome.

* The **signature feeds** in this module fail **OPEN**. A file that is missing,
  empty, unparseable or malformed logs a warning, is skipped, and triage
  carries on against the hard-baked baseline in :mod:`email_guard.triage`.
  These files are the part most likely to be half-written by a future
  auto-update, and a bad fetch must cost sensitivity, not stop the mail. Mail
  keeps flowing; the operator sees a warning.

The asymmetry is the design. Making the feeds fail closed would let a truncated
download halt every scan; making the scan rules fail open would let a typo
quietly disable detection. Neither is acceptable, so they differ.

Resolution order for a feed, highest first:

    1. the validated file under ``rules/reference/``
    2. TODO(cache): a last-known-good copy of the last feed that loaded
       cleanly, so a bad update degrades to yesterday's signatures rather than
       all the way to the baseline. Still not implemented HERE. The updater
       covers the case this was written for -- it rejects a bad pull whole, so
       the previous pack stays live and a corrupt feed never reaches this
       resolution order -- but a feed corrupted in place, after promotion,
       still falls straight through to 3.
    3. nothing: triage falls back to its hard-baked baseline markers.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

REFERENCE_DIRNAME = "reference"
INJECTION_FEED = "injection_signatures.json"
PHISHING_FEED = "phishing_signatures.json"

LITERAL = "literal"
REGEX = "regex"
SIGNATURE_TYPES = (LITERAL, REGEX)


@dataclass(frozen=True)
class Signature:
    """One reference entry, with its matcher already compiled."""

    id: str
    type: str
    pattern: str
    description: str = ""
    regex: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def matches(self, text: str) -> bool:
        if not text:
            return False
        if self.regex is not None:
            return bool(self.regex.search(text))
        # Literals are matched case-insensitively: the phrasing is what
        # matters, not how the sender capitalised it.
        return self.pattern.lower() in text.lower()


@dataclass(frozen=True)
class SignatureFeed:
    """The loaded feeds. An empty feed is valid and means "baseline only"."""

    injection: tuple[Signature, ...] = ()
    phishing: tuple[Signature, ...] = ()
    warnings: tuple[str, ...] = ()

    def injection_hits(self, text: str) -> list[str]:
        return [sig.id for sig in self.injection if sig.matches(text)]

    def phishing_hits(self, text: str) -> list[str]:
        return [sig.id for sig in self.phishing if sig.matches(text)]

    @property
    def degraded(self) -> bool:
        """True when something did not load cleanly -- worth surfacing in ops."""
        return bool(self.warnings)


def load_signature_feed(rules_dir: str | Path) -> SignatureFeed:
    """Load both feeds. Never raises -- see the module docstring."""
    base = Path(rules_dir) / REFERENCE_DIRNAME
    injection, injection_warnings = _load_one(base / INJECTION_FEED)
    phishing, phishing_warnings = _load_one(base / PHISHING_FEED)
    warnings = tuple(injection_warnings + phishing_warnings)
    for warning in warnings:
        log.warning("signature feed: %s", warning)
    return SignatureFeed(
        injection=tuple(injection), phishing=tuple(phishing), warnings=warnings
    )


def _load_one(path: Path) -> tuple[list[Signature], list[str]]:
    """One feed file -> its signatures plus any warnings. Never raises."""
    warnings: list[str] = []
    try:
        if not path.is_file():
            # Absent is not an error. A pack that ships no feed simply runs on
            # the baseline, which is the documented floor.
            return [], [f"{path.name} not found at {path}; using baseline only"]
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [f"{path.name} could not be read: {exc}; using baseline only"]

    if not raw.strip():
        return [], [f"{path.name} is empty; using baseline only"]

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [], [f"{path.name} is not valid JSON: {exc}; using baseline only"]

    if not isinstance(data, dict):
        return [], [f"{path.name} is not a JSON object; using baseline only"]

    if not isinstance(data.get("version"), int):
        warnings.append(f"{path.name} has no integer 'version'; loading anyway")
    if not isinstance(data.get("updated"), str):
        warnings.append(f"{path.name} has no 'updated' date string; loading anyway")

    entries = data.get("signatures")
    if entries is None:
        return [], warnings + [f"{path.name} has no 'signatures' list; using baseline only"]
    if not isinstance(entries, list):
        return [], warnings + [f"{path.name} 'signatures' is not a list; using baseline only"]

    signatures: list[Signature] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        signature, problem = _parse_entry(entry, path.name, index)
        if problem:
            # One bad entry costs that entry, not the whole feed.
            warnings.append(problem)
            continue
        if signature.id in seen:
            warnings.append(f"{path.name}[{index}]: duplicate id {signature.id!r}; skipped")
            continue
        seen.add(signature.id)
        signatures.append(signature)

    return signatures, warnings


def _parse_entry(entry: Any, source: str, index: int) -> tuple[Signature | None, str]:
    where = f"{source}[{index}]"
    if not isinstance(entry, dict):
        return None, f"{where}: not an object; skipped"

    identifier = entry.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        return None, f"{where}: missing 'id'; skipped"

    kind = entry.get("type")
    if kind not in SIGNATURE_TYPES:
        return None, f"{where} ({identifier}): type must be one of {SIGNATURE_TYPES}; skipped"

    pattern = entry.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        return None, f"{where} ({identifier}): missing 'pattern'; skipped"

    compiled: re.Pattern[str] | None = None
    if kind == REGEX:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            # A bad pattern here would otherwise raise mid-scan, on a message,
            # which is exactly what failing open exists to prevent.
            return None, f"{where} ({identifier}): invalid regex: {exc}; skipped"

    description = entry.get("description")
    return (
        Signature(
            id=identifier,
            type=kind,
            pattern=pattern,
            description=description if isinstance(description, str) else "",
            regex=compiled,
        ),
        "",
    )
