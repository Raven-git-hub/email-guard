"""Loading and validating an evaluation corpus.

A corpus is a directory, and deliberately nothing cleverer -- one message and
one label per case, so a reviewer can read a case with ``cat`` and correct it
with an editor::

    <corpus>/
      corpus.json                      # the manifest: synthetic_only, note
      lists/whitelist.json             # the FROZEN list context
      lists/greylist.json
      lists/blacklist.json
      cases/<id>/message.eml           # the raw message, byte for byte
      cases/<id>/expected.json         # the label

The lists are frozen *into the corpus* rather than read from the live
``data/lists`` because they decide the bucket as much as the rules do. A case
labelled ``cleared`` because its sender was greylisted stops meaning anything
the moment that greylist entry is edited, so the corpus carries its own.

``expected.json``::

    {
      "expected_bucket": "cleared",     # required: cleared | flagged | rejected
      "expected_level": 4,              # optional: also assert the final level
      "reviewed": true,                 # only reviewed cases are graded
      "synthetic": true,                # invented mail, safe to commit
      "note": "why this is the right answer"
    }

``reviewed`` is the whole reason the import helper is safe to point at today's
outbound. An imported case is pre-filled with the bucket the scanner *currently*
chose and marked ``reviewed: false``; the harness skips it until a human has
confirmed or corrected the label. Grading against the scanner's own output would
freeze today's mis-scoring in as the answer key, which is the opposite of the
point.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..lists import InvalidLists, Lists
from ..route import BUCKETS

MANIFEST_NAME = "corpus.json"
CASES_DIRNAME = "cases"
LISTS_DIRNAME = "lists"
MESSAGE_NAME = "message.eml"
EXPECTED_NAME = "expected.json"

# Levels the engine can assign; `expected_level` is checked against these so a
# typo surfaces at load rather than as a permanently failing case.
LEVELS = (1, 2, 3, 4, 5)

_KNOWN_KEYS = {"expected_bucket", "expected_level", "reviewed", "synthetic", "note"}


class CorpusError(Exception):
    """The corpus cannot be graded. Carries every problem, not just the first.

    Same shape as :class:`email_guard.rulespack.InvalidRulesPack` and
    :class:`email_guard.lists.InvalidLists`, and reported the same way: a
    reviewer fixing a corpus wants the whole list, not one round trip per typo.
    """

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass(frozen=True)
class Case:
    """One labelled message."""

    id: str
    message_path: Path
    expected_bucket: str
    reviewed: bool
    synthetic: bool
    note: str = ""
    expected_level: int | None = None

    def read(self) -> bytes:
        return self.message_path.read_bytes()


@dataclass(frozen=True)
class Corpus:
    """A directory of labelled messages, plus the list context they assume."""

    root: Path
    cases: tuple[Case, ...]
    synthetic_only: bool
    note: str = ""

    @property
    def lists_dir(self) -> Path:
        return self.root / LISTS_DIRNAME

    @property
    def reviewed(self) -> tuple[Case, ...]:
        return tuple(case for case in self.cases if case.reviewed)

    @property
    def unreviewed(self) -> tuple[Case, ...]:
        return tuple(case for case in self.cases if not case.reviewed)

    def lists(self) -> Lists:
        """The frozen list context, validated exactly as the scanner validates it.

        A corpus with contradictory lists would grade every case against a
        precedence accident, so it fails here for the same reason
        :meth:`email_guard.lists.Lists.load` fails closed for the live scanner.
        """
        try:
            return Lists.load(self.lists_dir)
        except InvalidLists as exc:
            raise CorpusError(
                [f"{LISTS_DIRNAME}/: {error}" for error in exc.errors]
            ) from exc

    @classmethod
    def load(cls, root: str | Path) -> "Corpus":
        base = Path(root)
        if not base.is_dir():
            raise CorpusError([f"corpus directory not found: {base}"])

        manifest, errors = _read_manifest(base)
        synthetic_only = bool(manifest.get("synthetic_only"))

        cases_dir = base / CASES_DIRNAME
        if not cases_dir.is_dir():
            raise CorpusError(errors + [f"{CASES_DIRNAME}/ not found under {base}"])

        cases: list[Case] = []
        for case_dir in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
            case, case_errors = _read_case(case_dir, default_synthetic=synthetic_only)
            errors.extend(case_errors)
            if case is not None:
                cases.append(case)

        if not cases and not errors:
            errors.append(f"{CASES_DIRNAME}/ holds no cases")

        # The mixing guard. A synthetic-only corpus is one that may be committed,
        # so a case carrying real mail in it is a privacy failure, not a
        # labelling one -- and it must stop the run rather than be skipped.
        if synthetic_only:
            real = [case.id for case in cases if not case.synthetic]
            if real:
                errors.append(
                    f"{MANIFEST_NAME} declares this corpus SYNTHETIC-ONLY, but "
                    f"{len(real)} case(s) are marked 'synthetic': false "
                    f"({', '.join(sorted(real)[:5])}). Real mail belongs in a "
                    "corpus under the gitignored data tree, never in a committed one."
                )

        if errors:
            raise CorpusError(errors)

        return cls(
            root=base,
            cases=tuple(cases),
            synthetic_only=synthetic_only,
            note=str(manifest.get("note") or ""),
        )


def declares_synthetic_only(root: str | Path) -> bool:
    """Read just the marker, touching nothing else.

    Exists so a caller can answer "may this corpus be committed?" *before*
    opening any case. A guard that has already walked the corpus to find out
    whether it was allowed to has the order backwards, and it makes the operator
    read a labelling complaint when the real problem is where the directory is.
    """
    manifest, _ = _read_manifest(Path(root))
    return bool(manifest.get("synthetic_only"))


def _read_manifest(base: Path) -> tuple[dict[str, Any], list[str]]:
    """The manifest is optional: an unmarked corpus is treated as a real one.

    Absent means "not declared synthetic", which is the safe default -- it means
    the corpus is subject to the ignored-path check in :mod:`.privacy`, and
    cannot be graded from inside the committed tree.
    """
    path = base / MANIFEST_NAME
    if not path.is_file():
        return {}, []
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {}, [f"{MANIFEST_NAME}: unreadable ({exc})"]
    if not isinstance(data, dict):
        return {}, [f"{MANIFEST_NAME}: expected an object at the top level"]
    return data, []


def _read_case(case_dir: Path, *, default_synthetic: bool) -> tuple[Case | None, list[str]]:
    case_id = case_dir.name
    where = f"{CASES_DIRNAME}/{case_id}"
    errors: list[str] = []

    message = case_dir / MESSAGE_NAME
    if not message.is_file():
        errors.append(f"{where}: no {MESSAGE_NAME}")

    expected_path = case_dir / EXPECTED_NAME
    if not expected_path.is_file():
        return None, errors + [f"{where}: no {EXPECTED_NAME}"]

    try:
        with expected_path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, errors + [f"{where}/{EXPECTED_NAME}: unreadable ({exc})"]

    if not isinstance(data, dict):
        return None, errors + [f"{where}/{EXPECTED_NAME}: expected an object"]

    bucket = data.get("expected_bucket")
    if bucket not in BUCKETS:
        errors.append(
            f"{where}/{EXPECTED_NAME}: 'expected_bucket' is {bucket!r}, "
            f"not one of {', '.join(BUCKETS)}"
        )

    level = data.get("expected_level")
    if level is not None and level not in LEVELS:
        errors.append(
            f"{where}/{EXPECTED_NAME}: 'expected_level' is {level!r}, "
            f"not one of {', '.join(str(value) for value in LEVELS)}"
        )

    reviewed = data.get("reviewed")
    if not isinstance(reviewed, bool):
        errors.append(
            f"{where}/{EXPECTED_NAME}: 'reviewed' must be true or false "
            "(a case is graded only once a human has confirmed its label)"
        )
        reviewed = False

    synthetic = data.get("synthetic")
    if synthetic is None:
        # Inherit the corpus. A hand-written case in a synthetic-only corpus is
        # synthetic by construction, and making every one restate that would be
        # noise the reviewer stops reading.
        synthetic = default_synthetic
    elif not isinstance(synthetic, bool):
        errors.append(f"{where}/{EXPECTED_NAME}: 'synthetic' must be true or false")
        synthetic = False

    unknown = sorted(set(data) - _KNOWN_KEYS - {"_note"})
    if unknown:
        errors.append(
            f"{where}/{EXPECTED_NAME}: unexpected key(s) {', '.join(unknown)}"
        )

    if errors:
        return None, errors

    return (
        Case(
            id=case_id,
            message_path=message,
            expected_bucket=str(bucket),
            reviewed=bool(reviewed),
            synthetic=bool(synthetic),
            note=str(data.get("note") or ""),
            expected_level=level,
        ),
        [],
    )
