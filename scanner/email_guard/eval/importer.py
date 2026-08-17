"""Building a real corpus out of what the scanner has already stored.

Every scan writes ``<outbound>/<bucket>/<job>/message.eml`` beside its report,
so the operator's mailbox has been assembling the raw material for a corpus all
along. This copies it into corpus shape.

**It pre-fills the label and refuses to trust it.** ``expected_bucket`` is set
to the bucket the message actually landed in, and ``reviewed`` is set to
``false``, which means the harness will not grade the case. That is the entire
design: the reason a harness is being built is that the scanner mis-scores real
mail, so grading against its own past output would score it as perfect and
freeze today's mistakes in as the answer key. The bucket is a starting guess to
save typing. The human asserts the truth by flipping ``reviewed`` to ``true``.

Two things it will not do:

* import into a corpus marked ``synthetic_only`` -- that corpus is committed,
  and this function's whole input is real mail;
* overwrite an existing case -- a re-import after a week of reviewing must not
  reset every label to ``reviewed: false``.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..route import BUCKETS, REPORT_NAME
from .corpus import (
    CASES_DIRNAME,
    EXPECTED_NAME,
    LISTS_DIRNAME,
    MANIFEST_NAME,
    MESSAGE_NAME,
    CorpusError,
)

LIST_FILES = ("whitelist.json", "greylist.json", "blacklist.json")


@dataclass(frozen=True)
class Imported:
    """What one import run did."""

    corpus: Path
    imported: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    froze_lists: Path | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "corpus": str(self.corpus),
            "imported": len(self.imported),
            "imported_ids": list(self.imported),
            "skipped": list(self.skipped),
            "froze_lists": str(self.froze_lists) if self.froze_lists else None,
        }


def import_from_outbound(
    outbound_dir: str | Path,
    corpus_dir: str | Path,
    *,
    lists_dir: str | Path | None = None,
) -> Imported:
    """Copy every stored message under ``outbound_dir`` into ``corpus_dir``."""
    outbound = Path(outbound_dir)
    corpus = Path(corpus_dir)

    if not outbound.is_dir():
        raise CorpusError([f"outbound directory not found: {outbound}"])

    _refuse_synthetic_target(corpus)

    (corpus / CASES_DIRNAME).mkdir(parents=True, exist_ok=True)
    froze = _freeze_lists(corpus, lists_dir)
    _write_manifest(corpus)

    imported: list[str] = []
    skipped: list[str] = []

    for bucket in BUCKETS:
        bucket_dir = outbound / bucket
        if not bucket_dir.is_dir():
            continue
        for job_dir in sorted(entry for entry in bucket_dir.iterdir() if entry.is_dir()):
            message = job_dir / MESSAGE_NAME
            if not message.is_file():
                # A `--from-json` scan stores message.json instead. The corpus
                # format is .eml only, so those are passed over rather than
                # half-imported into a case that cannot be read.
                continue
            case_id = _case_id(bucket, job_dir.name)
            target = corpus / CASES_DIRNAME / case_id
            if target.exists():
                skipped.append(case_id)
                continue
            _write_case(target, message, bucket, job_dir)
            imported.append(case_id)

    return Imported(
        corpus=corpus,
        imported=tuple(imported),
        skipped=tuple(skipped),
        froze_lists=froze,
    )


def _refuse_synthetic_target(corpus: Path) -> None:
    """A committed corpus is not a place to put the operator's mail."""
    manifest = corpus / MANIFEST_NAME
    if not manifest.is_file():
        return
    try:
        with manifest.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return
    if isinstance(data, dict) and data.get("synthetic_only"):
        raise CorpusError(
            [
                f"{corpus} is marked SYNTHETIC-ONLY in {MANIFEST_NAME} and is "
                "committed to git. Importing real mail into it would put real "
                "messages in the repository. Import into a corpus under the "
                "gitignored data tree instead, e.g. data/eval-corpus/."
            ]
        )


def _case_id(bucket: str, job: str) -> str:
    """``<bucket>-<job>``: unique, and readable as "where this started".

    The bucket prefix is not decoration. The same message re-scanned after a
    rule change lands in a different bucket and therefore a different job
    directory, and without the prefix the two would collide on one case id.
    """
    return f"{bucket}-{job}"


def _write_case(target: Path, message: Path, bucket: str, job_dir: Path) -> None:
    target.mkdir(parents=True)
    shutil.copyfile(message, target / MESSAGE_NAME)

    observed = _observed(job_dir)
    detail = f" (final level {observed})" if observed is not None else ""

    expected = {
        "expected_bucket": bucket,
        "reviewed": False,
        "synthetic": False,
        "note": (
            f"IMPORTED, NOT REVIEWED. The scanner put this in '{bucket}'{detail}; "
            "that is what it does today, not necessarily what it should do. "
            "Confirm or correct expected_bucket, replace this note with why, then "
            "set \"reviewed\": true. Until then this case is not graded."
        ),
    }
    _write_json(target / EXPECTED_NAME, expected)


def _observed(job_dir: Path) -> int | None:
    """The final level from the stored report, purely to inform the reviewer."""
    report = job_dir / REPORT_NAME
    if not report.is_file():
        return None
    try:
        with report.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    level = data.get("final_level") if isinstance(data, dict) else None
    return level if isinstance(level, int) else None


def _freeze_lists(corpus: Path, lists_dir: str | Path | None) -> Path | None:
    """Copy the live lists into the corpus, once.

    Once, and never again: the frozen context is half of what a label means, so
    re-importing must not silently re-point old cases at edited lists. A corpus
    whose list context needs updating is a corpus whose labels need re-reviewing,
    and that is a decision for the operator, not for an import helper.
    """
    target = corpus / LISTS_DIRNAME
    if target.exists() or lists_dir is None:
        return None
    source = Path(lists_dir)
    if not source.is_dir():
        return None

    target.mkdir(parents=True)
    copied = False
    for name in LIST_FILES:
        if (source / name).is_file():
            shutil.copyfile(source / name, target / name)
            copied = True
    return source if copied else None


def _write_manifest(corpus: Path) -> None:
    """Stamp a real corpus as real, so nothing later mistakes it for synthetic."""
    path = corpus / MANIFEST_NAME
    if path.is_file():
        return
    _write_json(
        path,
        {
            "synthetic_only": False,
            "note": (
                "REAL MAIL. Imported from the scanner's outbound store. This "
                "corpus must stay under the gitignored data tree and must never "
                "be committed."
            ),
        },
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    """Same fixed formatting the scanner uses, so a re-import produces no diff noise."""
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)
    path.write_text(text + "\n", encoding="utf-8")


__all__ = ["Imported", "import_from_outbound"]
