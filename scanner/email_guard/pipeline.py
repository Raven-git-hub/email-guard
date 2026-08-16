"""The scanner as one function: parsed message in, verdict out.

parse -> clean -> triage -> deep scan -> [canary] -> assess -> route -> verdict

Two entry points, sharing everything up to the verdict:

* :func:`scan_parsed` -- pure. Computes the verdict and writes nothing.
* :func:`scan_and_write` -- the CLI's default path. Same verdict, then routes
  the message to ``<outbound_dir>/<bucket>/<job>/`` and stages a daily-brief
  candidate when the message is worth a human's attention.

The date used for the daily-brief folder is a parameter (``now``), not a call
to the clock buried in the logic: the same message scanned twice with the same
date must produce identical files.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from . import canary as canary_module
from . import deepscan, loop, propose, route, triage
from .clean import clean
from .lists import Lists, classify_greylist
from .outputs import build_verdict
from .route import SourceMessage
from .rulespack import RulesPack


@dataclass(frozen=True)
class ScanResult:
    """Everything the output stage needs, beyond the verdict itself."""

    verdict: dict[str, Any]
    message: dict[str, Any]
    proposal: dict[str, Any]
    greylist_entry: dict[str, Any] | None


def scan(
    parsed: dict[str, Any],
    lists: Lists,
    pack: RulesPack,
    job_id: str | None = None,
) -> ScanResult:
    """Run the full pipeline over one parsed message. Writes nothing."""
    message = clean(parsed, lists, job_id=job_id)

    sender = message["original_sender"]
    sender_domain = sender.split("@")[1] if "@" in sender else ""
    greylist_classification, grey_entry, _structure = classify_greylist(
        lists.greylist, sender, sender_domain, message["title"], message["clean_text"]
    )

    initial_level, reasons = triage.initial_level(
        message, greylist_classification, pack.signature_feed
    )

    report = loop.run(message, initial_level, reasons, pack, deepscan)
    final_level = report["finalLevel"]

    # The Canary sees only the high-threat levels (root README, step 4).
    canary_result = (
        canary_module.evaluate(message)
        if canary_module.should_evaluate(final_level)
        else {
            "injection": None,
            "phishing": None,
            "reason": "not applicable at this level",
            "available": False,
        }
    )

    proposal = propose.classify(message, greylist_classification)
    verdict = build_verdict(message, report, greylist_classification, canary_result, proposal)

    return ScanResult(
        verdict=verdict, message=message, proposal=proposal, greylist_entry=grey_entry
    )


def scan_parsed(
    parsed: dict[str, Any],
    lists: Lists,
    pack: RulesPack,
    job_id: str | None = None,
) -> dict[str, Any]:
    """The verdict alone -- the library form, unchanged and side-effect free."""
    return scan(parsed, lists, pack, job_id=job_id).verdict


def scan_and_write(
    parsed: dict[str, Any],
    lists: Lists,
    pack: RulesPack,
    source: SourceMessage,
    *,
    outbound_dir: str | Path,
    daily_brief_dir: str | Path,
    job_id: str | None = None,
    now: date | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Scan, then persist: the verdict, the original message, and any candidate.

    Returns the verdict with its ``written`` section filled in -- or left null
    under ``dry_run``, which computes everything and touches no disk.
    """
    result = scan(parsed, lists, pack, job_id=job_id)
    verdict = result.verdict
    if dry_run:
        return verdict

    day = now or date.today()
    # An id-less message still needs a stable home, so the slug falls back to a
    # hash of the raw source rather than anything per-run.
    job = route.job_slug(verdict.get("message_id"), fallback=source.raw)
    paths = route.plan_paths(outbound_dir, verdict["bucket"], job, source)

    candidate = None
    candidate_file: Path | None = None
    if propose.wants_candidate(result.proposal):
        candidate_file = propose.candidate_path(daily_brief_dir, day, job)
        candidate = propose.build_candidate(
            result.message,
            verdict,
            result.proposal,
            job=job,
            day=day,
            greylist_entry=result.greylist_entry,
        )

    # Planned before anything is written, so report.json records its own paths.
    verdict["written"] = {
        "job": job,
        "bucket": verdict["bucket"],
        "date": day.isoformat(),
        "dir": str(paths["dir"]),
        "report": str(paths["report"]),
        "message": str(paths["message"]),
        "candidate": str(candidate_file) if candidate_file else None,
    }

    route.write_outbound(verdict, source, paths)
    if candidate is not None and candidate_file is not None:
        propose.write_candidate(candidate, candidate_file)

    return verdict
