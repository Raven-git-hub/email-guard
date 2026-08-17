"""Rendering a scorecard for a terminal.

The JSON is the machine-readable record; this is what an operator actually reads
at the end of a run, so it is ordered by what they need to decide next:

1. did anything dangerous get through -- the one line that decides the push;
2. the totals, and how many cases were skipped for want of a review;
3. the confusion matrix, which shows the *shape* of the mistakes at a glance;
4. the failures in full, dangerous first, each with enough forensics to act on.

No colour and no unicode box-drawing: this output goes into CI logs and terminal
scrollback as often as a live terminal, and both mangle them.
"""

from __future__ import annotations

from typing import Any

from ..route import BUCKETS
from .grade import DANGEROUS, CaseResult, Diff, Scorecard

_WIDTH = 78


def render(scorecard: Scorecard, *, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.extend(_header(scorecard))
    lines.append("")
    lines.extend(_totals(scorecard))
    lines.append("")
    lines.extend(_confusion(scorecard))

    if scorecard.failures:
        lines.append("")
        lines.append("FAILURES")
        for result in scorecard.failures:
            lines.extend(_failure(result, verbose=verbose))

    if verbose and scorecard.passed:
        lines.append("")
        lines.append("PASSED")
        for result in scorecard.passed:
            lines.append(
                f"  ok  {result.id}: {result.actual_bucket} "
                f"(level {result.final_level}, {result.decided_by})"
            )

    lines.append("")
    lines.append(_verdict_line(scorecard))
    return "\n".join(lines)


def _header(scorecard: Scorecard) -> list[str]:
    marker = " [SYNTHETIC-ONLY]" if scorecard.synthetic_only else ""
    return [
        "=" * _WIDTH,
        f"rule evaluation: {scorecard.corpus_root}{marker}",
        f"rules pack:      {scorecard.rules_dir}",
        "=" * _WIDTH,
    ]


def _totals(scorecard: Scorecard) -> list[str]:
    lines = [
        f"graded {scorecard.graded}  |  passed {len(scorecard.passed)}  "
        f"failed {len(scorecard.failures)}  "
        f"(dangerous {len(scorecard.dangerous)}, advisory {len(scorecard.advisory)})"
    ]
    if scorecard.unreviewed:
        # Not a footnote. An operator who imported 200 cases and reviewed 3 is
        # otherwise looking at a very green scorecard that means almost nothing.
        lines.append(
            f"  ! {len(scorecard.unreviewed)} case(s) NOT GRADED: awaiting review. "
            "Set \"reviewed\": true in expected.json once the label is confirmed."
        )
    return lines


def _confusion(scorecard: Scorecard) -> list[str]:
    matrix = scorecard.confusion
    width = max(len(bucket) for bucket in BUCKETS) + 2
    header = "expected \\ actual".ljust(20) + "".join(
        bucket.rjust(width) for bucket in BUCKETS
    )
    lines = ["confusion matrix", "  " + header]
    for expected in BUCKETS:
        row = matrix[expected]
        cells = "".join(str(row[actual]).rjust(width) for actual in BUCKETS)
        lines.append("  " + expected.ljust(20) + cells)
    return lines


def _failure(result: CaseResult, *, verbose: bool = False) -> list[str]:
    tag = "DANGEROUS" if result.direction == DANGEROUS else "advisory"
    lines = [
        "",
        f"  [{tag}] {result.id}",
        f"      expected {result.expected_bucket}, got {result.actual_bucket}"
        + (
            f"  (expected level {result.expected_level}, got {result.final_level})"
            if result.expected_level is not None
            and result.expected_level != result.final_level
            else ""
        ),
        f"      levels:   initial {result.initial_level} -> final {result.final_level}",
        f"      decided:  {result.decided_by}, {result.decided_list}",
        f"      because:  {result.reason}",
    ]
    if result.note:
        lines.append(f"      label:    {result.note}")
    if result.error:
        lines.append(f"      ERROR:    {result.error}")
    if verbose and result.forensic_log:
        lines.append("      forensic log:")
        lines.extend(f"        - {entry}" for entry in result.forensic_log)
    return lines


def _verdict_line(scorecard: Scorecard) -> str:
    if scorecard.dangerous:
        return (
            f"FAIL: {len(scorecard.dangerous)} dangerous false-clear(s) -- "
            "mail that should have been held back reached 'cleared'. Do not push."
        )
    if scorecard.failures:
        return (
            f"PASS (with {len(scorecard.failures)} advisory failure(s)): no dangerous "
            "false-clears. Over-blocking is a nuisance, not a breach."
        )
    return "PASS: every graded case landed in its expected bucket."


def render_diff(diff: Diff, baseline_path: str) -> str:
    """The ``--baseline`` section: what this change did, in five lists."""
    lines = ["", "-" * _WIDTH, f"vs baseline: {baseline_path}", "-" * _WIDTH]

    if not diff.moved and not diff.still_failing:
        lines.append("  no change: the same cases pass and fail as before.")
        return "\n".join(lines)

    for label, ids, prefix in (
        ("FIXED", diff.fixed, "  + "),
        ("NEWLY BROKEN", diff.broken, "  - "),
        ("still failing", diff.still_failing, "    "),
        ("new cases", diff.added, "  > "),
        ("cases removed since the baseline", diff.removed, "  < "),
    ):
        if not ids:
            continue
        lines.append(f"{label} ({len(ids)}):")
        lines.extend(f"{prefix}{case_id}" for case_id in ids)

    if diff.newly_dangerous:
        lines.append("")
        lines.append(
            f"  !! {len(diff.newly_dangerous)} case(s) became DANGEROUS false-clears: "
            + ", ".join(diff.newly_dangerous)
        )
    return "\n".join(lines)


def render_import(summary: dict[str, Any]) -> str:
    """What the import helper did, and the one thing the operator must do next."""
    lines = [
        f"imported {summary['imported']} case(s) into {summary['corpus']}",
    ]
    if summary.get("skipped"):
        lines.append(
            f"  {len(summary['skipped'])} already in the corpus, left untouched "
            "(an existing label is never overwritten)"
        )
    if summary.get("froze_lists"):
        lines.append(f"  froze the list context from {summary['froze_lists']}")
    if summary["imported"]:
        lines.append("")
        lines.append(
            "  Every imported case is marked \"reviewed\": false and is NOT graded. "
            "The pre-filled expected_bucket is what the scanner chose today, which "
            "is a starting guess, not the answer. Confirm or correct it, then set "
            "\"reviewed\": true."
        )
    return "\n".join(lines)
