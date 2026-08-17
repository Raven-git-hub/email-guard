"""Running the corpus through the real scanner, and scoring the result.

The scan itself is three lines; everything else here is about making a failure
diagnosable without opening the message. A scorecard that says "3 failed" sends
the reviewer back to the .eml files one at a time, so each failure carries the
levels, the stage that decided, the list that decided, and the forensic line the
engine itself wrote.

**Direction, not just pass/fail.** The two ways to be wrong are not comparable:

* expected ``flagged``/``rejected``, actually ``cleared`` -- bad mail reached the
  inbox. :data:`DANGEROUS`, and the only thing that fails the run.
* everything else -- over-blocking, or a miss that landed in the wrong
  quarantine bucket. :data:`ADVISORY`: reported in full, exit code unaffected.

Gating on advisory failures would make the gate useless. Tightening a rule
almost always costs a few over-blocks before it is tuned, and a gate that
refuses every tightening step is a gate people learn to bypass.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import parse
from ..loop import TERMINAL_LEVELS
from ..pipeline import scan_parsed
from ..route import BUCKETS, CLEARED
from ..rulespack import RulesPack
from .corpus import Case, Corpus

DANGEROUS = "dangerous"
ADVISORY = "advisory"


@dataclass(frozen=True)
class CaseResult:
    """One graded case: what was expected, what happened, and why."""

    id: str
    expected_bucket: str
    actual_bucket: str
    passed: bool
    direction: str | None
    initial_level: int | None
    final_level: int | None
    expected_level: int | None
    decided_by: str
    decided_list: str
    reason: str
    note: str = ""
    forensic_log: tuple[str, ...] = ()
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "expected_bucket": self.expected_bucket,
            "actual_bucket": self.actual_bucket,
            "passed": self.passed,
            "direction": self.direction,
            "initial_level": self.initial_level,
            "final_level": self.final_level,
            "expected_level": self.expected_level,
            "decided_by": self.decided_by,
            "decided_list": self.decided_list,
            "reason": self.reason,
            "note": self.note,
            "forensic_log": list(self.forensic_log),
            "error": self.error,
        }


@dataclass(frozen=True)
class Scorecard:
    """The whole run: every graded case, plus what was skipped and why."""

    corpus_root: Path
    rules_dir: Path
    synthetic_only: bool
    results: tuple[CaseResult, ...] = ()
    unreviewed: tuple[str, ...] = ()

    @property
    def graded(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> tuple[CaseResult, ...]:
        return tuple(result for result in self.results if result.passed)

    @property
    def failures(self) -> tuple[CaseResult, ...]:
        """Failures, dangerous first -- the order a reviewer should read them in."""
        failed = [result for result in self.results if not result.passed]
        return tuple(
            sorted(failed, key=lambda result: (result.direction != DANGEROUS, result.id))
        )

    @property
    def dangerous(self) -> tuple[CaseResult, ...]:
        return tuple(r for r in self.results if r.direction == DANGEROUS)

    @property
    def advisory(self) -> tuple[CaseResult, ...]:
        return tuple(r for r in self.results if r.direction == ADVISORY)

    @property
    def confusion(self) -> dict[str, dict[str, int]]:
        """Expected bucket x actual bucket. Every cell present, including zeros.

        A dense matrix rather than a sparse one: the shape of the mistakes is
        the point, and a missing row reads as "no data" when it means "none".
        """
        matrix = {
            expected: {actual: 0 for actual in BUCKETS} for expected in BUCKETS
        }
        for result in self.results:
            row = matrix.get(result.expected_bucket)
            if row is None or result.actual_bucket not in row:
                continue
            row[result.actual_bucket] += 1
        return matrix

    @property
    def clean(self) -> bool:
        """No dangerous false-clears. This, and only this, is the gate."""
        return not self.dangerous

    def as_dict(self) -> dict[str, Any]:
        return {
            "corpus": str(self.corpus_root),
            "rules_dir": str(self.rules_dir),
            "synthetic_only": self.synthetic_only,
            "totals": {
                "cases": self.graded + len(self.unreviewed),
                "graded": self.graded,
                "unreviewed": len(self.unreviewed),
                "passed": len(self.passed),
                "failed": len(self.failures),
                "dangerous": len(self.dangerous),
                "advisory": len(self.advisory),
            },
            "confusion": self.confusion,
            "cases": [result.as_dict() for result in self.results],
            "unreviewed_ids": list(self.unreviewed),
        }


def grade_corpus(
    corpus: Corpus, rules_dir: str | Path, *, pack: RulesPack | None = None
) -> Scorecard:
    """Score a corpus against a rules pack.

    ``pack`` is injectable so a caller grading several corpora (or the same one
    twice, for the determinism test) pays the validate-and-import cost once. The
    pack is stateless across scans -- it is data plus imported modules -- so
    sharing one changes no verdict.
    """
    base = Path(rules_dir)
    loaded = pack if pack is not None else RulesPack.load(base)
    lists = corpus.lists()

    results = [_grade_case(case, lists, loaded) for case in corpus.reviewed]

    return Scorecard(
        corpus_root=corpus.root,
        rules_dir=base,
        synthetic_only=corpus.synthetic_only,
        results=tuple(results),
        unreviewed=tuple(case.id for case in corpus.unreviewed),
    )


def _grade_case(case: Case, lists, pack: RulesPack) -> CaseResult:
    try:
        parsed = parse.parse_eml(case.read())
        # The case id as the job id, not a fresh uuid: `clean` stamps the job id
        # into the message, so a random one would make two runs of the same
        # corpus differ. Determinism is the whole basis for a baseline diff.
        verdict = scan_parsed(parsed, lists, pack, job_id=case.id)
    except Exception as exc:  # a case that cannot be scanned is a failure, not a crash
        return CaseResult(
            id=case.id,
            expected_bucket=case.expected_bucket,
            actual_bucket="error",
            passed=False,
            direction=ADVISORY,
            initial_level=None,
            final_level=None,
            expected_level=case.expected_level,
            decided_by="not scanned",
            decided_list="unknown",
            reason=f"{type(exc).__name__}: {exc}",
            note=case.note,
            error=f"{type(exc).__name__}: {exc}",
        )

    actual = verdict["bucket"]
    bucket_ok = actual == case.expected_bucket
    level_ok = case.expected_level is None or verdict["final_level"] == case.expected_level
    passed = bucket_ok and level_ok

    return CaseResult(
        id=case.id,
        expected_bucket=case.expected_bucket,
        actual_bucket=actual,
        passed=passed,
        direction=None if passed else classify_direction(case.expected_bucket, actual),
        initial_level=verdict["initial_level"],
        final_level=verdict["final_level"],
        expected_level=case.expected_level,
        decided_by=deciding_stage(verdict),
        decided_list=deciding_list(verdict),
        reason=forensic_reason(verdict),
        note=case.note,
        forensic_log=tuple(verdict.get("forensic_log") or ()),
    )


def classify_direction(expected: str, actual: str) -> str:
    """How wrong is wrong.

    Only one shape is dangerous: mail that should have been held back, cleared.
    A message expected to be ``rejected`` that came out ``flagged`` is a
    mis-grade worth fixing, but it is still in quarantine -- nobody's inbox saw
    it -- so it is advisory, exactly like over-blocking.
    """
    if actual == CLEARED and expected != CLEARED:
        return DANGEROUS
    return ADVISORY


def deciding_stage(verdict: dict[str, Any]) -> str:
    """Which half of the pipeline settled the level.

    Read from the levels rather than from the log text: levels 1 and 5 are
    triage-terminal (``email_guard.loop`` returns before the deep scan runs at
    all), so an initial level of 1 or 5 *is* the statement that triage decided.
    """
    initial = verdict.get("initial_level")
    final = verdict.get("final_level")
    if initial in TERMINAL_LEVELS:
        return f"triage (level {initial} is terminal)"
    if initial == final:
        return f"deep-scan (confirmed level {final})"
    return f"deep-scan (level {initial} -> {final})"


def deciding_list(verdict: dict[str, Any]) -> str:
    """Which list, if any, shaped the outcome -- identity is half of every verdict."""
    hits = verdict.get("list_hits") or {}
    classification = verdict.get("greylist_classification")
    if hits.get("blacklist"):
        return "blacklist"
    if hits.get("greylist"):
        return f"greylist ({classification})"
    if hits.get("whitelist"):
        return "whitelist"
    return "no list"


def forensic_reason(verdict: dict[str, Any]) -> str:
    """The engine's own words: the triage line, and the last thing that happened.

    The full log stays in the JSON; this is the one-line form for a terminal,
    and those two entries are where the answer nearly always is -- what triage
    made of it, and what the last assessment did about that.
    """
    log = list(verdict.get("forensic_log") or ())
    if not log:
        return "no forensic log"
    if len(log) == 1:
        return log[0]
    return f"{log[0]} || {log[-1]}"


# --- comparing two runs ---------------------------------------------------------


@dataclass(frozen=True)
class Diff:
    """What a change did: the question ``--baseline`` exists to answer."""

    fixed: tuple[str, ...] = ()
    broken: tuple[str, ...] = ()
    still_failing: tuple[str, ...] = ()
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    newly_dangerous: tuple[str, ...] = ()

    @property
    def moved(self) -> bool:
        return bool(self.fixed or self.broken or self.added or self.removed)

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "fixed": list(self.fixed),
            "broken": list(self.broken),
            "still_failing": list(self.still_failing),
            "added": list(self.added),
            "removed": list(self.removed),
            "newly_dangerous": list(self.newly_dangerous),
        }


def diff_against(baseline: dict[str, Any], current: Scorecard) -> Diff:
    """Compare this run to a previous run's JSON.

    Cases are matched by id. A case only in one run is reported as added or
    removed rather than silently counted as a change -- "I deleted the failing
    case" and "I fixed the failing case" must not look the same.
    """
    before = {
        entry.get("id"): entry
        for entry in (baseline.get("cases") or [])
        if isinstance(entry, dict) and entry.get("id")
    }
    now = {result.id: result for result in current.results}

    shared = set(before) & set(now)
    fixed = sorted(i for i in shared if not before[i].get("passed") and now[i].passed)
    broken = sorted(i for i in shared if before[i].get("passed") and not now[i].passed)
    still = sorted(
        i for i in shared if not before[i].get("passed") and not now[i].passed
    )

    return Diff(
        fixed=tuple(fixed),
        broken=tuple(broken),
        still_failing=tuple(still),
        added=tuple(sorted(set(now) - set(before))),
        removed=tuple(sorted(set(before) - set(now))),
        # Called out separately because it is the one transition that turns a
        # green run red, and burying it in `broken` invites skimming past it.
        newly_dangerous=tuple(
            sorted(
                i
                for i in shared
                if now[i].direction == DANGEROUS
                and before[i].get("direction") != DANGEROUS
            )
        ),
    )
