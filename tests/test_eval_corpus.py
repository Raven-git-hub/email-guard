"""The committed synthetic corpus, graded in the normal test run.

This is the harness pointed at itself: every case in ``tests/eval-corpus/`` is
run through the real scanner against the working-tree rules pack, and each
reviewed case must land in the bucket its label claims.

Two things it is for:

* **the corpus guards behaviours forever.** A phishing message carrying an
  instruction override must stay rejected, and a catalogued receipt from a
  greylisted sender must stay cleared, for every user of the shared pack -- not
  just on the operator's machine where the real corpus lives.
* **it proves the harness reflects reality.** A scorer that agrees with nothing
  is as useless as one that agrees with everything, so the corpus deliberately
  contains cases that pass today and one that does not.

The zero-width case is that one, and it is a ``strict`` xfail: when the bug is
fixed it starts passing, the strict marker turns that into a failure, and
whoever fixed it is told to promote the case to an ordinary guard. An xfail that
quietly keeps passing is how a regression test stops being one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from email_guard.eval import DANGEROUS, Corpus, grade_corpus
from email_guard.rulespack import RulesPack

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = PROJECT_ROOT / "tests" / "eval-corpus"

ZERO_WIDTH_CASE = "greylist-zero-width-padding"

# Why this one is expected to fail, in the place a reader hits it first.
ZERO_WIDTH_REASON = (
    "the zero-width bug: triage.injection_markers() raises 'hidden_unicode' on "
    "bare U+200B/U+FEFF padding with no payload beneath it, so a catalogued "
    "receipt from a greylisted sender is rejected at level 1. When the fix lands "
    "this xfail becomes an XPASS -- delete the marker and let the case stand as "
    "an ordinary guard."
)


@pytest.fixture(scope="module")
def corpus() -> Corpus:
    return Corpus.load(CORPUS_DIR)


@pytest.fixture(scope="module")
def scorecard(corpus: Corpus, rules_dir: Path):
    # One pack for the module: loading it validates and imports the whole pack,
    # and it holds no per-scan state.
    return grade_corpus(corpus, rules_dir, pack=RulesPack.load(rules_dir))


def _result(scorecard, case_id: str):
    for result in scorecard.results:
        if result.id == case_id:
            return result
    raise AssertionError(f"{case_id} was not graded")


# --- the corpus itself ------------------------------------------------------


def test_the_committed_corpus_is_marked_synthetic_only(corpus: Corpus):
    """The marker is load-bearing: it is what refuses real cases in here."""
    assert corpus.synthetic_only is True
    assert corpus.cases
    assert all(case.synthetic for case in corpus.cases)


def test_every_committed_case_is_reviewed(corpus: Corpus):
    """An unreviewed case in the committed corpus guards nothing.

    Unreviewed means "not graded", so committing one would look like coverage
    and be none. The import helper's reviewed:false stub belongs in the
    operator's local corpus until a human has confirmed the label.
    """
    assert [case.id for case in corpus.unreviewed] == []


# --- the grades -------------------------------------------------------------


@pytest.mark.parametrize(
    "case_id",
    [
        "phishing-injection-rejected",
        "greylist-receipt-cleared",
        pytest.param(
            ZERO_WIDTH_CASE,
            marks=pytest.mark.xfail(strict=True, reason=ZERO_WIDTH_REASON),
        ),
    ],
)
def test_reviewed_case_lands_in_its_expected_bucket(scorecard, case_id: str):
    result = _result(scorecard, case_id)

    assert result.actual_bucket == result.expected_bucket, (
        f"{case_id}: {result.reason}"
    )
    assert result.passed, f"{case_id}: {result.reason}"


def test_the_corpus_has_no_dangerous_false_clears(scorecard):
    """The gate, asserted in the suite as well as at the command line.

    Over-blocking is allowed to fail here -- the zero-width case does -- but
    nothing may reach 'cleared' that the corpus says should have been held back.
    """
    assert [result.id for result in scorecard.dangerous] == []
    assert scorecard.clean is True


def test_the_known_failure_is_over_blocking_not_a_false_clear(scorecard):
    """Direction matters more than the failure count.

    The zero-width bug quarantines a legitimate receipt. That is a nuisance to
    fix, not a breach, and the harness must classify it that way -- otherwise
    the exit-code gate fires on a corpus that is behaving as documented.
    """
    result = _result(scorecard, ZERO_WIDTH_CASE)

    assert result.passed is False
    assert result.direction != DANGEROUS
    assert result.actual_bucket == "rejected"
    assert "hidden_unicode" in result.reason


def test_the_two_receipt_cases_differ_only_by_invisible_characters():
    """What makes the zero-width case evidence rather than an anecdote.

    If the clean receipt and the padded one diverged in any visible way, the
    padded one's rejection could be blamed on that instead. Stripping the
    zero-width characters and the message id must leave the same body.
    """
    clean = (CORPUS_DIR / "cases" / "greylist-receipt-cleared" / "message.eml").read_text(
        encoding="utf-8"
    )
    padded = (CORPUS_DIR / "cases" / ZERO_WIDTH_CASE / "message.eml").read_text(
        encoding="utf-8"
    )

    assert any(char in padded for char in ("​", "﻿"))
    assert not any(char in clean for char in ("​", "﻿"))

    def body(text: str) -> str:
        stripped = text.split("\n\n", 1)[1]
        return stripped.replace("​", "").replace("﻿", "")

    # Only the reference number and the trailing SYNTHETIC note differ.
    assert body(clean).split("<p>Amount")[0] == body(padded).split("<p>Amount")[0]


# --- determinism ------------------------------------------------------------


def test_grading_the_same_corpus_twice_is_identical(corpus: Corpus, rules_dir: Path):
    """A baseline diff is meaningless if a re-run can move a case on its own.

    The scanner is deterministic by design, but the harness could still break
    that -- ``clean()`` stamps a fresh uuid as the job id when none is given, so
    grading has to pass a stable one. This is the test that would catch it.
    """
    pack = RulesPack.load(rules_dir)

    first = grade_corpus(corpus, rules_dir, pack=pack).as_dict()
    second = grade_corpus(corpus, rules_dir, pack=pack).as_dict()

    assert first == second


def test_a_freshly_loaded_pack_grades_the_same(corpus: Corpus, rules_dir: Path):
    """And re-loading the pack between runs changes nothing either."""
    first = grade_corpus(corpus, rules_dir, pack=RulesPack.load(rules_dir)).as_dict()
    second = grade_corpus(corpus, rules_dir, pack=RulesPack.load(rules_dir)).as_dict()

    assert first == second
