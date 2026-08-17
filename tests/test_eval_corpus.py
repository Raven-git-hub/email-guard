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
  is as useless as one that agrees with everything, so the corpus pins both
  directions of every judgement it can.

The zero-width pair is the sharpest example. ``greylist-zero-width-padding``
was a ``strict`` xfail while the hidden-unicode marker fired on any zero-width
character at all; the precision fix in :mod:`email_guard.triage` made it pass,
so it now stands as an ordinary guard against the over-rejection coming back.
``injection-zero-width-split-rejected`` is its opposite number, added with the
fix: the same character class used to cut an injection phrase mid-word, which
must still be rejected. Neither case means much without the other -- one alone
could be satisfied by deleting the marker or by keeping the old blunt one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from email_guard.eval import Corpus, grade_corpus
from email_guard.rulespack import RulesPack

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = PROJECT_ROOT / "tests" / "eval-corpus"

ZERO_WIDTH_PADDING_CASE = "greylist-zero-width-padding"
ZERO_WIDTH_SPLIT_CASE = "injection-zero-width-split-rejected"


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
        ZERO_WIDTH_PADDING_CASE,
        ZERO_WIDTH_SPLIT_CASE,
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

    Over-blocking is allowed to fail here -- it is advisory, not a breach -- but
    nothing may reach 'cleared' that the corpus says should have been held back.
    """
    assert [result.id for result in scorecard.dangerous] == []
    assert scorecard.clean is True


def test_the_zero_width_pair_divides_on_concealment_not_on_characters(scorecard):
    """The fix, stated as the difference between two messages.

    Both bodies carry the same class of invisible character. The padded receipt
    clears because the characters conceal nothing; the split one is rejected,
    and its reason names ``hidden_unicode``, because they cut an instruction
    override into pieces no phrase matcher would see. Asserting the reason and
    not just the bucket is what stops the split case passing for some unrelated
    signal -- the sender is on no list and the phrasing is invisible to both the
    floor's override pattern and the signature feed.
    """
    padding = _result(scorecard, ZERO_WIDTH_PADDING_CASE)
    split = _result(scorecard, ZERO_WIDTH_SPLIT_CASE)

    assert padding.actual_bucket == "cleared" and padding.final_level == 4
    assert "hidden_unicode" not in padding.reason

    assert split.actual_bucket == "rejected" and split.final_level == 1
    assert "hidden_unicode" in split.reason


def test_the_two_receipt_cases_differ_only_by_invisible_characters():
    """What makes the zero-width case evidence rather than an anecdote.

    If the clean receipt and the padded one diverged in any visible way, the
    padded one's verdict could be blamed on that instead. Stripping the
    zero-width characters and the message id must leave the same body -- which
    is also what makes it a live guard now that it clears: only the invisible
    characters can be responsible for either answer.
    """
    clean = (CORPUS_DIR / "cases" / "greylist-receipt-cleared" / "message.eml").read_text(
        encoding="utf-8"
    )
    padded = (CORPUS_DIR / "cases" / ZERO_WIDTH_PADDING_CASE / "message.eml").read_text(
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
