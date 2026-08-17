"""The harness itself: scoring, direction, the gate, the diff, the importer.

``test_eval_corpus.py`` grades the shipped corpus and answers "do the rules
classify correctly". This file answers the prior question -- "does the scorer
score correctly" -- because a harness that mislabels a false-clear as advisory
is worse than none: it reports green over exactly the failure it exists to
catch.

Corpora here are built in ``tmp_path`` from the committed synthetic one, so the
messages are real inputs to the real scanner and only the *labels* are varied.
Asserting the gate against a fabricated verdict would test the assertion, not
the scanner.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from email_guard.eval import ADVISORY, DANGEROUS, Corpus, CorpusError, diff_against, grade_corpus
from email_guard.eval import __main__ as eval_cli
from email_guard.eval.grade import classify_direction, deciding_list, deciding_stage
from email_guard.eval.importer import import_from_outbound
from email_guard.rulespack import RulesPack

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = PROJECT_ROOT / "tests" / "eval-corpus"

CLEAN_RECEIPT = "greylist-receipt-cleared"   # scans to `cleared`
PHISHING = "phishing-injection-rejected"     # scans to `rejected`
ZERO_WIDTH_PADDING = "greylist-zero-width-padding"          # scans to `cleared`
ZERO_WIDTH_SPLIT = "injection-zero-width-split-rejected"    # scans to `rejected`
GRADED_CASES = 4                             # the committed corpus, all reviewed

# Every case in the committed corpus passes, which is the state a corpus should
# be kept in -- so the harness tests that need a *failure* to look at make one,
# by relabelling a case rather than by relying on a broken one being shipped.
# (The zero-width case used to be that broken one; the triage precision fix
# turned it into a guard.) Two relabels, named for the direction they produce:
#
#   OVER_BLOCK  a message that is rejected, labelled `cleared` -- advisory.
#   FALSE_CLEAR a message that clears, labelled `rejected` -- dangerous.
OVER_BLOCK = dict(expected_bucket="cleared", expected_level=None)
FALSE_CLEAR = dict(expected_bucket="rejected", expected_level=None)


@pytest.fixture(scope="module")
def pack(rules_dir: Path) -> RulesPack:
    return RulesPack.load(rules_dir)


@pytest.fixture
def corpus_copy(tmp_path: Path) -> Path:
    """A writable copy of the committed corpus: same messages, editable labels."""
    target = tmp_path / "corpus"
    shutil.copytree(CORPUS_DIR, target)
    return target


def relabel(corpus: Path, case_id: str, **changes) -> None:
    path = corpus / "cases" / case_id / "expected.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(changes)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def drop(corpus: Path, case_id: str) -> None:
    shutil.rmtree(corpus / "cases" / case_id)


def score(corpus: Path, rules_dir: Path, pack: RulesPack):
    return grade_corpus(Corpus.load(corpus), rules_dir, pack=pack)


def result_for(scorecard, case_id: str):
    return next(r for r in scorecard.results if r.id == case_id)


# --- comparing buckets ------------------------------------------------------


def test_a_case_passes_when_the_actual_bucket_matches(corpus_copy, rules_dir, pack):
    assert result_for(score(corpus_copy, rules_dir, pack), CLEAN_RECEIPT).passed


def test_a_case_fails_when_the_bucket_differs(corpus_copy, rules_dir, pack):
    relabel(corpus_copy, CLEAN_RECEIPT, expected_bucket="flagged", expected_level=None)

    result = result_for(score(corpus_copy, rules_dir, pack), CLEAN_RECEIPT)

    assert result.passed is False
    assert (result.expected_bucket, result.actual_bucket) == ("flagged", "cleared")


def test_an_expected_level_that_differs_fails_a_matching_bucket(
    corpus_copy, rules_dir, pack
):
    """The bucket is the grade; ``expected_level`` is an optional tightening.

    Levels 4 and 5 share the `cleared` bucket, so a case that pins the level
    catches a change the bucket alone would hide.
    """
    relabel(corpus_copy, CLEAN_RECEIPT, expected_level=5)

    result = result_for(score(corpus_copy, rules_dir, pack), CLEAN_RECEIPT)

    assert result.actual_bucket == result.expected_bucket == "cleared"
    assert result.final_level == 4
    assert result.passed is False


def test_an_absent_expected_level_is_not_checked(corpus_copy, rules_dir, pack):
    relabel(corpus_copy, CLEAN_RECEIPT, expected_level=None)

    assert result_for(score(corpus_copy, rules_dir, pack), CLEAN_RECEIPT).passed


# --- direction: the distinction the whole gate rests on ---------------------


@pytest.mark.parametrize(
    "expected, actual, direction",
    [
        # Bad mail in the inbox. The only dangerous shape.
        ("rejected", "cleared", DANGEROUS),
        ("flagged", "cleared", DANGEROUS),
        # Over-blocking: annoying, not a breach.
        ("cleared", "rejected", ADVISORY),
        ("cleared", "flagged", ADVISORY),
        # Wrong quarantine bucket: still quarantined, so nobody saw it.
        ("rejected", "flagged", ADVISORY),
        ("flagged", "rejected", ADVISORY),
    ],
)
def test_direction_classification(expected: str, actual: str, direction: str):
    assert classify_direction(expected, actual) == direction


def test_a_false_clear_is_marked_dangerous_end_to_end(corpus_copy, rules_dir, pack):
    """The real thing: a message that clears, labelled as one that must not."""
    relabel(corpus_copy, CLEAN_RECEIPT, expected_bucket="rejected", expected_level=None)

    scorecard = score(corpus_copy, rules_dir, pack)

    assert result_for(scorecard, CLEAN_RECEIPT).direction == DANGEROUS
    assert [r.id for r in scorecard.dangerous] == [CLEAN_RECEIPT]
    assert scorecard.clean is False


def test_over_blocking_alone_leaves_the_run_clean(corpus_copy, rules_dir, pack):
    """A failing run that is still a pass: one over-block, no false-clear."""
    relabel(corpus_copy, PHISHING, **OVER_BLOCK)

    scorecard = score(corpus_copy, rules_dir, pack)

    assert [result.id for result in scorecard.failures] == [PHISHING]
    assert not scorecard.dangerous
    assert scorecard.clean is True


def test_failures_are_ordered_dangerous_first(corpus_copy, rules_dir, pack):
    """Whatever else is wrong, the false-clear is the line to read first."""
    relabel(corpus_copy, CLEAN_RECEIPT, **FALSE_CLEAR)
    relabel(corpus_copy, PHISHING, **OVER_BLOCK)

    failures = score(corpus_copy, rules_dir, pack).failures

    assert [result.id for result in failures] == [CLEAN_RECEIPT, PHISHING]
    assert failures[0].direction == DANGEROUS


# --- the exit-code gate -----------------------------------------------------


def test_the_cli_exits_zero_on_a_corpus_that_fully_passes(corpus_copy, rules_dir, capsys):
    code = eval_cli.main([str(corpus_copy), "--rules-dir", str(rules_dir)])

    assert code == eval_cli.EXIT_OK
    assert "every graded case landed in its expected bucket" in capsys.readouterr().out


def test_the_cli_exits_zero_on_advisory_failures_only(corpus_copy, rules_dir, capsys):
    """The distinction the gate exists to make: failing, but not dangerously."""
    relabel(corpus_copy, PHISHING, **OVER_BLOCK)

    code = eval_cli.main([str(corpus_copy), "--rules-dir", str(rules_dir)])

    assert code == eval_cli.EXIT_OK
    assert "no dangerous false-clears" in capsys.readouterr().out


def test_the_cli_exits_nonzero_on_a_dangerous_false_clear(
    corpus_copy, rules_dir, capsys
):
    relabel(corpus_copy, CLEAN_RECEIPT, **FALSE_CLEAR)

    code = eval_cli.main([str(corpus_copy), "--rules-dir", str(rules_dir)])

    assert code == eval_cli.EXIT_DANGEROUS
    assert code != 0
    assert "Do not push" in capsys.readouterr().out


def test_the_cli_exits_with_an_error_on_a_broken_corpus(tmp_path, rules_dir, capsys):
    """A corpus that cannot be read must not be reported as a clean run."""
    (tmp_path / "cases").mkdir(parents=True)

    code = eval_cli.main([str(tmp_path), "--rules-dir", str(rules_dir)])

    assert code == eval_cli.EXIT_ERROR
    assert "corpus INVALID" in capsys.readouterr().err


def test_the_cli_writes_the_scorecard_as_json(corpus_copy, rules_dir, tmp_path):
    out = tmp_path / "run.json"

    eval_cli.main(
        [str(corpus_copy), "--rules-dir", str(rules_dir), "--json", str(out)]
    )

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["totals"]["graded"] == GRADED_CASES
    assert {case["id"] for case in payload["cases"]} == {
        CLEAN_RECEIPT,
        PHISHING,
        ZERO_WIDTH_PADDING,
        ZERO_WIDTH_SPLIT,
    }


# --- the confusion matrix ---------------------------------------------------


def test_the_confusion_matrix_counts_every_graded_case(corpus_copy, rules_dir, pack):
    # One off-diagonal cell on purpose: a matrix that only ever fills its
    # diagonal cannot show that a miss is counted where the miss happened.
    relabel(corpus_copy, ZERO_WIDTH_PADDING, expected_bucket="flagged", expected_level=None)

    matrix = score(corpus_copy, rules_dir, pack).confusion

    total = sum(sum(row.values()) for row in matrix.values())
    assert total == GRADED_CASES
    assert matrix["cleared"]["cleared"] == 1      # the clean receipt
    assert matrix["flagged"]["cleared"] == 1      # the relabelled padding case
    assert matrix["rejected"]["rejected"] == 2    # phishing, and the split payload


def test_the_confusion_matrix_is_dense(corpus_copy, rules_dir, pack):
    """Every cell present, including the zeros: absent reads as "no data"."""
    matrix = score(corpus_copy, rules_dir, pack).confusion

    assert set(matrix) == {"cleared", "flagged", "rejected"}
    for row in matrix.values():
        assert set(row) == {"cleared", "flagged", "rejected"}
    assert matrix["flagged"]["flagged"] == 0


# --- forensics on a failure -------------------------------------------------


def test_a_failure_carries_enough_to_diagnose_without_opening_the_file(
    corpus_copy, rules_dir, pack
):
    """Levels, deciding stage, deciding list and the engine's own reason.

    The zero-width split case is the one worth reading here: "rejected, not
    cleared" says nothing on its own, and `hidden_unicode` in the reason is the
    whole diagnosis.
    """
    relabel(corpus_copy, ZERO_WIDTH_SPLIT, **OVER_BLOCK)

    result = result_for(score(corpus_copy, rules_dir, pack), ZERO_WIDTH_SPLIT)

    assert result.passed is False
    assert result.initial_level == 1 and result.final_level == 1
    assert "triage" in result.decided_by
    assert result.decided_list == "no list"
    assert "hidden_unicode" in result.reason
    assert result.forensic_log


def test_the_deciding_stage_names_triage_for_a_terminal_level():
    assert "triage" in deciding_stage({"initial_level": 1, "final_level": 1})
    assert "triage" in deciding_stage({"initial_level": 5, "final_level": 5})


def test_the_deciding_stage_names_the_deep_scan_when_it_moved_the_level():
    moved = deciding_stage({"initial_level": 3, "final_level": 4})
    held = deciding_stage({"initial_level": 4, "final_level": 4})

    assert "deep-scan" in moved and "3 -> 4" in moved
    assert "deep-scan" in held and "confirmed" in held


def test_the_deciding_list_reports_the_list_that_shaped_the_verdict():
    hits = {"whitelist": False, "greylist": False, "blacklist": False}

    assert deciding_list({"list_hits": {**hits, "blacklist": True}}) == "blacklist"
    assert deciding_list({"list_hits": {**hits, "whitelist": True}}) == "whitelist"
    assert deciding_list({"list_hits": hits}) == "no list"
    assert "known" in deciding_list(
        {"list_hits": {**hits, "greylist": True}, "greylist_classification": "known"}
    )


# --- the baseline diff ------------------------------------------------------


def test_the_diff_reports_a_newly_broken_case(corpus_copy, rules_dir, pack):
    baseline = score(corpus_copy, rules_dir, pack).as_dict()
    relabel(corpus_copy, CLEAN_RECEIPT, expected_bucket="flagged", expected_level=None)

    diff = diff_against(baseline, score(corpus_copy, rules_dir, pack))

    assert diff.broken == (CLEAN_RECEIPT,)
    assert diff.fixed == ()


def test_the_diff_reports_a_fixed_case(corpus_copy, rules_dir, pack):
    relabel(corpus_copy, CLEAN_RECEIPT, expected_bucket="flagged", expected_level=None)
    baseline = score(corpus_copy, rules_dir, pack).as_dict()
    relabel(corpus_copy, CLEAN_RECEIPT, expected_bucket="cleared", expected_level=4)

    diff = diff_against(baseline, score(corpus_copy, rules_dir, pack))

    assert diff.fixed == (CLEAN_RECEIPT,)
    assert diff.broken == ()


def test_the_diff_keeps_still_failing_separate_from_newly_broken(
    corpus_copy, rules_dir, pack
):
    """A case failing in both runs is not news, and must not be reported as it."""
    relabel(corpus_copy, PHISHING, **OVER_BLOCK)
    baseline = score(corpus_copy, rules_dir, pack).as_dict()

    diff = diff_against(baseline, score(corpus_copy, rules_dir, pack))

    assert diff.still_failing == (PHISHING,)
    assert diff.broken == () and diff.fixed == ()
    assert diff.moved is False


def test_a_deleted_case_is_removed_not_fixed(corpus_copy, rules_dir, pack):
    """Deleting a failing case must not look like fixing it."""
    relabel(corpus_copy, PHISHING, **OVER_BLOCK)
    baseline = score(corpus_copy, rules_dir, pack).as_dict()
    drop(corpus_copy, PHISHING)

    diff = diff_against(baseline, score(corpus_copy, rules_dir, pack))

    assert diff.removed == (PHISHING,)
    assert diff.fixed == ()


def test_a_new_case_is_added_not_broken(corpus_copy, rules_dir, pack):
    baseline_corpus = Corpus.load(corpus_copy)
    baseline = grade_corpus(baseline_corpus, rules_dir, pack=pack).as_dict()
    baseline["cases"] = [
        case for case in baseline["cases"] if case["id"] != PHISHING
    ]

    diff = diff_against(baseline, score(corpus_copy, rules_dir, pack))

    assert diff.added == (PHISHING,)
    assert diff.broken == ()


def test_the_diff_calls_out_a_case_that_became_dangerous(corpus_copy, rules_dir, pack):
    """A newly dangerous case is buried inside `broken` unless it is named."""
    baseline = score(corpus_copy, rules_dir, pack).as_dict()
    relabel(corpus_copy, CLEAN_RECEIPT, expected_bucket="rejected", expected_level=None)

    diff = diff_against(baseline, score(corpus_copy, rules_dir, pack))

    assert diff.newly_dangerous == (CLEAN_RECEIPT,)


def test_the_cli_prints_the_diff(corpus_copy, rules_dir, tmp_path, capsys):
    baseline_path = tmp_path / "baseline.json"
    eval_cli.main(
        [str(corpus_copy), "--rules-dir", str(rules_dir), "--json", str(baseline_path)]
    )
    relabel(corpus_copy, CLEAN_RECEIPT, expected_bucket="flagged", expected_level=None)
    capsys.readouterr()

    eval_cli.main(
        [str(corpus_copy), "--rules-dir", str(rules_dir), "--baseline", str(baseline_path)]
    )

    out = capsys.readouterr().out
    assert "NEWLY BROKEN" in out
    assert CLEAN_RECEIPT in out


# --- the import helper ------------------------------------------------------


@pytest.fixture
def outbound(tmp_path: Path) -> Path:
    """An outbound store shaped exactly as the scanner's output stage writes it."""
    root = tmp_path / "outbound"
    for bucket, case_id, level in (
        ("cleared", "a1-quietservice.example", 4),
        ("rejected", "b2-phisher.example", 1),
    ):
        job = root / bucket / case_id
        job.mkdir(parents=True)
        source = CORPUS_DIR / "cases" / (
            CLEAN_RECEIPT if bucket == "cleared" else PHISHING
        ) / "message.eml"
        shutil.copyfile(source, job / "message.eml")
        (job / "report.json").write_text(
            json.dumps({"bucket": bucket, "final_level": level}), encoding="utf-8"
        )
    return root


def test_the_importer_stubs_every_case_as_unreviewed(outbound, tmp_path):
    target = tmp_path / "local-corpus"

    result = import_from_outbound(outbound, target)

    assert len(result.imported) == 2
    for case_id in result.imported:
        expected = json.loads(
            (target / "cases" / case_id / "expected.json").read_text(encoding="utf-8")
        )
        assert expected["reviewed"] is False
        assert expected["synthetic"] is False
        assert "NOT REVIEWED" in expected["note"]


def test_the_importer_prefills_the_bucket_the_message_landed_in(outbound, tmp_path):
    """A starting guess to save typing -- explicitly not the answer key."""
    target = tmp_path / "local-corpus"

    import_from_outbound(outbound, target)

    def bucket_of(case_id: str) -> str:
        return json.loads(
            (target / "cases" / case_id / "expected.json").read_text(encoding="utf-8")
        )["expected_bucket"]

    assert bucket_of("cleared-a1-quietservice.example") == "cleared"
    assert bucket_of("rejected-b2-phisher.example") == "rejected"


def test_imported_cases_are_not_graded(outbound, tmp_path, rules_dir, pack):
    """The point of reviewed:false: today's mis-scoring cannot grade itself right."""
    target = tmp_path / "local-corpus"
    (target).mkdir()
    shutil.copytree(CORPUS_DIR / "lists", target / "lists")
    import_from_outbound(outbound, target)

    scorecard = grade_corpus(Corpus.load(target), rules_dir, pack=pack)

    assert scorecard.graded == 0
    assert len(scorecard.unreviewed) == 2
    assert scorecard.clean is True


def test_a_reviewed_imported_case_is_then_graded(outbound, tmp_path, rules_dir, pack):
    target = tmp_path / "local-corpus"
    target.mkdir()
    shutil.copytree(CORPUS_DIR / "lists", target / "lists")
    import_from_outbound(outbound, target)
    relabel(target, "cleared-a1-quietservice.example", reviewed=True)

    scorecard = grade_corpus(Corpus.load(target), rules_dir, pack=pack)

    assert scorecard.graded == 1
    assert result_for(scorecard, "cleared-a1-quietservice.example").passed


def test_the_importer_copies_the_message_verbatim(outbound, tmp_path):
    target = tmp_path / "local-corpus"

    import_from_outbound(outbound, target)

    original = (outbound / "cleared" / "a1-quietservice.example" / "message.eml").read_bytes()
    copied = (
        target / "cases" / "cleared-a1-quietservice.example" / "message.eml"
    ).read_bytes()
    assert copied == original


def test_re_importing_never_overwrites_a_reviewed_label(outbound, tmp_path):
    """A week of reviewing must survive the next import."""
    target = tmp_path / "local-corpus"
    import_from_outbound(outbound, target)
    relabel(
        target,
        "cleared-a1-quietservice.example",
        reviewed=True,
        expected_bucket="flagged",
        note="reviewed by hand",
    )

    again = import_from_outbound(outbound, target)

    expected = json.loads(
        (
            target / "cases" / "cleared-a1-quietservice.example" / "expected.json"
        ).read_text(encoding="utf-8")
    )
    assert again.imported == ()
    assert len(again.skipped) == 2
    assert expected["reviewed"] is True
    assert expected["expected_bucket"] == "flagged"


def test_the_importer_freezes_the_list_context_once(outbound, tmp_path):
    target = tmp_path / "local-corpus"
    lists = tmp_path / "live-lists"
    shutil.copytree(CORPUS_DIR / "lists", lists)

    import_from_outbound(outbound, target, lists_dir=lists)
    frozen = (target / "lists" / "greylist.json").read_text(encoding="utf-8")

    # An edit to the live lists after the freeze must not reach the corpus:
    # the frozen context is half of what every existing label means.
    (lists / "greylist.json").write_text('{"greylist": []}', encoding="utf-8")
    import_from_outbound(outbound, target, lists_dir=lists)

    assert (target / "lists" / "greylist.json").read_text(encoding="utf-8") == frozen


def test_the_importer_stamps_a_real_corpus_manifest(outbound, tmp_path):
    target = tmp_path / "local-corpus"

    import_from_outbound(outbound, target)

    manifest = json.loads((target / "corpus.json").read_text(encoding="utf-8"))
    assert manifest["synthetic_only"] is False
    assert "never be committed" in manifest["note"]


def test_a_json_only_scan_is_skipped_rather_than_half_imported(outbound, tmp_path):
    """`--from-json` scans store message.json; the corpus format is .eml."""
    job = outbound / "flagged" / "c3-json-only"
    job.mkdir(parents=True)
    (job / "message.json").write_text("{}", encoding="utf-8")

    result = import_from_outbound(outbound, tmp_path / "local-corpus")

    assert not any("c3-json-only" in case_id for case_id in result.imported)


# --- corpus validation ------------------------------------------------------


def test_a_case_with_an_unknown_bucket_is_refused(corpus_copy):
    relabel(corpus_copy, CLEAN_RECEIPT, expected_bucket="quarantined")

    with pytest.raises(CorpusError) as raised:
        Corpus.load(corpus_copy)

    assert any("expected_bucket" in error for error in raised.value.errors)


def test_a_case_without_a_reviewed_flag_is_refused(corpus_copy):
    """Defaulting it either way is wrong: silently graded, or silently skipped."""
    path = corpus_copy / "cases" / CLEAN_RECEIPT / "expected.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["reviewed"]
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(CorpusError) as raised:
        Corpus.load(corpus_copy)

    assert any("'reviewed'" in error for error in raised.value.errors)


def test_every_problem_is_reported_at_once(corpus_copy):
    relabel(corpus_copy, CLEAN_RECEIPT, expected_bucket="nonsense")
    relabel(corpus_copy, PHISHING, expected_level=9)

    with pytest.raises(CorpusError) as raised:
        Corpus.load(corpus_copy)

    assert len(raised.value.errors) >= 2


def test_a_corpus_with_contradictory_lists_is_refused(corpus_copy):
    """The list context is validated exactly as the live scanner validates it."""
    (corpus_copy / "lists" / "whitelist.json").write_text(
        json.dumps(
            {
                "whitelist": [
                    {"email": "notices@quietservice.example", "known_structures": []}
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CorpusError) as raised:
        Corpus.load(corpus_copy).lists()

    assert any("more than one list" in error for error in raised.value.errors)


def test_a_case_that_cannot_be_scanned_fails_rather_than_crashing(
    corpus_copy, rules_dir, pack, monkeypatch
):
    """One case that blows up must not take the whole scorecard down with it.

    A run over a few hundred imported messages that aborts on message 40 has
    told the operator nothing about the other 260. The case is recorded as a
    failure carrying the exception, and grading continues.
    """
    from email_guard.eval import grade as grade_module

    real = grade_module.scan_parsed

    def explode(parsed, lists, pack, job_id=None):
        if job_id == CLEAN_RECEIPT:
            raise RuntimeError("boom")
        return real(parsed, lists, pack, job_id=job_id)

    monkeypatch.setattr(grade_module, "scan_parsed", explode)

    scorecard = score(corpus_copy, rules_dir, pack)

    result = result_for(scorecard, CLEAN_RECEIPT)
    assert result.passed is False
    assert result.actual_bucket == "error"
    assert "RuntimeError: boom" in (result.error or "")
    # ...and every other case was still graded.
    assert scorecard.graded == GRADED_CASES
    assert result_for(scorecard, PHISHING).passed


# --- the harness stays out of the scan path -------------------------------------


def test_the_scan_path_does_not_import_the_harness():
    """The scanner container runs `--read-only --network none --cap-drop ALL`.

    The harness lives inside `email_guard` so it can call the real classifier
    rather than a copy of it, which does mean its files ride along in the
    scanner image. What must stay true is that no scan ever *executes* them:
    a dev tool that reads corpora and shells out to git has no business being
    reachable from the per-message hot path.
    """
    probe = (
        "import email_guard.cli, email_guard.pipeline, email_guard.route, sys;"
        "print(sorted(m for m in sys.modules if m.startswith('email_guard.eval')))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )

    assert completed.stdout.strip() == "[]", (
        "importing the scan path pulled in the eval harness: "
        f"{completed.stdout.strip()}"
    )


def test_the_harness_needs_no_dependency_the_scanner_does_not_have():
    """`pyproject.toml` declares `dependencies = []`, and this must not change that.

    Run under `-S` with only the scanner package root on the path: site-packages
    is gone, so an import of anything third-party fails outright instead of
    being quietly satisfied by the dev environment. The harness reads corpora
    with the stdlib and classifies with the scanner that is already there.
    """
    completed = subprocess.run(
        [sys.executable, "-S", "-c", "import email_guard.eval.__main__"],
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "PYTHONPATH": str(PROJECT_ROOT / "scanner"),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )

    assert completed.returncode == 0, (
        "the eval harness needs something outside the stdlib and the scanner:\n"
        + completed.stderr
    )
