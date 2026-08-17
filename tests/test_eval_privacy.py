"""The privacy guards: real mail must not be able to reach git.

A corpus is a pile of whole messages with real senders in them, and this
repository was briefly public. So the rule "the real corpus lives under the
gitignored data tree" is enforced in three independent places, because any one
of them can be got around:

1. **The index guard** (:func:`~email_guard.eval.privacy.tracked_eml_outside`)
   fails the build if git tracks any ``.eml`` outside the sanctioned synthetic
   directories. This is the backstop: it catches a message copied in by hand and
   ``git add``-ed, which no amount of tooling discipline would.
2. **The ignored-path check** refuses to *run* a corpus of real mail that git is
   not ignoring, so the harness never blesses a corpus sitting somewhere it
   could be committed from.
3. **The mixing check** refuses a corpus marked SYNTHETIC-ONLY that contains a
   case marked ``"synthetic": false``, and the importer refuses to write real
   mail into such a corpus at all.

Guard 1 is the one that matters if the others are ever bypassed, so it runs
against the real repository rather than a fixture.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from email_guard.eval import Corpus, CorpusError
from email_guard.eval.importer import import_from_outbound
from email_guard.eval.privacy import (
    SYNTHETIC_EML_ROOTS,
    NotIgnored,
    corpus_probe,
    is_ignored,
    refuse_if_committable,
    tracked_eml_outside,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = PROJECT_ROOT / "tests" / "eval-corpus"

needs_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="the privacy guards ask git, not a pattern matcher"
)


def git(*args: str, cwd: Path) -> str:
    completed = subprocess.run(
        [
            "git",
            "-c",
            "user.email=tests@example.invalid",
            "-c",
            "user.name=Email Guard Tests",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


# --- guard 1: nothing real is tracked -------------------------------------------


@needs_git
def test_no_eml_is_tracked_outside_the_synthetic_directories():
    """The build breaks loudly rather than a real email leaking quietly.

    Two directories are allowed, and both are synthetic by policy:
    ``tests/eval-corpus/`` (this harness's committed corpus, whose manifest
    declares it and whose cases are refused if marked real) and
    ``tests/fixtures/eml/`` (the scanner's own hand-made fixtures, which predate
    the harness -- every one carries a SYNTHETIC note and reserved .example
    domains). Anywhere else is a leak.
    """
    leaked = tracked_eml_outside(PROJECT_ROOT)

    assert leaked == [], (
        "these .eml files are tracked by git outside the synthetic corpora "
        f"{SYNTHETIC_EML_ROOTS}: {leaked}. If any is real mail, it must be "
        "removed from the index (and from history if it was pushed); if it is "
        "invented, move it into one of those directories."
    )


@needs_git
def test_the_guard_actually_finds_a_tracked_eml(tmp_path: Path):
    """A guard that cannot fail is not a guard.

    Asserting the healthy state above proves nothing on its own -- a function
    that always returned [] would pass it. This stages a leak in a throwaway
    repository and requires it to be caught.
    """
    repo = tmp_path / "repo"
    (repo / "somewhere").mkdir(parents=True)
    git("init", "-b", "main", cwd=repo)
    (repo / "somewhere" / "real-mail.eml").write_text("From: a@b\n\nhi\n", encoding="utf-8")
    git("add", "-A", cwd=repo)

    assert tracked_eml_outside(repo) == ["somewhere/real-mail.eml"]


@needs_git
def test_the_guard_allows_the_synthetic_directories(tmp_path: Path):
    repo = tmp_path / "repo"
    for root in SYNTHETIC_EML_ROOTS:
        (repo / root).mkdir(parents=True)
        (repo / root / "case.eml").write_text("From: a@b\n\nhi\n", encoding="utf-8")
    git("init", "-b", "main", cwd=repo)
    git("add", "-A", cwd=repo)

    assert tracked_eml_outside(repo) == []


@needs_git
def test_the_local_corpus_path_is_gitignored():
    """`data/eval-corpus/` is where the operator's real corpus goes.

    Asked of git rather than matched against `.gitignore` by hand: a check that
    disagrees with git would report safe where git would commit. And asked about
    a *message path*, not the directory -- `data/eval-corpus/**` ignores the
    contents while leaving the directory itself trackable, which is what keeps
    `.gitkeep` committable.
    """
    local = PROJECT_ROOT / "data" / "eval-corpus"

    assert is_ignored(corpus_probe(local)) is True
    assert is_ignored(local / "lists" / "greylist.json") is True
    # The directory node itself is deliberately NOT ignored, so .gitkeep can be
    # committed. Pinned so the distinction is not "fixed" away later.
    assert is_ignored(local) is False


@needs_git
def test_the_local_corpus_is_accepted_by_the_run_time_guard():
    """The pairing that matters: ignored contents means the harness will run it.

    This is the regression for asking git the wrong question. Probing the
    directory rather than a message inside it reported the repository's own
    documented corpus location as committable, and refused every local run.
    """
    refuse_if_committable(
        PROJECT_ROOT / "data" / "eval-corpus", synthetic_only=False
    )  # must not raise


@needs_git
def test_the_committed_corpus_is_not_gitignored():
    """The other half: the synthetic corpus must actually be committable."""
    assert is_ignored(corpus_probe(CORPUS_DIR)) is False


# --- guard 2: a real corpus git could commit is refused -------------------------


@needs_git
def test_a_real_corpus_in_a_tracked_location_is_refused(tmp_path: Path):
    repo = tmp_path / "repo"
    corpus = repo / "corpus"
    corpus.mkdir(parents=True)
    git("init", "-b", "main", cwd=repo)

    with pytest.raises(NotIgnored) as raised:
        refuse_if_committable(corpus, synthetic_only=False)

    assert "does NOT ignore it" in str(raised.value)
    assert "data/eval-corpus" in str(raised.value)


@needs_git
def test_a_real_corpus_in_an_ignored_location_is_allowed(tmp_path: Path):
    repo = tmp_path / "repo"
    corpus = repo / "data" / "eval-corpus"
    corpus.mkdir(parents=True)
    git("init", "-b", "main", cwd=repo)
    (repo / ".gitignore").write_text("data/eval-corpus/\n", encoding="utf-8")

    refuse_if_committable(corpus, synthetic_only=False)  # must not raise


@needs_git
def test_a_synthetic_corpus_is_exempt(tmp_path: Path):
    """Being committed is what the synthetic corpus is for."""
    repo = tmp_path / "repo"
    corpus = repo / "tests" / "eval-corpus"
    corpus.mkdir(parents=True)
    git("init", "-b", "main", cwd=repo)

    refuse_if_committable(corpus, synthetic_only=True)  # must not raise


def test_a_corpus_outside_any_repository_is_allowed(tmp_path: Path):
    """Nothing outside a work tree can be committed to this project by accident."""
    refuse_if_committable(tmp_path, synthetic_only=False)  # must not raise


# --- guard 3: no mixing real cases into the committed tree ----------------------


def test_a_synthetic_only_corpus_refuses_a_real_case(tmp_path: Path):
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS_DIR, corpus)
    path = corpus / "cases" / "greylist-receipt-cleared" / "expected.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["synthetic"] = False
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(CorpusError) as raised:
        Corpus.load(corpus)

    message = " ".join(raised.value.errors)
    assert "SYNTHETIC-ONLY" in message
    assert "greylist-receipt-cleared" in message


def test_hand_written_cases_inherit_the_corpus_marker(tmp_path: Path):
    """Requiring every case to restate `"synthetic": true` would be noise.

    So an unmarked case inherits the corpus, and only an explicit
    ``"synthetic": false`` -- which is what the importer writes -- trips the
    mixing guard.
    """
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS_DIR, corpus)
    for case_dir in (corpus / "cases").iterdir():
        path = case_dir / "expected.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data.pop("synthetic", None)
        path.write_text(json.dumps(data), encoding="utf-8")

    loaded = Corpus.load(corpus)

    assert loaded.synthetic_only is True
    assert all(case.synthetic for case in loaded.cases)


def test_the_importer_refuses_a_synthetic_only_corpus(tmp_path: Path):
    """The path by which real mail would most plausibly reach the committed tree."""
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS_DIR, corpus)
    outbound = tmp_path / "outbound" / "cleared" / "job1"
    outbound.mkdir(parents=True)
    shutil.copyfile(
        CORPUS_DIR / "cases" / "greylist-receipt-cleared" / "message.eml",
        outbound / "message.eml",
    )

    with pytest.raises(CorpusError) as raised:
        import_from_outbound(tmp_path / "outbound", corpus)

    message = " ".join(raised.value.errors)
    assert "SYNTHETIC-ONLY" in message
    assert "data/eval-corpus" in message


def test_the_importer_wrote_nothing_into_the_refused_corpus(tmp_path: Path):
    """Refusing after copying half the messages in would be worse than allowing it."""
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS_DIR, corpus)
    before = sorted(p.name for p in (corpus / "cases").iterdir())
    outbound = tmp_path / "outbound" / "cleared" / "job1"
    outbound.mkdir(parents=True)
    shutil.copyfile(
        CORPUS_DIR / "cases" / "greylist-receipt-cleared" / "message.eml",
        outbound / "message.eml",
    )

    with pytest.raises(CorpusError):
        import_from_outbound(tmp_path / "outbound", corpus)

    assert sorted(p.name for p in (corpus / "cases").iterdir()) == before


# --- the corpus's own contents --------------------------------------------------


def test_every_committed_case_uses_reserved_example_domains():
    """The .eml files themselves, not just their labels.

    `.example` is reserved by RFC 2606 and can never be a real correspondent, so
    a committed message that only ever addresses `.example` domains cannot be
    somebody's mail. This reads the raw bytes because that is what is committed.
    """
    offenders: list[str] = []
    for message in sorted(CORPUS_DIR.rglob("*.eml")):
        text = message.read_text(encoding="utf-8")
        for line in text.splitlines():
            lowered = line.lower()
            if not lowered.startswith(("from:", "to:", "return-path:", "message-id:")):
                continue
            if "@" in line and ".example" not in lowered and "@example.com" not in lowered:
                offenders.append(f"{message.relative_to(PROJECT_ROOT)}: {line}")

    assert offenders == [], (
        "committed corpus messages must address reserved domains only "
        f"(.example / example.com), found: {offenders}"
    )


def test_every_committed_case_says_it_is_synthetic():
    """A reader who opens one of these files must not wonder whose mail it is."""
    for message in sorted(CORPUS_DIR.rglob("*.eml")):
        assert "SYNTHETIC" in message.read_text(encoding="utf-8"), message


@needs_git
def test_the_cli_refuses_a_real_corpus_before_it_opens_it(tmp_path, capsys, monkeypatch):
    """The refusal must beat corpus validation to the punch.

    Checked after loading, the operator gets a labelling complaint about a
    directory whose real problem is that it is somewhere git would commit it --
    and the guard has walked the corpus to work out it was not allowed to.
    """
    from email_guard.eval import __main__ as eval_cli

    repo = tmp_path / "repo"
    corpus = repo / "corpus"
    corpus.mkdir(parents=True)
    (corpus / "corpus.json").write_text(
        json.dumps({"synthetic_only": False}), encoding="utf-8"
    )
    # Deliberately also invalid: no cases/ at all. The location must be reported,
    # not the missing directory.
    git("init", "-b", "main", cwd=repo)
    monkeypatch.chdir(repo)

    code = eval_cli.main([str(corpus)])

    assert code == eval_cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "does NOT ignore it" in err
    assert "corpus INVALID" not in err
