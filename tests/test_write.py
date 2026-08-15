"""The output stage: route to a bucket, persist the message, stage candidates.

Every test writes into a pytest ``tmp_path`` and reads SYNTHETIC list fixtures.
Nothing here may touch the repo's real ``data/`` -- those are the live lists and
the live quarantine (root README, "Storage & privacy"), so the tests pass the
output directories in explicitly on every run.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from email_guard import parse
from email_guard.cli import main
from email_guard.pipeline import scan_and_write
from email_guard.propose import CANDIDATE_VERSION
from email_guard.route import SourceMessage, job_slug

from tests.conftest import FIXTURES, LIST_FIXTURES, RULES_DIR

# Pinned everywhere a daily-brief folder is asserted on: the date is injected,
# never taken from the clock, so these paths are stable forever.
DAY = date(2026, 5, 15)

CLEARED_FIXTURE = "json/quietservice_receipt.json"  # greylist known  -> cleared
FLAGGED_FIXTURE = "json/northgate_spoof.json"  # spoofed sender  -> flagged
REJECTED_FIXTURE = "json/blacklisted_offer.json"  # blacklisted     -> rejected
NEW_STRUCTURE_FIXTURE = "json/northgate_1.json"  # greylisted, uncatalogued shape
UNKNOWN_DOMAIN_FIXTURE = "eml/simple.eml"  # sender on no list


def load_source(fixture: str) -> tuple[dict, SourceMessage]:
    """Read a fixture the way the CLI does: parse it, and keep the raw bytes."""
    path = FIXTURES / fixture
    raw = path.read_bytes()
    if path.suffix == ".eml":
        return parse.parse_eml(raw), SourceMessage.from_eml(raw)
    return parse.parse_json(json.loads(raw)), SourceMessage.from_json(raw)


@pytest.fixture
def outputs(tmp_path: Path) -> dict[str, Path]:
    return {"outbound": tmp_path / "outbound", "brief": tmp_path / "daily-brief"}


@pytest.fixture
def write(lists, pack, outputs):
    """Scan one fixture and write its outputs under the tmp directories."""

    def _write(fixture: str, *, now: date = DAY, dry_run: bool = False) -> dict:
        parsed, source = load_source(fixture)
        return scan_and_write(
            parsed,
            lists,
            pack,
            source,
            outbound_dir=outputs["outbound"],
            daily_brief_dir=outputs["brief"],
            job_id="test-job",
            now=now,
            dry_run=dry_run,
        )

    return _write


def written_files(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}


# --- routing / persistence ----------------------------------------------------


@pytest.mark.parametrize(
    "fixture, bucket, copy_name",
    [
        (CLEARED_FIXTURE, "cleared", "message.json"),
        (FLAGGED_FIXTURE, "flagged", "message.json"),
        (REJECTED_FIXTURE, "rejected", "message.json"),
        (UNKNOWN_DOMAIN_FIXTURE, "flagged", "message.eml"),
    ],
)
def test_message_lands_in_its_bucket(write, outputs, fixture, bucket, copy_name):
    verdict = write(fixture)

    assert verdict["bucket"] == bucket

    job_dir = outputs["outbound"] / bucket / verdict["written"]["job"]
    assert job_dir.is_dir()
    assert written_files(outputs["outbound"]) == {
        f"{bucket}/{verdict['written']['job']}/report.json",
        f"{bucket}/{verdict['written']['job']}/{copy_name}",
    }

    report = json.loads((job_dir / "report.json").read_text(encoding="utf-8"))
    assert report["bucket"] == bucket
    assert report["message_id"] == verdict["message_id"]
    assert report["final_level"] == verdict["final_level"]
    # The report records where it was written, itself included.
    assert report["written"]["report"] == str(job_dir / "report.json")


def test_the_stored_copy_is_the_original_byte_for_byte(write, outputs):
    """Quarantine is forensic storage: no re-serialisation, no normalisation."""
    verdict = write(REJECTED_FIXTURE)

    stored = Path(verdict["written"]["message"])
    assert stored.name == "message.json"
    assert stored.read_bytes() == (FIXTURES / REJECTED_FIXTURE).read_bytes()


def test_an_eml_is_stored_as_eml(write):
    verdict = write(UNKNOWN_DOMAIN_FIXTURE)

    stored = Path(verdict["written"]["message"])
    assert stored.name == "message.eml"
    assert stored.read_bytes() == (FIXTURES / UNKNOWN_DOMAIN_FIXTURE).read_bytes()


def test_written_section_lists_every_path(write, outputs):
    verdict = write(NEW_STRUCTURE_FIXTURE)
    written = verdict["written"]

    assert written["bucket"] == verdict["bucket"]
    assert written["date"] == DAY.isoformat()
    assert Path(written["dir"]).is_dir()
    for key in ("report", "message", "candidate"):
        assert Path(written[key]).is_file()


def test_rescanning_the_same_message_reuses_its_job_directory(write, outputs):
    first = write(FLAGGED_FIXTURE)
    second = write(FLAGGED_FIXTURE)

    assert first["written"]["dir"] == second["written"]["dir"]
    assert len(list((outputs["outbound"] / "flagged").iterdir())) == 1


# --- proposals ----------------------------------------------------------------


def test_new_structure_stages_a_candidate(write, outputs):
    verdict = write(NEW_STRUCTURE_FIXTURE)
    job = verdict["written"]["job"]

    path = outputs["brief"] / f"daily-brief-{DAY.isoformat()}" / job / "candidate.json"
    assert path.is_file()
    assert verdict["written"]["candidate"] == str(path)

    candidate = json.loads(path.read_text(encoding="utf-8"))
    assert candidate["candidate_version"] == CANDIDATE_VERSION
    assert candidate["classification"] == "new_structure"
    assert candidate["date"] == DAY.isoformat()
    assert candidate["job"] == job
    assert candidate["sender"]["email"] == "notifications@notify.northgate-bank.example"
    # The message is parked in the outbound store; the candidate points at it.
    assert candidate["outbound"] == {"bucket": verdict["bucket"], "job": job}

    # One proposal only: the domain is already greylisted, so the new shape is
    # offered against the *listed* domain, not the sending subdomain.
    assert len(candidate["proposed_entries"]) == 1
    entry = candidate["proposed_entries"][0]
    assert entry["list"] == "greylist"
    assert entry["operation"] == "add_structure"
    assert entry["match"] == {"domain": "northgate-bank.example"}
    assert entry["entry"]["known_structures"] == [candidate["proposed_structure"]]
    assert candidate["proposed_structure"]["key_phrases"] == [
        "Subject: Payment sent Ref:[NB4471209]"
    ]


def test_unknown_domain_stages_one_proposal_per_list(write, outputs):
    verdict = write(UNKNOWN_DOMAIN_FIXTURE)

    path = Path(verdict["written"]["candidate"])
    assert path.is_file()

    candidate = json.loads(path.read_text(encoding="utf-8"))
    assert candidate["classification"] == "unknown_domain"
    assert candidate["sender"] == {
        "email": "sam@unknown-sender.example",
        "domain": "unknown-sender.example",
        "friendly_name": "proton-sam",
    }

    # The reviewer picks one; the applier applies only what was picked.
    proposals = {entry["list"]: entry for entry in candidate["proposed_entries"]}
    assert set(proposals) == {"whitelist", "greylist", "blacklist"}
    assert all(entry["operation"] == "add_entry" for entry in proposals.values())
    assert proposals["whitelist"]["entry"]["email"] == "sam@unknown-sender.example"
    assert proposals["greylist"]["entry"]["domain"] == "unknown-sender.example"

    # Evidence a reviewer needs to judge the card, de-fanged links included.
    assert candidate["evidence"]["subject"] == "Project notes for Thursday"
    assert candidate["evidence"]["links"] == [
        "h_ttps://notes[.]unknown-sender[.]example/thursday"
    ]


def test_a_known_structure_stages_nothing(write, outputs):
    verdict = write(CLEARED_FIXTURE)

    assert verdict["greylist_classification"] == "known"
    assert verdict["proposal"]["classification"] == "skip"
    assert verdict["written"]["candidate"] is None
    assert not outputs["brief"].exists()


def test_a_blacklisted_sender_stages_nothing(write, outputs):
    """`skip` covers both directions: nothing is proposed for a listed sender."""
    verdict = write(REJECTED_FIXTURE)

    assert verdict["written"]["candidate"] is None
    assert not outputs["brief"].exists()


def test_the_daily_brief_date_is_injected_not_read_from_the_clock(write, outputs):
    """A date far from any plausible "today" must be the one on disk."""
    write(NEW_STRUCTURE_FIXTURE, now=date(2019, 1, 2))

    job = job_slug("<26870113-1ed5-40c7-85c4-fcc190ad575d@notify.northgate-bank.example>")
    assert written_files(outputs["brief"]) == {
        f"daily-brief-2019-01-02/{job}/candidate.json"
    }


def test_the_live_lists_are_never_touched(write):
    """The learning loop proposes; only the applier writes lists."""
    before = {p: p.read_bytes() for p in LIST_FIXTURES.glob("*.json")}

    write(NEW_STRUCTURE_FIXTURE)
    write(UNKNOWN_DOMAIN_FIXTURE)

    assert {p: p.read_bytes() for p in LIST_FIXTURES.glob("*.json")} == before


# --- dry run ------------------------------------------------------------------


def test_dry_run_writes_nothing(write, outputs):
    verdict = write(UNKNOWN_DOMAIN_FIXTURE, dry_run=True)

    assert verdict["written"] is None
    assert not outputs["outbound"].exists()
    assert not outputs["brief"].exists()


def test_dry_run_computes_the_same_verdict(write):
    dry = write(UNKNOWN_DOMAIN_FIXTURE, dry_run=True)
    wet = write(UNKNOWN_DOMAIN_FIXTURE)

    assert wet["written"] is not None
    assert {k: v for k, v in wet.items() if k != "written"} == {
        k: v for k, v in dry.items() if k != "written"
    }


# --- determinism --------------------------------------------------------------


def test_the_same_input_and_date_produce_identical_files(write, outputs):
    write(NEW_STRUCTURE_FIXTURE)
    first = {
        path: path.read_bytes()
        for root in outputs.values()
        for path in root.rglob("*")
        if path.is_file()
    }

    write(NEW_STRUCTURE_FIXTURE)
    second = {
        path: path.read_bytes()
        for root in outputs.values()
        for path in root.rglob("*")
        if path.is_file()
    }

    assert first and second == first


def test_output_content_does_not_depend_on_where_it_is_written(
    lists, pack, tmp_path: Path
):
    def run(root: Path) -> dict[str, bytes]:
        parsed, source = load_source(NEW_STRUCTURE_FIXTURE)
        scan_and_write(
            parsed,
            lists,
            pack,
            source,
            outbound_dir=root / "outbound",
            daily_brief_dir=root / "daily-brief",
            job_id="test-job",
            now=DAY,
        )
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    left = run(tmp_path / "left")
    right = run(tmp_path / "right")

    assert set(left) == set(right)
    # The candidate carries no absolute paths at all, so it must match exactly.
    candidate = next(name for name in left if name.endswith("candidate.json"))
    assert left[candidate] == right[candidate]

    # The report differs only in the `written` paths it records.
    report = next(name for name in left if name.endswith("report.json"))
    stripped = [
        {k: v for k, v in json.loads(side[report]).items() if k != "written"}
        for side in (left, right)
    ]
    assert stripped[0] == stripped[1]


# --- job slugs ----------------------------------------------------------------


@pytest.mark.parametrize(
    "message_id, expected",
    [
        ("<plain-0001@unknown-sender.example>", "plain-0001-unknown-sender.example"),
        ("no-angle-brackets@example.com", "no-angle-brackets-example.com"),
        ("  <spaced@example.com>  ", "spaced-example.com"),
        # Path separators go; the dots survive only inside a longer name, where
        # they cannot make the slug "." or ".." and traverse out of the bucket.
        ("<a/b/../c@example.com>", "a-b-..-c-example.com"),
        ("<weird spaces & symbols@example.com>", "weird-spaces-symbols-example.com"),
    ],
)
def test_job_slug_is_filesystem_safe(message_id, expected):
    slug = job_slug(message_id)

    assert slug == expected
    assert "/" not in slug and "\\" not in slug
    assert slug not in {".", ".."}


@pytest.mark.parametrize("message_id", ["", "   ", "N/A", None, "<>", "<...>", 42])
def test_a_message_without_a_usable_id_falls_back_to_a_content_hash(message_id):
    slug = job_slug(message_id, fallback=b"raw message bytes")

    assert slug == job_slug(message_id, fallback=b"raw message bytes")
    assert slug.startswith("msg-")
    assert slug != job_slug(message_id, fallback=b"different bytes")


def test_a_very_long_id_is_truncated_but_stays_unique():
    first = job_slug("<" + "a" * 300 + "1@example.com>")
    second = job_slug("<" + "a" * 300 + "2@example.com>")

    assert len(first) <= 110
    assert first != second


def test_an_id_less_message_still_gets_its_own_directory(lists, pack, tmp_path: Path):
    raw = (
        b"From: sam@unknown-sender.example\r\n"
        b"Subject: No message id here\r\n"
        b"\r\n"
        b"body\r\n"
    )
    verdict = scan_and_write(
        parse.parse_eml(raw),
        lists,
        pack,
        SourceMessage.from_eml(raw),
        outbound_dir=tmp_path / "outbound",
        daily_brief_dir=tmp_path / "daily-brief",
        now=DAY,
    )

    assert verdict["message_id"] == "N/A"
    assert verdict["written"]["job"].startswith("msg-")
    assert Path(verdict["written"]["message"]).read_bytes() == raw


# --- the CLI ------------------------------------------------------------------


def cli_args(tmp_path: Path, fixture: str) -> list[str]:
    path = FIXTURES / fixture
    source = ["--from-json", str(path)] if path.suffix == ".json" else [str(path)]
    return source + [
        "--lists-dir",
        str(LIST_FIXTURES),
        "--rules-dir",
        str(RULES_DIR),
        "--outbound-dir",
        str(tmp_path / "outbound"),
        "--daily-brief-dir",
        str(tmp_path / "daily-brief"),
        "--now",
        DAY.isoformat(),
    ]


def test_cli_writes_by_default(tmp_path: Path, capsys):
    assert main(cli_args(tmp_path, NEW_STRUCTURE_FIXTURE)) == 0

    verdict = json.loads(capsys.readouterr().out)
    assert verdict["written"]["bucket"] == verdict["bucket"]
    assert Path(verdict["written"]["report"]).is_file()
    assert Path(verdict["written"]["message"]).is_file()
    assert Path(verdict["written"]["candidate"]).is_file()


def test_cli_dry_run_writes_nothing(tmp_path: Path, capsys):
    assert main(cli_args(tmp_path, NEW_STRUCTURE_FIXTURE) + ["--dry-run"]) == 0

    verdict = json.loads(capsys.readouterr().out)
    assert verdict["written"] is None
    assert not (tmp_path / "outbound").exists()
    assert not (tmp_path / "daily-brief").exists()


def test_cli_rejects_a_malformed_now(tmp_path: Path, capsys):
    assert main(cli_args(tmp_path, NEW_STRUCTURE_FIXTURE) + ["--now", "last tuesday"]) == 1

    assert "--now must be a YYYY-MM-DD date" in capsys.readouterr().err
    assert not (tmp_path / "outbound").exists()
