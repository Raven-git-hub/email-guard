"""The applier: decisions in, live lists out -- and the loop closing.

The counterpart to ``test_write.py``'s ``test_the_live_lists_are_never_touched``.
The scanner proposes and never writes; this module is the only thing that does,
and the guarantees it owes are the ones tested here: mutual exclusivity,
all-or-nothing validation, idempotence and atomic writes (root README, "The
learning loop").

The headline is the round trip. A message from an unknown domain stages a
candidate, a reviewer's decision greylists that domain with one catalogued
shape, and the *same* message re-scanned afterwards comes back cleared -- which
is the whole point of the loop and cannot be proven by testing either half
alone.

Every test writes into ``tmp_path``. The ``live_lists`` fixture takes a copy of
``tests/fixtures/lists/``, because the committed fixtures are read-only data and
nothing else in the suite would notice them changing.
"""

from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path

import pytest

from email_guard.apply import (
    DECISIONS_VERSION,
    InvalidDecisions,
    apply_decisions,
    load_decisions,
    validate_decisions,
)
from email_guard.cli import EXIT_INVALID_DECISIONS, EXIT_OK, main
from email_guard.lists import GREYLIST_KNOWN, GREYLIST_NEW_STRUCTURE, Lists
from email_guard.parse import parse_eml
from email_guard.pipeline import scan_and_write, scan_parsed
from email_guard.route import SourceMessage
from tests.conftest import EML_FIXTURES, RULES_DIR

DAY = date(2026, 5, 15)

UNKNOWN_EML = EML_FIXTURES / "simple.eml"
UNKNOWN_DOMAIN = "unknown-sender.example"


# --- helpers -------------------------------------------------------------------


def document(*decisions: dict, reviewed: str = DAY.isoformat()) -> dict:
    return {
        "decisions_version": DECISIONS_VERSION,
        "reviewed": reviewed,
        "decisions": list(decisions),
    }


def greylist_decision(domain: str, structure: dict | None = None, **entry) -> dict:
    decision = {
        "candidate": f"job-{domain}",
        "action": "greylist",
        "entry": {"domain": domain, **entry},
    }
    if structure is not None:
        decision["structure"] = structure
    return decision


def structure(name: str, *phrases: str, disposition: str = "allowed", tags=()) -> dict:
    return {
        "name": name,
        "key_phrases": list(phrases),
        "disposition": disposition,
        "tags": list(tags),
    }


def eml(subject: str, sender: str = f"sam@{UNKNOWN_DOMAIN}", body: str = "Nothing odd here.") -> bytes:
    return (
        f"Return-Path: <{sender}>\r\n"
        f'From: "Sam Example" <{sender}>\r\n'
        f"To: owner@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: <{abs(hash(subject))}@{UNKNOWN_DOMAIN}>\r\n"
        f"Content-Type: text/plain\r\n"
        f"\r\n"
        f"{body}\r\n"
    ).encode()


def list_bytes(lists_dir: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in sorted(lists_dir.glob("*.json"))}


def read_list(lists_dir: Path, name: str) -> list[dict]:
    return json.loads((lists_dir / f"{name}.json").read_text(encoding="utf-8"))[name]


@pytest.fixture
def stage(pack, tmp_path: Path):
    """Scan a raw message against a lists directory, staging what it stages."""

    def _stage(raw: bytes, lists_dir: Path) -> dict:
        return scan_and_write(
            parse_eml(raw),
            Lists.load(lists_dir),
            pack,
            SourceMessage.from_eml(raw),
            outbound_dir=tmp_path / "outbound",
            daily_brief_dir=tmp_path / "brief",
            job_id="test-job",
            now=DAY,
        )

    return _stage


@pytest.fixture
def rescan(pack):
    """Re-scan a raw message against the lists as they now stand on disk."""

    def _rescan(raw: bytes, lists_dir: Path) -> dict:
        return scan_parsed(parse_eml(raw), Lists.load(lists_dir), pack, job_id="test-job")

    return _rescan


# --- the loop, end to end ------------------------------------------------------


def test_a_greylist_decision_teaches_the_scanner_the_shape(live_lists, stage, rescan):
    """Propose -> decide -> apply -> re-scan, the whole loop in one pass.

    An unknown sender stages a candidate; the reviewer greylists the domain with
    one allowed structure; afterwards the same message is catalogued and clears,
    carrying the structure's tags for the downstream webhook. A *different*
    shape from that same domain is still unrecognised, which is what stops a
    single approval from waving the whole domain through.
    """
    raw = UNKNOWN_EML.read_bytes()

    staged = stage(raw, live_lists)
    assert staged["proposal"]["classification"] == "unknown_domain"
    assert staged["written"]["candidate"] is not None

    result = apply_decisions(
        document(
            greylist_decision(
                UNKNOWN_DOMAIN,
                structure("Project Notes", "Subject: Project notes", tags=["work"]),
                tags=["colleague"],
            )
        ),
        live_lists,
    )

    # (a) the live greylist gained the entry
    assert result["written"] == [str(live_lists / "greylist.json")]
    entries = read_list(live_lists, "greylist")
    added = [entry for entry in entries if entry["domain"] == UNKNOWN_DOMAIN]
    assert len(added) == 1
    assert added[0]["known_structures"][0]["name"] == "Project Notes"
    assert added[0]["tags"] == ["colleague"]

    # (b) the same message is now catalogued, cleared, and carries its tags
    verdict = rescan(raw, live_lists)
    assert verdict["greylist_classification"] == GREYLIST_KNOWN
    assert verdict["bucket"] == "cleared"
    assert verdict["tags"] == ["work"]

    # (c) a different shape from that domain is still unrecognised
    other = rescan(eml("Invoice 88213 attached"), live_lists)
    assert other["greylist_classification"] == GREYLIST_NEW_STRUCTURE
    assert other["tags"] == []
    assert other["proposal"]["classification"] == "new_structure"


def test_a_denied_structure_decision_rejects_the_matching_message(live_lists, rescan):
    """The mirror image: a catalogued shape the reviewer does not want.

    Level 1, exactly as a blacklist hit -- the domain is otherwise fine, this
    shape from it is not.
    """
    apply_decisions(
        document(
            greylist_decision(
                UNKNOWN_DOMAIN,
                structure(
                    "Password Reset Bait",
                    "Subject: Reset your password",
                    disposition="denied",
                ),
            )
        ),
        live_lists,
    )

    verdict = rescan(eml("Reset your password now"), live_lists)
    assert verdict["greylist_classification"] == "denied"
    assert verdict["initial_level"] == 1
    assert verdict["bucket"] == "rejected"
    assert verdict["tags"] == []
    # Already catalogued, so there is nothing left for a reviewer to decide.
    assert verdict["proposal"]["classification"] == "skip"


def test_a_denied_structure_wins_over_an_allowed_one_on_the_same_domain(live_lists, rescan):
    """Two decisions, one domain: the allowed shape does not rescue the denied."""
    apply_decisions(
        document(
            greylist_decision(UNKNOWN_DOMAIN, structure("Everything", tags=["bulk"])),
            greylist_decision(
                UNKNOWN_DOMAIN,
                structure("Bait", "Subject: Reset your password", disposition="denied"),
            ),
        ),
        live_lists,
    )

    assert rescan(eml("Ordinary Tuesday update"), live_lists)["bucket"] == "cleared"
    assert rescan(eml("Reset your password"), live_lists)["bucket"] == "rejected"


# --- mutual exclusivity --------------------------------------------------------


def test_moving_a_domain_to_the_whitelist_removes_the_greylist_entry(live_lists):
    """A domain lives on exactly one list; the new decision is the one that wins."""
    assert any(e["domain"] == "quietservice.example" for e in read_list(live_lists, "greylist"))

    result = apply_decisions(
        document(
            {
                "candidate": "job-quiet",
                "action": "whitelist",
                "entry": {"domain": "quietservice.example", "tags": ["receipts"]},
            }
        ),
        live_lists,
    )

    assert not any(
        e["domain"] == "quietservice.example" for e in read_list(live_lists, "greylist")
    )
    assert any(
        e.get("domain") == "quietservice.example" for e in read_list(live_lists, "whitelist")
    )

    removals = [c for c in result["changes"] if c["operation"] == "remove_entry"]
    assert removals == [
        {
            "candidate": "job-quiet",
            "list": "greylist",
            "operation": "remove_entry",
            "key": "quietservice.example",
            "detail": "'quietservice.example' now lives on the whitelist",
        }
    ]


def test_an_address_decision_claims_the_whole_domain(live_lists):
    """An email-keyed entry conflicts when its domain is claimed elsewhere.

    Blacklisting one address at ``shopfast.example`` takes the domain off the
    greylist: exclusivity is a domain rule, so half-listing a domain is not a
    state the applier can leave behind.
    """
    apply_decisions(
        document(
            {
                "candidate": "job-shopfast",
                "action": "blacklist",
                "entry": {"email": "spam@shopfast.example", "friendly_name": "Shopfast Spam"},
            }
        ),
        live_lists,
    )

    assert not any(e["domain"] == "shopfast.example" for e in read_list(live_lists, "greylist"))
    blacklisted = read_list(live_lists, "blacklist")
    assert any(e.get("email") == "spam@shopfast.example" for e in blacklisted)


def test_removal_is_exact_and_never_sweeps_a_parent_domain(live_lists):
    """A decision about a subdomain leaves the broader entry alone.

    Matching is subdomain-inclusive; removal deliberately is not. Whitelisting
    ``notify.northgate-bank.example`` must not silently discard the reviewer's
    far broader ``northgate-bank.example`` greylist entry, which they never
    mentioned.
    """
    apply_decisions(
        document(
            {
                "candidate": "job-notify",
                "action": "whitelist",
                "entry": {"domain": "notify.northgate-bank.example"},
            }
        ),
        live_lists,
    )

    assert any(
        e["domain"] == "northgate-bank.example" for e in read_list(live_lists, "greylist")
    )


def test_the_applied_lists_load_cleanly_through_the_validator(live_lists):
    """Whatever the applier writes, the loader must accept."""
    apply_decisions(
        document(
            greylist_decision(UNKNOWN_DOMAIN, structure("Notes", "Subject: Project notes")),
            {
                "candidate": "job-quiet",
                "action": "whitelist",
                "entry": {"domain": "quietservice.example"},
            },
        ),
        live_lists,
    )

    loaded = Lists.load(live_lists)
    assert any(e["domain"] == UNKNOWN_DOMAIN for e in loaded.greylist)


# --- idempotence ---------------------------------------------------------------


def test_re_applying_the_same_document_changes_nothing(live_lists):
    """Byte for byte: a second run is a no-op, not a re-write."""
    doc = document(
        greylist_decision(
            UNKNOWN_DOMAIN, structure("Notes", "Subject: Project notes", tags=["work"])
        ),
        {"candidate": "job-friend", "action": "whitelist", "entry": {"email": "friend@example.org"}},
    )

    apply_decisions(doc, live_lists)
    after_first = list_bytes(live_lists)

    result = apply_decisions(doc, live_lists)

    assert list_bytes(live_lists) == after_first
    assert result["written"] == []
    assert all(change["operation"] == "no_op" for change in result["changes"])


def test_a_structure_already_on_the_entry_is_not_appended_twice(live_lists):
    """The idempotence rule at the structure level: append only by name."""
    doc = document(
        greylist_decision(
            "northgate-bank.example",
            {"name": "Northgate Statement Ready", "key_phrases": []},
        )
    )
    apply_decisions(doc, live_lists)

    entry = next(
        e for e in read_list(live_lists, "greylist") if e["domain"] == "northgate-bank.example"
    )
    names = [s["name"] for s in entry["known_structures"]]
    assert names.count("Northgate Statement Ready") == 1


def test_a_structure_of_the_same_name_is_replaced_not_dropped(live_lists, rescan):
    """Flipping a catalogued shape from allowed to denied has to be possible.

    "Append only when the name is new" would otherwise make the one operation a
    reviewer most needs -- a domain starts sending something nasty -- silently
    do nothing.
    """
    apply_decisions(
        document(greylist_decision(UNKNOWN_DOMAIN, structure("Notes", "Subject: Project notes"))),
        live_lists,
    )
    assert rescan(UNKNOWN_EML.read_bytes(), live_lists)["bucket"] == "cleared"

    result = apply_decisions(
        document(
            greylist_decision(
                UNKNOWN_DOMAIN,
                structure("Notes", "Subject: Project notes", disposition="denied"),
            )
        ),
        live_lists,
    )

    assert [c["operation"] for c in result["changes"]] == ["update_structure"]
    assert rescan(UNKNOWN_EML.read_bytes(), live_lists)["bucket"] == "rejected"


def test_applying_to_a_known_grey_domain_appends_to_the_existing_entry(live_lists):
    """A known grey domain is just a greylist decision with a new structure."""
    apply_decisions(
        document(
            greylist_decision(
                "northgate-bank.example", structure("Northgate Overdraft Notice", "overdrawn")
            )
        ),
        live_lists,
    )

    entries = [e for e in read_list(live_lists, "greylist") if e["domain"] == "northgate-bank.example"]
    assert len(entries) == 1
    assert [s["name"] for s in entries[0]["known_structures"]] == [
        "Northgate Statement Ready",
        "Northgate Fund Transfer Advice",
        "Northgate Overdraft Notice",
    ]


def test_discard_touches_nothing(live_lists):
    before = list_bytes(live_lists)

    result = apply_decisions(
        document({"candidate": "job-noise", "action": "discard"}), live_lists
    )

    assert list_bytes(live_lists) == before
    assert result["written"] == []
    assert [c["operation"] for c in result["changes"]] == ["discard"]


# --- validation, all or nothing ------------------------------------------------


@pytest.mark.parametrize(
    "decision, fragment",
    [
        ({"candidate": "c", "action": "greenlist", "entry": {"domain": "x.example"}},
         "unknown action 'greenlist'"),
        ({"candidate": "c", "action": "greylist", "entry": {"domain": "x.example"},
          "structure": {"name": "S", "disposition": "denyed"}},
         "'disposition' is 'denyed'"),
        ({"candidate": "c", "action": "whitelist", "entry": {}},
         "exactly one of 'email' or 'domain'"),
        ({"candidate": "c", "action": "whitelist",
          "entry": {"email": "a@x.example", "domain": "x.example"}},
         "exactly one of 'email' or 'domain'"),
        ({"candidate": "c", "action": "greylist", "entry": {"email": "a@x.example"}},
         "greylist entries key on 'domain'"),
        ({"candidate": "c", "action": "whitelist", "entry": {"domain": "x.example", "tags": "work"}},
         "'tags' must be a list"),
        ({"candidate": "c", "action": "greylist", "entry": {"domain": "x.example"},
          "structure": {"name": ""}},
         "needs a non-empty 'name'"),
        ({"candidate": "", "action": "discard"}, "needs a non-empty 'candidate'"),
    ],
    ids=[
        "unknown-action",
        "bad-disposition",
        "no-key",
        "both-keys",
        "greylist-keyed-on-email",
        "tags-not-a-list",
        "structure-without-a-name",
        "no-candidate",
    ],
)
def test_a_malformed_decision_is_rejected_naming_the_candidate(
    live_lists, decision, fragment
):
    before = list_bytes(live_lists)

    with pytest.raises(InvalidDecisions) as caught:
        apply_decisions(document(decision), live_lists)

    assert any(fragment in error for error in caught.value.errors)
    assert any("decisions[0]" in error for error in caught.value.errors)
    # The whole document is checked before anything is applied.
    assert list_bytes(live_lists) == before


def test_one_bad_decision_leaves_every_earlier_one_unapplied(live_lists):
    """All-or-nothing: a good decision ahead of a bad one is not written either."""
    before = list_bytes(live_lists)

    with pytest.raises(InvalidDecisions):
        apply_decisions(
            document(
                greylist_decision(UNKNOWN_DOMAIN, structure("Notes", "Subject: Project notes")),
                {"candidate": "job-bad", "action": "sideline", "entry": {"domain": "y.example"}},
            ),
            live_lists,
        )

    assert list_bytes(live_lists) == before


def test_every_error_is_reported_not_just_the_first(live_lists):
    with pytest.raises(InvalidDecisions) as caught:
        apply_decisions(
            document(
                {"candidate": "a", "action": "nonsense"},
                {"candidate": "b", "action": "whitelist", "entry": {}},
                reviewed="last tuesday",
            ),
            live_lists,
        )

    assert len(caught.value.errors) == 3


def test_an_unsupported_version_is_rejected(live_lists):
    with pytest.raises(InvalidDecisions) as caught:
        apply_decisions({"decisions_version": 2, "reviewed": "2026-05-15", "decisions": []}, live_lists)

    assert "unsupported decisions_version" in caught.value.errors[0]


def test_two_decisions_claiming_one_domain_for_different_lists_are_rejected(live_lists):
    """Otherwise document order silently decides which list the domain lands on."""
    with pytest.raises(InvalidDecisions) as caught:
        apply_decisions(
            document(
                greylist_decision("x.example", structure("S")),
                {"candidate": "job-x", "action": "blacklist", "entry": {"email": "a@x.example"}},
            ),
            live_lists,
        )

    assert any("claims it for the greylist" in error for error in caught.value.errors)


def test_an_empty_review_is_a_valid_document(live_lists):
    before = list_bytes(live_lists)

    result = apply_decisions(document(), live_lists)

    assert result["changes"] == []
    assert list_bytes(live_lists) == before


def test_validate_decisions_returns_errors_rather_than_raising():
    """The pure form, mirroring the rules pack's ``validate_pack``."""
    assert validate_decisions(document()) == []
    assert validate_decisions({"decisions_version": 1, "reviewed": "2026-05-15"}) == [
        "'decisions' must be a list"
    ]


def test_malformed_json_is_an_invalid_document(tmp_path: Path):
    path = tmp_path / "decisions.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(InvalidDecisions) as caught:
        load_decisions(path)

    assert "invalid JSON" in caught.value.errors[0]


# --- writing -------------------------------------------------------------------


def test_the_file_wrapper_and_its_sibling_keys_survive_a_rewrite(live_lists):
    """``_note`` and the ``{"greylist": [...]}`` wrapper are the operator's, not ours."""
    apply_decisions(
        document(greylist_decision(UNKNOWN_DOMAIN, structure("Notes"))), live_lists
    )

    document_on_disk = json.loads((live_lists / "greylist.json").read_text(encoding="utf-8"))
    assert "_note" in document_on_disk
    assert list(document_on_disk) == ["_note", "greylist"]


def test_a_bare_array_list_file_is_rewritten_as_a_bare_array(tmp_path: Path):
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "greylist.json").write_text(
        json.dumps([{"domain": "x.example", "known_structures": []}]), encoding="utf-8"
    )

    apply_decisions(document(greylist_decision("x.example", structure("S"))), lists_dir)

    assert isinstance(json.loads((lists_dir / "greylist.json").read_text(encoding="utf-8")), list)


def test_a_missing_list_file_is_created_wrapped(tmp_path: Path):
    """A clean install has no lists at all; the first decision creates one."""
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()

    apply_decisions(document(greylist_decision("x.example", structure("S"))), lists_dir)

    payload = json.loads((lists_dir / "greylist.json").read_text(encoding="utf-8"))
    assert payload["greylist"][0]["domain"] == "x.example"
    assert not (lists_dir / "whitelist.json").exists()


def test_the_applied_file_matches_the_house_json_formatting(live_lists):
    """Same formatting as ``route.write_json``, so hand-edits and applies diff alike."""
    apply_decisions(document(greylist_decision(UNKNOWN_DOMAIN, structure("Notes"))), live_lists)

    text = (live_lists / "greylist.json").read_text(encoding="utf-8")
    assert text.endswith("}\n")
    assert '\n  "greylist": [' in text


def test_a_failed_write_leaves_the_previous_list_intact(live_lists, monkeypatch):
    """Temp file plus rename: a crash mid-write must not truncate a live list."""
    before = (live_lists / "greylist.json").read_bytes()

    def explode(*args, **kwargs):
        raise OSError("disk went away")

    monkeypatch.setattr(os, "replace", explode)

    with pytest.raises(OSError):
        apply_decisions(
            document(greylist_decision(UNKNOWN_DOMAIN, structure("Notes"))), live_lists
        )

    assert (live_lists / "greylist.json").read_bytes() == before
    assert list(live_lists.glob("*.tmp")) == []


def test_dry_run_computes_everything_and_writes_nothing(live_lists):
    before = list_bytes(live_lists)

    result = apply_decisions(
        document(greylist_decision(UNKNOWN_DOMAIN, structure("Notes"))),
        live_lists,
        dry_run=True,
    )

    assert result["dry_run"] is True
    assert result["written"] == []
    assert [c["operation"] for c in result["changes"]] == ["add_entry", "add_structure"]
    assert list_bytes(live_lists) == before


# --- the CLI verb --------------------------------------------------------------


def decisions_file(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "decisions.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_cli_apply_writes_the_lists_and_prints_the_report(live_lists, tmp_path, capsys):
    path = decisions_file(
        tmp_path, document(greylist_decision(UNKNOWN_DOMAIN, structure("Notes")))
    )

    assert main(["apply", str(path), "--lists-dir", str(live_lists)]) == EXIT_OK

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["written"] == [str(live_lists / "greylist.json")]
    assert f"wrote {live_lists / 'greylist.json'}" in captured.err


def test_cli_apply_dry_run_writes_nothing(live_lists, tmp_path, capsys):
    before = list_bytes(live_lists)
    path = decisions_file(
        tmp_path, document(greylist_decision(UNKNOWN_DOMAIN, structure("Notes")))
    )

    assert main(["apply", str(path), "--lists-dir", str(live_lists), "--dry-run"]) == EXIT_OK

    assert json.loads(capsys.readouterr().out)["written"] == []
    assert list_bytes(live_lists) == before


def test_cli_apply_reports_a_malformed_document_as_bullets(live_lists, tmp_path, capsys):
    before = list_bytes(live_lists)
    path = decisions_file(
        tmp_path, document({"candidate": "c", "action": "greenlist", "entry": {"domain": "x.example"}})
    )

    code = main(["apply", str(path), "--lists-dir", str(live_lists)])

    assert code == EXIT_INVALID_DECISIONS
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "decisions INVALID" in captured.err
    assert "  - decisions[0]" in captured.err
    assert "no list was written" in captured.err
    assert list_bytes(live_lists) == before


def test_cli_apply_reports_a_missing_document(live_lists, tmp_path, capsys):
    code = main(["apply", str(tmp_path / "absent.json"), "--lists-dir", str(live_lists)])

    assert code == 1
    assert "cannot apply decisions" in capsys.readouterr().err


def test_the_scan_cli_still_works_without_a_verb(live_lists, tmp_path, capsys):
    """Dispatching on ``apply`` must not have made a verb mandatory."""
    code = main(
        [
            str(UNKNOWN_EML),
            "--lists-dir",
            str(live_lists),
            "--rules-dir",
            str(RULES_DIR),
            "--outbound-dir",
            str(tmp_path / "outbound"),
            "--daily-brief-dir",
            str(tmp_path / "brief"),
            "--now",
            DAY.isoformat(),
        ]
    )

    assert code == EXIT_OK
    assert json.loads(capsys.readouterr().out)["sender"] == f"sam@{UNKNOWN_DOMAIN}"
