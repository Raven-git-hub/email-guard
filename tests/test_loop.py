"""The scan/assess orchestration loop, and the level-5 inversion fix."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from email_guard import loop
from email_guard.route import bucket_for

MESSAGE = {
    "job_id": "test-job",
    "messageID": "<loop@example.com>",
    "attachments": [],
    "links": [],
    "metadata": {},
    "integrity": {},
    "content": {},
}


class FakeDeepScan:
    """Stands in for :mod:`email_guard.deepscan` -- records which levels ran."""

    def __init__(self):
        self.levels: list[int] = []

    def scan(self, message, level, pack, context):
        self.levels.append(level)
        return {"core": {}, "metadata": {}, "integrity": {}, "content": {}}


def fake_pack(decisions=None):
    """Build a pack whose assessors follow a scripted sequence per level.

    ``decisions`` maps a level to a list of ``(revised_level, scan_complete)``
    pairs, consumed one per visit to that level.
    """
    decisions = decisions or {}
    scripts = {level: list(steps) for level, steps in decisions.items()}

    def make_assessor(level: int):
        def assess(report, context):
            revised, complete = scripts[level].pop(0)
            report["header"]["revisedLevel"] = revised
            report["header"]["scanComplete"] = complete
            block = report["scanResults"][list(report["scanResults"])[-1]]
            block["assessment"] = {
                "revise_level": "complete" if complete else "pivot",
                "decision": revised,
                "log": f"level {level} -> {revised}",
            }
            return report

        return SimpleNamespace(assess=assess)

    return SimpleNamespace(assessors={level: make_assessor(level) for level in scripts})


def run(initial_level, pack, deepscan=None):
    deepscan = deepscan or FakeDeepScan()
    report = loop.run(MESSAGE, initial_level, ["test"], pack, deepscan)
    return report, deepscan


# --- terminal levels -----------------------------------------------------------


@pytest.mark.parametrize("level", [1, 5])
def test_terminal_levels_skip_the_deep_scan(level):
    report, deepscan = run(level, fake_pack())
    assert report["finalLevel"] == level
    assert deepscan.levels == []
    assert report["scanResults"] == {}
    assert any("terminal" in line for line in report["forensicLog"])


# --- stabilisation -------------------------------------------------------------


def test_stops_when_the_level_stabilises():
    report, deepscan = run(3, fake_pack({3: [(3, True)]}))
    assert report["finalLevel"] == 3
    assert deepscan.levels == [3]


def test_reruns_the_scan_at_the_revised_level():
    report, deepscan = run(3, fake_pack({3: [(4, False)], 4: [(4, True)]}))
    assert deepscan.levels == [3, 4]
    assert report["finalLevel"] == 4


def test_stops_when_a_revised_level_becomes_terminal():
    report, deepscan = run(2, fake_pack({2: [(1, False)]}))
    assert report["finalLevel"] == 1
    assert deepscan.levels == [2]  # level 1 has no library to run


# --- oscillation and the iteration cap -----------------------------------------

def test_oscillation_between_two_levels_stops_the_loop():
    """3 -> 2 -> 3 is detected on the second assessment, before a third scan."""
    pack = fake_pack({3: [(2, False), (2, False)], 2: [(3, False), (3, False)]})
    report, deepscan = run(3, pack)

    assert deepscan.levels == [3, 2]
    assert any("oscillation detected" in line for line in report["forensicLog"])
    assert report["finalLevel"] == 3
    assert report["header"]["scanComplete"] is True


def test_level_stabilises_even_if_the_pack_forgets_scan_complete():
    """A pack that revises to the same level must not loop forever."""
    pack = fake_pack({3: [(3, False)] * 8})
    report, deepscan = run(3, pack)

    assert deepscan.levels == [3]
    assert any("stabilised" in line for line in report["forensicLog"])
    assert report["finalLevel"] == 3


def test_loop_always_terminates_within_the_iteration_cap():
    """The cap is a backstop: no pack script can run the scan more than 6 times.

    In practice the stabilisation and oscillation guards fire first for every
    move sequence the ALLOWED_MOVES matrix permits, so the cap should never be
    the reason a real scan stops -- but it bounds the work regardless.
    """
    pack = fake_pack(
        {
            2: [(3, False)] * 12,
            3: [(4, False), (2, False)] * 6,
            4: [(3, False)] * 12,
        }
    )
    report, deepscan = run(2, pack)

    assert len(deepscan.levels) <= loop.MAX_ITERATIONS
    assert report["header"]["scanComplete"] is True
    assert report["finalLevel"] in {1, 2, 3, 4, 5}


# --- the allowed-move matrix ---------------------------------------------------


@pytest.mark.parametrize(
    "level,allowed",
    [(2, {1, 2, 3}), (3, {2, 3, 4}), (4, {3, 4})],
)
def test_allowed_moves_match_the_corrected_matrix(level, allowed):
    assert loop.ALLOWED_MOVES[level] == allowed


def test_level_5_is_never_an_allowed_assessment_target():
    """Level 5 is triage-terminal trust; the loop must never promote into it."""
    for targets in loop.ALLOWED_MOVES.values():
        assert 5 not in targets


def test_a_disallowed_move_is_refused_and_the_level_held():
    """A rules pack asking for an impossible jump does not get it."""
    report, _ = run(4, fake_pack({4: [(5, True)]}))

    assert report["finalLevel"] == 4
    assert any("not permitted" in line for line in report["forensicLog"])


# --- the level-5 inversion fix -------------------------------------------------


def build_level4_block(sender_status: str, links_status: str) -> dict:
    return {
        "core": {"original_sender": sender_status},
        "metadata": {},
        "integrity": {},
        "content": {"links": links_status},
    }


def assess_level4(pack, sender_status: str, links_status: str) -> dict:
    report = loop.new_report(MESSAGE, 4, ["test"])
    report["scanResults"]["pass1-level4"] = build_level4_block(sender_status, links_status)
    pack.assessors[4].assess(report, {"report": report})
    return report


def test_clean_level4_deep_dive_confirms_cleared(pack):
    report = assess_level4(pack, "pass", "pass")
    assert report["header"]["revisedLevel"] == 4
    assert report["header"]["scanComplete"] is True
    assert bucket_for(report["header"]["revisedLevel"]) == "cleared"


@pytest.mark.parametrize(
    "sender_status,links_status",
    [("fail", "pass"), ("pass", "fail"), ("fail", "fail")],
)
def test_suspicious_level4_downgrades_to_flagged_never_to_trusted(
    pack, sender_status, links_status
):
    """The fix: a suspicious deep dive must move toward threat, not trust.

    Root README, "Known issues" -> "Level-5 inversion": the prototype sent this
    case to level 5, the most-trusted tier, which routing clears.
    """
    report = assess_level4(pack, sender_status, links_status)

    assert report["header"]["revisedLevel"] == 3
    assert report["header"]["revisedLevel"] != 5
    assert bucket_for(report["header"]["revisedLevel"]) == "flagged"
    assert report["header"]["scanComplete"] is True


def test_level4_fix_end_to_end(scan):
    """A greylisted sender with a perfect level-3 profile: 3 -> 4 -> 3."""
    verdict = scan("json/greylist_clean_profile.json")

    assert verdict["initial_level"] == 3
    assert verdict["final_level"] == 3
    assert verdict["bucket"] == "flagged"

    log = " | ".join(verdict["forensic_log"])
    assert "Downgrading to Level 4" in log
    assert "Suspicious patterns identified" in log
    assert "level4" in log


# --- routing -------------------------------------------------------------------


@pytest.mark.parametrize(
    "level,bucket",
    [(1, "rejected"), (2, "flagged"), (3, "flagged"), (4, "cleared"), (5, "cleared")],
)
def test_routing_buckets(level, bucket):
    assert bucket_for(level) == bucket
