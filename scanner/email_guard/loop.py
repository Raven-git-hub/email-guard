"""Orchestration: triage -> scan -> assess, iterating until the level settles.

Allowed moves (root README, "The scanning pipeline", as corrected for the
level-5 inversion):

    L2 -> {1, 2, 3}
    L3 -> {2, 3, 4}
    L4 -> {3, 4}

Level 5 is a *triage-terminal* trust state (whitelisted, no attachments); the
loop never promotes anything into it. See ``rules/assess/level4.py``.

The loop stops when the level stabilises, when an assessment marks the scan
complete, when the level becomes terminal (1 or 5), when an oscillation A->B->A
is detected, or after a hard cap of 6 iterations.
"""

from __future__ import annotations

from typing import Any

MAX_ITERATIONS = 6
TERMINAL_LEVELS = (1, 5)

ALLOWED_MOVES: dict[int, set[int]] = {
    2: {1, 2, 3},
    3: {2, 3, 4},
    # L4 -> {3, 4}: a clean deep dive confirms 4, a suspicious one drops to 3.
    # NOT {4, 5} -- promoting a suspicious message to the most-trusted level is
    # the root README "Known issues" -> "Level-5 inversion" bug.
    4: {3, 4},
}


def new_report(message: dict[str, Any], level: int, triage_reasons: list[str]) -> dict[str, Any]:
    """The report structure the ported assessment scripts expect."""
    return {
        "header": {
            "job_id": message.get("job_id"),
            "messageID": message.get("messageID"),
            "initialLevel": level,
            "revisedLevel": "N/A",
            "scanComplete": False,
            "triageReasons": list(triage_reasons),
            "iterations": 0,
        },
        "messageContent": message,
        "stats": {
            "attachmentList": message.get("attachments") or [],
            "linkList": message.get("links") or [],
        },
        "scanResults": {},
    }


def run(
    message: dict[str, Any],
    initial_level: int,
    triage_reasons: list[str],
    pack,
    deepscan_module,
) -> dict[str, Any]:
    """Run the scan/assess loop, returning the finished report."""
    report = new_report(message, initial_level, triage_reasons)
    header = report["header"]
    forensic: list[str] = [f"triage: initial level {initial_level} ({', '.join(triage_reasons) or 'no signals'})"]
    report["forensicLog"] = forensic

    if initial_level in TERMINAL_LEVELS:
        header["revisedLevel"] = initial_level
        header["scanComplete"] = True
        forensic.append(f"level {initial_level} is terminal: no deep-scan library")
        report["finalLevel"] = initial_level
        return report

    level = initial_level
    history = [initial_level]

    for iteration in range(1, MAX_ITERATIONS + 1):
        header["iterations"] = iteration
        block_name = f"pass{iteration}-level{level}"

        context: dict[str, Any] = {"report": report, "level": level, "results": {}}
        report["scanResults"][block_name] = deepscan_module.scan(message, level, pack, context)

        assessor = pack.assessors.get(level)
        if assessor is None:
            forensic.append(f"{block_name}: no assessor for level {level}; stopping")
            break
        assessor.assess(report, context)

        assessment = report["scanResults"][block_name].get("assessment") or {}
        forensic.append(f"{block_name}: {assessment.get('log', 'no log')}")

        revised = header.get("revisedLevel")
        revised = level if revised in ("N/A", None) else int(revised)

        if revised != level and revised not in ALLOWED_MOVES.get(level, set()):
            forensic.append(
                f"{block_name}: move L{level}->L{revised} not permitted; holding at L{level}"
            )
            header["revisedLevel"] = level
            revised = level

        history.append(revised)

        if header.get("scanComplete"):
            forensic.append(f"{block_name}: assessment complete at level {revised}")
            level = revised
            break

        if revised in TERMINAL_LEVELS:
            forensic.append(f"{block_name}: level {revised} is terminal; stopping")
            level = revised
            break

        # Stabilised: the assessment did not move the level, so re-running the
        # same scan would produce the same answer. Checked independently of the
        # assessor's own scanComplete flag so a pack that forgets to set it
        # still terminates.
        if revised == level:
            forensic.append(f"{block_name}: level stabilised at {level}; stopping")
            break

        # Oscillation: A -> B -> A means the two levels disagree permanently.
        if len(history) >= 3 and history[-1] == history[-3]:
            forensic.append(
                f"{block_name}: oscillation detected "
                f"({history[-3]}->{history[-2]}->{history[-1]}); stopping"
            )
            level = revised
            break

        level = revised
    else:
        forensic.append(f"iteration cap ({MAX_ITERATIONS}) reached; stopping at level {level}")

    header["scanComplete"] = True
    report["finalLevel"] = level
    return report
