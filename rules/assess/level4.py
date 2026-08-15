"""Level 4 assessment -- ported from ``reference/n8n/level4assess.js``, with the
level-5 inversion fixed.

Level 4 is a cleared tier: a greylisted domain, or a whitelisted sender who
attached something. This is the last deep dive before the message is released,
so it looks at just two things -- does the sender check out, and do the links.

>>> FIX: level-5 inversion <<<

Root README, "Known issues": *"``level4assess`` escalates a suspicious message
to ``revisedLevel = 5``, but level 5 is most trusted and routing treats >= 4 as
cleared. Fix so a suspicious L4 escalates toward threat, not trust."* The
prototype sent every message that FAILED this deep dive to level 5 -- straight
into the consolidated inbox, the exact opposite of the intent recorded in its
own log line ("Suspicious patterns identified").

Corrected behaviour:

* clean deep dive      -> stay at level 4 (cleared), complete.
* suspicious deep dive -> drop to level 3 (flagged for review), complete.

Level 5 is a *triage-terminal* trust state -- whitelisted sender, no
attachments -- and is never reached by assessment. The downgrade target is 3
rather than 2 on purpose: a suspicious but known sender belongs in review, not
branded as sophisticated phishing.

Allowed moves from here: L4 -> {3, 4}.
"""

from __future__ import annotations

from typing import Any

CLEARED_LEVEL = 4
FLAGGED_LEVEL = 3


def assess(report: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    header = report["header"]

    block_names = list(report["scanResults"].keys())
    block = report["scanResults"][block_names[-1]]

    sender_reputation_pass = (block.get("core") or {}).get("original_sender") == "pass"
    link_sanity_pass = (block.get("content") or {}).get("links") == "pass"

    forensic_log: list[str] = []

    if sender_reputation_pass and link_sanity_pass:
        header["revisedLevel"] = CLEARED_LEVEL
        forensic_log.append(
            "FINAL VERDICT: Deep forensic analysis confirms legitimate service infrastructure."
        )
    else:
        header["revisedLevel"] = FLAGGED_LEVEL
        reasons = []
        if not sender_reputation_pass:
            reasons.append("sender reputation")
        if not link_sanity_pass:
            reasons.append("link sanity")
        forensic_log.append(
            "FINAL VERDICT: Suspicious patterns identified in deep forensic sweep "
            f"({', '.join(reasons)}); downgrading to level {FLAGGED_LEVEL} for review."
        )

    header["scanComplete"] = True

    block["assessment"] = {
        "revise_level": "complete",
        "decision": header["revisedLevel"],
        "log": " | ".join(forensic_log),
    }
    return report
