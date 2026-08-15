"""The scanner as one function: parsed message in, verdict out.

parse -> clean -> triage -> deep scan -> [canary] -> assess -> route -> verdict
"""

from __future__ import annotations

from typing import Any

from . import canary as canary_module
from . import deepscan, loop, propose, triage
from .clean import clean
from .lists import Lists, classify_greylist
from .outputs import build_verdict
from .rulespack import RulesPack


def scan_parsed(
    parsed: dict[str, Any],
    lists: Lists,
    pack: RulesPack,
    job_id: str | None = None,
) -> dict[str, Any]:
    """Run the full pipeline over one parsed message."""
    message = clean(parsed, lists, job_id=job_id)

    sender = message["original_sender"]
    sender_domain = sender.split("@")[1] if "@" in sender else ""
    greylist_classification, _entry, _structure = classify_greylist(
        lists.greylist, sender, sender_domain, message["title"], message["clean_text"]
    )

    initial_level, reasons = triage.initial_level(message, greylist_classification)

    report = loop.run(message, initial_level, reasons, pack, deepscan)
    final_level = report["finalLevel"]

    # The Canary sees only the high-threat levels (root README, step 4).
    canary_result = (
        canary_module.evaluate(message)
        if canary_module.should_evaluate(final_level)
        else {
            "injection": None,
            "phishing": None,
            "reason": "not applicable at this level",
            "available": False,
        }
    )

    proposal = propose.classify(message, greylist_classification)

    return build_verdict(message, report, greylist_classification, canary_result, proposal)
