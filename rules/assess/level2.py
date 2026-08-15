"""Level 2 assessment -- ported from ``reference/n8n/level2assess.js``.

Level 2 is the "targeted / sophisticated phishing" tier. The assessment runs a
cross-examination: if the message's identity anchor is solid (DKIM plus a rich
header set), individual authentication failures are overturned as collateral
from forwarding rather than evidence of forgery. Then the prosecution: any
attachment is upgraded to a critical failure.

Verdict: a critical failure means level 1; no soft failures at all means the
message is over-classified and drops to level 3; otherwise it stays at 2.

Allowed moves from here: L2 -> {1, 2, 3}.
"""

from __future__ import annotations

from typing import Any

CATEGORIES = ("core", "metadata", "integrity", "content")


def assess(report: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    header = report["header"]
    stats = report.get("stats") or {}

    block_names = list(report["scanResults"].keys())
    results = report["scanResults"][block_names[-1]]
    core = results.setdefault("core", {})
    metadata = results.setdefault("metadata", {})
    integrity = results.setdefault("integrity", {})

    forensic_log: list[str] = []

    # --- 1. The identity anchor -------------------------------------------
    dkim_status = metadata.get("authenticity-dkim")
    # Ported verbatim: the prototype tests `status.includes('pass')`, which is
    # also true for 'fail_pass'. Since the level-2 DKIM rule only ever returns
    # 'pass_downgrade' or 'fail_pass', this test is effectively always true.
    # TODO(tuning): substring matching on status names is almost certainly not
    # the intent -- an explicit allow-list ('pass', 'pass_downgrade') would
    # make the anchor mean something. Changing it moves real verdicts, so it
    # waits for a regression corpus.
    dkim_pass = isinstance(dkim_status, str) and "pass" in dkim_status
    high_headers = metadata.get("behavioural-header_count") in ("pass", "pass_downgrade")
    identity_solid = dkim_pass and high_headers

    # --- 2. Cross-examination: overturning fails --------------------------
    if identity_solid:
        if metadata.get("authenticity-dmarc") == "fail_pass":
            metadata["authenticity-dmarc"] = "pass"
            forensic_log.append("metadata-dmarc: OVERTURNED (Verified Institutional Anchor)")
        if metadata.get("authenticity-spf") == "fail_pass":
            metadata["authenticity-spf"] = "pass"
            forensic_log.append("metadata-spf: OVERTURNED (Verified Institutional Anchor)")
        if metadata.get("origin-sid_result") == "fail_pass":
            metadata["origin-sid_result"] = "pass"
            forensic_log.append("metadata-sid: OVERTURNED (Verified Institutional Anchor)")
        if core.get("title") == "fail_pass":
            core["title"] = "pass"
            forensic_log.append("core-title: OVERTURNED (Legitimate institutional notification)")
        if integrity.get("dkim_verified") == "fail_pass":
            integrity["dkim_verified"] = "pass"
            forensic_log.append(
                "integrity-dkim: OVERTURNED (Identity signature overrides pipe failure)"
            )

    # --- 3. Prosecution: upgrading threats --------------------------------
    if stats.get("attachmentList"):
        core["attachments"] = "fail_critical"
        forensic_log.append("core-attachments: UPGRADED to fail_critical (Payload detected)")

    # --- 4. Final triage ---------------------------------------------------
    all_statuses: list[str] = []
    for category in CATEGORIES:
        if results.get(category):
            all_statuses.extend(results[category].values())

    is_critical = "fail_critical" in all_statuses
    has_fail_pass = "fail_pass" in all_statuses

    assessed_level = 2
    if is_critical:
        assessed_level = 1
    elif not has_fail_pass:
        assessed_level = 3

    # --- 5. Header + logging ----------------------------------------------
    revised = header.get("revisedLevel")
    previous_level = header["initialLevel"] if revised in ("N/A", None) else revised

    header["revisedLevel"] = assessed_level
    header["scanComplete"] = assessed_level == previous_level

    results["assessment"] = {
        "revise_level": "complete",
        "decision": assessed_level,
        "log": " | ".join(forensic_log) if forensic_log else "No changes made to threat level.",
    }
    return report
