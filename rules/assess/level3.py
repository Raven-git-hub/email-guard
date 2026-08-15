"""Level 3 assessment -- ported from ``reference/n8n/level3assess.js``.

Level 3 is the "low-level phishing or spam" tier and the pipeline's centre of
gravity: most unfamiliar mail starts here. The assessment scores a confidence
profile (clean subject, clean body, aligned authentication) and then either
escalates on critical markers, promotes a perfect profile toward the cleared
tiers, or confirms level 3 and stops.

Allowed moves from here: L3 -> {2, 3, 4}.
"""

from __future__ import annotations

from typing import Any

CATEGORIES = ("core", "metadata", "content", "integrity")
PASSING = ("pass", "pass_service")


def assess(report: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    header = report["header"]

    block_names = list(report["scanResults"].keys())
    block = report["scanResults"][block_names[-1]]
    core = block.setdefault("core", {})
    metadata = block.setdefault("metadata", {})
    content = block.setdefault("content", {})

    forensic_log: list[str] = []
    confidence_score = 0
    has_any_fail = False
    has_critical_fail = False

    # --- Jury deliberation -------------------------------------------------
    if core.get("title") in PASSING:
        confidence_score += 1
    if core.get("clean_text") in PASSING:
        confidence_score += 1

    auth_string = metadata.get("authenticity-auth_string")
    if auth_string in PASSING:
        confidence_score += 2
    elif auth_string == "fail_critical":
        has_critical_fail = True

    is_complex = metadata.get("behavioural-header_count") in PASSING
    is_hidden_mailer = metadata.get("behavioural-mailer") in ("fail_spam", "fail")

    if is_complex and is_hidden_mailer:
        confidence_score += 1
        # Rewrites the stored status, not just the score.
        metadata["behavioural-mailer"] = "pass"
        forensic_log.append("OVERTURN: Mailer fail ignored due to high header complexity.")
    elif is_hidden_mailer:
        has_any_fail = True

    if content.get("links") in ("fail", "fail_critical"):
        has_critical_fail = True

    # --- Final scrub: collapse the status vocabulary to pass/fail ----------
    # The two checks run in sequence, exactly as in the prototype, so
    # 'fail_pass' becomes 'pass' (the first branch rewrites it, and the second
    # then tests the rewritten value) while 'fail_critical' becomes 'fail'.
    for category in CATEGORIES:
        section = block.get(category)
        if not section:
            continue
        for key, status in list(section.items()):
            if not isinstance(status, str):
                continue
            if "pass" in status:
                status = "pass"
            if "fail" in status:
                status = "fail"
            section[key] = status

    # --- Verdict -----------------------------------------------------------
    if has_critical_fail:
        assessed_level = 2
        header["scanComplete"] = False
        forensic_log.append("VERDICT: Critical markers found. Upgrading to Level 2.")
    elif confidence_score >= 4 and not has_any_fail:
        assessed_level = 4
        header["scanComplete"] = False
        forensic_log.append("VERDICT: Perfect profile. Downgrading to Level 4.")
    else:
        assessed_level = 3
        header["scanComplete"] = True
        forensic_log.append("VERDICT: Standard profile confirmed. Loop complete.")

    header["revisedLevel"] = assessed_level

    block["assessment"] = {
        "revise_level": "complete" if header["scanComplete"] else "pivot",
        "decision": assessed_level,
        "log": " | ".join(forensic_log) or "Level 3 assessment finished.",
    }
    return report
