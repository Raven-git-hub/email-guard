"""Deep scan: decompose the message into scan points and run the level's rules.

Decomposition follows the prototype's "Define Scan Items" node, which is why the
scan-point keys are exactly the ``scan_type`` strings in the reference rule
libraries::

    core-<field>                 original_sender, title, clean_text,
                                 attachments, links
    metadata-<section>-<key>     one per metadata pillar entry
    integrity-<key>              dkim_verified, source_pipe
    content-<key>                links, attachments, text, timestamp

Results are grouped the way the assessment scripts read them
(``results["metadata"]["authenticity-dkim"]``), so the ported assessors need no
translation layer.

Levels 1 and 5 are terminal and have no rule library -- see the root README,
"The scanning pipeline".
"""

from __future__ import annotations

import re
from typing import Any

# The full status vocabulary. `fail` is included because the prototype's
# level4.json emits it and level3assess collapses every status to `pass`/`fail`
# in its final scrub.
STATUSES = frozenset(
    {
        "pass",
        "pass_service",
        "pass_downgrade",
        "fail",
        "fail_pass",
        "fail_critical",
        "fail_spam",
        "ignore",
        "unknown",
    }
)

GROUPS = ("core", "metadata", "integrity", "content")

CORE_FIELDS = ("original_sender", "title", "clean_text", "attachments", "links")


def decompose(message: dict[str, Any]) -> list[tuple[str, str, str, Any]]:
    """Break a normalised message into ``(scan_point, group, key, value)`` tuples."""
    points: list[tuple[str, str, str, Any]] = []

    for field in CORE_FIELDS:
        points.append((f"core-{field}", "core", field, message.get(field)))

    for section, entries in (message.get("metadata") or {}).items():
        if not isinstance(entries, dict):
            continue
        for key, value in entries.items():
            points.append((f"metadata-{section}-{key}", "metadata", f"{section}-{key}", value))

    for key, value in (message.get("integrity") or {}).items():
        points.append((f"integrity-{key}", "integrity", key, value))

    for key, value in (message.get("content") or {}).items():
        points.append((f"content-{key}", "content", key, value))

    return points


def scan(message: dict[str, Any], level: int, pack, context: dict[str, Any]) -> dict[str, Any]:
    """Run the level's rule library over the message, returning a results block."""
    rules = {rule["field"]: rule for rule in pack.rules_for(level)}
    block: dict[str, dict[str, str]] = {group: {} for group in GROUPS}

    for scan_point, group, key, value in decompose(message):
        rule = rules.get(scan_point)
        if rule is None:
            # No rule covers this point at this level.
            block[group][key] = "unknown"
            continue
        block[group][key] = apply_rule(rule, value, message, context, pack)

    return block


def apply_rule(
    rule: dict[str, Any], value: Any, message: dict[str, Any], context: dict[str, Any], pack
) -> str:
    """Evaluate one rule against one scan-point value."""
    rule_type = rule.get("type")

    if rule_type == "ignore":
        return "ignore"

    if rule_type == "func":
        func = pack.resolve_func(rule["func"])
        status = func(value, message, context)
        return status if status in STATUSES else "unknown"

    matched = _matches(rule, rule_type, value)
    return rule["result_if_match"] if matched else rule["result_if_no_match"]


def _matches(rule: dict[str, Any], rule_type: str, value: Any) -> bool:
    if rule_type in ("regex_any", "regex_all"):
        flags = 0 if rule.get("ignore_case") is False else re.IGNORECASE
        text = _as_text(value)
        patterns = rule.get("patterns") or []
        if rule_type == "regex_any":
            return any(re.search(pattern, text, flags) for pattern in patterns)
        return all(re.search(pattern, text, flags) for pattern in patterns)

    if rule_type == "equals":
        expected = rule.get("value")
        if rule.get("ignore_case") and isinstance(value, str) and isinstance(expected, str):
            return value.casefold() == expected.casefold()
        # `is` comparison for booleans so 1 != True and 0 != False.
        if isinstance(expected, bool) or isinstance(value, bool):
            return value is expected
        return value == expected

    if rule_type == "in":
        return value in (rule.get("values") or [])

    if rule_type == "is_false":
        return value is False

    if rule_type == "non_empty":
        return bool(value)

    raise ValueError(f"unknown rule type: {rule_type!r}")


def _as_text(value: Any) -> str:
    """Flatten a scan-point value for regex matching.

    Lists (links, attachments) join with newlines so a pattern can match any
    element, matching the prototype's per-element ``.filter()`` checks.
    """
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "\n".join(_as_text(item) for item in value)
    if isinstance(value, dict):
        return "\n".join(f"{k}: {_as_text(v)}" for k, v in value.items())
    return str(value)
