"""Rules pack validator.

Run by the engine on load (a malformed pack is rejected before it can affect a
verdict) and standalone in CI:

    python -m email_guard --validate-rules
    python rules/validate.py [rules_dir]

Deliberately self-contained -- it imports nothing from the engine, so the pack
stays independently checkable and can move to its own repository later.

Replaces the prototype's pattern of storing logic as JavaScript strings run
through ``new Function()``, where a stray syntax error broke a scan at runtime
with no warning (root README, "Engine vs rules pack").
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

LEVELS = (2, 3, 4)

STATUSES = {
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

# type -> keys it must carry beyond `field` and `type`
REQUIRED_KEYS: dict[str, tuple[str, ...]] = {
    "regex_any": ("patterns", "result_if_match", "result_if_no_match"),
    "regex_all": ("patterns", "result_if_match", "result_if_no_match"),
    "equals": ("value", "result_if_match", "result_if_no_match"),
    "in": ("values", "result_if_match", "result_if_no_match"),
    "is_false": ("result_if_match", "result_if_no_match"),
    "non_empty": ("result_if_match", "result_if_no_match"),
    "func": ("func",),
    "ignore": (),
}

OPTIONAL_KEYS = {"comment", "ignore_case"}

STATUS_KEYS = ("result_if_match", "result_if_no_match")

_SCAN_POINT_RE = re.compile(r"^(core|metadata|integrity|content)-[a-z0-9_\-]+$", re.IGNORECASE)


def validate_pack(rules_dir: str | Path) -> list[str]:
    """Validate a rules pack. Returns a list of error strings; empty means valid."""
    base = Path(rules_dir)
    errors: list[str] = []

    if not base.is_dir():
        return [f"rules directory not found: {base}"]

    for level in LEVELS:
        errors.extend(_validate_scan_level(base, level))
        errors.extend(_validate_assess_level(base, level))

    errors.extend(_validate_signatures(base))
    return errors


def _validate_scan_level(base: Path, level: int) -> list[str]:
    path = base / "scan" / f"level{level}.json"
    where = f"scan/level{level}.json"

    if not path.is_file():
        return [f"{where}: missing"]

    try:
        with path.open(encoding="utf-8") as handle:
            rules = json.load(handle)
    except json.JSONDecodeError as exc:
        return [f"{where}: invalid JSON ({exc})"]

    if not isinstance(rules, list):
        return [f"{where}: expected a list of rule objects"]

    errors: list[str] = []
    seen_fields: set[str] = set()

    for index, rule in enumerate(rules):
        label = f"{where}[{index}]"

        if not isinstance(rule, dict):
            errors.append(f"{label}: expected an object")
            continue

        field = rule.get("field")
        if not isinstance(field, str) or not field:
            errors.append(f"{label}: missing 'field'")
        else:
            label = f"{where}[{field}]"
            if not _SCAN_POINT_RE.match(field):
                errors.append(
                    f"{label}: 'field' must be a scan point "
                    "(core-*, metadata-*, integrity-*, content-*)"
                )
            if field in seen_fields:
                errors.append(f"{label}: duplicate rule for this field")
            seen_fields.add(field)

        rule_type = rule.get("type")
        if rule_type not in REQUIRED_KEYS:
            errors.append(
                f"{label}: unknown type {rule_type!r} "
                f"(expected one of {', '.join(sorted(REQUIRED_KEYS))})"
            )
            continue

        for key in REQUIRED_KEYS[rule_type]:
            if key not in rule:
                errors.append(f"{label}: type '{rule_type}' requires '{key}'")

        allowed = set(REQUIRED_KEYS[rule_type]) | OPTIONAL_KEYS | {"field", "type"}
        for key in rule:
            if key not in allowed:
                errors.append(f"{label}: unexpected key '{key}' for type '{rule_type}'")

        for key in STATUS_KEYS:
            if key in rule and rule[key] not in STATUSES:
                errors.append(
                    f"{label}: '{key}' is {rule[key]!r}, "
                    f"not a known status ({', '.join(sorted(STATUSES))})"
                )

        if rule_type in ("regex_any", "regex_all"):
            errors.extend(_validate_patterns(label, rule.get("patterns")))

        if rule_type == "in" and not isinstance(rule.get("values"), list):
            errors.append(f"{label}: 'values' must be a list")

        if rule_type == "func":
            errors.extend(_validate_func(base, label, rule.get("func")))

    return errors


def _validate_patterns(label: str, patterns: Any) -> list[str]:
    if not isinstance(patterns, list) or not patterns:
        return [f"{label}: 'patterns' must be a non-empty list"]
    errors = []
    for pattern in patterns:
        if not isinstance(pattern, str):
            errors.append(f"{label}: pattern {pattern!r} is not a string")
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f"{label}: pattern {pattern!r} does not compile ({exc})")
    return errors


def _validate_func(base: Path, label: str, reference: Any) -> list[str]:
    if not isinstance(reference, str) or "." not in reference:
        return [f"{label}: 'func' must look like 'module.function'"]

    module_name, _, attr = reference.partition(".")
    path = base / "scan" / f"{module_name}.py"
    if not path.is_file():
        return [f"{label}: func module not found: scan/{module_name}.py"]

    try:
        module = _import_path(path, f"_rules_validate_scan_{module_name}")
    except Exception as exc:
        return [f"{label}: scan/{module_name}.py failed to import ({exc})"]

    func = getattr(module, attr, None)
    if func is None:
        return [f"{label}: scan/{module_name}.py has no '{attr}'"]
    if not callable(func):
        return [f"{label}: '{reference}' is not callable"]
    return []


def _validate_assess_level(base: Path, level: int) -> list[str]:
    path = base / "assess" / f"level{level}.py"
    where = f"assess/level{level}.py"

    if not path.is_file():
        return [f"{where}: missing"]

    try:
        module = _import_path(path, f"_rules_validate_assess_level{level}")
    except Exception as exc:
        return [f"{where}: failed to import ({exc})"]

    assess = getattr(module, "assess", None)
    if assess is None:
        return [f"{where}: does not expose assess()"]
    if not callable(assess):
        return [f"{where}: 'assess' is not callable"]
    return []


def _validate_signatures(base: Path) -> list[str]:
    path = base / "signatures" / "prompt-injection.json"
    if not path.is_file():
        # The signature DB starts empty and grows over time; absence is fine.
        return []
    try:
        with path.open(encoding="utf-8") as handle:
            json.load(handle)
    except json.JSONDecodeError as exc:
        return [f"signatures/prompt-injection.json: invalid JSON ({exc})"]
    return []


def _import_path(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    rules_dir = Path(args[0]) if args else Path(__file__).resolve().parent
    errors = validate_pack(rules_dir)
    if errors:
        print(f"rules pack INVALID ({rules_dir}):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"rules pack OK: {rules_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
