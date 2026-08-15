"""Loading the rules pack.

The pack is *data plus plain Python*, mounted at runtime and never pip-installed
-- that is what lets detection logic ship as a git update without rebuilding the
engine (root README, "Engine vs rules pack"). So everything here is loaded by
path via ``importlib``, not by package import.

The pack is validated on load by its own ``rules/validate.py``; an invalid pack
raises :class:`InvalidRulesPack` and the scanner refuses to run.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from types import ModuleType
from typing import Any

SCAN_LEVELS = (2, 3, 4)


class InvalidRulesPack(Exception):
    """Raised when the rules pack fails validation or cannot be loaded."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def load_module_from_path(path: Path, module_name: str) -> ModuleType:
    """Import a single .py file under a private module name."""
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # Registered so dataclasses/pickle and tracebacks behave; namespaced to
    # avoid colliding with anything the engine imports normally.
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@dataclass
class RulesPack:
    rules_dir: Path
    scan_rules: dict[int, list[dict[str, Any]]]
    assessors: dict[int, ModuleType]
    signatures: dict[str, Any]
    _func_modules: dict[str, ModuleType] = dataclass_field(default_factory=dict)

    @classmethod
    def load(cls, rules_dir: str | Path, validate: bool = True) -> "RulesPack":
        base = Path(rules_dir).resolve()
        if not base.is_dir():
            raise InvalidRulesPack([f"rules directory not found: {base}"])

        if validate:
            errors = run_validator(base)
            if errors:
                raise InvalidRulesPack(errors)

        scan_rules: dict[int, list[dict[str, Any]]] = {}
        assessors: dict[int, ModuleType] = {}

        for level in SCAN_LEVELS:
            rules_path = base / "scan" / f"level{level}.json"
            with rules_path.open(encoding="utf-8") as handle:
                scan_rules[level] = json.load(handle)

            assess_path = base / "assess" / f"level{level}.py"
            assessors[level] = load_module_from_path(
                assess_path, f"_email_guard_rules_assess_level{level}"
            )

        signatures_path = base / "signatures" / "prompt-injection.json"
        signatures: dict[str, Any] = {"signatures": []}
        if signatures_path.is_file():
            with signatures_path.open(encoding="utf-8") as handle:
                signatures = json.load(handle)

        return cls(
            rules_dir=base,
            scan_rules=scan_rules,
            assessors=assessors,
            signatures=signatures,
        )

    def rules_for(self, level: int) -> list[dict[str, Any]]:
        return self.scan_rules.get(level, [])

    def resolve_func(self, reference: str):
        """Resolve ``"level2_funcs.return_path_alignment"`` to a callable.

        The module is always named relative to ``rules/scan/``, so a rule may
        reference a helper from any level, not just its own.
        """
        module_name, _, attr = reference.partition(".")
        module = self._func_modules.get(module_name)
        if module is None:
            path = self.rules_dir / "scan" / f"{module_name}.py"
            if not path.is_file():
                raise InvalidRulesPack([f"rule function module not found: {module_name}.py"])
            module = load_module_from_path(path, f"_email_guard_rules_scan_{module_name}")
            self._func_modules[module_name] = module
        func = getattr(module, attr, None)
        if not callable(func):
            raise InvalidRulesPack([f"rule function not callable: {reference}"])
        return func


def run_validator(rules_dir: Path) -> list[str]:
    """Run the pack's own validator, returning a list of error strings."""
    validator_path = Path(rules_dir) / "validate.py"
    if not validator_path.is_file():
        return [f"rules pack has no validate.py: {validator_path}"]
    module = load_module_from_path(validator_path, "_email_guard_rules_validate")
    validate_pack = getattr(module, "validate_pack", None)
    if not callable(validate_pack):
        return ["rules/validate.py does not expose validate_pack()"]
    return list(validate_pack(rules_dir))
