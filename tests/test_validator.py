"""The rules-pack validator, and the engine's refusal to run on a bad pack.

Replaces the prototype's ``new Function()`` pattern, where a stray syntax error
in a rule broke a scan at runtime with no warning.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from email_guard.cli import main
from email_guard.rulespack import InvalidRulesPack, RulesPack
from tests.conftest import validate_pack


@pytest.fixture
def pack_copy(tmp_path: Path, rules_dir: Path) -> Path:
    """A writable copy of the real rules pack, for corrupting."""
    destination = tmp_path / "rules"
    shutil.copytree(rules_dir, destination)
    return destination


def read_rules(pack_dir: Path, level: int = 2) -> list:
    with (pack_dir / "scan" / f"level{level}.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def write_rules(pack_dir: Path, rules: list, level: int = 2) -> None:
    with (pack_dir / "scan" / f"level{level}.json").open("w", encoding="utf-8") as handle:
        json.dump(rules, handle)


def test_the_shipped_pack_is_valid(rules_dir: Path):
    assert validate_pack(rules_dir) == []


def test_unknown_rule_type_is_rejected(pack_copy: Path):
    rules = read_rules(pack_copy)
    rules[1]["type"] = "vibes_based"
    write_rules(pack_copy, rules)

    errors = validate_pack(pack_copy)
    assert any("unknown type" in error for error in errors)


def test_missing_required_key_is_rejected(pack_copy: Path):
    rules = read_rules(pack_copy)
    rules[1].pop("patterns")
    write_rules(pack_copy, rules)

    errors = validate_pack(pack_copy)
    assert any("requires 'patterns'" in error for error in errors)


def test_status_outside_the_vocabulary_is_rejected(pack_copy: Path):
    rules = read_rules(pack_copy)
    rules[1]["result_if_match"] = "very_bad"
    write_rules(pack_copy, rules)

    errors = validate_pack(pack_copy)
    assert any("not a known status" in error for error in errors)


def test_uncompilable_regex_is_rejected(pack_copy: Path):
    rules = read_rules(pack_copy)
    rules[1]["patterns"] = ["("]
    write_rules(pack_copy, rules)

    errors = validate_pack(pack_copy)
    assert any("does not compile" in error for error in errors)


def test_unresolvable_func_reference_is_rejected(pack_copy: Path):
    rules = read_rules(pack_copy)
    rules[0]["func"] = "level2_funcs.no_such_function"
    write_rules(pack_copy, rules)

    errors = validate_pack(pack_copy)
    assert any("has no 'no_such_function'" in error for error in errors)


def test_missing_func_module_is_rejected(pack_copy: Path):
    rules = read_rules(pack_copy)
    rules[0]["func"] = "ghost_funcs.something"
    write_rules(pack_copy, rules)

    errors = validate_pack(pack_copy)
    assert any("func module not found" in error for error in errors)


def test_func_module_with_a_syntax_error_is_rejected(pack_copy: Path):
    (pack_copy / "scan" / "level2_funcs.py").write_text("def broken(:\n", encoding="utf-8")

    errors = validate_pack(pack_copy)
    assert any("failed to import" in error for error in errors)


def test_scan_point_field_name_is_validated(pack_copy: Path):
    rules = read_rules(pack_copy)
    rules[1]["field"] = "not_a_scan_point"
    write_rules(pack_copy, rules)

    errors = validate_pack(pack_copy)
    assert any("must be a scan point" in error for error in errors)


def test_duplicate_field_is_rejected(pack_copy: Path):
    rules = read_rules(pack_copy)
    rules.append(dict(rules[1]))
    write_rules(pack_copy, rules)

    errors = validate_pack(pack_copy)
    assert any("duplicate rule" in error for error in errors)


def test_malformed_json_is_rejected(pack_copy: Path):
    (pack_copy / "scan" / "level3.json").write_text("[{,]", encoding="utf-8")

    errors = validate_pack(pack_copy)
    assert any("invalid JSON" in error for error in errors)


def test_missing_scan_library_is_rejected(pack_copy: Path):
    (pack_copy / "scan" / "level4.json").unlink()

    errors = validate_pack(pack_copy)
    assert any("scan/level4.json: missing" in error for error in errors)


def test_assess_module_without_assess_is_rejected(pack_copy: Path):
    (pack_copy / "assess" / "level3.py").write_text("X = 1\n", encoding="utf-8")

    errors = validate_pack(pack_copy)
    assert any("does not expose assess()" in error for error in errors)


def test_missing_assess_module_is_rejected(pack_copy: Path):
    (pack_copy / "assess" / "level2.py").unlink()

    errors = validate_pack(pack_copy)
    assert any("assess/level2.py: missing" in error for error in errors)


def test_absent_rules_directory_is_rejected(tmp_path: Path):
    errors = validate_pack(tmp_path / "nope")
    assert any("rules directory not found" in error for error in errors)


# --- the engine refuses to run on an invalid pack ------------------------------


def test_loading_an_invalid_pack_raises(pack_copy: Path):
    rules = read_rules(pack_copy)
    rules[1]["type"] = "vibes_based"
    write_rules(pack_copy, rules)

    with pytest.raises(InvalidRulesPack):
        RulesPack.load(pack_copy)


def test_cli_refuses_to_scan_with_an_invalid_pack(pack_copy: Path, capsys):
    from tests.conftest import EML_FIXTURES, LIST_FIXTURES

    rules = read_rules(pack_copy)
    rules[1]["result_if_match"] = "very_bad"
    write_rules(pack_copy, rules)

    exit_code = main(
        [
            str(EML_FIXTURES / "simple.eml"),
            "--rules-dir",
            str(pack_copy),
            "--lists-dir",
            str(LIST_FIXTURES),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code != 0
    assert "INVALID" in captured.err
    assert "refusing to scan" in captured.err
    assert captured.out == ""  # no verdict was emitted


def test_cli_validate_rules_flag(rules_dir: Path, capsys):
    assert main(["--validate-rules", "--rules-dir", str(rules_dir)]) == 0
    assert "rules pack OK" in capsys.readouterr().out


def test_cli_validate_rules_flag_reports_failure(pack_copy: Path, capsys):
    (pack_copy / "assess" / "level4.py").unlink()

    assert main(["--validate-rules", "--rules-dir", str(pack_copy)]) != 0
    assert "assess/level4.py: missing" in capsys.readouterr().err
