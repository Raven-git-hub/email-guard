"""Shared test fixtures.

Every test runs offline against SYNTHETIC list fixtures in
``tests/fixtures/lists/`` -- never the live lists, which are personal data and
git-ignored (root README, "Storage & privacy").
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from email_guard import parse
from email_guard.lists import Lists
from email_guard.rulespack import RulesPack, load_module_from_path

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_DIR.parent
FIXTURES = TESTS_DIR / "fixtures"
LIST_FIXTURES = FIXTURES / "lists"
JSON_FIXTURES = FIXTURES / "json"
EML_FIXTURES = FIXTURES / "eml"
RULES_DIR = PROJECT_ROOT / "rules"

# The rules pack is loaded by path, never imported as a package -- so tests
# reach its validator the same way the engine does.
_rules_validate = load_module_from_path(RULES_DIR / "validate.py", "_test_rules_validate")
validate_pack = _rules_validate.validate_pack


@pytest.fixture(scope="session")
def rules_dir() -> Path:
    return RULES_DIR


@pytest.fixture(scope="session")
def pack(rules_dir: Path) -> RulesPack:
    return RulesPack.load(rules_dir)


@pytest.fixture
def lists() -> Lists:
    return Lists.load(LIST_FIXTURES)


@pytest.fixture
def empty_lists() -> Lists:
    return Lists()


@pytest.fixture
def scan(lists: Lists, pack: RulesPack):
    """Run the full pipeline on a fixture file, returning the verdict."""
    from email_guard.pipeline import scan_parsed

    def _scan(fixture: str | Path, *, use_lists: Lists | None = None) -> dict:
        path = Path(fixture)
        if not path.is_absolute():
            path = FIXTURES / path
        parsed = (
            parse.parse_eml_file(path)
            if path.suffix == ".eml"
            else parse.parse_json_file(path)
        )
        return scan_parsed(parsed, use_lists or lists, pack, job_id="test-job")

    return _scan


def load_json_fixture(name: str) -> dict:
    with (JSON_FIXTURES / name).open(encoding="utf-8") as handle:
        return json.load(handle)
