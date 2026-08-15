"""Single named configuration for the scanner.

Replaces the prototype's conflicting path files and index-based path references
(``paths[13]``) -- see the root README, "Known issues" -> "Conflicting /
index-based config paths". Everything is looked up by name.

Resolution order, highest priority first:

    1. explicit CLI flag (``--lists-dir`` / ``--rules-dir`` / ``--config``)
    2. environment (``EMAIL_GUARD_LISTS_DIR`` / ``EMAIL_GUARD_RULES_DIR`` /
       ``EMAIL_GUARD_CONFIG``)
    3. ``config/config.json``
    4. built-in default

Relative paths inside ``config.json`` are resolved against the project root,
defined as the parent of the directory holding the config file.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_LISTS_DIR = "data/lists"
DEFAULT_RULES_DIR = "rules"


def project_root() -> Path:
    """Repo root: ``<root>/scanner/email_guard/config.py`` -> ``<root>``."""
    return Path(__file__).resolve().parents[2]


def default_config_path() -> Path:
    return project_root() / "config" / "config.json"


@dataclass(frozen=True)
class Config:
    lists_dir: Path
    rules_dir: Path
    config_path: Path | None


def load(
    config_path: str | os.PathLike[str] | None = None,
    lists_dir: str | os.PathLike[str] | None = None,
    rules_dir: str | os.PathLike[str] | None = None,
) -> Config:
    """Build the effective configuration from flags, environment and file."""
    chosen_config = config_path or os.environ.get("EMAIL_GUARD_CONFIG")
    path = Path(chosen_config) if chosen_config else default_config_path()

    data: dict = {}
    used_path: Path | None = None
    if path.is_file():
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        used_path = path
    elif chosen_config:
        # An explicitly requested config that does not exist is an error; the
        # default one being absent is not.
        raise FileNotFoundError(f"config file not found: {path}")

    # Relative entries in config.json hang off the project root, not the cwd,
    # so the scanner behaves the same however it is invoked.
    base = used_path.resolve().parent.parent if used_path else project_root()

    resolved_lists = _resolve(
        lists_dir,
        os.environ.get("EMAIL_GUARD_LISTS_DIR"),
        data.get("lists_dir"),
        DEFAULT_LISTS_DIR,
        base,
    )
    resolved_rules = _resolve(
        rules_dir,
        os.environ.get("EMAIL_GUARD_RULES_DIR"),
        data.get("rules_dir"),
        DEFAULT_RULES_DIR,
        base,
    )
    return Config(lists_dir=resolved_lists, rules_dir=resolved_rules, config_path=used_path)


def _resolve(flag, env, from_file, fallback, base: Path) -> Path:
    # Flags and environment values are user-supplied at the call site, so they
    # resolve against the cwd; only config.json values hang off the root.
    for candidate in (flag, env):
        if candidate:
            return Path(candidate).expanduser().resolve()
    value = from_file or fallback
    candidate_path = Path(value).expanduser()
    if not candidate_path.is_absolute():
        candidate_path = base / candidate_path
    return candidate_path.resolve()
