"""Checking a staged pack, on both sides of the fail-closed/fail-open split.

Two checks, deliberately asymmetric, mirroring exactly what the runtime does
(``scanner/email_guard/rulespack.py`` and ``scanner/email_guard/signatures.py``):

* :func:`validate_staged` runs the pack's OWN validator and **fails closed**.
  Any error and the caller must not promote.
* :func:`check_signature_feed` inspects ``reference/*_signatures.json`` and
  **fails open**. Every problem is a warning; none of them block a promote.

Do not unify them. A truncated signature download must cost sensitivity, not
stop the mail; a typo in a scan rule must not quietly disable detection.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)

# `rules/validate.py` prints "  - <error>" per problem, to stderr, under a
# "rules pack INVALID (...)" header. Parsing that is a contract with the pack,
# and a thin one: if it ever changes shape we still fail closed, because a
# nonzero exit with nothing parsed is reported as a single synthetic error.
_ERROR_LINE = re.compile(r"^\s+-\s+(?P<error>.+?)\s*$")

REFERENCE_DIR = "reference"
FEEDS = ("injection_signatures.json", "phishing_signatures.json")


def validate_staged(
    staged: Path, *, timeout: float = 60.0, python: str | None = None
) -> list[str]:
    """Validate a staged pack with its own ``validate.py``. Empty list = valid.

    **Run as a subprocess, not imported.** ``validate_pack()`` deliberately
    ``exec_module``s the pack's ``assess/*.py`` and ``scan/*_funcs.py`` in order
    to check they import and expose the right callables -- which means
    validating a freshly pulled pack *executes freshly pulled code*. In-process
    that would run inside the long-lived updater and leave the pulled modules in
    its ``sys.modules``; a subprocess confines both effects to a process that
    then exits.

    To be honest about what this is: isolation and repeatability, **not a
    sandbox**. The compensating controls are the container's -- non-root,
    read-only rootfs, all capabilities dropped, no docker access, no data
    volume, no lists. See the README section this docstring is referenced from.
    """
    validator = Path(staged) / "validate.py"
    if not validator.is_file():
        return [f"the pulled pack has no validate.py at {validator}"]

    argv = [python or sys.executable, str(validator), str(staged)]
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            # Deny the validator the ambient environment, and keep it from
            # writing bytecode into the staged tree.
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "LC_ALL": "C",
            },
        )
    except subprocess.TimeoutExpired:
        return [
            f"the pack validator did not finish within {timeout:.0f}s -- "
            "refusing to promote a pack that cannot be checked"
        ]
    except OSError as exc:
        return [f"could not run the pack validator: {exc}"]

    if completed.returncode == 0:
        return []

    errors = [
        match.group("error")
        for line in completed.stderr.splitlines()
        if (match := _ERROR_LINE.match(line))
    ]
    if errors:
        return errors

    # Nonzero with nothing parseable: still fail closed, and say what happened.
    detail = (completed.stderr or completed.stdout or "").strip() or "no output"
    return [f"the pack validator exited {completed.returncode}: {detail}"]


def check_signature_feed(staged: Path) -> list[str]:
    """Inspect the reference signature feeds. Returns WARNINGS, never errors.

    This exists because the pack validator does not look at ``reference/`` at
    all -- it checks ``signatures/prompt-injection.json`` and nothing else. So
    without this, a malformed injection feed would sail through a pull entirely
    unremarked, and the operator's first hint would be reduced detection.

    The checks mirror the shape ``scanner/email_guard/signatures.py`` enforces
    at load, re-implemented rather than imported: this package imports nothing
    from the engine, so that the pack and its updater stay independently
    movable.
    """
    base = Path(staged) / REFERENCE_DIR
    warnings: list[str] = []

    if not base.is_dir():
        return [
            f"{REFERENCE_DIR}/ is missing from the pulled pack: triage will run on "
            "the hard-baked injection floor alone"
        ]

    for name in FEEDS:
        warnings.extend(_check_one(base / name, name))
    return warnings


def _check_one(path: Path, name: str) -> list[str]:
    where = f"{REFERENCE_DIR}/{name}"

    if not path.is_file():
        return [f"{where}: missing; the scanner will fall back to its baseline"]

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [f"{where}: unreadable ({exc}); the scanner will fall back to its baseline"]

    if not text.strip():
        return [f"{where}: empty; the scanner will fall back to its baseline"]

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [f"{where}: invalid JSON ({exc}); the scanner will fall back to its baseline"]

    if not isinstance(data, dict):
        return [f"{where}: expected an object at the top level"]

    signatures = data.get("signatures")
    if not isinstance(signatures, list):
        return [f"{where}: 'signatures' is missing or not a list"]

    warnings: list[str] = []
    if not isinstance(data.get("version"), int):
        warnings.append(f"{where}: 'version' is missing or not an integer")
    if not isinstance(data.get("updated"), str):
        warnings.append(f"{where}: 'updated' is missing or not a string")

    seen: set[str] = set()
    for index, entry in enumerate(signatures):
        warnings.extend(_check_entry(entry, where, index, seen))
    return warnings


def _check_entry(entry: object, where: str, index: int, seen: set[str]) -> list[str]:
    """One bad entry costs that entry, not the feed -- same rule as the loader."""
    label = f"{where}[{index}]"
    if not isinstance(entry, dict):
        return [f"{label}: expected an object"]

    identifier = entry.get("id")
    if not isinstance(identifier, str) or not identifier:
        return [f"{label}: missing 'id'"]
    label = f"{where}[{identifier}]"
    if identifier in seen:
        return [f"{label}: duplicate id; the scanner will skip the later one"]
    seen.add(identifier)

    kind = entry.get("type")
    if kind not in ("literal", "regex"):
        return [f"{label}: unknown type {kind!r} (expected 'literal' or 'regex')"]

    pattern = entry.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        return [f"{label}: missing 'pattern'"]

    if kind == "regex":
        try:
            re.compile(pattern)
        except re.error as exc:
            return [f"{label}: pattern does not compile ({exc}); the scanner will skip it"]
    return []
