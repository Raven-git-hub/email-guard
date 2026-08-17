"""The rules updater's *validation environment*, not the pack it validates.

The pack has always been fine. What broke in production was the environment the
updater validates it in: `rules/scan/level*_funcs.py` call into the engine
(``from email_guard.links import ...``), and ``rules/validate.py`` proves a pack
will run by ``exec_module``-ing exactly those modules. So validation requires
``email_guard`` importable -- and the updater image installed only ``rules_sync``,
stubbing ``scanner/`` as an empty directory. Every pull came back with eleven
``failed to import (No module named 'email_guard')`` errors, the pack was
rejected, and the updater served the seed forever.

Nothing in the suite caught it because the dev and CI environment installs all
four package roots, so ``email_guard`` was always importable here. These tests
close that gap by refusing the ambient environment: they run the shipped
validator against the shipped pack on an import path built from *only the
package roots the updater's Dockerfile installs*.

``-S`` is what makes that real. It drops site-packages, so the editable install
of the dispatcher and the console cannot leak in and quietly satisfy an import
the container would not have. :func:`test_the_restricted_interpreter_is_actually_restricted`
holds that honest.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from email_guard_rules_sync import pack

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = PROJECT_ROOT / "rules_sync" / "Dockerfile"

# The package root -> the module name it installs. `scanner/` holding
# `email_guard` is the indirection that made the bug easy to miss by eye.
MODULES = {
    "scanner": "email_guard",
    "dispatcher": "email_guard_dispatcher",
    "webui": "email_guard_webui",
    "rules_sync": "email_guard_rules_sync",
}

# What the updater image installs is READ FROM the Dockerfile rather than
# restated here. That is the point: reverting the `COPY scanner/` line has to
# break the behaviour tests below, not just the one that greps the Dockerfile.
_COPY_RE = re.compile(r"^COPY\s+([A-Za-z_][A-Za-z0-9_]*)/", re.MULTILINE)


def updater_roots() -> list[str]:
    copied = set(_COPY_RE.findall(DOCKERFILE.read_text(encoding="utf-8")))
    return sorted(copied & set(MODULES))


@pytest.fixture(scope="module")
def updater_python(tmp_path_factory: pytest.TempPathFactory) -> str:
    """An interpreter that can import what the updater container can, and no more.

    A wrapper script rather than an argument list, because it is handed to
    :func:`pack.validate_staged` as its ``python`` -- which runs the real
    production code path, scrubbed environment and all, and would otherwise
    strip any ``PYTHONPATH`` we tried to pass in.
    """
    path = os.pathsep.join(str(PROJECT_ROOT / root) for root in updater_roots())
    launcher = tmp_path_factory.mktemp("updater-env") / "python"
    launcher.write_text(
        "#!/bin/sh\n"
        f'PYTHONPATH="{path}" exec "{sys.executable}" -S "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    return str(launcher)


def _run(updater_python: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [updater_python, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


# --- the guard on the guard -------------------------------------------------


def test_the_restricted_interpreter_is_actually_restricted(updater_python: str):
    """Without this, every test below could pass on the ambient environment.

    The whole point is that the dispatcher and the console are NOT importable.
    If site-packages leaked back in, the rest of this module would prove nothing
    and would go on passing while the container stayed broken.
    """
    stubbed = sorted(set(MODULES) - set(updater_roots()))
    assert stubbed == ["dispatcher", "webui"], (
        f"the updater image is expected to stub exactly those two, got {stubbed}"
    )

    for root in stubbed:
        completed = _run(updater_python, "-c", f"import {MODULES[root]}")

        assert completed.returncode != 0, (
            f"{MODULES[root]} is importable in the restricted interpreter, so it "
            "is not restricted -- these tests would pass on the dev environment "
            "instead of on the updater's"
        )
        assert "ModuleNotFoundError" in completed.stderr

    # ...and the roots the image DOES copy import, or we would be asserting
    # against an interpreter that simply cannot import anything.
    imports = ", ".join(MODULES[root] for root in updater_roots())
    completed = _run(updater_python, "-c", f"import {imports}")
    assert completed.returncode == 0, completed.stderr


# --- the regression ---------------------------------------------------------


def test_the_shipped_pack_validates_in_the_updaters_environment(
    updater_python: str, rules_dir: Path
):
    """The test that would have caught it: the pack, the validator, that env.

    Eleven errors of the form ``scan/level2_funcs.py failed to import (No module
    named 'email_guard')`` is what this produced against the shipped pack before
    the image installed the engine.
    """
    completed = _run(updater_python, str(rules_dir / "validate.py"), str(rules_dir))

    assert completed.returncode == 0, (
        "the shipped pack does not validate in the environment the updater "
        f"validates in:\n{completed.stderr}"
    )
    assert "rules pack OK" in completed.stdout


def test_the_updater_promotes_the_shipped_pack_rather_than_rejecting_it(
    updater_python: str, rules_dir: Path, tmp_path: Path
):
    """The same thing through the production call path, not a bare subprocess.

    ``validate_staged`` is what a pull actually runs, including the deliberately
    scrubbed subprocess environment, so this is the assertion that covers both
    halves: the image installs the engine, and nothing in ``validate_staged``
    strips it back out again.
    """
    staged = tmp_path / "releases" / "abc123" / "rules"
    shutil.copytree(rules_dir, staged)

    errors = pack.validate_staged(staged, python=updater_python)

    assert errors == []


def test_a_missing_engine_is_what_produced_the_reported_errors(
    rules_dir: Path, tmp_path: Path
):
    """Pin the failure too, so this file documents the bug and not just the fix.

    An interpreter with `rules_sync` but no `scanner` on its path IS the old
    image. If this ever stops reporting import errors -- because the pack
    stopped calling into the engine -- the fix above has become optional and
    someone should be told, rather than the coupling quietly rotting.
    """
    launcher = tmp_path / "python-without-the-engine"
    launcher.write_text(
        "#!/bin/sh\n"
        f'PYTHONPATH="{PROJECT_ROOT / "rules_sync"}" exec "{sys.executable}" -S "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o755)

    staged = tmp_path / "rules"
    shutil.copytree(rules_dir, staged)

    errors = pack.validate_staged(staged, python=str(launcher))

    assert errors, "a pack that imports the engine cannot validate without it"
    assert all("No module named 'email_guard'" in error for error in errors), errors
    # Every `func` rule in the pack, which is what the live deploy reported.
    assert len(errors) == 11, errors


# --- the coupling this rests on ---------------------------------------------


def test_the_pack_really_does_import_the_engine():
    """Why the image needs the engine at all, asserted rather than assumed."""
    funcs = sorted((PROJECT_ROOT / "rules" / "scan").glob("*_funcs.py"))

    assert funcs, "no scan func modules found"
    importers = [
        path.name
        for path in funcs
        if re.search(r"^from email_guard\.", path.read_text(encoding="utf-8"), re.M)
    ]
    assert importers == [path.name for path in funcs], (
        f"expected every scan func module to import the engine, got {importers}"
    )


def test_the_updater_and_scanner_images_are_documented_as_one_checkout():
    """The engine validated against must be the engine that will run the pack.

    Two images built from different checkouts can disagree about what
    `email_guard` exposes, and then the updater either promotes a pack the
    scanner cannot load or refuses one it could.
    """
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "same checkout" in dockerfile.lower(), (
        "rules_sync/Dockerfile must say the updater and scanner images have to "
        "be built from the same checkout"
    )
