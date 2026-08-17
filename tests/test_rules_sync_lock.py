"""The pull lock: the scheduled pull and the console button cannot race.

Two callers want to promote into the same tree. Only one may, and the other has
to be told so cleanly -- a `busy` result, not a wait, not an error, and above all
not a second concurrent promote.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from email_guard_rules_sync import store
from email_guard_rules_sync.config import SyncConfig
from email_guard_rules_sync.lock import PullBusy, pull_lock
from email_guard_rules_sync.sync import pull_and_promote


@pytest.fixture
def config(tmp_path: Path, rules_dir: Path) -> SyncConfig:
    return SyncConfig(
        # Deliberately unreachable: these tests are about the lock, and a pull
        # that never gets past it must not need a remote at all.
        repo_url=f"file://{tmp_path / 'nowhere'}",
        live_dir=tmp_path / "rules-live",
        seed_dir=rules_dir,
    )


def test_a_second_caller_gets_busy(config: SyncConfig):
    store.ensure_live_root(config.live_dir, config.seed_dir)
    held = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with pull_lock(config.lock_file):
            held.set()
            release.wait(timeout=10)

    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    assert held.wait(timeout=5)

    try:
        result = pull_and_promote(config)
    finally:
        release.set()
        holder.join(timeout=5)

    assert result.status == "busy"
    assert result.message


def test_busy_promotes_nothing_and_is_not_an_error(config: SyncConfig):
    """A double-clicked button must be a non-event, not a half-applied update."""
    store.ensure_live_root(config.live_dir, config.seed_dir)
    before_target = os.readlink(config.live_dir / "current")
    before_releases = sorted(p.name for p in (config.live_dir / "releases").iterdir())

    held = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with pull_lock(config.lock_file):
            held.set()
            release.wait(timeout=10)

    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    assert held.wait(timeout=5)

    try:
        result = pull_and_promote(config)
    finally:
        release.set()
        holder.join(timeout=5)

    assert result.validation_errors == ()
    assert result.old_commit == result.new_commit
    assert os.readlink(config.live_dir / "current") == before_target
    assert sorted(p.name for p in (config.live_dir / "releases").iterdir()) == before_releases


def test_two_in_process_callers_exclude_each_other(tmp_path: Path):
    """flock is per open file description, so threads really do exclude."""
    lock = tmp_path / ".lock"
    entered: list[int] = []
    busy: list[int] = []
    first_in = threading.Event()
    finish = threading.Event()

    def attempt(index: int) -> None:
        try:
            with pull_lock(lock):
                entered.append(index)
                first_in.set()
                finish.wait(timeout=10)
        except PullBusy:
            busy.append(index)

    one = threading.Thread(target=attempt, args=(1,), daemon=True)
    one.start()
    assert first_in.wait(timeout=5)

    two = threading.Thread(target=attempt, args=(2,), daemon=True)
    two.start()
    two.join(timeout=5)

    finish.set()
    one.join(timeout=5)

    assert entered == [1]
    assert busy == [2]


def test_the_lock_survives_a_crashed_holder(tmp_path: Path):
    """The reason this is flock and not an O_EXCL pidfile.

    A pidfile left behind by a killed updater would wedge every future pull
    until a human deleted it -- "the rules silently stopped updating" is the
    exact failure this component exists to prevent. The kernel drops an flock
    when the process dies, however it dies.
    """
    lock = tmp_path / ".lock"
    script = textwrap.dedent(
        f"""
        import fcntl, os
        fd = os.open({str(lock)!r}, os.O_RDWR | os.O_CREAT, 0o644)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os._exit(1)          # no unlock, no cleanup, no atexit
        """
    )
    crashed = subprocess.run([sys.executable, "-c", script], capture_output=True)
    assert crashed.returncode == 1
    assert lock.exists()

    with pull_lock(lock):
        pass  # acquired without a manual cleanup step


def test_the_lock_is_released_when_the_body_raises(tmp_path: Path):
    lock = tmp_path / ".lock"

    with pytest.raises(ValueError):
        with pull_lock(lock):
            raise ValueError("boom")

    with pull_lock(lock):
        pass


def test_the_lock_file_is_not_removed(tmp_path: Path):
    """Never unlinked, which sidesteps the create/unlink race entirely."""
    lock = tmp_path / ".lock"

    with pull_lock(lock):
        pass

    assert lock.exists()
