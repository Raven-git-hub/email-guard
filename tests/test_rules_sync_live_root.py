"""A live root this uid cannot write: one actionable line, not a traceback.

Docker creates a missing bind source as a **root-owned** directory on the first
`up`, and the updater runs as uid 1000. Its very first write -- the lock file,
or `releases/` -- then fails, and unhandled that is a `PermissionError` stack
trace repeated forever by `restart: unless-stopped`, with the one sentence that
names the fix (`chown` it) nowhere in sight.

So the failure is recognised and reported as itself. What is asserted here is
the behaviour, not the wording: that the message names the uid, the path and the
chown; that a pull reports it as a clean `error` result rather than raising; and
that the process exits instead of spinning.

The real chmod-a-directory test is the last one, and it can only run as a
non-root uid -- root ignores directory permissions. The rest hold in any
environment, which is what keeps this covered in a root CI container too.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

import pytest

from email_guard_rules_sync import __main__ as entrypoint
from email_guard_rules_sync import store
from email_guard_rules_sync.config import SyncConfig
from email_guard_rules_sync.sync import pull_and_promote

ROOT_IGNORES_PERMISSIONS = pytest.mark.skipif(
    os.geteuid() == 0, reason="root writes regardless of mode; needs an unprivileged uid"
)


@pytest.fixture
def config(tmp_path: Path, rules_dir: Path) -> SyncConfig:
    return SyncConfig(
        repo_url=f"file://{tmp_path / 'upstream'}",
        live_dir=tmp_path / "rules-live",
        seed_dir=rules_dir,
    )


# --- the message ------------------------------------------------------------


def test_the_message_names_the_uid_the_path_and_the_fix(tmp_path: Path):
    """Three facts, because each one is a question the operator would ask next."""
    error = store.not_writable_error(
        tmp_path / "rules-live", PermissionError(13, "Permission denied")
    )

    text = str(error)
    assert str(tmp_path / "rules-live") in text
    assert f"uid {os.getuid()}:{os.getgid()}" in text
    assert "chown" in text
    assert "EMAIL_GUARD_UID" in text and "EMAIL_GUARD_GID" in text


def test_it_is_one_line(tmp_path: Path):
    """A wall of text at ERROR reads as a crash; one line reads as an instruction."""
    error = store.not_writable_error(tmp_path, PermissionError(13, "Permission denied"))

    assert "\n" not in str(error)


# --- recognising it ---------------------------------------------------------


def test_an_unrelated_permission_error_is_not_mistaken_for_this(tmp_path: Path):
    """The live root is writable here, so this failure is something else.

    Without the re-check, every PermissionError anywhere in a pull would be
    reported as "chown your rules-live", which is worse than a traceback.
    """
    tmp_path.joinpath("rules-live").mkdir()

    assert store.as_not_writable(tmp_path / "rules-live", PermissionError(13, "nope")) is None
    assert store.as_not_writable(tmp_path / "rules-live", OSError("disk on fire")) is None


def test_the_dedicated_error_is_always_recognised(tmp_path: Path):
    """Raised from `ensure_live_root`, it needs no re-check to be classified."""
    raised = store.not_writable_error(tmp_path, PermissionError(13, "Permission denied"))

    assert store.as_not_writable(tmp_path, raised) is raised


# --- how a pull reports it --------------------------------------------------


def test_a_pull_reports_it_as_an_error_result_rather_than_raising(
    config: SyncConfig, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    """`pull_and_promote` never raises -- the console has to get an answer."""
    def boom(live_dir, seed_dir=None):
        raise store.not_writable_error(Path(live_dir), PermissionError(13, "Permission denied"))

    monkeypatch.setattr(store, "ensure_live_root", boom)

    with caplog.at_level(logging.ERROR):
        result = pull_and_promote(config)

    assert result.status == "error"
    assert "chown" in result.message
    assert "Traceback" not in caplog.text
    assert len([r for r in caplog.records if r.levelno >= logging.ERROR]) == 1


def test_the_updater_exits_instead_of_spinning_on_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    """Nothing in here can fix it, so retrying forever only hides the message."""
    def boom(config, stop=None, **kwargs):
        raise store.not_writable_error(tmp_path, PermissionError(13, "Permission denied"))

    monkeypatch.setattr(entrypoint, "run_forever", boom)
    monkeypatch.setenv("EMAIL_GUARD_RULES_LIVE_DIR", str(tmp_path / "rules-live"))
    monkeypatch.setenv("EMAIL_GUARD_RULES_SEED_DIR", str(tmp_path / "seed"))

    with caplog.at_level(logging.ERROR):
        code = entrypoint.main(["--no-serve"])

    assert code == entrypoint.EXIT_ERROR
    assert len([r for r in caplog.records if r.levelno >= logging.ERROR]) == 1
    assert "chown" in caplog.text


# --- against a genuinely unwritable directory -------------------------------


@ROOT_IGNORES_PERMISSIONS
def test_a_root_owned_live_root_raises_the_dedicated_error(config: SyncConfig):
    """The real thing: `ensure_live_root` on a directory we may not write."""
    config.live_dir.mkdir(parents=True)
    config.live_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)

    try:
        with pytest.raises(store.LiveRootNotWritable) as raised:
            store.ensure_live_root(config.live_dir, config.seed_dir)
    finally:
        config.live_dir.chmod(0o755)

    assert "chown" in str(raised.value)


@ROOT_IGNORES_PERMISSIONS
def test_a_pull_against_one_says_the_same_thing(
    config: SyncConfig, caplog: pytest.LogCaptureFixture
):
    """The lock file lives in the live root, so this fails before any git runs."""
    config.live_dir.mkdir(parents=True)
    config.live_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)

    try:
        with caplog.at_level(logging.ERROR):
            result = pull_and_promote(config)
    finally:
        config.live_dir.chmod(0o755)

    assert result.status == "error"
    assert "chown" in result.message
    assert "Traceback" not in caplog.text
