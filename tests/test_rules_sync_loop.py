"""The scheduled loop: pacing, backoff, and the one thing `off` must still do.

No wall clock and no network anywhere here -- ``sleep`` and ``pull`` are both
injected, the same seam ``dispatcher/email_guard_dispatcher/runner.py`` uses.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

import pytest

from email_guard_rules_sync.config import SyncConfig
from email_guard_rules_sync.loop import INITIAL_BACKOFF, MAX_BACKOFF, run_forever
from email_guard_rules_sync.sync import PullResult


@pytest.fixture
def config(tmp_path: Path, rules_dir: Path) -> SyncConfig:
    return SyncConfig(
        repo_url="https://example.invalid/repo",
        live_dir=tmp_path / "rules-live",
        seed_dir=rules_dir,
        interval_seconds=86400.0,
    )


def result(status: str, **kwargs) -> PullResult:
    return PullResult(status=status, timestamp="2026-08-17T00:00:00+00:00", **kwargs)


def stopping_after(count: int, delays: list[float]):
    """A `sleep` that records its delays and stops the loop after N waits."""

    def sleep(delay: float) -> bool:
        delays.append(delay)
        return len(delays) >= count

    return sleep


def test_off_disables_scheduled_pulls(config: SyncConfig):
    calls: list[SyncConfig] = []
    stop = threading.Event()
    stop.set()

    run_forever(
        SyncConfig(
            repo_url=config.repo_url,
            live_dir=config.live_dir,
            seed_dir=config.seed_dir,
            interval_seconds=None,
        ),
        stop,
        pull=lambda cfg: calls.append(cfg) or result("updated"),
    )

    assert calls == []


def test_off_still_seeds_the_live_tree(config: SyncConfig):
    """Manual-only must not mean an empty promote target.

    The mounts may already point here, so the tree has to serve the committed
    pack whether or not a pull is ever scheduled.
    """
    stop = threading.Event()
    stop.set()

    run_forever(
        SyncConfig(
            repo_url=config.repo_url,
            live_dir=config.live_dir,
            seed_dir=config.seed_dir,
            interval_seconds=None,
        ),
        stop,
        pull=lambda cfg: result("updated"),
    )

    assert (config.live_dir / "current" / "scan" / "level2.json").is_file()


def test_the_loop_waits_the_configured_interval(config: SyncConfig):
    delays: list[float] = []

    run_forever(
        config,
        threading.Event(),
        sleep=stopping_after(3, delays),
        pull=lambda cfg: result("no_change"),
    )

    assert delays == [86400.0, 86400.0, 86400.0]


def test_the_loop_backs_off_after_an_error(config: SyncConfig):
    """A DNS blip must not become a hot retry loop against GitHub."""
    delays: list[float] = []

    run_forever(
        config,
        threading.Event(),
        sleep=stopping_after(4, delays),
        pull=lambda cfg: result("error", message="unreachable"),
    )

    assert delays == [
        INITIAL_BACKOFF,
        INITIAL_BACKOFF * 2,
        INITIAL_BACKOFF * 4,
        INITIAL_BACKOFF * 8,
    ]


def test_the_backoff_is_capped(config: SyncConfig):
    delays: list[float] = []

    run_forever(
        config,
        threading.Event(),
        sleep=stopping_after(12, delays),
        pull=lambda cfg: result("error"),
    )

    assert max(delays) == MAX_BACKOFF


def test_the_backoff_resets_after_a_good_pull(config: SyncConfig):
    delays: list[float] = []
    statuses = iter(["error", "error", "updated", "error"])

    run_forever(
        config,
        threading.Event(),
        sleep=stopping_after(4, delays),
        pull=lambda cfg: result(next(statuses)),
    )

    assert delays == [INITIAL_BACKOFF, INITIAL_BACKOFF * 2, 86400.0, INITIAL_BACKOFF]


def test_a_rejected_pull_is_not_an_error_for_pacing(config: SyncConfig):
    """Rejection means the updater worked: it caught a bad pack.

    Backing off would slow down noticing the fix when upstream lands one.
    """
    delays: list[float] = []

    run_forever(
        config,
        threading.Event(),
        sleep=stopping_after(2, delays),
        pull=lambda cfg: result("rejected", validation_errors=("scan/level2.json: bad",)),
    )

    assert delays == [86400.0, 86400.0]


def test_the_loop_stops_on_the_stop_event(config: SyncConfig):
    stop = threading.Event()
    calls: list[int] = []

    def pull(cfg: SyncConfig) -> PullResult:
        calls.append(1)
        stop.set()
        return result("no_change")

    run_forever(config, stop, sleep=lambda delay: stop.is_set(), pull=pull)

    assert len(calls) == 1


def test_the_loop_survives_a_pull_that_returns_an_error(config: SyncConfig):
    """`pull_and_promote` never raises, but the loop must not assume it."""
    delays: list[float] = []

    run_forever(
        config,
        threading.Event(),
        sleep=stopping_after(2, delays),
        pull=lambda cfg: result("error", message="boom"),
    )

    assert len(delays) == 2


@pytest.mark.parametrize(
    ("status", "level", "needle"),
    [
        pytest.param("updated", logging.INFO, "rules updated", id="updated"),
        pytest.param("no_change", logging.INFO, "rules unchanged", id="no-change"),
        pytest.param("rejected", logging.ERROR, "REJECTED", id="rejected"),
        pytest.param("busy", logging.INFO, "skipped", id="busy"),
        pytest.param("error", logging.ERROR, "error", id="error"),
    ],
)
def test_each_outcome_is_logged(
    config: SyncConfig, caplog: pytest.LogCaptureFixture, status: str, level: int, needle: str
):
    """`docker compose logs rules-updater` is the primary operator interface."""
    delays: list[float] = []

    with caplog.at_level(logging.INFO):
        run_forever(
            config,
            threading.Event(),
            sleep=stopping_after(1, delays),
            pull=lambda cfg: result(status, message="something happened"),
        )

    matching = [r for r in caplog.records if needle in r.getMessage()]
    assert matching, f"no log line mentioning {needle!r}"
    assert any(r.levelno == level for r in matching)


def test_a_rejection_logs_every_validation_error(
    config: SyncConfig, caplog: pytest.LogCaptureFixture
):
    delays: list[float] = []
    errors = ("scan/level2.json: invalid JSON", "assess/level3.py: failed to import")

    with caplog.at_level(logging.ERROR):
        run_forever(
            config,
            threading.Event(),
            sleep=stopping_after(1, delays),
            pull=lambda cfg: result("rejected", validation_errors=errors),
        )

    logged = caplog.text
    for error in errors:
        assert error in logged
