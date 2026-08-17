"""The scheduled pull loop.

Mirrors ``dispatcher/email_guard_dispatcher/runner.py``: an interruptible wait on
a :class:`threading.Event` rather than ``time.sleep``, so a container ``SIGTERM``
stops the loop between passes instead of after a full interval; and injected
``sleep``/``pull`` seams so the tests need no wall clock and no network.

The loop must not die. A pull that fails is logged and retried later with a
backoff -- an updater that exits on the first DNS blip is an updater that
silently stops updating, which is the failure mode this whole component exists
to prevent.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable

from . import store
from .config import SyncConfig
from .sync import STATUS_ERROR, PullResult, pull_and_promote

log = logging.getLogger(__name__)

INITIAL_BACKOFF = 300.0     # 5 minutes
MAX_BACKOFF = 21600.0       # 6 hours


def run_forever(
    config: SyncConfig,
    stop: threading.Event | None = None,
    *,
    sleep: Callable[[float], bool] | None = None,
    pull: Callable[[SyncConfig], PullResult] | None = None,
) -> None:
    """Pull on the configured interval until ``stop`` is set.

    ``sleep`` takes seconds and returns True if the wait was interrupted, which
    is exactly ``threading.Event.wait``'s contract.
    """
    halt = stop if stop is not None else threading.Event()
    wait = sleep if sleep is not None else halt.wait
    do_pull = pull if pull is not None else pull_and_promote

    # Seed first, and unconditionally -- including when the interval is off. A
    # live root that has never been promoted into must still serve the committed
    # pack, or repointing the mounts at it would break scanning.
    store.ensure_live_root(config.live_dir, config.seed_dir)

    if config.interval_seconds is None:
        log.info(
            "rules pull interval is 'off': no scheduled pulls. "
            "Manual refresh from the review console still works."
        )
        while not halt.is_set():
            if wait(3600.0):
                break
        return

    log.info(
        "rules updater: pulling %s (%s, %s/) every %.0fs",
        config.repo_url,
        config.branch,
        config.subpath,
        config.interval_seconds,
    )

    backoff = INITIAL_BACKOFF
    while not halt.is_set():
        result = do_pull(config)
        _log_result(result)

        if result.status == STATUS_ERROR:
            delay = min(backoff, MAX_BACKOFF)
            log.warning("rules pull failed; retrying in %.0fs", delay)
            backoff = min(backoff * 2, MAX_BACKOFF)
        else:
            delay = config.interval_seconds
            backoff = INITIAL_BACKOFF

        if wait(delay):
            break

    log.info("rules updater: stopping")


def _log_result(result: PullResult) -> None:
    """One line per outcome, at a level that matches how much it matters."""
    if result.status == "updated":
        log.info(
            "rules updated: %s -> %s%s",
            (result.old_commit or "none")[:12],
            (result.new_commit or "none")[:12],
            f" ({len(result.warnings)} feed warning(s))" if result.warnings else "",
        )
    elif result.status == "no_change":
        log.info("rules unchanged (%s)", (result.new_commit or "none")[:12])
    elif result.status == "rejected":
        log.error(
            "rules pull REJECTED: %s -- live pack unchanged, scanning continues on it",
            result.message,
        )
        for error in result.validation_errors:
            log.error("  - %s", error)
    elif result.status == "busy":
        log.info("rules pull skipped: %s", result.message)
    else:
        log.error("rules pull error: %s", result.message)
