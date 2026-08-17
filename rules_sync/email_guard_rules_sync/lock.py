"""The pull lock: one writer of the live tree, ever.

Two callers can ask for a pull at the same time -- the scheduled loop and the
console's "Refresh rules" button -- and they must not both stage and promote.
The second caller gets a clean *busy* result rather than a race or a wait.

``fcntl.flock`` rather than an ``O_EXCL`` pidfile, for one reason that matters
more than the others: **the kernel releases a flock when the fd closes, including
when the process dies abnormally.** A pidfile left behind by a killed updater
would wedge every future pull until someone deleted it by hand, and "the rules
stopped updating and nothing said why" is the exact failure this whole component
exists to avoid.

The lock file is never unlinked, which sidesteps the classic create/unlink race
where one process removes the file another has just opened.
"""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class PullBusy(RuntimeError):
    """Another pull holds the lock. Not an error -- a result."""


@contextmanager
def pull_lock(path: str | Path) -> Iterator[None]:
    """Hold the exclusive pull lock, or raise :class:`PullBusy` immediately.

    Non-blocking on purpose: a caller that waited would turn a double-clicked
    button into a queue of pulls, and there is nothing useful for the second one
    to do -- the first is already fetching the same commit.

    flock is held per *open file description*, so the loop thread and the
    control server thread each open their own fd and genuinely exclude each
    other. No additional in-process lock is needed.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise PullBusy(
                "another rules pull is already running; try again in a moment"
            ) from exc
        yield
    finally:
        # Closing releases the lock. Doing it in `finally` (rather than
        # unlocking explicitly) means an exception inside the body cannot leak
        # the lock either.
        os.close(fd)
