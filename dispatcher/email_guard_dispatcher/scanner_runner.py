"""The dispatcher -> scanner seam.

One method, one direction: raw message bytes in, a verdict out.

    class ScannerRunner(Protocol):
        def scan(self, raw: bytes) -> ScanOutcome: ...

That is the entire interface, and it is what lets the *isolation strategy*
change without dispatch logic changing with it. :class:`SubprocessRunner`
(:mod:`.scanner_client`) runs the scanner as a child process on this host;
:class:`ContainerRunner` (:mod:`.container_runner`) runs it as a throwaway
hardened container, one per message. The runner in :mod:`.runner` cannot tell
which it holds, and must never learn -- everything that makes a container
different (mounts, capabilities, resource caps, reaping) lives behind this
method.

Both implementations report failure the same way: a :class:`ScanOutcome` with
``ok=False``, never an exception. That is what keeps the retry-then-quarantine
path in :meth:`Runner._scan_with_retries` identical for both, and it is why a
container that was OOM-killed and a scanner that exited non-zero need no
special handling anywhere upstream.

``ScanOutcome`` lives here rather than in :mod:`.scanner_client` because both
implementations return it; ``scanner_client`` re-exports it so existing
imports keep working.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger(__name__)

SUBPROCESS = "subprocess"
CONTAINER = "container"
RUNNERS = (SUBPROCESS, CONTAINER)


@dataclass(frozen=True)
class ScanOutcome:
    """One scanner run. ``ok`` means exit 0 *and* a parseable verdict."""

    ok: bool
    exit_code: int
    verdict: dict[str, Any] | None = None
    stderr: str = field(default="", repr=False)
    error: str = ""

    @property
    def bucket(self) -> str | None:
        return (self.verdict or {}).get("bucket")

    @property
    def final_level(self) -> int | None:
        return (self.verdict or {}).get("final_level")

    @property
    def sender(self) -> str | None:
        return (self.verdict or {}).get("sender")


@runtime_checkable
class ScannerRunner(Protocol):
    """Scan one message. Never raises for a scanner-side failure."""

    def scan(self, raw: bytes) -> ScanOutcome: ...


def build_scanner_runner(config) -> ScannerRunner:
    """Pick the runner named by configuration.

    The code default is ``subprocess``: it needs no daemon, so a bare
    ``pip install -e .`` checkout and the whole test suite work untouched. The
    *deployed* dispatcher is switched to ``container`` by compose, which is
    where the isolation is actually wanted.
    """
    timeout = config.imap.scan_timeout_seconds
    if config.scanner_runner == CONTAINER:
        from .container_runner import ContainerRunner

        log.info("scanner runner: one hardened container per message")
        return ContainerRunner(config.container, timeout=timeout)

    from .scanner_client import SubprocessRunner

    log.info("scanner runner: subprocess -- no container isolation")
    return SubprocessRunner(timeout=timeout)
