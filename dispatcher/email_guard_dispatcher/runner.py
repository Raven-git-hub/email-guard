"""The loop: fetch, scan, commit, repeat.

Threading model, which is the whole design of this module:

* **Scans run in parallel.** A scan is a subprocess doing real work, so up to
  ``concurrency`` of them run at once in a thread pool. Each worker touches
  nothing but its own message bytes and its own subprocess.
* **Everything else runs on the calling thread.** The workers *return* their
  outcomes; the main thread then records state, sets ``\\Seen`` and fires sinks,
  one message at a time.

That split is not stylistic. ``imaplib.IMAP4`` has no locking around its tagged
command exchange, so two threads issuing ``UID STORE`` on the same connection
interleave and corrupt the session. And ``ProcessedState.add`` is a
read-modify-write of a single JSON file, so concurrent adds lose each other's
updates -- the atomic rename keeps the file well-formed, but the last writer
still wins. Committing on one thread makes both problems impossible rather than
unlikely, and costs nothing: the slow part was always the scanning.

Delivery is at-least-once. Sinks fire *before* the message is recorded as
processed, so a crash in between replays the message rather than losing the
notification. Rescanning is safe -- the scanner is deterministic and rewrites
its own output files identically -- and for a security tool a duplicate alert
beats a missing one.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from .mailsource import MailSource
from .scanner_runner import ScannerRunner, ScanOutcome
from .sinks import Sink
from .state import ProcessedState

log = logging.getLogger(__name__)

PROCESSED = "processed"
QUARANTINED = "quarantined"

INITIAL_RECONNECT_BACKOFF = 2.0
MAX_RECONNECT_BACKOFF = 300.0


@dataclass(frozen=True)
class MessageResult:
    uid: str
    status: str
    attempts: int
    verdict: dict[str, Any] | None = None
    error: str = ""

    @property
    def sender(self) -> str | None:
        return (self.verdict or {}).get("sender")

    @property
    def bucket(self) -> str | None:
        return (self.verdict or {}).get("bucket")

    @property
    def final_level(self) -> int | None:
        return (self.verdict or {}).get("final_level")


@dataclass
class DrainReport:
    """What one pass over the mailbox did."""

    fetched: int = 0
    skipped: int = 0
    results: list[MessageResult] = field(default_factory=list)

    @property
    def processed(self) -> list[MessageResult]:
        return [r for r in self.results if r.status == PROCESSED]

    @property
    def quarantined(self) -> list[MessageResult]:
        return [r for r in self.results if r.status == QUARANTINED]

    def summary(self) -> str:
        return (
            f"fetched={self.fetched} scanned={len(self.processed)} "
            f"quarantined={len(self.quarantined)} already-done={self.skipped}"
        )


class Runner:
    def __init__(
        self,
        source: MailSource,
        scanner: ScannerRunner,
        state: ProcessedState,
        sinks: Sequence[Sink],
        *,
        max_attempts: int = 3,
        concurrency: int = 4,
        poll_interval_seconds: float = 30.0,
        retry_backoff_seconds: float = 1.0,
        reconnect_backoff_seconds: float = INITIAL_RECONNECT_BACKOFF,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.source = source
        self.scanner = scanner
        self.state = state
        self.sinks = list(sinks)
        self.max_attempts = max(1, max_attempts)
        self.concurrency = max(1, concurrency)
        self.poll_interval_seconds = poll_interval_seconds
        self.retry_backoff_seconds = retry_backoff_seconds
        self.reconnect_backoff_seconds = reconnect_backoff_seconds
        self._sleep = sleep

    # -- one pass -------------------------------------------------------------

    def drain_once(self) -> DrainReport:
        """Scan everything currently waiting, then return what happened."""
        messages = list(self.source.fetch_new())
        uid_validity = self.source.uid_validity
        report = DrainReport(fetched=len(messages))

        pending: list[tuple[str, bytes]] = []
        for uid, raw in messages:
            if self.state.has(uid_validity, uid):
                # Already done in an earlier run: the state file is the
                # authority, not the \Seen flag, so re-serving it is expected
                # and simply skipped here.
                report.skipped += 1
                self._mark_seen(uid)
                continue
            pending.append((uid, raw))

        if not pending:
            return report

        scanned = self._scan_all(pending)
        for uid, _raw in pending:
            attempts, outcome = scanned[uid]
            report.results.append(self._commit(uid_validity, uid, attempts, outcome))
        return report

    def _scan_all(
        self, pending: Sequence[tuple[str, bytes]]
    ) -> dict[str, tuple[int, ScanOutcome]]:
        """Run the scans concurrently. Workers share nothing but the pool."""
        if len(pending) == 1 or self.concurrency == 1:
            return {uid: self._scan_with_retries(uid, raw) for uid, raw in pending}

        workers = min(self.concurrency, len(pending))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan") as pool:
            futures = {
                pool.submit(self._scan_with_retries, uid, raw): uid for uid, raw in pending
            }
            return {futures[future]: future.result() for future in futures}

    def _scan_with_retries(self, uid: str, raw: bytes) -> tuple[int, ScanOutcome]:
        """Scan one message, retrying transient failures. Pure: no shared state.

        Retries happen here, inside the drain, so ``--once`` is deterministic.
        A process that dies mid-retry simply leaves the uid unrecorded and
        unflagged, and the next run picks it up again from scratch.
        """
        outcome = ScanOutcome(ok=False, exit_code=-1, error="not attempted")
        for attempt in range(1, self.max_attempts + 1):
            outcome = self.scanner.scan(raw)
            if outcome.ok:
                return attempt, outcome
            log.warning(
                "scan attempt %s/%s failed for uid=%s: %s",
                attempt,
                self.max_attempts,
                uid,
                outcome.error or f"exit {outcome.exit_code}",
            )
            if attempt < self.max_attempts and self.retry_backoff_seconds:
                self._sleep(self.retry_backoff_seconds * attempt)
        return self.max_attempts, outcome

    def _commit(
        self, uid_validity: str, uid: str, attempts: int, outcome: ScanOutcome
    ) -> MessageResult:
        """Main thread only: sinks, then state, then the IMAP flag."""
        if not outcome.ok:
            # Out of attempts. Record why, mark it done anyway -- one bad
            # message must not wedge the queue behind it forever.
            self.state.quarantine(
                uid_validity,
                uid,
                attempts=attempts,
                exit_code=outcome.exit_code,
                error=outcome.error,
                stderr=outcome.stderr,
            )
            self._mark_seen(uid)
            return MessageResult(
                uid=uid, status=QUARANTINED, attempts=attempts, error=outcome.error
            )

        verdict = outcome.verdict or {}
        self._deliver(verdict, uid)
        self.state.add(uid_validity, uid)
        self._mark_seen(uid)
        return MessageResult(uid=uid, status=PROCESSED, attempts=attempts, verdict=verdict)

    def _deliver(self, verdict: dict[str, Any], uid: str) -> None:
        for sink in self.sinks:
            try:
                sink.deliver(verdict, uid)
            except Exception:  # noqa: BLE001 - a sink must never fail a message
                log.exception("sink %s raised for uid=%s", type(sink).__name__, uid)

    def _mark_seen(self, uid: str) -> None:
        try:
            self.source.mark_processed(uid)
        except Exception as exc:  # noqa: BLE001 - state already records it
            log.warning("could not flag uid=%s as seen: %s", uid, exc)

    # -- the long-running loop ------------------------------------------------

    def run_forever(self, stop: threading.Event | None = None) -> None:
        """Drain on arrival, and on a timer regardless. Survives anything transient.

        The loop body is unconditionally :meth:`drain_once` -- a full
        enumeration of the mailbox. What changes between iterations is only how
        long the wait before the next one was, and why it ended:

        * a **push** (IMAP IDLE) ends it early, which is what makes processing
          near-instant rather than up to ``poll_interval_seconds`` late;
        * a **timeout** ends it otherwise, and that is the correctness
          guarantee -- a full drain happens at least every
          ``poll_interval_seconds`` whatever the server does or does not
          announce, so a missed push or a silently-dropped IDLE connection
          costs latency and cannot strand a message.

        Nothing here ever acts on *which* message was announced. The notifi-
        cation is a trigger; the mailbox is still the queue and the state file
        is still the done-list.
        """
        stop = stop or threading.Event()
        backoff = self.reconnect_backoff_seconds
        self._connect()

        while not stop.is_set():
            try:
                report = self.drain_once()
            except Exception as exc:  # noqa: BLE001 - the loop must not die
                log.warning("drain failed (%s); reconnecting in %.0fs", exc, backoff)
                if stop.wait(backoff):
                    break
                backoff = min(backoff * 2, MAX_RECONNECT_BACKOFF)
                self._reconnect()
                continue

            backoff = self.reconnect_backoff_seconds
            if report.fetched:
                log.info("drain: %s", report.summary())
            self._wait_for_work(stop, self.poll_interval_seconds)

    def _wait_for_work(self, stop: threading.Event, timeout: float) -> None:
        """Wait for a push, or for the poll deadline -- whichever comes first.

        Duck-typed like :meth:`_connect`: a source that cannot push simply does
        not have ``wait_for_activity``, and the plain sleep is used instead.
        The source is contracted not to raise, but the guard stays anyway --
        this is the one call between drains, and an exception escaping it would
        be indistinguishable from a drain failure and would trigger a pointless
        reconnect.
        """
        waiter = getattr(self.source, "wait_for_activity", None)
        if callable(waiter):
            try:
                waiter(timeout, stop)
                return
            except Exception as exc:  # noqa: BLE001 - degrade to the poll schedule
                log.warning("wait_for_activity failed (%s); sleeping instead", exc)
        stop.wait(timeout)

    def _connect(self) -> None:
        connect = getattr(self.source, "connect", None)
        if callable(connect):
            connect()

    def _reconnect(self) -> None:
        reconnect = getattr(self.source, "reconnect", None)
        if not callable(reconnect):
            return
        try:
            reconnect()
        except Exception as exc:  # noqa: BLE001 - next iteration backs off again
            log.warning("reconnect failed: %s", exc)


def describe(results: Iterable[MessageResult]) -> str:
    """One line per message, for ``--verbose`` and the ``--once`` summary."""
    lines = []
    for result in results:
        if result.status == PROCESSED:
            lines.append(
                f"  uid={result.uid} sender={result.sender} "
                f"level={result.final_level} bucket={result.bucket}"
            )
        else:
            lines.append(f"  uid={result.uid} QUARANTINED after {result.attempts} attempts: {result.error}")
    return "\n".join(lines)
