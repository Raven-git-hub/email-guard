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
# The re-scan's failure status. Deliberately not QUARANTINED: quarantining
# writes the uid into the state file, and the re-scan writes nothing there.
FAILED = "failed"

# The scanner's bucket vocabulary, duplicated rather than imported -- the
# dispatcher imports nothing from ``email_guard`` (see the test that pins it),
# and this is only used to order a summary line. A bucket that is not in this
# tuple still gets counted; it is just reported after these three.
BUCKETS = ("cleared", "flagged", "rejected")

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


@dataclass
class RescanReport:
    """What the one-shot re-scan did.

    Reported per *bucket* rather than per status, because the point of a
    re-scan is the sort: an operator wants to know how the backlog broke down,
    and how many of it came back needing a human.
    """

    fetched: int = 0
    limit: int | None = None
    results: list[MessageResult] = field(default_factory=list)

    @property
    def processed(self) -> list[MessageResult]:
        return [r for r in self.results if r.status == PROCESSED]

    @property
    def failed(self) -> list[MessageResult]:
        return [r for r in self.results if r.status != PROCESSED]

    @property
    def bucket_counts(self) -> dict[str, int]:
        """Every bucket the pass produced, the three known ones always present."""
        counts = {name: 0 for name in BUCKETS}
        for result in self.processed:
            bucket = result.bucket or "unknown"
            counts[bucket] = counts.get(bucket, 0) + 1
        return counts

    @property
    def candidates(self) -> int:
        """How many messages the scanner staged for the review console."""
        return sum(
            1
            for result in self.processed
            if ((result.verdict or {}).get("written") or {}).get("candidate")
        )

    def summary(self) -> str:
        counts = self.bucket_counts
        ordered = list(BUCKETS) + sorted(set(counts) - set(BUCKETS))
        buckets = " ".join(f"{name}={counts[name]}" for name in ordered)
        line = (
            f"mailbox={self.fetched} scanned={len(self.processed)} "
            f"failed={len(self.failed)} {buckets} candidates={self.candidates}"
        )
        return f"{line} (limit={self.limit})" if self.limit is not None else line


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

    # -- the one-shot re-scan -------------------------------------------------

    def rescan(self, limit: int | None = None) -> RescanReport:
        """Run every message in the mailbox through the scanner, once.

        The onboarding pass. It differs from :meth:`drain_once` in exactly
        three ways, and each is deliberate:

        * **It asks for everything.** ``fetch_all`` is ``SEARCH ALL``, so
          ``\\Seen`` is irrelevant -- read mail, filed mail and mail that
          arrived before this tool existed are all in scope.
        * **It ignores the watermark.** The processed-state file is never
          consulted, so a uid the live loop finished with last week is scanned
          again regardless.
        * **It writes no state at all.** No ``state.add``, no
          ``state.quarantine``, no ``\\Seen`` flag set. The live loop's
          done-list means precisely what it meant before this ran, and a
          message that was unread stays unread.

        That last point is what makes the mode safe to offer, and also why it
        is a one-shot to run *while the dispatcher is stopped*: two processes
        scanning the same mailbox would each fire the other's webhooks and race
        on the scanner's output directories. Nothing enforces that -- it is an
        operational instruction, and it is in the README and in ``--help``.

        Re-filing is not a special case here: the scanner writes
        ``outbound/<bucket>/<job>/`` and stages the review candidate itself, on
        every run, keyed by message id. A re-scan therefore re-sorts and
        re-stages by doing nothing more than scanning again.

        Sequential on purpose, where the drain uses a pool: a full inbox at one
        hardened container per message is a long job, and an operator watching
        it wants a progress count that only goes up and webhook deliveries that
        arrive in mailbox order. The parallelism is worth more on the live
        path, where latency is the whole point.
        """
        messages = list(self.source.fetch_all())
        report = RescanReport(fetched=len(messages), limit=limit)
        if limit is not None:
            messages = messages[: max(0, limit)]

        total = len(messages)
        log.info("rescan: %s message(s) to scan of %s in the mailbox", total, report.fetched)
        for index, (uid, raw) in enumerate(messages, start=1):
            attempts, outcome = self._scan_with_retries(uid, raw)
            result = self._observe(uid, attempts, outcome)
            report.results.append(result)
            if result.status == PROCESSED:
                log.info(
                    "rescan %s/%s: uid=%s level=%s bucket=%s",
                    index,
                    total,
                    uid,
                    result.final_level,
                    result.bucket,
                )
            else:
                log.error(
                    "rescan %s/%s: uid=%s FAILED after %s attempts: %s",
                    index,
                    total,
                    uid,
                    attempts,
                    result.error,
                )
        return report

    def _observe(self, uid: str, attempts: int, outcome: ScanOutcome) -> MessageResult:
        """:meth:`_commit` without the commits: sinks fire, nothing persists.

        A failure here is recorded in the report and logged, and that is all.
        Writing it to the quarantine log would also add the uid to the state
        file -- see :meth:`ProcessedState.quarantine` -- and a re-scan that
        quietly marked live mail as done would be the one way this mode could
        cost a message.
        """
        if not outcome.ok:
            return MessageResult(
                uid=uid, status=FAILED, attempts=attempts, error=outcome.error
            )
        verdict = outcome.verdict or {}
        self._deliver(verdict, uid)
        return MessageResult(uid=uid, status=PROCESSED, attempts=attempts, verdict=verdict)

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
        connected = False

        while not stop.is_set():
            # Connecting is part of the loop, not a prelude to it. The first
            # connect is exactly as likely to fail as any later one -- under
            # compose the dispatcher starts alongside the bridge and will beat
            # it to readiness, so a first attempt that raises ConnectionRefused
            # or an EOF abort is ordinary startup, not a fatal condition. It
            # used to escape this method and kill the process, leaving the
            # container runtime's `restart: unless-stopped` to retry at its own
            # coarse cadence.
            if not connected:
                try:
                    self._connect()
                except Exception as exc:  # noqa: BLE001 - the loop must not die
                    log.warning("could not connect (%s); retrying in %.0fs", exc, backoff)
                    if stop.wait(backoff):
                        break
                    backoff = min(backoff * 2, MAX_RECONNECT_BACKOFF)
                    continue
                connected = True
                backoff = self.reconnect_backoff_seconds

            try:
                report = self.drain_once()
            except Exception as exc:  # noqa: BLE001 - the loop must not die
                # One recovery path for both failure modes: drop the connection
                # and let the top of the loop rebuild it under the same backoff.
                log.warning("drain failed (%s); reconnecting in %.0fs", exc, backoff)
                connected = False
                if stop.wait(backoff):
                    break
                backoff = min(backoff * 2, MAX_RECONNECT_BACKOFF)
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
        """Open the source, if it is the kind that needs opening.

        Raises on failure by design -- :meth:`run_forever` owns the retry, and
        that is the only place that should. ``ImapMailSource.connect`` closes
        any existing connection first, so this doubles as the reconnect.
        """
        connect = getattr(self.source, "connect", None)
        if callable(connect):
            connect()


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
            lines.append(
                f"  uid={result.uid} {result.status.upper()} "
                f"after {result.attempts} attempts: {result.error}"
            )
    return "\n".join(lines)
