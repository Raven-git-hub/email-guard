"""The dispatcher loop, end to end, offline.

Everything here runs against :class:`FakeMailSource` -- no server, no sockets,
no credentials -- but the scans are **real**: the runner spawns
``python -m email_guard`` exactly as it will in production, and the assertions
check the files the scanner actually wrote.

That is a deliberate departure from the rest of the suite, which calls
``email_guard.cli.main([...])`` in process. Here the subprocess boundary *is*
the thing under test: it is the entire dispatcher-to-scanner interface, so
stubbing it out would test nothing.

The scanner is steered to ``tmp_path`` purely through the ``EMAIL_GUARD_*``
environment it already documents -- the dispatcher passes no ``--outbound-dir``
of its own. That is what keeps it ignorant of the scanner's configuration, and
it is also what keeps the autouse ``repo_data_stays_empty`` guard happy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from email_guard_dispatcher.mailsource import FakeMailSource
from email_guard_dispatcher.runner import PROCESSED, Runner
from email_guard_dispatcher.scanner_client import ScanOutcome, ScannerClient
from email_guard_dispatcher.state import ProcessedState

from tests.conftest import EML_FIXTURES, LIST_FIXTURES, RULES_DIR

# (uid, fixture, expected bucket) -- the buckets are what the scanner actually
# produces against the SYNTHETIC lists, verified by running it.
MAILBOX = [
    ("101", "blacklisted.eml", "rejected"),
    ("102", "greylist_receipt.eml", "cleared"),
    ("103", "simple.eml", "flagged"),
]


def read_fixture(name: str) -> bytes:
    return (EML_FIXTURES / name).read_bytes()


@pytest.fixture
def outputs(tmp_path: Path) -> dict[str, Path]:
    return {
        "outbound": tmp_path / "outbound",
        "brief": tmp_path / "daily-brief",
        "state": tmp_path / "dispatcher" / "state.json",
        "quarantine": tmp_path / "dispatcher" / "quarantine.log",
    }


@pytest.fixture
def scanner(outputs) -> ScannerClient:
    """A real scanner subprocess, pointed at tmp dirs and synthetic lists."""
    return ScannerClient(
        extra_env={
            "EMAIL_GUARD_LISTS_DIR": str(LIST_FIXTURES),
            "EMAIL_GUARD_RULES_DIR": str(RULES_DIR),
            "EMAIL_GUARD_OUTBOUND_DIR": str(outputs["outbound"]),
            "EMAIL_GUARD_DAILY_BRIEF_DIR": str(outputs["brief"]),
        }
    )


@pytest.fixture
def source() -> FakeMailSource:
    return FakeMailSource([(uid, read_fixture(name)) for uid, name, _ in MAILBOX])


@pytest.fixture
def state(outputs) -> ProcessedState:
    return ProcessedState(outputs["state"], outputs["quarantine"])


class RecordingSink:
    """Captures what was delivered, so sink wiring is assertable."""

    def __init__(self) -> None:
        self.delivered: list[tuple[str, dict]] = []

    def deliver(self, verdict: dict, uid: str) -> None:
        self.delivered.append((uid, verdict))


def build_runner(source, scanner, state, sinks=None, **kwargs) -> Runner:
    kwargs.setdefault("retry_backoff_seconds", 0)
    return Runner(
        source=source,
        scanner=scanner,
        state=state,
        sinks=sinks if sinks is not None else [],
        **kwargs,
    )


# -- the happy path ----------------------------------------------------------


def test_drain_files_every_message_and_captures_its_verdict(
    source, scanner, state, outputs
):
    sink = RecordingSink()
    report = build_runner(source, scanner, state, [sink]).drain_once()

    assert report.fetched == len(MAILBOX)
    assert report.skipped == 0
    assert len(report.processed) == len(MAILBOX)
    assert report.quarantined == []

    by_uid = {result.uid: result for result in report.results}
    for uid, _name, expected_bucket in MAILBOX:
        result = by_uid[uid]
        assert result.status == PROCESSED
        assert result.attempts == 1
        assert result.bucket == expected_bucket

        # The message was really filed, in the bucket the verdict claims.
        written = result.verdict["written"]
        message_path = Path(written["message"])
        assert message_path.is_file()
        assert message_path.parent.parent == outputs["outbound"] / expected_bucket
        assert message_path.read_bytes() == read_fixture(
            dict((u, n) for u, n, _ in MAILBOX)[uid]
        )
        # ...and its report sits beside it.
        report_path = Path(written["report"])
        assert json.loads(report_path.read_text(encoding="utf-8"))["bucket"] == expected_bucket

    # Every uid was marked processed, in state and on the mailbox.
    for uid, _name, _bucket in MAILBOX:
        assert state.has(source.uid_validity, uid)
        assert uid in source.seen

    assert [uid for uid, _ in sink.delivered] == [uid for uid, _, _ in MAILBOX]


def test_imap_and_state_are_only_ever_touched_from_the_calling_thread(
    source, scanner, state
):
    """The reason the pool returns outcomes instead of committing them.

    ``imaplib`` has no locking around its tagged command exchange, and
    ``ProcessedState.add`` is a read-modify-write of one file. Both are safe
    only because every call happens on one thread while the pool does nothing
    but run scanner subprocesses.
    """
    import threading

    main_thread = threading.current_thread().name
    callers: dict[str, set[str]] = {"mark": set(), "state": set(), "scan": set()}

    real_mark = source.mark_processed
    real_add = state.add
    real_scan = scanner.scan

    def watched_mark(uid):
        callers["mark"].add(threading.current_thread().name)
        return real_mark(uid)

    def watched_add(uid_validity, uid):
        callers["state"].add(threading.current_thread().name)
        return real_add(uid_validity, uid)

    def watched_scan(raw):
        callers["scan"].add(threading.current_thread().name)
        return real_scan(raw)

    source.mark_processed = watched_mark
    state.add = watched_add
    scanner.scan = watched_scan

    report = build_runner(source, scanner, state, concurrency=4).drain_once()
    assert len(report.processed) == len(MAILBOX)

    assert callers["mark"] == {main_thread}
    assert callers["state"] == {main_thread}
    # ...while the scans really did run off the main thread.
    assert callers["scan"] and main_thread not in callers["scan"]


def test_concurrency_does_not_change_the_outcome(source, scanner, state, outputs):
    """The pool parallelises scans only; commits stay ordered and complete."""
    report = build_runner(source, scanner, state, concurrency=4).drain_once()

    assert [r.uid for r in report.results] == [uid for uid, _, _ in MAILBOX]
    assert {r.bucket for r in report.results} == {b for _, _, b in MAILBOX}
    assert state.count(source.uid_validity) == len(MAILBOX)


# -- idempotency and restart -------------------------------------------------


def test_second_drain_processes_nothing(source, scanner, state):
    runner = build_runner(source, scanner, state)
    assert len(runner.drain_once().processed) == len(MAILBOX)

    again = runner.drain_once()
    assert again.fetched == 0  # FakeMailSource stops serving \Seen messages
    assert again.results == []


def test_state_survives_a_restart(source, scanner, state, outputs):
    build_runner(source, scanner, state).drain_once()

    # A new process: fresh state object over the same file, fresh runner, and a
    # mailbox that lost its \Seen flags (another client cleared them).
    source.seen.clear()
    restarted_state = ProcessedState(outputs["state"], outputs["quarantine"])
    assert restarted_state.count(source.uid_validity) == len(MAILBOX)

    report = build_runner(source, scanner, restarted_state).drain_once()
    assert report.fetched == len(MAILBOX)
    assert report.skipped == len(MAILBOX)  # recognised, not rescanned
    assert report.results == []
    # The flags were repaired on the way past.
    assert source.seen == {uid for uid, _, _ in MAILBOX}


def test_uid_validity_change_means_a_different_message(source, scanner, state):
    """UID 101 under a new UIDVALIDITY is not the UID 101 already processed."""
    build_runner(source, scanner, state).drain_once()
    assert state.has("1", "101")

    source.set_uid_validity("2")
    assert not state.has("2", "101")

    source.seen.clear()
    report = build_runner(source, scanner, state).drain_once()
    assert len(report.processed) == len(MAILBOX)


# -- poison messages ---------------------------------------------------------


class FailingScanner:
    """A scanner that always exits non-zero, and counts the attempts."""

    def __init__(self, exit_code: int = 1) -> None:
        self.calls = 0
        self._exit_code = exit_code

    def scan(self, raw: bytes) -> ScanOutcome:
        self.calls += 1
        return ScanOutcome(
            ok=False,
            exit_code=self._exit_code,
            stderr="error: cannot read message",
            error=f"scanner exited {self._exit_code}",
        )


class PoisonScanner:
    """Real scans, except for one message that always fails."""

    def __init__(self, real: ScannerClient, poison: bytes) -> None:
        self._real = real
        self._poison = poison
        self.poison_calls = 0

    def scan(self, raw: bytes) -> ScanOutcome:
        if raw == self._poison:
            self.poison_calls += 1
            return ScanOutcome(ok=False, exit_code=2, error="rules pack INVALID")
        return self._real.scan(raw)


def test_poison_message_is_retried_then_quarantined(state, source):
    failing = FailingScanner()
    runner = build_runner(source, failing, state, max_attempts=3)
    report = runner.drain_once()

    assert len(report.quarantined) == len(MAILBOX)
    assert report.processed == []
    assert failing.calls == 3 * len(MAILBOX)  # max_attempts each, no more

    records = state.read_quarantine()
    assert len(records) == len(MAILBOX)
    assert {record["uid"] for record in records} == {uid for uid, _, _ in MAILBOX}
    for record in records:
        assert record["attempts"] == 3
        assert record["exit_code"] == 1
        assert "cannot read message" in record["stderr"]
        assert record["timestamp"]


def test_quarantined_uid_is_recorded_in_state_so_a_restart_skips_it(
    state, source, outputs
):
    """\\Seen alone is not enough -- a cleared flag must not replay the poison."""
    failing = FailingScanner()
    build_runner(source, failing, state, max_attempts=2).drain_once()
    assert failing.calls == 2 * len(MAILBOX)

    for uid, _name, _bucket in MAILBOX:
        assert state.has(source.uid_validity, uid)

    source.seen.clear()
    restarted = ProcessedState(outputs["state"], outputs["quarantine"])
    second = FailingScanner()
    report = build_runner(source, second, restarted, max_attempts=2).drain_once()

    assert second.calls == 0  # never re-scanned
    assert report.skipped == len(MAILBOX)
    assert len(restarted.read_quarantine()) == len(MAILBOX)  # no duplicate records


def test_one_poison_message_does_not_block_the_others(source, scanner, state, outputs):
    poison = read_fixture("blacklisted.eml")
    runner = build_runner(
        source, PoisonScanner(scanner, poison), state, max_attempts=2, concurrency=4
    )
    report = runner.drain_once()

    assert [r.uid for r in report.quarantined] == ["101"]
    assert {r.uid for r in report.processed} == {"102", "103"}
    # The healthy two were still filed properly.
    for result in report.processed:
        assert Path(result.verdict["written"]["message"]).is_file()


def test_real_scanner_failure_is_seen_as_non_zero_exit(outputs, tmp_path):
    """The exit-code handling is checked against the actual CLI, not just a stub.

    A rules pack that does not exist makes the real scanner exit non-zero; the
    client must report that as a failure rather than a verdict.
    """
    client = ScannerClient(
        extra_env={
            "EMAIL_GUARD_LISTS_DIR": str(LIST_FIXTURES),
            "EMAIL_GUARD_RULES_DIR": str(tmp_path / "no-such-rules"),
            "EMAIL_GUARD_OUTBOUND_DIR": str(outputs["outbound"]),
            "EMAIL_GUARD_DAILY_BRIEF_DIR": str(outputs["brief"]),
        }
    )
    outcome = client.scan(read_fixture("simple.eml"))

    assert not outcome.ok
    assert outcome.exit_code != 0
    assert outcome.verdict is None


def test_scanner_client_removes_its_temp_file(scanner):
    """The staged .eml must not survive the scan."""
    import tempfile

    before = set(Path(tempfile.gettempdir()).glob("email-guard-*.eml"))
    outcome = scanner.scan(read_fixture("simple.eml"))
    after = set(Path(tempfile.gettempdir()).glob("email-guard-*.eml"))

    assert outcome.ok
    assert after == before


# -- resilience --------------------------------------------------------------


def test_transient_fetch_failure_does_not_kill_the_loop(source, scanner, state):
    """A dropped connection is caught, backed off and reconnected, not fatal."""
    import threading

    source.fail_times = 2
    runner = build_runner(
        source,
        scanner,
        state,
        poll_interval_seconds=0,
        reconnect_backoff_seconds=0.01,
    )
    stop = threading.Event()

    drains = {"count": 0}
    original = runner.drain_once

    def counting_drain():
        result = original()
        drains["count"] += 1
        if drains["count"] >= 1:
            stop.set()
        return result

    runner.drain_once = counting_drain
    runner.run_forever(stop)

    assert source.connect_calls >= 2  # initial connect + at least one reconnect
    assert state.count(source.uid_validity) == len(MAILBOX)
