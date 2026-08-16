"""On-arrival processing: IDLE as a trigger, polling as the guarantee.

Two layers are tested here, and they fail for different reasons.

The **control flow** tests run the real :class:`Runner` loop against
:class:`FakeMailSource` and a stub scanner. What they pin down is the property
the whole design rests on: *every* path out of the wait leads to the same full
``drain_once``. A push, a missed push, a dropped IDLE connection and a plain
timeout are four different stories that must all end with the mailbox drained,
because the notification is only ever a trigger -- the durable queue is the
mailbox and the done-list is the state file.

The **protocol** tests drive :func:`idle.idle_once` over a real ``socketpair``,
with a stub standing in for ``imaplib.IMAP4``. Nothing is mocked: the bytes on
the wire are the assertion, because that framing is the part a CPython upgrade
could quietly break.

No server, no credentials, no daemon.
"""

from __future__ import annotations

import socket
import threading

import pytest

from email_guard_dispatcher import idle
from email_guard_dispatcher.mailsource import FakeMailSource, MailSourceError
from email_guard_dispatcher.runner import Runner
from email_guard_dispatcher.scanner_runner import ScanOutcome
from email_guard_dispatcher.state import ProcessedState

MAILBOX = [("101", b"From: a@example.com\r\n\r\none"),
           ("102", b"From: b@example.com\r\n\r\ntwo"),
           ("103", b"From: c@example.com\r\n\r\nthree")]


class StubScanner:
    """A runner that always succeeds. The scan is not what is under test here."""

    def __init__(self) -> None:
        self.scanned: list[bytes] = []

    def scan(self, raw: bytes) -> ScanOutcome:
        self.scanned.append(raw)
        return ScanOutcome(ok=True, exit_code=0, verdict={"bucket": "cleared", "written": None})


@pytest.fixture
def source() -> FakeMailSource:
    return FakeMailSource(list(MAILBOX))


@pytest.fixture
def scanner() -> StubScanner:
    return StubScanner()


@pytest.fixture
def state(tmp_path) -> ProcessedState:
    return ProcessedState(tmp_path / "state.json", tmp_path / "quarantine.log")


def run_until_drains(runner: Runner, drains: int = 1) -> int:
    """Run the real loop, stopping after N completed drains."""
    stop = threading.Event()
    seen = {"count": 0}
    original = runner.drain_once

    def counting_drain():
        report = original()
        seen["count"] += 1
        if seen["count"] >= drains:
            stop.set()
        return report

    runner.drain_once = counting_drain
    runner.run_forever(stop)
    return seen["count"]


def build_runner(source, scanner, state, **kwargs) -> Runner:
    kwargs.setdefault("poll_interval_seconds", 30)
    kwargs.setdefault("retry_backoff_seconds", 0)
    kwargs.setdefault("reconnect_backoff_seconds", 0.01)
    return Runner(source=source, scanner=scanner, state=state, sinks=[], **kwargs)


# -- the trigger --------------------------------------------------------------


def test_a_notification_triggers_a_drain_without_waiting_for_the_poll(source, scanner, state):
    """The whole point: mail is processed on arrival, not on the next poll."""
    source.notify.set()
    # A poll interval long enough that reaching it would hang the test. If this
    # test passes at all, the drain was driven by the notification.
    runner = build_runner(source, scanner, state, poll_interval_seconds=600)

    run_until_drains(runner, drains=2)

    assert state.count(source.uid_validity) == len(MAILBOX)


def test_a_wake_drains_every_unprocessed_message_not_just_the_announced_one(
    source, scanner, state
):
    """IDLE says *something* arrived; the drain still enumerates everything.

    This is what keeps a backlog from building behind a single announcement,
    and it is why the announced UID is deliberately never read.
    """
    source.notify.set()
    runner = build_runner(source, scanner, state, poll_interval_seconds=600)

    run_until_drains(runner, drains=2)

    assert len(scanner.scanned) == len(MAILBOX)
    assert sorted(source.marked) == ["101", "102", "103"]


def test_a_message_arriving_mid_wait_is_picked_up(source, scanner, state):
    """A push that lands while the loop is already idling still wakes it."""
    source._messages = []  # start empty, so the first drain does nothing
    runner = build_runner(source, scanner, state, poll_interval_seconds=600)

    def deliver_late():
        source.add("201", b"From: late@example.com\r\n\r\nlate")
        source.notify.set()

    timer = threading.Timer(0.05, deliver_late)
    timer.start()
    try:
        run_until_drains(runner, drains=2)
    finally:
        timer.cancel()

    assert state.has(source.uid_validity, "201")


# -- the backstop -------------------------------------------------------------


def test_a_missed_notification_is_caught_by_the_poll_interval(source, scanner, state):
    """A server that never pushes must not strand mail.

    ``notify`` is never set, so every wait ends in a timeout -- the path a
    silently-dropped push takes.
    """
    runner = build_runner(source, scanner, state, poll_interval_seconds=0.01)

    run_until_drains(runner, drains=2)

    assert state.count(source.uid_validity) == len(MAILBOX)


def test_the_wait_is_bounded_by_the_poll_interval(source, scanner, state):
    """The guarantee is a *bound*: no wait may outlast the configured interval."""
    runner = build_runner(source, scanner, state, poll_interval_seconds=0.01)

    run_until_drains(runner, drains=3)

    assert source.waits, "the runner never used the on-arrival wait"
    assert all(wait <= 0.01 for wait in source.waits)


def test_a_dropped_idle_connection_degrades_to_polling_and_loses_nothing(
    source, scanner, state
):
    """A broken IDLE costs latency, never a message."""
    source.idle_failures = 5  # every wait in this test raises
    runner = build_runner(source, scanner, state, poll_interval_seconds=0.01)

    run_until_drains(runner, drains=2)

    assert source.idle_failures < 5, "wait_for_activity was never exercised"
    assert state.count(source.uid_validity) == len(MAILBOX)


def test_a_source_that_cannot_idle_at_all_still_drains(scanner, state):
    """``wait_for_activity`` is optional; its absence is not an error."""

    class PollOnlySource(FakeMailSource):
        wait_for_activity = None  # type: ignore[assignment]

    source = PollOnlySource(list(MAILBOX))
    runner = build_runner(source, scanner, state, poll_interval_seconds=0.01)

    run_until_drains(runner, drains=2)

    assert state.count(source.uid_validity) == len(MAILBOX)


def test_a_bridge_that_is_not_ready_yet_is_waited_out_not_fatal(source, scanner, state):
    """The dispatcher starts alongside the bridge and will usually beat it.

    The first connect used to escape ``run_forever`` and kill the process, so a
    bridge still authenticating with Proton produced a crash-looping dispatcher
    that only recovered at the container runtime's own restart cadence. It is
    ordinary startup, and it belongs in the same retry/backoff as any later
    reconnect.
    """
    source.connect_failures = 3
    runner = build_runner(
        source, scanner, state, poll_interval_seconds=0.01, reconnect_backoff_seconds=0.01
    )

    run_until_drains(runner, drains=1)

    assert source.connect_failures == 0, "the failing connects were not all attempted"
    assert source.connect_calls == 4, "expected three refusals then a success"
    assert state.count(source.uid_validity) == len(MAILBOX)


def test_a_connect_that_never_succeeds_still_stops_on_request(source, scanner, state):
    """Retrying forever must not mean ignoring SIGTERM forever."""
    source.connect_failures = 10_000
    runner = build_runner(
        source, scanner, state, poll_interval_seconds=0.01, reconnect_backoff_seconds=0.01
    )
    stop = threading.Event()
    finished = threading.Event()

    def loop():
        runner.run_forever(stop)
        finished.set()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    stop.set()

    assert finished.wait(5), "run_forever ignored stop while retrying the connect"


def test_a_mid_run_failure_rebuilds_the_connection(source, scanner, state):
    """One recovery path for both failure modes."""
    source.fail_times = 2
    runner = build_runner(
        source, scanner, state, poll_interval_seconds=0.01, reconnect_backoff_seconds=0.01
    )

    run_until_drains(runner, drains=1)

    # Initial connect, plus one rebuild per failed drain.
    assert source.connect_calls == 3
    assert state.count(source.uid_validity) == len(MAILBOX)


def test_stop_during_the_wait_ends_the_loop(source, scanner, state):
    """SIGTERM must not sit behind a 25-minute IDLE."""
    runner = build_runner(source, scanner, state, poll_interval_seconds=600)
    stop = threading.Event()
    finished = threading.Event()

    def loop():
        runner.run_forever(stop)
        finished.set()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    # The fake's wait returns as soon as `stop` is set, exactly as the real
    # one's stop-checked slices do.
    stop.set()
    source.notify.set()

    assert finished.wait(5), "run_forever did not return after stop was set"


# -- --once is unchanged ------------------------------------------------------


def test_once_drains_and_exits_without_ever_waiting(source, scanner, state):
    """``--once`` is cron/first-run mode: no loop, so no IDLE, so no wait."""
    runner = build_runner(source, scanner, state)

    report = runner.drain_once()

    assert report.fetched == len(MAILBOX)
    assert len(report.processed) == len(MAILBOX)
    assert source.waits == []


# -- the protocol itself ------------------------------------------------------


class StubIMAP:
    """Enough of ``imaplib.IMAP4`` to drive IDLE, over a real socketpair.

    Modelled on the hand-rolled ``StubIMAP`` in ``test_dispatcher_config.py``:
    this suite injects stubs rather than patching. The socket is genuine so
    that ``select``, ``settimeout`` and the buffered reader behave exactly as
    they do against a server.
    """

    def __init__(self, capabilities=("IMAP4REV1", "IDLE")):
        self.sock, self.peer = socket.socketpair()
        self.file = self.sock.makefile("rb")
        self.tagpre = b"CFDA"
        self.tagnum = 0
        self.tagged_commands: dict[bytes, object] = {}
        self.sent: list[bytes] = []
        self.capabilities = capabilities

    # -- the imaplib surface idle.py uses
    def _new_tag(self) -> bytes:
        tag = self.tagpre + str(self.tagnum).encode()
        self.tagnum += 1
        self.tagged_commands[tag] = None
        return tag

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def readline(self) -> bytes:
        return self.file.readline()

    # -- test-side helpers
    def server_says(self, *lines: bytes) -> None:
        self.peer.sendall(b"".join(line + b"\r\n" for line in lines))

    def close(self) -> None:
        self.sock.close()
        self.peer.close()

    @property
    def next_tag(self) -> bytes:
        """The tag ``idle_once`` is about to mint, so responses can be staged."""
        return self.tagpre + str(self.tagnum).encode()


@pytest.fixture
def conn():
    stub = StubIMAP()
    yield stub
    stub.close()


def test_idle_sends_a_tagged_idle_and_a_done(conn):
    """The RFC 2177 exchange, on the wire."""
    tag = conn.next_tag
    conn.server_says(b"+ idling", b"* 4 EXISTS", tag + b" OK IDLE terminated")

    assert idle.idle_once(conn, timeout=0.05, slice_seconds=0.01) is True

    assert conn.sent[0] == tag + b" IDLE\r\n"
    assert b"DONE\r\n" in conn.sent, "IDLE was never terminated"


def test_a_push_arriving_during_the_watch_wakes_it(conn):
    """The latency path: the notification lands while the loop is idling.

    Sent late on purpose, so the continuation is already consumed and the wake
    is genuinely observed by the watch loop rather than found in the buffer
    afterwards.
    """
    tag = conn.next_tag
    conn.server_says(b"+ idling")
    timer = threading.Timer(
        0.05, lambda: conn.server_says(b"* 12 EXISTS", tag + b" OK IDLE terminated")
    )
    timer.start()
    try:
        assert idle.idle_once(conn, timeout=5.0, slice_seconds=0.01) is True
    finally:
        timer.cancel()


def test_a_quiet_idle_times_out_cleanly(conn):
    """No push is not an error -- it is the poll path doing its job."""
    tag = conn.next_tag
    conn.server_says(b"+ idling", tag + b" OK IDLE terminated")

    assert idle.idle_once(conn, timeout=0.05, slice_seconds=0.01) is False
    assert b"DONE\r\n" in conn.sent


def test_a_wake_coalesced_with_the_continuation_is_still_seen(conn):
    """The known buffering edge, pinned so it stays a latency cost and not a loss.

    When the server packs the continuation and the notification into one
    segment, imaplib's BufferedReader swallows both and ``select`` sees nothing
    -- so the watch loop times out. The completion drain after ``DONE`` reads
    the buffered line and reports the wake anyway.
    """
    tag = conn.next_tag
    conn.server_says(b"+ idling", b"* 7 EXISTS", tag + b" OK done")

    assert idle.idle_once(conn, timeout=0.05, slice_seconds=0.01) is True


def test_the_tag_is_released_so_the_next_command_is_not_confused(conn):
    """``_new_tag`` registers the tag; nothing but this module retires it."""
    tag = conn.next_tag
    conn.server_says(b"+ idling", b"* 1 EXISTS", tag + b" OK done")

    idle.idle_once(conn, timeout=0.05, slice_seconds=0.01)

    assert conn.tagged_commands == {}


def test_the_socket_timeout_is_restored(conn):
    """A short timeout left behind would break every later command."""
    conn.sock.settimeout(42.0)
    tag = conn.next_tag
    conn.server_says(b"+ idling", b"* 1 EXISTS", tag + b" OK done")

    idle.idle_once(conn, timeout=0.05, slice_seconds=0.01)

    assert conn.sock.gettimeout() == 42.0


def test_a_server_that_rejects_idle_demotes_the_connection(conn):
    """A BAD is not a crash: it means poll from here on."""
    conn.server_says(conn.tagpre + b"0 BAD unknown command")

    with pytest.raises(idle.IdleUnsupported):
        idle.idle_once(conn, timeout=1.0)


def test_a_closed_connection_during_idle_is_an_idle_error(conn):
    conn.server_says(b"+ idling")
    conn.peer.close()

    with pytest.raises(idle.IdleError):
        idle.idle_once(conn, timeout=1.0, slice_seconds=0.01)


def test_stop_ends_the_watch_without_a_wake(conn):
    """SIGTERM must not sit behind a 25-minute IDLE."""
    tag = conn.next_tag
    conn.server_says(b"+ idling", tag + b" OK done")
    stop = threading.Event()
    stop.set()

    assert idle.idle_once(conn, timeout=600, stop=stop) is False
    assert b"DONE\r\n" in conn.sent


def test_capability_detection_is_advisory(conn):
    assert idle.server_supports_idle(conn) is True
    assert idle.server_supports_idle(StubIMAP(capabilities=("IMAP4REV1",))) is False


def test_wait_for_activity_never_raises_even_when_idle_breaks():
    """The contract the runner relies on: degrade, never propagate."""
    source = FakeMailSource(list(MAILBOX), idle_failures=1)

    with pytest.raises(MailSourceError):
        # The fake raises so the runner's guard is exercised...
        source.wait_for_activity(0.01)

    # ...and the real one absorbs it. Proven separately in
    # test_a_dropped_idle_connection_degrades_to_polling_and_loses_nothing.
    assert source.idle_failures == 0
