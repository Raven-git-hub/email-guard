"""The one-shot re-scan / onboarding pass.

Same offline arrangement as ``test_dispatcher.py`` -- :class:`FakeMailSource`
in front, a **real** scanner subprocess behind -- because the thing worth
proving is that a re-scan reaches mail an ordinary drain cannot, and files it
the same way. A stubbed scanner would leave both halves of that unchecked.

What each test here is pinning, in one line each:

* the re-scan ignores ``\\Seen`` **and** the processed-state watermark, where a
  drain honours both;
* it leaves the live loop's state exactly as it found it, so the dispatcher can
  be started again afterwards with nothing to unpick;
* webhooks are opt-in, ``--limit`` bounds the pass, and the summary counts what
  actually happened.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from email_guard_dispatcher.__main__ import (
    build_parser,
    parse_args,
    webhook_url_for,
)
from email_guard_dispatcher.mailsource import FakeMailSource
from email_guard_dispatcher.runner import FAILED, PROCESSED, Runner
from email_guard_dispatcher.scanner_client import ScanOutcome, ScannerClient
from email_guard_dispatcher.state import ProcessedState

from tests.conftest import EML_FIXTURES, LIST_FIXTURES, RULES_DIR

# The same three fixtures the drain tests use, and the same buckets: one per
# bucket, which is what makes the summary line's counts meaningful.
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
    def __init__(self) -> None:
        self.delivered: list[tuple[str, dict]] = []

    def deliver(self, verdict: dict, uid: str) -> None:
        self.delivered.append((uid, verdict))


class CountingScanner:
    """Cheap stand-in for the tests that only care how many scans happened."""

    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def scan(self, raw: bytes) -> ScanOutcome:
        self.calls.append(raw)
        return ScanOutcome(
            ok=True,
            exit_code=0,
            verdict={"bucket": "cleared", "final_level": 5, "written": {}},
        )


def build_runner(source, scanner, state, sinks=None, **kwargs) -> Runner:
    kwargs.setdefault("retry_backoff_seconds", 0)
    return Runner(
        source=source,
        scanner=scanner,
        state=state,
        sinks=sinks if sinks is not None else [],
        **kwargs,
    )


# -- it reaches what a drain cannot ------------------------------------------


def test_rescan_processes_messages_a_drain_would_skip(source, scanner, state, outputs):
    """The whole point: \\Seen and the done-list are both irrelevant here.

    The mailbox is first drained normally, which leaves every message flagged
    and recorded. A second drain therefore has nothing to do -- and the re-scan
    that follows it scans all three regardless.
    """
    drained = build_runner(source, scanner, state).drain_once()
    assert len(drained.processed) == len(MAILBOX)

    # A drain now sees nothing: the fake stops serving \Seen messages, and the
    # state file would skip them even if it did.
    assert build_runner(source, scanner, state).drain_once().results == []

    report = build_runner(source, scanner, state).rescan()

    assert report.fetched == len(MAILBOX)
    assert len(report.processed) == len(MAILBOX)
    assert report.failed == []
    assert {r.uid for r in report.results} == {uid for uid, _, _ in MAILBOX}


def test_rescan_ignores_the_state_watermark_without_any_drain_first(
    source, scanner, state
):
    """State alone is enough to prove it -- no \\Seen flags involved.

    Every uid is pre-recorded as done. A drain would count all three as
    already-handled; the re-scan does not consult the file at all.
    """
    for uid, _name, _bucket in MAILBOX:
        state.add(source.uid_validity, uid)

    assert build_runner(source, scanner, state).drain_once().skipped == len(MAILBOX)

    report = build_runner(source, scanner, state).rescan()
    assert len(report.processed) == len(MAILBOX)


def test_rescan_refiles_every_report_into_its_bucket(source, scanner, state, outputs):
    """Re-filing and re-staging are the deliverable, not the counts."""
    report = build_runner(source, scanner, state).rescan()

    by_uid = {result.uid: result for result in report.results}
    for uid, name, expected_bucket in MAILBOX:
        result = by_uid[uid]
        assert result.status == PROCESSED
        assert result.bucket == expected_bucket

        written = result.verdict["written"]
        message_path = Path(written["message"])
        assert message_path.is_file()
        assert message_path.parent.parent == outputs["outbound"] / expected_bucket
        assert message_path.read_bytes() == read_fixture(name)

    # ...and the review candidates the scanner staged really exist on disk.
    staged = [
        Path(r.verdict["written"]["candidate"])
        for r in report.processed
        if r.verdict["written"].get("candidate")
    ]
    assert staged, "no candidate was staged -- the fixture set should produce one"
    assert all(path.is_file() for path in staged)
    assert report.candidates == len(staged)


# -- and disturbs nothing ----------------------------------------------------


def test_rescan_writes_no_dispatcher_state_and_marks_nothing_seen(
    source, scanner, state, outputs
):
    """A re-scan must leave the live loop's semantics exactly as it found them.

    If it recorded uids, the dispatcher would afterwards skip real, unread mail;
    if it set \\Seen, the mailbox would lie to every other client. Neither
    happens, which is what makes the mode safe to hand an operator.
    """
    build_runner(source, scanner, state).rescan()

    assert state.count() == 0
    assert not outputs["state"].exists()
    assert source.marked == []
    assert source.seen == set()

    # ...so a drain afterwards still has all three messages to do.
    report = build_runner(source, scanner, state).drain_once()
    assert len(report.processed) == len(MAILBOX)


def test_a_failing_scan_is_reported_but_never_quarantined(source, state):
    """Quarantining writes the uid into the state file. A re-scan writes nothing.

    The failure is visible in the report (and in the exit code the CLI derives
    from it), and the message is left in the mailbox for the live loop to
    handle properly.
    """

    class FailingScanner:
        def scan(self, raw: bytes) -> ScanOutcome:
            return ScanOutcome(ok=False, exit_code=3, error="scanner exited 3")

    report = build_runner(source, FailingScanner(), state, max_attempts=2).rescan()

    assert len(report.failed) == len(MAILBOX)
    assert all(r.status == FAILED for r in report.failed)
    assert report.processed == []
    assert state.count() == 0
    assert state.read_quarantine() == []
    assert source.seen == set()


# -- webhook emission is opt-in ----------------------------------------------


def test_no_sink_fires_when_webhooks_are_not_requested(source, state):
    """Built with no webhook sink, a re-scan delivers nowhere."""
    scanner = CountingScanner()
    report = build_runner(source, scanner, state, sinks=[]).rescan()

    assert len(report.processed) == len(MAILBOX)
    assert len(scanner.calls) == len(MAILBOX)  # it still scanned everything


def test_the_sink_fires_once_per_message_when_it_is_requested(source, state):
    sink = RecordingSink()
    report = build_runner(source, CountingScanner(), state, sinks=[sink]).rescan()

    assert len(report.processed) == len(MAILBOX)
    # In mailbox order: an onboarding replay should reach the downstream in the
    # order the messages arrived, which is why the pass is sequential.
    assert [uid for uid, _ in sink.delivered] == [uid for uid, _, _ in MAILBOX]


def test_emit_webhooks_gates_which_url_the_sinks_are_built_from():
    """The gate itself, where main() makes the decision."""

    class Settings:
        webhook_url = "https://example.invalid/hook"

    settings = Settings()

    assert webhook_url_for(parse_args(["--rescan"]), settings) is None
    assert (
        webhook_url_for(parse_args(["--rescan", "--emit-webhooks"]), settings)
        == settings.webhook_url
    )
    # Every other mode delivers as configured, with no flag needed.
    assert webhook_url_for(parse_args(["--once"]), settings) == settings.webhook_url
    assert webhook_url_for(parse_args([]), settings) == settings.webhook_url


def test_build_sinks_adds_a_webhook_only_when_it_has_a_url():
    """The other half of the gate: a None url builds the logging sink alone."""
    from email_guard_dispatcher.sinks import WebhookSink, build_sinks

    assert not any(isinstance(s, WebhookSink) for s in build_sinks(None))
    assert any(isinstance(s, WebhookSink) for s in build_sinks("https://x.invalid/h"))


# -- scale ---------------------------------------------------------------------


def test_limit_bounds_the_number_of_messages_scanned(source, state):
    scanner = CountingScanner()
    report = build_runner(source, scanner, state).rescan(limit=2)

    assert len(scanner.calls) == 2
    assert len(report.results) == 2
    assert [r.uid for r in report.results] == ["101", "102"]
    # The mailbox count stays honest about what was there to do.
    assert report.fetched == len(MAILBOX)
    assert report.limit == 2


def test_a_limit_larger_than_the_mailbox_is_harmless(source, state):
    scanner = CountingScanner()
    report = build_runner(source, scanner, state).rescan(limit=99)

    assert len(scanner.calls) == len(MAILBOX)
    assert len(report.results) == len(MAILBOX)


def test_the_summary_counts_each_bucket_and_the_staged_candidates(
    source, scanner, state
):
    """One fixture per bucket, so the line is checkable exactly."""
    report = build_runner(source, scanner, state).rescan()
    summary = report.summary()

    assert report.bucket_counts == {"cleared": 1, "flagged": 1, "rejected": 1}
    assert "mailbox=3" in summary
    assert "scanned=3" in summary
    assert "failed=0" in summary
    assert "cleared=1 flagged=1 rejected=1" in summary
    assert f"candidates={report.candidates}" in summary
    assert "limit" not in summary  # only reported when one was asked for


def test_the_summary_separates_failures_from_scans(source, state):
    """A failed message must not be counted into any bucket."""

    class HalfFailingScanner:
        def scan(self, raw: bytes) -> ScanOutcome:
            if raw == read_fixture("simple.eml"):
                return ScanOutcome(ok=False, exit_code=1, error="boom")
            return ScanOutcome(
                ok=True,
                exit_code=0,
                verdict={"bucket": "flagged", "final_level": 3, "written": {}},
            )

    report = build_runner(source, HalfFailingScanner(), state, max_attempts=1).rescan(
        limit=3
    )

    assert len(report.processed) == 2
    assert len(report.failed) == 1
    assert report.bucket_counts == {"cleared": 0, "flagged": 2, "rejected": 0}
    assert "scanned=2 failed=1" in report.summary()
    assert "(limit=3)" in report.summary()


# -- the CLI contract ----------------------------------------------------------


def test_rescan_and_once_are_mutually_exclusive():
    """argparse refuses the pair outright rather than silently preferring one."""
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["--once", "--rescan"])
    assert exit_info.value.code == 2

    # And through the wrapper main() actually uses.
    with pytest.raises(SystemExit):
        parse_args(["--rescan", "--once"])

    # Each on its own is fine, and neither is on by default.
    assert parse_args(["--rescan"]).rescan is True
    assert parse_args(["--once"]).once is True
    defaults = parse_args([])
    assert (defaults.rescan, defaults.once, defaults.emit_webhooks) == (
        False,
        False,
        False,
    )
    assert defaults.limit is None


@pytest.mark.parametrize(
    "argv",
    [
        ["--emit-webhooks"],
        ["--once", "--emit-webhooks"],
        ["--limit", "5"],
        ["--once", "--limit", "5"],
        ["--rescan", "--limit", "0"],
        ["--rescan", "--limit", "-1"],
    ],
)
def test_the_rescan_only_flags_are_refused_elsewhere(argv):
    """Ignoring them would read as a promise the other modes do not keep."""
    with pytest.raises(SystemExit) as exit_info:
        parse_args(argv)
    assert exit_info.value.code == 2
