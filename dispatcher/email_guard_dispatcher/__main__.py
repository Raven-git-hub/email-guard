"""Command line entry point.

    python -m email_guard_dispatcher            # poll until stopped
    python -m email_guard_dispatcher --once     # drain what is unread, exit
    python -m email_guard_dispatcher --verbose  # one line per message

``--once`` is the first-live-run and cron mode: it drains the messages that are
UNSEEN right now and exits with 0 if every one of them scanned, 1 if any had to
be quarantined.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from . import __version__, config
from .mailsource import ImapMailSource
from .runner import Runner, describe
from .scanner_client import ScannerClient
from .sinks import build_sinks
from .state import ProcessedState, StateError

EXIT_OK = 0
EXIT_ERROR = 1

log = logging.getLogger("email_guard_dispatcher")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email_guard_dispatcher",
        description="Pull new mail from the Proton bridge and scan each message.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="drain the currently-unread messages once and exit",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="log each message's uid, sender, final level and bucket",
    )
    parser.add_argument("--config", metavar="PATH", help="path to config.json")
    parser.add_argument("--mailbox", metavar="NAME", help="mailbox to watch (default INBOX)")
    parser.add_argument(
        "--version", action="version", version=f"email-guard-dispatcher {__version__}"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.verbose)

    try:
        settings = config.load(config_path=args.config, mailbox=args.mailbox)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        state = ProcessedState(settings.state_file, settings.quarantine_log)
    except StateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    source = ImapMailSource(settings.imap)
    runner = Runner(
        source=source,
        scanner=ScannerClient(timeout=settings.imap.scan_timeout_seconds),
        state=state,
        sinks=build_sinks(settings.webhook_url),
        max_attempts=settings.imap.max_attempts,
        concurrency=settings.imap.concurrency,
        poll_interval_seconds=settings.imap.poll_interval_seconds,
    )

    try:
        if args.once:
            return _drain_once(runner, source, verbose=args.verbose)
        _run_forever(runner)
    except config.ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        source.close()
    return EXIT_OK


def _drain_once(runner: Runner, source, verbose: bool) -> int:
    source.connect()
    report = runner.drain_once()
    print(f"drain: {report.summary()}")
    if verbose and report.results:
        print(describe(report.results))
    return EXIT_ERROR if report.quarantined else EXIT_OK


def _run_forever(runner: Runner) -> None:
    stop = threading.Event()

    def _handle(signum, _frame):
        log.info("signal %s received, finishing the current pass", signum)
        stop.set()

    # A daemon under systemd or docker gets SIGTERM; a human gets SIGINT. Both
    # ask the loop to stop between passes rather than mid-scan.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _handle)

    runner.run_forever(stop)


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )


if __name__ == "__main__":
    sys.exit(main())
