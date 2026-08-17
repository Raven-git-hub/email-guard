"""Command line entry point.

    python -m email_guard_dispatcher            # poll until stopped
    python -m email_guard_dispatcher --once     # drain what is unread, exit
    python -m email_guard_dispatcher --rescan   # scan the WHOLE mailbox, exit
    python -m email_guard_dispatcher --verbose  # one line per message

``--once`` is the first-live-run and cron mode: it drains the messages that are
UNSEEN right now and exits with 0 if every one of them scanned, 1 if any had to
be quarantined.

``--rescan`` is the onboarding mode, and it is a **one-shot to run while the
live dispatcher is stopped**. It scans every message in the mailbox --
``SEARCH ALL``, so ``\\Seen`` and the processed-state watermark are both
irrelevant -- and re-files each report into its bucket and re-stages its review
candidate exactly as a drain does. It writes no state of its own: nothing is
added to the done-list, nothing is flagged ``\\Seen``, nothing is quarantined,
so the live loop resumes afterwards with the semantics it had before. Webhooks
stay silent unless ``--emit-webhooks`` asks for them, which is how a recognised,
tagged backlog gets injected into a downstream. ``--limit N`` trims the pass to
the first N messages for a trial run.

The three modes are mutually exclusive: ``--once`` drains, ``--rescan``
re-scans, and neither one enters the IDLE loop.
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
from .scanner_runner import build_scanner_runner
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
    # argparse enforces the exclusivity, so `--once --rescan` exits 2 with a
    # usage error rather than silently picking one. Neither flag enters the
    # IDLE loop, which is the third, default mode.
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--once",
        action="store_true",
        help="drain the currently-unread messages once and exit",
    )
    mode.add_argument(
        "--rescan",
        action="store_true",
        help=(
            "one-shot: scan EVERY message in the mailbox (ignoring \\Seen and the "
            "processed-state watermark), re-file the reports and re-stage review "
            "candidates, then exit. Writes no dispatcher state. Run it with the "
            "live dispatcher stopped."
        ),
    )
    parser.add_argument(
        "--emit-webhooks",
        action="store_true",
        help=(
            "--rescan only: also fire the configured webhook for each message, "
            "to inject the recognised backlog into a downstream. Off by default, "
            "so a plain --rescan re-sorts locally and notifies nothing."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="--rescan only: stop after N messages (a trial subset)",
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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and cross-check. Exits 2 with a usage message on a bad combination.

    ``--emit-webhooks`` and ``--limit`` are refused outside ``--rescan`` rather
    than ignored. Both would otherwise read as promises the other modes do not
    keep: a drain already fires the configured webhook, and it has no notion of
    a subset at all.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.emit_webhooks and not args.rescan:
        parser.error("--emit-webhooks only applies to --rescan (a drain always emits)")
    if args.limit is not None:
        if not args.rescan:
            parser.error("--limit only applies to --rescan")
        if args.limit < 1:
            parser.error(f"--limit must be at least 1, got {args.limit}")
    return args


def webhook_url_for(args: argparse.Namespace, settings) -> str | None:
    """Which webhook URL the sinks should be built from, for this invocation.

    A re-scan is opt-in: re-sorting a mailbox locally must not, by itself,
    replay months of mail into someone's automation. Every other mode delivers
    as configured.
    """
    if args.rescan and not args.emit_webhooks:
        return None
    return settings.webhook_url


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
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

    try:
        scanner = build_scanner_runner(settings)
    except ValueError as exc:
        # A misconfigured container runner is a startup error on purpose: the
        # alternative is discovering it one message at a time.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Before anything is drained. A dispatcher killed mid-scan leaves its
    # container running -- `--rm` only fires on a clean exit -- and those
    # accumulate across restarts, each still holding its memory and pid quota.
    _reap_orphans(scanner)

    webhook_url = webhook_url_for(args, settings)
    if args.rescan and settings.webhook_url and not webhook_url:
        log.info(
            "rescan: webhook emission is OFF (pass --emit-webhooks to deliver "
            "this backlog downstream)"
        )

    source = ImapMailSource(settings.imap)
    runner = Runner(
        source=source,
        scanner=scanner,
        state=state,
        sinks=build_sinks(webhook_url),
        max_attempts=settings.imap.max_attempts,
        concurrency=settings.imap.concurrency,
        poll_interval_seconds=settings.imap.poll_interval_seconds,
    )

    try:
        if args.rescan:
            return _rescan(runner, source, limit=args.limit, verbose=args.verbose)
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


def _reap_orphans(scanner) -> None:
    """Ask the runner to clean up after a previous life, if it can.

    Duck-typed: only the container runner has orphans to reap, and a reaping
    failure must never stop the dispatcher from draining mail.
    """
    reap = getattr(scanner, "reap_orphans", None)
    if not callable(reap):
        return
    try:
        removed = reap()
    except Exception as exc:  # noqa: BLE001 - housekeeping never blocks the queue
        log.warning("could not reap orphaned scan containers: %s", exc)
        return
    if removed:
        log.info("reaped %s orphaned scan container(s)", removed)


def _drain_once(runner: Runner, source, verbose: bool) -> int:
    source.connect()
    report = runner.drain_once()
    print(f"drain: {report.summary()}")
    if verbose and report.results:
        print(describe(report.results))
    return EXIT_ERROR if report.quarantined else EXIT_OK


def _rescan(runner: Runner, source, limit: int | None, verbose: bool) -> int:
    """The onboarding pass. Exits non-zero if any message could not be scanned.

    Unlike ``--once`` a failure here is not quarantined -- the re-scan writes no
    state -- so the exit code is the only durable record of one. The per-message
    error is on stderr, and the message is still sitting in the mailbox to try
    again.
    """
    source.connect()
    log.info(
        "rescan: one-shot pass over the whole mailbox; no dispatcher state is "
        "written and nothing is marked \\Seen. The live dispatcher should be stopped."
    )
    report = runner.rescan(limit=limit)
    print(f"rescan: {report.summary()}")
    if verbose and report.results:
        print(describe(report.results))
    return EXIT_ERROR if report.failed else EXIT_OK


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
