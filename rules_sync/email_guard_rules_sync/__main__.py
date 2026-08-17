"""The rules updater entry point.

Two modes, the same code:

* the default -- start the control endpoint, then loop on the configured
  interval. This is what the compose service runs.
* ``--once`` -- do exactly one pull and exit with its outcome as the exit code.
  Useful from the host during bring-up (VALIDATION.md), and for anyone who would
  rather drive the schedule from cron than from a long-lived container.

Signals are handled the way the dispatcher handles them: SIGINT/SIGTERM set the
stop event, so a ``docker compose down`` ends the loop between pulls rather than
in the middle of a promote.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading

from . import store
from .config import ConfigError, load
from .control import build_server, serve_in_background
from .loop import run_forever
from .sync import STATUS_ERROR, STATUS_REJECTED, pull_and_promote

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REJECTED = 2   # the pull ran and the pack was refused: distinct from a crash

log = logging.getLogger("email_guard_rules_sync")


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m email_guard_rules_sync",
        description="Pull, validate and promote the Email Guard rules pack.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="run a single pull and exit (0 promoted or unchanged, 2 rejected, 1 error)",
    )
    parser.add_argument(
        "--no-serve",
        action="store_true",
        help="do not start the control endpoint the review console calls",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="debug logging")
    return parser.parse_args(argv if argv is not None else sys.argv[1:])


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    try:
        config = load()
    except ConfigError as exc:
        # Configuration problems are the operator's to fix, and saying so on
        # stderr beats a stack trace in `docker compose logs`.
        print(f"rules updater: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.once:
        result = pull_and_promote(config)
        print(json.dumps(result.as_dict(), indent=2))
        if result.status == STATUS_REJECTED:
            return EXIT_REJECTED
        return EXIT_ERROR if result.status == STATUS_ERROR else EXIT_OK

    stop = threading.Event()

    def handle(signum: int, _frame: object) -> None:
        log.info("received signal %s: stopping after the current pull", signum)
        stop.set()

    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)

    server = None
    if not args.no_serve:
        try:
            server = build_server(config)
            serve_in_background(server)
        except OSError as exc:
            # A control endpoint that cannot bind must not take the scheduled
            # pull down with it -- the loop is the more important half.
            log.error("could not start the control endpoint: %s", exc)

    try:
        run_forever(config, stop)
    except store.LiveRootNotWritable as exc:
        # The one failure that is neither transient nor fixable from in here:
        # the operator has to chown the bind directory on the host. Say that in
        # a single line and exit -- a PermissionError traceback repeated by
        # `restart: unless-stopped` buries the sentence that names the fix.
        log.error("rules updater cannot start: %s", exc)
        return EXIT_ERROR
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
