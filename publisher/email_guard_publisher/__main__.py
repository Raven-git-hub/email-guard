"""The CLI the two systemd units invoke.

    python3 -m email_guard_publisher publish     # the path unit + its backstop timer
    python3 -m email_guard_publisher cleanup     # the daily retention timer
    python3 -m email_guard_publisher status      # what a run would do, changing nothing

Logging goes to stderr, which is where systemd's journal picks it up, so
``journalctl -u email-guard-publisher`` is the whole operational view.

Exit codes are chosen for how systemd reads them, and the important one is that
an unreachable destination is **not** a failure:

    0   the run completed -- including "the partition is down, nothing was
        copied, everything is still here". A NAS reboot is an expected state of
        the world, and marking the unit failed for it would mean an operator
        wakes up to a red unit for a condition that has already resolved
        itself.
    1   at least one job could not be copied (a real, per-job error).
    2   the configuration is unusable -- nothing ran.
"""

from __future__ import annotations

import argparse
import logging
import sys

from .cleanup import cleanup
from .config import ConfigError, Settings
from .publish import pending_jobs, publish

EXIT_OK = 0
EXIT_FAILED_JOBS = 1
EXIT_CONFIG = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m email_guard_publisher",
        description=(
            "Bridge finished Email Guard jobs from local disk to the network "
            "partition, and expire the local copies once they are safely there."
        ),
    )
    parser.add_argument(
        "command",
        choices=("publish", "cleanup", "status"),
        help="publish: copy finished jobs; cleanup: apply retention; status: report only",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="log at DEBUG rather than INFO"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        settings = Settings.from_env()
    except ConfigError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return EXIT_CONFIG

    if args.command == "status":
        return _status(settings)
    if args.command == "cleanup":
        return EXIT_OK if cleanup(settings).ok else EXIT_FAILED_JOBS

    report = publish(settings)
    # `destination_reachable` is deliberately not consulted: see the module
    # docstring. Only a per-job failure is a failure.
    return EXIT_OK if not report.failed else EXIT_FAILED_JOBS


def _status(settings: Settings) -> int:
    """Print the configuration and the backlog, and touch nothing."""
    pending = pending_jobs(settings)
    print(f"source      {settings.source_dir}")
    print(f"destination {settings.dest_dir}")
    print(f"buckets     {', '.join(settings.buckets)}")
    print(f"retention   {settings.retention_days} day(s)")
    print(f"pending     {len(pending)} job(s)")
    for job in pending:
        print(f"  {job.name}")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
