"""Retention: delete local job directories that are published and old.

Run by a daily systemd timer on the host. Two conditions, and BOTH must hold:

* the job carries ``.published`` -- it is on the network partition;
* that marker is older than ``EMAIL_GUARD_OUTBOUND_RETENTION_DAYS`` (default 14).

An unpublished job is never deleted, at any age. That is the rule that makes a
network outage cost disk instead of mail: while the partition is unreachable,
jobs pile up locally with no ``.published`` marker, and this sweep walks past
every one of them. If the outage lasts a month, the month's mail is still there
when the mount comes back.

The destination is never touched. This module never reads ``dest_dir`` and never
opens a path outside ``source_dir`` -- acheron's copy is the downstream
consumer's, and its lifetime is that machine's business, not ours.

"Old" is measured from the ``.published`` marker's mtime -- the moment the job
was published, not the moment it was scanned. A job that sat unpublished through
an outage therefore gets its full retention window on disk after it finally goes
out, rather than being deleted the day the mount returns.

The clock is a parameter (``now``), never read from inside the walk, so the
boundary cases are testable without touching system time.
"""

from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings
from .markers import PUBLISHED

log = logging.getLogger(__name__)

_SECONDS_PER_DAY = 86400.0


@dataclass
class CleanupReport:
    """What one sweep did."""

    deleted: list[str] = field(default_factory=list)
    kept_unpublished: list[str] = field(default_factory=list)
    kept_recent: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failed


def expired_jobs(settings: Settings, now: float) -> list[Path]:
    """Published job directories whose retention window has passed."""
    return [job for job, verdict in _classify(settings, now) if verdict == "expired"]


def cleanup(settings: Settings, now: float | None = None) -> CleanupReport:
    """Delete every expired job directory. Never raises."""
    report = CleanupReport()
    moment = time.time() if now is None else now

    for job_dir, verdict in _classify(settings, moment):
        name = f"{job_dir.parent.name}/{job_dir.name}"
        if verdict == "unpublished":
            report.kept_unpublished.append(name)
            continue
        if verdict == "recent":
            report.kept_recent.append(name)
            continue
        try:
            shutil.rmtree(job_dir)
        except OSError:
            log.exception("could not delete %s", job_dir)
            report.failed.append(name)
            continue
        report.deleted.append(name)

    log.info(
        "retention %d day(s): deleted %d, kept %d unpublished and %d within the window"
        "%s",
        settings.retention_days,
        len(report.deleted),
        len(report.kept_unpublished),
        len(report.kept_recent),
        f", {len(report.failed)} failed" if report.failed else "",
    )
    return report


def _classify(settings: Settings, now: float) -> list[tuple[Path, str]]:
    """Every job directory in the configured buckets, with its verdict.

    One walk, three answers -- ``unpublished``, ``recent``, ``expired`` -- so the
    sweep and the "what would it delete?" query cannot disagree.
    """
    cutoff = now - settings.retention_days * _SECONDS_PER_DAY
    classified: list[tuple[Path, str]] = []

    for bucket in settings.buckets:
        bucket_dir = settings.source_dir / bucket
        if not bucket_dir.is_dir():
            continue
        for job_dir in sorted(bucket_dir.iterdir()):
            if not job_dir.is_dir():
                continue
            marker = job_dir / PUBLISHED
            if not marker.is_file():
                classified.append((job_dir, "unpublished"))
                continue
            try:
                published_at = marker.stat().st_mtime
            except OSError:  # pragma: no cover - a marker that vanished mid-walk
                classified.append((job_dir, "unpublished"))
                continue
            classified.append((job_dir, "expired" if published_at <= cutoff else "recent"))

    return classified
