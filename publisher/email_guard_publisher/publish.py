"""Copy finished job directories onto the network partition, whole or not at all.

Fired by a systemd **path unit** the moment a new ``.complete`` appears under the
outbound tree, so a job reaches the downstream consumer within a second or so of
being scanned. A backstop timer runs the same command on a slow interval, which
is what makes the delivery guarantee unconditional rather than event-shaped --
see ``publisher/systemd/``.

The whole design is three promises to the consumer and one to the operator.

**A job directory appears whole, or not at all.** The copy is assembled in a
staging directory *inside the destination bucket* -- same filesystem, so the
final step is a single ``rename``, which POSIX guarantees is atomic. Under the
real ``<job>`` name a consumer therefore sees either nothing or a complete
package: never a half-copied report, never an attachment arriving after the
report that describes it.

The staging directory is named ``publishing-<job>.<pid>``, and it is deliberately
NOT hidden. It cannot be: acheron is a CIFS/SMB share whose server refuses to
create any name beginning with a dot, so the original ``.publishing-`` prefix
made the first ``mkdir`` fail with ENOENT and nothing published at all (see
:data:`~email_guard_publisher.markers.STAGING_PREFIX`). Nothing about the
guarantee rested on hiding it. The rename is what makes a package appear
atomically under its real name, and Smiley -- the primary consumer -- is
webhook-triggered with the exact job name rather than scanning the bucket. A
consumer that does scan should skip entries starting with the staging prefix,
the same way it would skip any other work-in-progress name.

**The path is deterministic.** ``${DEST}/<bucket>/<job>/`` -- the same bucket and
the same job slug the scanner used locally, both already filesystem-safe. A
consumer told the bucket and the job id can construct the path; nothing here
renames, re-slugs or re-orders anything.

**The package is clean.** ``.complete`` and ``.published`` are ours, and they
stay on the host. Acheron gets ``report.json``, the verbatim message, and the
extracted attachments.

**Nothing is ever lost.** The local job directory is never deleted here (that is
the retention sweep's job, and only for published jobs), ``.published`` is
written only after a copy has fully landed, and an unreachable destination is a
skip, not a failure -- jobs accumulate locally and go out on the next fire. A
week-long outage costs a week of disk, not a single message.

The one thing this program deliberately does not do is look inside a file. It
copies bytes. The attachments it carries have never been opened by anything on
this host -- inspecting them is the downstream consumer's job, on its own
machine, which is the entire reason a package is published rather than parsed.
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings
from .markers import COMPLETE, INTERNAL_MARKERS, PUBLISHED, STAGING_PREFIX

log = logging.getLogger(__name__)

#: Copy buffer. Attachments are ordinary mail attachments, not disk images.
_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Job:
    """One local job directory that is finished and not yet published."""

    bucket: str
    job: str
    path: Path

    @property
    def name(self) -> str:
        return f"{self.bucket}/{self.job}"


@dataclass
class PublishReport:
    """What one run did. Returned rather than logged-and-forgotten, so it is testable."""

    published: list[str] = field(default_factory=list)
    already_published: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    destination_reachable: bool = True

    @property
    def ok(self) -> bool:
        return not self.failed and self.destination_reachable


def pending_jobs(settings: Settings) -> list[Job]:
    """Every job directory carrying ``.complete`` and not ``.published``.

    Sorted, so a run's order is reproducible and its log reads in a stable
    order. A directory without the sentinel is skipped in silence: it is either
    being written right now, or it was written by a scanner container whose
    output has not been merged into the shared tree yet.
    """
    found: list[Job] = []
    for bucket in settings.buckets:
        bucket_dir = settings.source_dir / bucket
        if not bucket_dir.is_dir():
            continue
        for job_dir in sorted(bucket_dir.iterdir()):
            if not job_dir.is_dir():
                continue
            if not (job_dir / COMPLETE).is_file():
                continue
            if (job_dir / PUBLISHED).exists():
                continue
            found.append(Job(bucket=bucket, job=job_dir.name, path=job_dir))
    return found


def publish(settings: Settings) -> PublishReport:
    """Publish every pending job. Never raises; every outcome is in the report."""
    report = PublishReport()

    jobs = pending_jobs(settings)
    if not jobs:
        log.debug("nothing to publish under %s", settings.source_dir)
        return report

    # Checked once per run, before any work: an unreachable partition is the
    # expected failure (a rebooting NAS, a dropped mount), and there is nothing
    # to be gained from discovering it once per job.
    if not destination_reachable(settings.dest_dir):
        report.destination_reachable = False
        log.warning(
            "destination %s is not reachable -- %d job(s) stay local and will be "
            "retried on the next fire",
            settings.dest_dir,
            len(jobs),
        )
        return report

    for job in jobs:
        try:
            outcome = publish_job(job, settings.dest_dir)
        except Exception:  # noqa: BLE001 - one bad job must not stop the queue
            log.exception("could not publish %s -- left local, will retry", job.name)
            report.failed.append(job.name)
            continue
        (report.published if outcome else report.already_published).append(job.name)

    log.info(
        "published %d job(s), %d already on the destination, %d failed",
        len(report.published),
        len(report.already_published),
        len(report.failed),
    )
    return report


def destination_reachable(dest_dir: Path) -> bool:
    """Is the partition mounted and writable right now?

    Deliberately weak: it asks whether the destination is a directory this user
    can write to, and nothing more. A stale NFS handle can still pass this and
    fail mid-copy -- which is why the copy itself is transactional rather than
    trusting this check.
    """
    try:
        return dest_dir.is_dir() and os.access(dest_dir, os.W_OK | os.X_OK)
    except OSError:
        return False


def publish_job(job: Job, dest_dir: Path) -> bool:
    """Copy one job to ``<dest>/<bucket>/<job>/`` and mark it published locally.

    Returns True if this run put the package there, False if the destination
    already had it -- which happens after a crash between the rename and the
    marker write. Both are success: the package is on acheron and the local
    marker now says so.

    Raises on a failed copy, having removed its own staging directory and
    written no marker. The caller logs it; the job stays pending and the next
    fire tries again.
    """
    bucket_dir = dest_dir / job.bucket
    bucket_dir.mkdir(parents=True, exist_ok=True)
    final = bucket_dir / job.job

    if final.exists():
        log.info("%s is already on the destination -- marking it published", job.name)
        mark_published(job.path, final)
        return False

    # Staged INSIDE the destination bucket, which is what makes the final step a
    # rename rather than a second copy: `os.rename` is atomic within one
    # filesystem and refuses to cross one. Staging in /tmp would silently
    # degrade to a copy, and a copy is exactly what must not be observable.
    #
    # The name comes from STAGING_PREFIX and must stay dot-free -- the SMB
    # server backing acheron rejects leading-dot names outright, which is what
    # broke the first version of this. The pid keeps two concurrent runs from
    # assembling into one directory.
    staging = bucket_dir / f"{STAGING_PREFIX}{job.job}.{os.getpid()}"
    _remove(staging)
    try:
        _copy_package(job.path, staging)
        try:
            os.rename(staging, final)
        except OSError:
            # Lost the race with another run (or a retry that had already got
            # there). The destination holds a whole package either way.
            if not final.exists():
                raise
            log.info("%s appeared on the destination mid-copy -- keeping it", job.name)
            _remove(staging)
            mark_published(job.path, final)
            return False
    except Exception:
        _remove(staging)
        raise

    mark_published(job.path, final)
    log.info("published %s -> %s", job.name, final)
    return True


def _copy_package(source: Path, staging: Path) -> None:
    """Copy a job directory's publishable contents into ``staging``.

    Excludes the internal markers, and only the internal markers: whatever else
    the scanner put in the job directory is part of the package. Each file is
    flushed to the destination before the rename, so a host that loses power
    between the two cannot leave a job directory that exists but is empty.
    """
    staging.mkdir(parents=True)
    for entry in sorted(source.iterdir()):
        if entry.name in INTERNAL_MARKERS:
            continue
        target = staging / entry.name
        if entry.is_dir():
            # The scanner writes a flat job directory today. Handled anyway, so
            # a future addition (`links/`, say) does not silently go missing.
            shutil.copytree(entry, target)
            continue
        _copy_file(entry, target)
    _fsync_dir(staging)


def _copy_file(source: Path, target: Path) -> None:
    with source.open("rb") as reader, target.open("wb") as writer:
        while True:
            chunk = reader.read(_CHUNK)
            if not chunk:
                break
            writer.write(chunk)
        writer.flush()
        os.fsync(writer.fileno())
    shutil.copystat(source, target)


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:  # pragma: no cover - some network filesystems refuse this
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - and some accept the open but not the sync
        pass
    finally:
        os.close(fd)


def mark_published(job_dir: Path, destination: Path) -> Path:
    """Write the local ``.published`` marker naming where the package went.

    Written only after the package is on the destination, so its presence is
    never a lie. The path it records is for a human reading the tree with `cat`;
    nothing parses this file, and the retention sweep reads only its mtime,
    which is the publication time.
    """
    marker = Path(job_dir) / PUBLISHED
    marker.write_text(f"{destination}\n", encoding="utf-8")
    return marker


def _remove(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
