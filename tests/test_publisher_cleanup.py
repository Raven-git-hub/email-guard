"""Retention: what the daily sweep deletes, and everything it must not.

The sweep is the only thing in Email Guard that deletes mail, so the tests are
written around the two ways that could go wrong: deleting something that has not
been published (mail loss), and reaching outside the local tree (deleting the
downstream consumer's copy).

The clock is injected on every call. Nothing here reads system time, so the
boundary cases -- exactly at the window, one second either side -- are exact
rather than approximate.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from email_guard_publisher.cleanup import cleanup, expired_jobs
from email_guard_publisher.config import Settings
from email_guard_publisher.markers import COMPLETE, PUBLISHED

DAY = 86400.0
# A fixed "now", so every age in these tests is arithmetic rather than a sleep.
NOW = 1_800_000_000.0


@pytest.fixture
def trees(tmp_path: Path) -> dict[str, Path]:
    dest = tmp_path / "acheron" / "email-guard"
    dest.mkdir(parents=True)
    return {"source": tmp_path / "outbound", "dest": dest}


@pytest.fixture
def settings(trees) -> Settings:
    return Settings(
        source_dir=trees["source"],
        dest_dir=trees["dest"],
        buckets=("cleared", "flagged", "rejected"),
        retention_days=14,
    )


def make_job(
    source: Path,
    job: str,
    *,
    bucket: str = "cleared",
    published_days_ago: float | None = None,
) -> Path:
    """A finished job, optionally published ``published_days_ago`` days back."""
    directory = source / bucket / job
    directory.mkdir(parents=True)
    (directory / "report.json").write_bytes(b"{}")
    (directory / "message.eml").write_bytes(b"From: someone\r\n\r\nhello\r\n")
    (directory / COMPLETE).write_bytes(b"")
    if published_days_ago is not None:
        marker = directory / PUBLISHED
        marker.write_text("published\n", encoding="utf-8")
        when = NOW - published_days_ago * DAY
        os.utime(marker, (when, when))
    return directory


def job_names(source: Path) -> set[str]:
    return {
        f"{job.parent.name}/{job.name}"
        for bucket in source.iterdir()
        for job in bucket.iterdir()
    }


# --- what goes -----------------------------------------------------------------------


def test_a_published_job_past_the_window_is_deleted(settings, trees):
    job = make_job(trees["source"], "old", published_days_ago=20)

    report = cleanup(settings, now=NOW)

    assert report.deleted == ["cleared/old"]
    assert not job.exists()


def test_the_window_boundary_is_exact(settings, trees):
    make_job(trees["source"], "just-inside", published_days_ago=13.99)
    make_job(trees["source"], "exactly-at", published_days_ago=14)
    make_job(trees["source"], "just-outside", published_days_ago=14.01)

    cleanup(settings, now=NOW)

    assert job_names(trees["source"]) == {"cleared/just-inside"}


def test_every_configured_bucket_is_swept(settings, trees):
    make_job(trees["source"], "a", bucket="cleared", published_days_ago=20)
    make_job(trees["source"], "b", bucket="flagged", published_days_ago=20)
    make_job(trees["source"], "c", bucket="rejected", published_days_ago=20)

    report = cleanup(settings, now=NOW)

    assert sorted(report.deleted) == ["cleared/a", "flagged/b", "rejected/c"]
    assert job_names(trees["source"]) == set()


def test_a_zero_day_window_still_requires_publication(trees):
    """`0` means "as soon as it is safely there", not "delete everything"."""
    settings = Settings(
        source_dir=trees["source"],
        dest_dir=trees["dest"],
        buckets=("cleared",),
        retention_days=0,
    )
    make_job(trees["source"], "published", published_days_ago=0)
    make_job(trees["source"], "not-published")

    cleanup(settings, now=NOW)

    assert job_names(trees["source"]) == {"cleared/not-published"}


# --- what stays ----------------------------------------------------------------------


def test_an_unpublished_job_is_never_deleted_however_old(settings, trees):
    """The rule that turns a network outage into a disk cost, not a mail loss."""
    ancient = make_job(trees["source"], "ancient")
    os.utime(ancient, (NOW - 400 * DAY, NOW - 400 * DAY))

    report = cleanup(settings, now=NOW)

    assert report.deleted == []
    assert report.kept_unpublished == ["cleared/ancient"]
    assert (ancient / "report.json").is_file()


def test_a_recently_published_job_is_kept(settings, trees):
    job = make_job(trees["source"], "recent", published_days_ago=1)

    report = cleanup(settings, now=NOW)

    assert report.kept_recent == ["cleared/recent"]
    assert job.is_dir()


def test_a_job_still_being_written_is_kept(settings, trees):
    """No sentinel, no marker: it is not published, so it is not touched."""
    directory = trees["source"] / "cleared" / "in-flight"
    directory.mkdir(parents=True)
    (directory / "message.eml").write_bytes(b"half a message")

    cleanup(settings, now=NOW)

    assert directory.is_dir()


def test_a_month_long_outage_costs_disk_and_nothing_else(settings, trees):
    """The scenario, end to end: nothing published for 30 days, nothing deleted."""
    for day in range(30):
        make_job(trees["source"], f"job-{day:04d}")

    report = cleanup(settings, now=NOW)

    assert report.deleted == []
    assert len(report.kept_unpublished) == 30
    assert len(job_names(trees["source"])) == 30


def test_buckets_outside_the_configuration_are_not_swept(trees):
    settings = Settings(
        source_dir=trees["source"],
        dest_dir=trees["dest"],
        buckets=("cleared",),
        retention_days=14,
    )
    make_job(trees["source"], "a", bucket="cleared", published_days_ago=20)
    quarantined = make_job(trees["source"], "b", bucket="rejected", published_days_ago=20)

    cleanup(settings, now=NOW)

    assert quarantined.is_dir()


# --- the destination is out of bounds --------------------------------------------------


def test_the_destination_is_never_touched(settings, trees):
    """Acheron's copy belongs to the consumer. Its lifetime is not ours to manage."""
    make_job(trees["source"], "old", published_days_ago=20)
    landed = trees["dest"] / "cleared" / "old"
    landed.mkdir(parents=True)
    (landed / "report.json").write_bytes(b"{}")
    (landed / "message.eml").write_bytes(b"From: someone\r\n\r\nhello\r\n")

    before = {path.relative_to(trees["dest"]) for path in trees["dest"].rglob("*")}
    cleanup(settings, now=NOW)
    after = {path.relative_to(trees["dest"]) for path in trees["dest"].rglob("*")}

    assert before == after
    assert (landed / "report.json").is_file()


def test_the_sweep_only_opens_paths_under_the_source_tree(settings, trees, monkeypatch):
    """Belt and braces: record every path the sweep removes."""
    removed: list[Path] = []
    from email_guard_publisher import cleanup as cleanup_module

    real_rmtree = cleanup_module.shutil.rmtree

    def spy(path, *args, **kwargs):
        removed.append(Path(path))
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(cleanup_module.shutil, "rmtree", spy)

    make_job(trees["source"], "old", published_days_ago=20)
    cleanup(settings, now=NOW)

    assert removed == [trees["source"] / "cleared" / "old"]
    for path in removed:
        assert path.is_relative_to(trees["source"])


# --- reporting -------------------------------------------------------------------------


def test_expired_jobs_lists_what_a_sweep_would_delete(settings, trees):
    make_job(trees["source"], "old", published_days_ago=20)
    make_job(trees["source"], "recent", published_days_ago=1)
    make_job(trees["source"], "unpublished")

    expired = expired_jobs(settings, now=NOW)

    assert expired == [trees["source"] / "cleared" / "old"]
    # ... and asking did not delete anything.
    assert len(job_names(trees["source"])) == 3


def test_a_missing_source_tree_is_not_an_error(settings):
    report = cleanup(settings, now=NOW)

    assert report.deleted == []
    assert report.ok is True


def test_a_failed_deletion_is_reported_not_raised(settings, trees, monkeypatch):
    from email_guard_publisher import cleanup as cleanup_module

    def refuse(path, *args, **kwargs):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(cleanup_module.shutil, "rmtree", refuse)
    make_job(trees["source"], "old", published_days_ago=20)

    report = cleanup(settings, now=NOW)

    assert report.failed == ["cleared/old"]
    assert report.ok is False
    assert (trees["source"] / "cleared" / "old").is_dir()
