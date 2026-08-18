"""The host-side publisher: local disk -> the network partition.

Everything here runs offline against ``tmp_path`` directories. There is no
acheron in a test, and there does not need to be one: what the publisher relies
on is that the destination is *a filesystem it can rename within*, which two tmp
directories model exactly.

The properties under test are the ones a downstream consumer and an operator
actually depend on:

* a job appears on the destination **whole** -- a consumer scanning mid-copy
  never sees a partial package;
* publishing twice is a no-op;
* an unreachable destination loses nothing: no marker, no deletion, and the job
  is still pending afterwards;
* the internal markers never leave the host.
"""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path

import pytest

from email_guard_publisher import publish as publish_module
from email_guard_publisher.config import ConfigError, Settings
from email_guard_publisher.markers import COMPLETE, PUBLISHED, STAGING_PREFIX
from email_guard_publisher.publish import pending_jobs, publish, publish_job

REPORT = json.dumps({"bucket": "cleared", "final_level": 4}, indent=2).encode()
MESSAGE = b"From: notices@quietservice.example\r\n\r\nYour receipt.\r\n"
ATTACHMENT = b"\x89PNG\r\n\x1a\n" + bytes(range(256))


@pytest.fixture
def trees(tmp_path: Path) -> dict[str, Path]:
    source = tmp_path / "outbound"
    dest = tmp_path / "acheron" / "email-guard"
    dest.mkdir(parents=True)
    return {"source": source, "dest": dest}


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
    job: str = "job-0001",
    *,
    bucket: str = "cleared",
    complete: bool = True,
    published: bool = False,
    attachments: dict[str, bytes] | None = None,
) -> Path:
    """A job directory exactly as the scanner leaves one."""
    directory = source / bucket / job
    directory.mkdir(parents=True)
    (directory / "report.json").write_bytes(REPORT)
    (directory / "message.eml").write_bytes(MESSAGE)
    for name, data in (attachments or {}).items():
        (directory / name).write_bytes(data)
    if complete:
        (directory / COMPLETE).write_bytes(b"")
    if published:
        (directory / PUBLISHED).write_text("already\n", encoding="utf-8")
    return directory


def names_in(directory: Path) -> set[str]:
    return {entry.name for entry in directory.iterdir()}


# --- what gets picked up ----------------------------------------------------------


def test_only_complete_unpublished_jobs_are_pending(settings, trees):
    make_job(trees["source"], "finished")
    make_job(trees["source"], "still-writing", complete=False)
    make_job(trees["source"], "already-done", published=True)

    assert [job.job for job in pending_jobs(settings)] == ["finished"]


def test_a_job_without_the_sentinel_is_never_published(settings, trees):
    """The half-written case. The sentinel is the only signal that matters."""
    make_job(trees["source"], "still-writing", complete=False)

    report = publish(settings)

    assert report.published == []
    assert not (trees["dest"] / "cleared").exists() or names_in(
        trees["dest"] / "cleared"
    ) == set()
    assert not (trees["source"] / "cleared" / "still-writing" / PUBLISHED).exists()


def test_every_configured_bucket_is_swept(settings, trees):
    make_job(trees["source"], "a", bucket="cleared")
    make_job(trees["source"], "b", bucket="flagged")
    make_job(trees["source"], "c", bucket="rejected")

    report = publish(settings)

    assert sorted(report.published) == ["cleared/a", "flagged/b", "rejected/c"]
    assert (trees["dest"] / "flagged" / "b" / "report.json").read_bytes() == REPORT


def test_buckets_outside_the_configuration_are_left_alone(trees):
    settings = Settings(
        source_dir=trees["source"],
        dest_dir=trees["dest"],
        buckets=("cleared",),
        retention_days=14,
    )
    make_job(trees["source"], "a", bucket="cleared")
    quarantined = make_job(trees["source"], "b", bucket="rejected")

    report = publish(settings)

    assert report.published == ["cleared/a"]
    assert not (quarantined / PUBLISHED).exists()
    assert not (trees["dest"] / "rejected").exists()


# --- the package that lands -------------------------------------------------------


def test_the_whole_package_is_copied_byte_for_byte(settings, trees):
    make_job(trees["source"], "job-0001", attachments={"receipt.png": ATTACHMENT})

    publish(settings)
    landed = trees["dest"] / "cleared" / "job-0001"

    assert (landed / "report.json").read_bytes() == REPORT
    assert (landed / "message.eml").read_bytes() == MESSAGE
    assert (landed / "receipt.png").read_bytes() == ATTACHMENT


def test_the_internal_markers_are_never_copied(settings, trees):
    """Acheron gets the package. The bookkeeping stays on the host."""
    make_job(trees["source"], "job-0001", attachments={"receipt.png": ATTACHMENT})

    publish(settings)

    assert names_in(trees["dest"] / "cleared" / "job-0001") == {
        "report.json",
        "message.eml",
        "receipt.png",
    }


def test_the_destination_path_is_deterministic(settings, trees):
    """Bucket + job id, unchanged -- what the consumer is promised it can construct."""
    make_job(trees["source"], "a1b2-bank.example", bucket="flagged")

    publish(settings)

    assert (trees["dest"] / "flagged" / "a1b2-bank.example" / "report.json").is_file()


def test_a_subdirectory_in_a_job_is_carried_too(settings, trees):
    """The scanner writes a flat job today; a future addition must not vanish."""
    job = make_job(trees["source"], "job-0001")
    (job / "links").mkdir()
    (job / "links" / "resolved.json").write_bytes(b"{}")

    publish(settings)

    assert (trees["dest"] / "cleared" / "job-0001" / "links" / "resolved.json").is_file()


def test_the_local_job_is_left_exactly_as_it_was_plus_the_marker(settings, trees):
    job = make_job(trees["source"], "job-0001", attachments={"receipt.png": ATTACHMENT})

    publish(settings)

    assert names_in(job) == {"report.json", "message.eml", "receipt.png", COMPLETE, PUBLISHED}
    assert (job / "report.json").read_bytes() == REPORT
    assert (job / PUBLISHED).read_text(encoding="utf-8").strip() == str(
        trees["dest"] / "cleared" / "job-0001"
    )


# --- atomicity ---------------------------------------------------------------------


def test_a_consumer_scanning_mid_copy_never_sees_a_partial_job(settings, trees, monkeypatch):
    """The promise, tested by looking at the destination from inside the copy.

    The copy is intercepted after each file lands. At every one of those
    moments, the real ``<job>`` name must not exist yet: it appears in one step,
    at the rename. That -- not hiding the staging directory -- is what the
    guarantee rests on. The staging directory IS visible while the copy runs
    (it cannot be hidden; see `test_the_staging_prefix_is_never_dot_prefixed`),
    so a consumer that scans the bucket skips entries carrying its prefix, the
    same way it would skip any work-in-progress name.
    """
    observations: list[set[str]] = []
    real_copy_file = publish_module._copy_file

    def observing_copy(source: Path, target: Path) -> None:
        real_copy_file(source, target)
        bucket = trees["dest"] / "cleared"
        observations.append(
            {
                entry.name
                for entry in bucket.iterdir()
                if not entry.name.startswith(STAGING_PREFIX)
            }
        )

    monkeypatch.setattr(publish_module, "_copy_file", observing_copy)

    make_job(
        trees["source"],
        "job-0001",
        attachments={"receipt.png": ATTACHMENT, "statement.pdf": b"%PDF-1.7"},
    )
    publish(settings)

    assert observations, "the copy never ran"
    assert all(seen == set() for seen in observations), observations
    assert names_in(trees["dest"] / "cleared") == {"job-0001"}


def test_the_partial_package_is_never_under_the_real_job_name(settings, trees, monkeypatch):
    """The same promise, stated without reference to what the staging is called.

    Whatever the staging directory is named, ``<bucket>/<job>`` must not exist
    until it is complete -- so a consumer that resolves the deterministic path
    (which is what Smiley does, from the webhook) either misses or gets
    everything.
    """
    seen: list[bool] = []
    real_copy_file = publish_module._copy_file

    def observing_copy(source: Path, target: Path) -> None:
        real_copy_file(source, target)
        seen.append((trees["dest"] / "cleared" / "job-0001").exists())

    monkeypatch.setattr(publish_module, "_copy_file", observing_copy)

    make_job(trees["source"], "job-0001", attachments={"receipt.png": ATTACHMENT})
    publish(settings)

    assert seen, "the copy never ran"
    assert not any(seen), "the job path existed before the rename"
    assert (trees["dest"] / "cleared" / "job-0001" / "report.json").is_file()


def test_the_staging_prefix_is_never_dot_prefixed():
    """Regression: acheron is SMB, and its server rejects leading-dot names.

    Confirmed on the host -- ``mkdir with.dots`` succeeds on
    ``//192.168.1.71/acheron``, ``mkdir .anything`` fails with ENOENT. The
    staging directory is created ON THE SHARE, so a dot-prefixed prefix made the
    first ``mkdir`` raise ``FileNotFoundError`` and NO job ever published, on
    every run, silently as far as the destination was concerned.

    The internal markers keep their leading dots deliberately: they are written
    only to the LOCAL outbound tree, which is ext4. The asymmetry is the point,
    so both halves are asserted here.
    """
    assert not STAGING_PREFIX.startswith("."), (
        "the acheron SMB share refuses to create leading-dot names -- a "
        "dot-prefixed staging directory means nothing is ever published"
    )
    assert STAGING_PREFIX, "the staging directory still needs a distinguishing prefix"
    assert COMPLETE.startswith(".") and PUBLISHED.startswith("."), (
        "the markers are local-only (ext4) and stay hidden"
    )


def test_nothing_that_reaches_the_share_starts_with_a_dot(settings, trees, tmp_path, lists, pack):
    """The same SMB constraint, applied to everything the publisher copies.

    The staging prefix was the name this bug surfaced under, but any leading-dot
    name created on the share fails the same way -- so this walks a real scanned
    job, attachment names and all, and asserts every name that lands is dot-free.
    The sanitiser is what guarantees it for attachments (`.hidden.pdf` is stored
    as `hidden.pdf`) and `job_slug` for the directory; this is the test that
    would catch either of them relaxing.
    """
    from email_guard import parse
    from email_guard.pipeline import scan_and_write
    from email_guard.route import SourceMessage

    from tests.test_attachments import PNG_BYTES, build_eml

    outbound = trees["source"]
    raw = build_eml([(".hidden.pdf", PNG_BYTES, "application", "pdf")])
    scan_and_write(
        parse.parse_eml(raw),
        lists,
        pack,
        SourceMessage.from_eml(raw),
        outbound_dir=outbound,
        daily_brief_dir=tmp_path / "daily-brief",
        job_id="test-job",
    )

    assert publish(settings).published, "the job never published"

    landed = [path for path in trees["dest"].rglob("*")]
    assert landed, "nothing reached the destination"
    for path in landed:
        assert not path.name.startswith("."), (
            f"{path} would fail to create on the acheron SMB share"
        )


def test_the_staging_directory_lives_inside_the_destination(settings, trees, monkeypatch):
    """Staging elsewhere would make the last step a copy, not a rename."""
    seen: list[Path] = []
    real_copy_package = publish_module._copy_package

    def spy(source: Path, staging: Path) -> None:
        seen.append(staging)
        real_copy_package(source, staging)

    monkeypatch.setattr(publish_module, "_copy_package", spy)

    make_job(trees["source"], "job-0001")
    publish(settings)

    assert len(seen) == 1
    assert seen[0].parent == trees["dest"] / "cleared"
    # The prefix comes from markers.py, which is the single source of truth --
    # never spelled out here, so the constant cannot be changed in one place
    # only.
    assert seen[0].name.startswith(STAGING_PREFIX)
    assert seen[0].name != "job-0001"


def test_the_final_step_is_a_rename(settings, trees, monkeypatch):
    renames: list[tuple[str, str]] = []
    real_rename = os.rename

    def spy(source, target):
        renames.append((str(source), str(target)))
        return real_rename(source, target)

    monkeypatch.setattr(publish_module.os, "rename", spy)

    make_job(trees["source"], "job-0001")
    publish(settings)

    assert len(renames) == 1
    source, target = renames[0]
    assert Path(source).name.startswith(STAGING_PREFIX)
    assert target == str(trees["dest"] / "cleared" / "job-0001")


# --- idempotency -------------------------------------------------------------------


def test_a_second_run_is_a_no_op(settings, trees):
    make_job(trees["source"], "job-0001")

    first = publish(settings)
    landed = trees["dest"] / "cleared" / "job-0001" / "report.json"
    stamp = landed.stat().st_mtime_ns
    second = publish(settings)

    assert first.published == ["cleared/job-0001"]
    assert second.published == []
    assert second.already_published == []
    assert landed.stat().st_mtime_ns == stamp


def test_a_job_the_destination_already_has_is_marked_not_recopied(settings, trees):
    """The crash-between-rename-and-marker case: converge, do not duplicate."""
    job = make_job(trees["source"], "job-0001")
    landed = trees["dest"] / "cleared" / "job-0001"
    landed.mkdir(parents=True)
    (landed / "report.json").write_bytes(b"the copy that already got there")

    report = publish(settings)

    assert report.already_published == ["cleared/job-0001"]
    assert report.published == []
    assert (landed / "report.json").read_bytes() == b"the copy that already got there"
    assert (job / PUBLISHED).is_file()


def test_a_published_job_is_not_swept_again_after_a_rescan(settings, trees):
    """A rescan rewrites the local files; the marker still says "already sent"."""
    job = make_job(trees["source"], "job-0001")
    publish(settings)

    (job / "report.json").write_bytes(b'{"rescanned": true}')
    report = publish(settings)

    assert report.published == []
    assert (trees["dest"] / "cleared" / "job-0001" / "report.json").read_bytes() == REPORT


# --- an unreachable destination ------------------------------------------------------


def test_an_unreachable_destination_loses_nothing(trees):
    """The outage case: no marker, no deletion, still pending afterwards."""
    settings = Settings(
        source_dir=trees["source"],
        dest_dir=trees["dest"].parent / "not-mounted" / "email-guard",
        buckets=("cleared",),
        retention_days=14,
    )
    job = make_job(trees["source"], "job-0001", attachments={"receipt.png": ATTACHMENT})

    report = publish(settings)

    assert report.destination_reachable is False
    assert report.published == []
    assert not (job / PUBLISHED).exists()
    assert names_in(job) == {"report.json", "message.eml", "receipt.png", COMPLETE}
    assert [pending.job for pending in pending_jobs(settings)] == ["job-0001"]


def test_the_backlog_drains_when_the_destination_returns(trees):
    settings = Settings(
        source_dir=trees["source"],
        dest_dir=trees["dest"].parent / "later" / "email-guard",
        buckets=("cleared",),
        retention_days=14,
    )
    make_job(trees["source"], "job-0001")
    make_job(trees["source"], "job-0002")

    assert publish(settings).published == []

    settings.dest_dir.mkdir(parents=True)
    report = publish(settings)

    assert sorted(report.published) == ["cleared/job-0001", "cleared/job-0002"]
    assert (trees["dest"].parent / "later" / "email-guard" / "cleared" / "job-0002").is_dir()


def test_a_copy_that_fails_midway_leaves_no_marker_and_no_debris(settings, trees, monkeypatch):
    """ENOSPC halfway through: the job stays pending and the staging is gone."""
    calls = {"n": 0}
    real_copy_file = publish_module._copy_file

    def failing_copy(source: Path, target: Path) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError(errno.ENOSPC, "No space left on device")
        real_copy_file(source, target)

    monkeypatch.setattr(publish_module, "_copy_file", failing_copy)

    job = make_job(trees["source"], "job-0001", attachments={"receipt.png": ATTACHMENT})
    report = publish(settings)

    assert report.failed == ["cleared/job-0001"]
    assert report.ok is False
    assert not (job / PUBLISHED).exists()
    assert names_in(trees["dest"] / "cleared") == set()
    assert [pending.job for pending in pending_jobs(settings)] == ["job-0001"]


def test_one_bad_job_does_not_stop_the_queue(settings, trees, monkeypatch):
    real_publish_job = publish_module.publish_job

    def failing_for_one(job, dest_dir):
        if job.job == "job-0002":
            raise OSError(errno.EIO, "I/O error")
        return real_publish_job(job, dest_dir)

    monkeypatch.setattr(publish_module, "publish_job", failing_for_one)

    for name in ("job-0001", "job-0002", "job-0003"):
        make_job(trees["source"], name)

    report = publish(settings)

    assert sorted(report.published) == ["cleared/job-0001", "cleared/job-0003"]
    assert report.failed == ["cleared/job-0002"]


def test_nothing_local_is_ever_deleted_by_publishing(settings, trees):
    """The publisher only ever adds. Deletion is the retention sweep's job."""
    job = make_job(trees["source"], "job-0001", attachments={"receipt.png": ATTACHMENT})
    before = {entry.name: entry.read_bytes() for entry in job.iterdir()}

    publish(settings)

    after = {entry.name: entry.read_bytes() for entry in job.iterdir()}
    assert before.items() <= after.items()
    assert set(after) - set(before) == {PUBLISHED}


# --- the contract with the scanner ---------------------------------------------------


def test_the_marker_names_match_the_scanners():
    """Duplicated across the host/container boundary on purpose -- so pin them.

    The publisher runs on the host with no scanner package installed, so it
    restates the two filenames rather than importing them. If the scanner ever
    renames its sentinel, this fails loudly instead of the publisher silently
    never finding a job again.
    """
    from email_guard.route import COMPLETE_NAME, PUBLISHED_NAME

    assert COMPLETE == COMPLETE_NAME
    assert PUBLISHED == PUBLISHED_NAME


def test_publish_job_returns_whether_it_did_the_copy(settings, trees):
    from email_guard_publisher.publish import Job

    make_job(trees["source"], "job-0001")
    job = Job(bucket="cleared", job="job-0001", path=trees["source"] / "cleared" / "job-0001")

    assert publish_job(job, trees["dest"]) is True
    (job.path / PUBLISHED).unlink()
    assert publish_job(job, trees["dest"]) is False


# --- configuration --------------------------------------------------------------------


def test_settings_default_to_the_agreed_paths():
    settings = Settings.from_env({})

    assert settings.source_dir == Path("data/outbound")
    assert settings.dest_dir == Path("/mnt/network/acheron/email-guard")
    assert settings.buckets == ("cleared", "flagged", "rejected")
    assert settings.retention_days == 14


def test_settings_come_from_the_environment():
    settings = Settings.from_env(
        {
            "EMAIL_GUARD_OUTBOUND_DIR": "/opt/email-guard/data/outbound",
            "EMAIL_GUARD_PUBLISH_DEST": "/mnt/network/acheron/email-guard",
            "EMAIL_GUARD_PUBLISH_BUCKETS": "cleared, flagged",
            "EMAIL_GUARD_OUTBOUND_RETENTION_DAYS": "30",
        }
    )

    assert settings.source_dir == Path("/opt/email-guard/data/outbound")
    assert settings.buckets == ("cleared", "flagged")
    assert settings.retention_days == 30


@pytest.mark.parametrize("raw", ["not-a-number", "-1", "14.5"])
def test_a_bad_retention_window_is_refused(raw):
    with pytest.raises(ConfigError):
        Settings.from_env({"EMAIL_GUARD_OUTBOUND_RETENTION_DAYS": raw})


@pytest.mark.parametrize(
    "source, dest",
    [
        # The actively destructive mistake: publish into the tree being swept,
        # and retention is free to delete the published copy.
        ("/opt/email-guard/data/outbound", "/opt/email-guard/data/outbound"),
        ("/opt/email-guard/data/outbound", "/opt/email-guard/data/outbound/acheron"),
        ("/mnt/network/acheron/email-guard/local", "/mnt/network/acheron/email-guard"),
    ],
)
def test_overlapping_trees_are_refused(source, dest):
    with pytest.raises(ConfigError):
        Settings.from_env(
            {"EMAIL_GUARD_OUTBOUND_DIR": source, "EMAIL_GUARD_PUBLISH_DEST": dest}
        )


@pytest.mark.parametrize("bucket", ["..", "../etc", "with/slash"])
def test_an_unusable_bucket_name_is_refused(bucket):
    with pytest.raises(ConfigError):
        Settings.from_env({"EMAIL_GUARD_PUBLISH_BUCKETS": bucket})


# --- the whole path, scanner to partition ---------------------------------------------


def test_a_scanned_message_reaches_the_partition_intact(tmp_path, lists, pack):
    """End to end: the scanner writes a job, the publisher ships exactly it.

    The two halves are developed and tested separately -- one runs in a
    container, one on the host -- so this is the test that they agree: the
    sentinel the scanner writes is the one the publisher looks for, the
    attachments it extracts are the ones that land on acheron, and the markers
    stay behind.
    """
    from email_guard import parse
    from email_guard.pipeline import scan_and_write
    from email_guard.route import SourceMessage

    from tests.test_attachments import PNG_BYTES, build_eml

    outbound = tmp_path / "outbound"
    dest = tmp_path / "acheron" / "email-guard"
    dest.mkdir(parents=True)

    raw = build_eml([("receipt.png", PNG_BYTES, "image", "png")])
    verdict = scan_and_write(
        parse.parse_eml(raw),
        lists,
        pack,
        SourceMessage.from_eml(raw),
        outbound_dir=outbound,
        daily_brief_dir=tmp_path / "daily-brief",
        job_id="test-job",
    )

    settings = Settings(
        source_dir=outbound,
        dest_dir=dest,
        buckets=("cleared", "flagged", "rejected"),
        retention_days=14,
    )
    report = publish(settings)

    job = verdict["written"]["job"]
    landed = dest / "cleared" / job
    assert report.published == [f"cleared/{job}"]
    assert names_in(landed) == {"report.json", "message.eml", "receipt.png"}
    assert (landed / "receipt.png").read_bytes() == PNG_BYTES
    assert (landed / "message.eml").read_bytes() == raw

    # The package describes itself: the manifest in the published report names
    # the files beside it, and the hashes match what arrived.
    import hashlib

    published_report = json.loads((landed / "report.json").read_text(encoding="utf-8"))
    for entry in published_report["extracted_attachments"]:
        arrived = (landed / entry["stored_name"]).read_bytes()
        assert hashlib.sha256(arrived).hexdigest() == entry["sha256"]
        assert len(arrived) == entry["size"]
