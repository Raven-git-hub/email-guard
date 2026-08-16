"""One hardened container per message -- everything reachable without a daemon.

**There is no Docker daemon in the environment this was built in.** `docker
version` finds the client and then fails to reach `/var/run/docker.sock`. So
nothing here has ever actually started a container, and these tests do not
pretend otherwise: they inject a fake Docker client and assert on the *argv*
the runner constructs, the results it derives from canned exit codes, and the
files it moves afterwards.

That boundary is a real one and worth being blunt about. What is verified here
is that the runner asks for the right thing. What cannot be verified here is
whether the daemon grants it -- whether the image exists, whether the
socket-proxy permits the call, and above all whether the *host* paths resolve
to the directories intended. ``VALIDATION.md`` is the runbook for the half that
needs a host.

The argv assertions are deliberately exact rather than "contains something
like". Every flag in that command is a containment boundary around hostile
input, so a silent reordering or a dropped `--network none` is exactly the
regression worth failing loudly on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from email_guard_dispatcher.container_runner import (
    CONTAINER_DAILY_BRIEF,
    CONTAINER_LISTS,
    CONTAINER_MESSAGE,
    CONTAINER_OUTBOUND,
    ContainerConfigError,
    ContainerRunner,
    ContainerSettings,
    DockerResult,
)

RAW = b"From: sender@example.com\r\nSubject: hello\r\n\r\nbody"
TOKEN = "deadbeefcafe0001"

VERDICT = {
    "sender": "sender@example.com",
    "bucket": "flagged",
    "final_level": 3,
    "written": {
        "job": "hello-1",
        "bucket": "flagged",
        "dir": f"{CONTAINER_OUTBOUND}/flagged/hello-1",
        "report": f"{CONTAINER_OUTBOUND}/flagged/hello-1/report.json",
        "message": f"{CONTAINER_OUTBOUND}/flagged/hello-1/message.eml",
        "candidate": f"{CONTAINER_DAILY_BRIEF}/daily-brief-2026-08-16/hello-1/candidate.json",
    },
}


class FakeDocker:
    """Records every argv and answers with canned results.

    The seam that makes this module testable at all. Injected rather than
    patched, matching the way the rest of this suite builds doubles.
    """

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.timeouts: list[float | None] = []
        self.handlers: dict[str, object] = {}

    def run(self, args, timeout=None, stdin=None) -> DockerResult:
        args = list(args)
        self.calls.append(args)
        self.timeouts.append(timeout)
        handler = self.handlers.get(args[0])
        if handler is None:
            return DockerResult(exit_code=0, stdout=b"{}")
        return handler(args)

    def on(self, subcommand: str, handler) -> None:
        self.handlers[subcommand] = handler

    # -- readers
    def calls_of(self, subcommand: str) -> list[list[str]]:
        return [call for call in self.calls if call and call[0] == subcommand]

    @property
    def last_run(self) -> list[str]:
        runs = self.calls_of("run")
        assert runs, "no `docker run` was issued"
        return runs[-1]

    def flag(self, name: str, argv: list[str] | None = None) -> str:
        """The value following ``name`` in the run argv."""
        argv = argv if argv is not None else self.last_run
        return argv[argv.index(name) + 1]

    def flags(self, name: str, argv: list[str] | None = None) -> list[str]:
        argv = argv if argv is not None else self.last_run
        return [argv[i + 1] for i, item in enumerate(argv) if item == name]


def mount_source(argv: list[str], container_path: str) -> Path:
    """The host side of the mount landing at ``container_path``."""
    for value in [argv[i + 1] for i, item in enumerate(argv) if item == "--volume"]:
        source, target = value.split(":")[0], value.split(":")[1]
        if target == container_path:
            return Path(source)
    raise AssertionError(f"no mount for {container_path} in {argv}")


def scanner_writes(verdict=VERDICT, report=b'{"ok": true}', candidate=b"{}"):
    """A handler that behaves like a scanner container: files out, verdict on stdout.

    It writes through the *mount source* in the argv, which is what makes the
    host-path translation observable: point the mapping somewhere wrong and
    these files land somewhere wrong too.
    """

    def handler(argv: list[str]) -> DockerResult:
        outbound = mount_source(argv, CONTAINER_OUTBOUND)
        brief = mount_source(argv, CONTAINER_DAILY_BRIEF)
        job = (outbound / "flagged" / "hello-1")
        job.mkdir(parents=True, exist_ok=True)
        (job / "report.json").write_bytes(report)
        (job / "message.eml").write_bytes(RAW)
        staged = brief / "daily-brief-2026-08-16" / "hello-1"
        staged.mkdir(parents=True, exist_ok=True)
        (staged / "candidate.json").write_bytes(candidate)
        return DockerResult(exit_code=0, stdout=json.dumps(verdict).encode())

    return handler


@pytest.fixture
def layout(tmp_path) -> dict[str, Path]:
    """A dispatcher-side data root, laid out the way compose mounts one."""
    data = tmp_path / "data"
    rules = tmp_path / "rules"
    for path in (data / "lists", data / "outbound", data / "daily-brief", rules):
        path.mkdir(parents=True)
    return {"root": tmp_path, "data": data, "rules": rules}


@pytest.fixture
def settings(layout) -> ContainerSettings:
    """Host paths equal to local ones -- the un-containerised dispatcher case."""
    data = layout["data"]
    return ContainerSettings(
        host_data_dir=data,
        data_dir=data,
        host_rules_dir=layout["rules"],
        rules_dir=layout["rules"],
        lists_dir=data / "lists",
        outbound_dir=data / "outbound",
        daily_brief_dir=data / "daily-brief",
        spool_dir=data / "dispatcher" / "scan-spool",
        user="1000:1000",
    )


@pytest.fixture
def docker() -> FakeDocker:
    return FakeDocker()


@pytest.fixture
def runner(settings, docker) -> ContainerRunner:
    return ContainerRunner(settings, timeout=90.0, docker=docker, token_factory=lambda: TOKEN)


# -- the hardening ------------------------------------------------------------


def test_the_container_is_disposable_and_unprivileged(runner, docker):
    """The flags that bound a hostile message, asserted one by one."""
    docker.on("run", scanner_writes())
    runner.scan(RAW)
    argv = docker.last_run

    assert argv[0] == "run"
    assert "--rm" in argv, "the container must delete itself"
    assert docker.flag("--network") == "none", "a scanner must have no network"
    assert "--read-only" in argv, "the root filesystem must be immutable"
    assert docker.flag("--cap-drop") == "ALL"
    assert docker.flag("--security-opt") == "no-new-privileges"
    assert docker.flag("--user") == "1000:1000"


def test_a_crafted_message_is_bounded_by_resource_caps(runner, docker):
    """An archive bomb or a fork bomb dies with the container, not with the host."""
    docker.on("run", scanner_writes())
    runner.scan(RAW)

    assert docker.flag("--memory") == "512m"
    # Equal to --memory, or the cap is evaded by swapping.
    assert docker.flag("--memory-swap") == docker.flag("--memory")
    assert docker.flag("--pids-limit") == "128"
    assert docker.flag("--cpus") == "1.0"

    tmpfs = docker.flag("--tmpfs")
    assert tmpfs.startswith("/tmp:")
    for option in ("noexec", "nosuid", "nodev", "size=64m"):
        assert option in tmpfs, f"tmpfs is missing {option}"


def test_the_docker_socket_is_never_mounted(runner, docker):
    """The whole reason a socket-proxy exists: that path is host-root-equivalent."""
    docker.on("run", scanner_writes())
    runner.scan(RAW)

    assert not any("docker.sock" in item for item in docker.last_run)


def test_the_scan_container_is_labelled_for_reaping_and_carries_no_personal_data(
    runner, docker
):
    docker.on("run", scanner_writes())
    runner.scan(RAW)
    argv = docker.last_run

    assert "email-guard.role=scanner" in docker.flags("--label")
    assert f"email-guard.scan={TOKEN}" in docker.flags("--label")
    assert docker.flag("--name") == f"email-guard-scan-{TOKEN}"
    # `docker ps` output is not a place for correspondents' addresses.
    assert not any("sender@example.com" in item for item in argv)


# -- what the container can and cannot see ------------------------------------


def test_only_this_message_the_rules_and_the_lists_go_in_and_all_read_only(
    runner, docker, settings
):
    docker.on("run", scanner_writes())
    runner.scan(RAW)
    mounts = docker.flags("--volume")

    spool = settings.spool_dir / TOKEN
    assert f"{spool / 'message.eml'}:{CONTAINER_MESSAGE}:ro" in mounts
    assert f"{settings.rules_dir}:/rules:ro" in mounts
    assert f"{settings.lists_dir}:{CONTAINER_LISTS}:ro" in mounts


def test_the_shared_outbound_is_never_exposed_to_the_message(runner, docker, settings):
    """A suspect message does not get the archive of every prior suspect message."""
    docker.on("run", scanner_writes())
    runner.scan(RAW)
    mounts = docker.flags("--volume")

    writable = [mount for mount in mounts if not mount.endswith(":ro")]
    assert len(writable) == 2, "exactly two writable mounts: this scan's own output"
    for mount in writable:
        source = Path(mount.split(":")[0])
        assert settings.spool_dir in source.parents, f"{source} is not private to this scan"
    assert str(settings.outbound_dir) not in [m.split(":")[0] for m in mounts]
    assert str(settings.daily_brief_dir) not in [m.split(":")[0] for m in mounts]


def test_the_scanner_is_steered_only_through_its_own_environment(runner, docker):
    """No --outbound-dir flags: the scanner resolves its own configuration."""
    docker.on("run", scanner_writes())
    runner.scan(RAW)
    env = docker.flags("--env")

    assert "EMAIL_GUARD_RULES_DIR=/rules" in env
    assert f"EMAIL_GUARD_LISTS_DIR={CONTAINER_LISTS}" in env
    assert f"EMAIL_GUARD_OUTBOUND_DIR={CONTAINER_OUTBOUND}" in env
    assert f"EMAIL_GUARD_DAILY_BRIEF_DIR={CONTAINER_DAILY_BRIEF}" in env
    assert not any(item.startswith("--outbound-dir") for item in docker.last_run)


def test_the_image_and_the_message_are_the_last_two_arguments(runner, docker):
    docker.on("run", scanner_writes())
    runner.scan(RAW)

    assert docker.last_run[-2:] == ["email-guard-scanner:0.1.0", CONTAINER_MESSAGE]


def test_the_image_is_never_pulled_from_a_registry(runner, docker):
    """A scanner image fetched from the internet is not the scanner image."""
    docker.on("run", scanner_writes())
    runner.scan(RAW)

    assert docker.flag("--pull") == "never"


# -- the host path model ------------------------------------------------------


def test_mount_sources_are_host_paths_not_the_dispatchers_own(layout, docker):
    """The gotcha: the daemon resolves the source, so it must be a host path.

    Pass the dispatcher's internal path and the container mounts nothing
    useful -- and fails later with an unrelated-looking rules-pack error.
    """
    data = layout["data"]
    host_root = Path("/srv/email-guard")
    settings = ContainerSettings(
        host_data_dir=host_root / "data",
        data_dir=data,
        host_rules_dir=host_root / "rules",
        rules_dir=layout["rules"],
        lists_dir=data / "lists",
        outbound_dir=data / "outbound",
        daily_brief_dir=data / "daily-brief",
        spool_dir=data / "dispatcher" / "scan-spool",
        user="1000:1000",
    )
    runner = ContainerRunner(settings, docker=docker, token_factory=lambda: TOKEN)
    docker.on("run", lambda argv: DockerResult(exit_code=0, stdout=json.dumps(VERDICT).encode()))
    runner.scan(RAW)

    assert mount_source(docker.last_run, CONTAINER_MESSAGE) == (
        host_root / "data" / "dispatcher" / "scan-spool" / TOKEN / "message.eml"
    )
    assert mount_source(docker.last_run, CONTAINER_LISTS) == host_root / "data" / "lists"
    assert mount_source(docker.last_run, "/rules") == host_root / "rules"
    # And nothing leaked the dispatcher's own view of those trees.
    assert not any(str(data) in item for item in docker.flags("--volume"))


def test_a_data_directory_outside_the_root_is_refused_at_startup(layout, tmp_path):
    """Untranslatable paths are a configuration error, not a per-message surprise."""
    settings = ContainerSettings(
        host_data_dir=layout["data"],
        data_dir=layout["data"],
        host_rules_dir=layout["rules"],
        rules_dir=layout["rules"],
        lists_dir=tmp_path / "elsewhere" / "lists",  # outside the data root
        outbound_dir=layout["data"] / "outbound",
        daily_brief_dir=layout["data"] / "daily-brief",
        spool_dir=layout["data"] / "dispatcher" / "scan-spool",
        user="1000:1000",
    )
    with pytest.raises(ContainerConfigError, match="outside the data root"):
        ContainerRunner(settings, docker=FakeDocker())


def test_a_missing_mount_is_refused_at_startup(layout):
    """A data root that is not there means a volume the dispatcher never got."""
    settings = ContainerSettings(
        host_data_dir=layout["root"] / "absent",
        data_dir=layout["root"] / "absent",
        host_rules_dir=layout["rules"],
        rules_dir=layout["rules"],
        lists_dir=layout["root"] / "absent" / "lists",
        outbound_dir=layout["root"] / "absent" / "outbound",
        daily_brief_dir=layout["root"] / "absent" / "daily-brief",
        spool_dir=layout["root"] / "absent" / "spool",
        user="1000:1000",
    )
    with pytest.raises(ContainerConfigError, match="does not exist inside the dispatcher"):
        ContainerRunner(settings, docker=FakeDocker())


def test_a_root_scanner_container_is_refused(settings):
    """Non-root even inside a throwaway."""
    with pytest.raises(ContainerConfigError, match="must not run as root"):
        ContainerRunner(
            ContainerSettings(**{**settings.__dict__, "user": "0:0"}), docker=FakeDocker()
        )


def test_an_empty_image_is_refused(settings):
    with pytest.raises(ContainerConfigError, match="container.image is empty"):
        ContainerRunner(
            ContainerSettings(**{**settings.__dict__, "image": ""}), docker=FakeDocker()
        )


# -- the verdict contract, identical to the subprocess runner ------------------


def test_a_clean_scan_returns_the_verdict(runner, docker):
    docker.on("run", scanner_writes())

    outcome = runner.scan(RAW)

    assert outcome.ok
    assert outcome.exit_code == 0
    assert outcome.bucket == "flagged"
    assert outcome.sender == "sender@example.com"


def test_a_non_zero_exit_is_a_failed_outcome_not_an_exception(runner, docker):
    docker.on("run", lambda argv: DockerResult(exit_code=3, stderr=b"contradictory lists"))

    outcome = runner.scan(RAW)

    assert not outcome.ok
    assert outcome.exit_code == 3
    assert "contradictory lists" in outcome.stderr


def test_a_missing_image_says_so_rather_than_failing_downstream(runner, docker):
    """The failure a stale build produces, named at its source."""
    docker.on(
        "run",
        lambda argv: DockerResult(
            exit_code=125, stderr=b"docker: Error response from daemon: No such image: x"
        ),
    )

    outcome = runner.scan(RAW)

    assert not outcome.ok
    assert "docker compose build scanner" in outcome.error


def test_an_oom_kill_is_reported_as_the_memory_cap(runner, docker):
    docker.on("run", lambda argv: DockerResult(exit_code=137))

    outcome = runner.scan(RAW)

    assert not outcome.ok
    assert "512m memory cap" in outcome.error


def test_unparseable_stdout_is_a_failure(runner, docker):
    docker.on("run", lambda argv: DockerResult(exit_code=0, stdout=b"not json"))

    outcome = runner.scan(RAW)

    assert not outcome.ok
    assert "not valid JSON" in outcome.error


def test_a_json_non_object_is_a_failure(runner, docker):
    docker.on("run", lambda argv: DockerResult(exit_code=0, stdout=b"[1, 2]"))

    outcome = runner.scan(RAW)

    assert not outcome.ok
    assert "not a JSON object" in outcome.error


def test_docker_missing_entirely_is_a_failed_outcome(runner, docker):
    docker.on("run", lambda argv: DockerResult(exit_code=-1, error="cannot run docker: [Errno 2]"))

    outcome = runner.scan(RAW)

    assert not outcome.ok
    assert "cannot run docker" in outcome.error


# -- timeout ------------------------------------------------------------------


def test_a_timed_out_container_is_killed_by_name(runner, docker):
    """``--rm`` only fires on a clean exit, so a hung scan has to be removed."""
    docker.on("run", lambda argv: DockerResult(exit_code=-1, timed_out=True))

    outcome = runner.scan(RAW)

    assert not outcome.ok
    assert "timed out after 90.0s" in outcome.error
    assert docker.calls_of("rm") == [["rm", "--force", f"email-guard-scan-{TOKEN}"]]


def test_the_scan_timeout_is_handed_to_docker(runner, docker):
    docker.on("run", scanner_writes())
    runner.scan(RAW)

    assert docker.timeouts[docker.calls.index(docker.last_run)] == 90.0


# -- output collection --------------------------------------------------------


def test_the_private_output_is_moved_into_the_shared_stores(runner, docker, settings):
    docker.on("run", scanner_writes())

    runner.scan(RAW)

    report = settings.outbound_dir / "flagged" / "hello-1" / "report.json"
    assert report.read_bytes() == b'{"ok": true}'
    assert (settings.outbound_dir / "flagged" / "hello-1" / "message.eml").read_bytes() == RAW
    candidate = (
        settings.daily_brief_dir / "daily-brief-2026-08-16" / "hello-1" / "candidate.json"
    )
    assert candidate.is_file()


def test_the_verdict_paths_point_at_where_the_files_actually_are(runner, docker, settings):
    """A webhook receiver gets paths that exist, not container-internal ones."""
    docker.on("run", scanner_writes())

    outcome = runner.scan(RAW)

    written = outcome.verdict["written"]
    assert written["report"] == str(
        settings.outbound_dir / "flagged" / "hello-1" / "report.json"
    )
    assert written["candidate"].startswith(str(settings.daily_brief_dir))
    # Non-path fields are untouched.
    assert written["job"] == "hello-1"
    assert written["bucket"] == "flagged"


def test_the_spool_is_cleaned_up_after_every_scan(runner, docker, settings):
    docker.on("run", scanner_writes())

    runner.scan(RAW)

    assert not (settings.spool_dir / TOKEN).exists()


def test_the_spool_is_cleaned_up_even_when_the_scan_fails(runner, docker, settings):
    docker.on("run", lambda argv: DockerResult(exit_code=1, stderr=b"boom"))

    runner.scan(RAW)

    assert not (settings.spool_dir / TOKEN).exists()


def test_a_verdict_without_a_written_section_survives_unharmed(runner, docker):
    """``--dry-run`` verdicts carry ``written: null``."""
    docker.on(
        "run",
        lambda argv: DockerResult(
            exit_code=0, stdout=json.dumps({"bucket": "cleared", "written": None}).encode()
        ),
    )

    outcome = runner.scan(RAW)

    assert outcome.ok
    assert outcome.verdict["written"] is None


# -- orphan reaping -----------------------------------------------------------


def test_orphans_from_a_previous_life_are_removed(runner, docker):
    """A dispatcher killed mid-scan leaves a container holding its quotas."""
    docker.on("ps", lambda argv: DockerResult(exit_code=0, stdout=b"abc123\ndef456\n"))

    removed = runner.reap_orphans()

    assert removed == 2
    assert docker.calls_of("ps")[0] == [
        "ps",
        "--all",
        "--quiet",
        "--filter",
        "label=email-guard.role=scanner",
    ]
    assert docker.calls_of("rm") == [["rm", "--force", "abc123", "def456"]]


def test_no_orphans_means_no_removal_call(runner, docker):
    docker.on("ps", lambda argv: DockerResult(exit_code=0, stdout=b"\n"))

    assert runner.reap_orphans() == 0
    assert docker.calls_of("rm") == []


def test_a_failure_to_list_orphans_never_blocks_the_queue(runner, docker):
    """Draining mail matters more than tidy bookkeeping."""
    docker.on("ps", lambda argv: DockerResult(exit_code=1, stderr=b"permission denied"))

    assert runner.reap_orphans() == 0
    assert docker.calls_of("rm") == []


def test_a_failure_to_remove_orphans_never_raises(runner, docker):
    docker.on("ps", lambda argv: DockerResult(exit_code=0, stdout=b"abc123\n"))
    docker.on("rm", lambda argv: DockerResult(exit_code=1, stderr=b"no such container"))

    assert runner.reap_orphans() == 0
