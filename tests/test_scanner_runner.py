"""Choosing a runner, and the seam that makes the choice possible.

The dispatcher's whole view of the scanner is one method. These tests pin that
down from both ends: the configuration that selects an implementation, and the
invariant that neither implementation is allowed to leak scanner internals back
into the dispatcher.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from email_guard_dispatcher import config
from email_guard_dispatcher.container_runner import ContainerRunner
from email_guard_dispatcher.scanner_client import ScannerClient, SubprocessRunner
from email_guard_dispatcher.scanner_runner import (
    ScannerRunner,
    ScanOutcome,
    build_scanner_runner,
)

DISPATCHER_PACKAGE = Path(config.__file__).resolve().parent


def load(environ=None, **kwargs):
    return config.load(environ=environ or {}, **kwargs)


# -- the seam -----------------------------------------------------------------


def test_both_runners_satisfy_the_interface():
    """One method, two isolation strategies, no difference upstream."""
    assert isinstance(SubprocessRunner(), ScannerRunner)
    # ContainerRunner is checked structurally rather than built here: it
    # validates its mounts at construction, which needs a real layout.
    assert hasattr(ContainerRunner, "scan")


def test_the_old_name_still_works():
    """The README's prose and the existing tests both say ``ScannerClient``."""
    assert ScannerClient is SubprocessRunner


def test_a_failed_scan_is_an_outcome_not_an_exception():
    """What keeps retry-then-quarantine identical for both runners."""
    outcome = ScanOutcome(ok=False, exit_code=125, error="nope")
    assert outcome.bucket is None
    assert outcome.final_level is None
    assert outcome.sender is None


# -- selection ----------------------------------------------------------------


def test_the_code_default_needs_no_daemon():
    """A plain checkout and the test suite must work with nothing installed."""
    assert load().scanner_runner == "subprocess"
    assert isinstance(build_scanner_runner(load()), SubprocessRunner)


def test_the_runner_can_be_selected_from_the_config_file(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"dispatcher": {"scanner_runner": "container"}}')

    assert load(config_path=path).scanner_runner == "container"


def test_the_environment_beats_the_config_file(tmp_path):
    """The documented resolution order, which compose relies on."""
    path = tmp_path / "config.json"
    path.write_text('{"dispatcher": {"scanner_runner": "subprocess"}}')

    settings = load({"EMAIL_GUARD_SCANNER_RUNNER": "container"}, config_path=path)

    assert settings.scanner_runner == "container"


def test_an_unknown_runner_is_refused_loudly(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"dispatcher": {"scanner_runner": "kubernetes"}}')

    with pytest.raises(config.ConfigError, match="scanner_runner must be one of"):
        load(config_path=path)


def test_selecting_the_container_runner_builds_one(tmp_path):
    """Including its startup validation -- a bad mapping fails here, not later."""
    data = tmp_path / "data"
    rules = tmp_path / "rules"
    for directory in (data / "lists", data / "outbound", data / "daily-brief", rules):
        directory.mkdir(parents=True)
    # config/config.json, not config.json: relative paths in the file resolve
    # against the *project root*, which is the config file's parent's parent.
    path = tmp_path / "config" / "config.json"
    path.parent.mkdir()
    path.write_text('{"dispatcher": {"scanner_runner": "container"}}')

    settings = load(
        {
            "EMAIL_GUARD_SCANNER_RUNNER": "container",
            "EMAIL_GUARD_CONTAINER_DATA_DIR": str(data),
            "EMAIL_GUARD_CONTAINER_RULES_DIR": str(rules),
            # This test process runs as root in CI containers; the scanner
            # container must not, so the uid is named explicitly.
            "EMAIL_GUARD_CONTAINER_USER": "1000:1000",
        },
        config_path=path,
    )

    assert isinstance(build_scanner_runner(settings), ContainerRunner)


# -- the container block ------------------------------------------------------


def test_the_scanner_image_defaults_to_the_tag_compose_builds():
    """A default that does not match `docker compose build scanner` is a trap."""
    assert load().container.image == "email-guard-scanner:0.1.0"


def test_the_scanner_image_can_be_named_in_config(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"dispatcher": {"container": {"image": "email-guard-scanner:2.0"}}}')

    assert load(config_path=path).container.image == "email-guard-scanner:2.0"


def test_the_scanner_image_can_be_named_in_the_environment():
    settings = load({"EMAIL_GUARD_SCANNER_IMAGE": "email-guard-scanner:dev"})

    assert settings.container.image == "email-guard-scanner:dev"


def test_host_paths_default_to_the_dispatchers_own(tmp_path):
    """Correct whenever the dispatcher is not itself containerised."""
    settings = load({"EMAIL_GUARD_CONTAINER_DATA_DIR": str(tmp_path / "data")})

    assert settings.container.host_data_dir == settings.container.data_dir


def test_host_paths_can_be_pointed_somewhere_else_entirely(tmp_path):
    """Which is what compose does, because the daemon resolves the host side."""
    settings = load(
        {
            "EMAIL_GUARD_CONTAINER_DATA_DIR": "/app/data",
            "EMAIL_GUARD_HOST_DATA_DIR": "/srv/email-guard/data",
            "EMAIL_GUARD_CONTAINER_RULES_DIR": "/app/rules",
            "EMAIL_GUARD_HOST_RULES_DIR": "/srv/email-guard/rules",
        }
    )

    assert settings.container.data_dir == Path("/app/data")
    assert settings.container.host_data_dir == Path("/srv/email-guard/data")
    assert settings.container.rules_dir == Path("/app/rules")
    assert settings.container.host_rules_dir == Path("/srv/email-guard/rules")


def test_the_resource_caps_have_documented_defaults():
    """These multiply by `concurrency`; the README states the total."""
    container = load().container

    assert container.memory == "512m"
    assert container.pids_limit == 128
    assert container.cpus == "1.0"
    assert container.tmpfs_size == "64m"


def test_the_resource_caps_are_tunable(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        '{"dispatcher": {"container": '
        '{"memory": "256m", "pids_limit": 64, "cpus": "0.5", "tmpfs_size": "32m"}}}'
    )

    container = load(config_path=path).container

    assert (container.memory, container.pids_limit) == ("256m", 64)
    assert (container.cpus, container.tmpfs_size) == ("0.5", "32m")


def test_the_container_block_must_be_an_object(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"dispatcher": {"container": "yes please"}}')

    with pytest.raises(config.ConfigError, match="must be an object"):
        load(config_path=path)


# -- IDLE settings ------------------------------------------------------------


def test_idle_is_on_by_default_and_re_issued_inside_the_server_window():
    """On-arrival processing is the point; 1500s is inside the ~29 minute limit."""
    imap = load().imap

    assert imap.idle is True
    assert imap.idle_timeout_seconds == 1500
    assert imap.idle_timeout_seconds < 29 * 60


def test_idle_can_be_turned_off_without_editing_the_config_file():
    assert load({"EMAIL_GUARD_IMAP_IDLE": "0"}).imap.idle is False
    assert load({"EMAIL_GUARD_IMAP_IDLE": "false"}).imap.idle is False
    assert load({"EMAIL_GUARD_IMAP_IDLE": "1"}).imap.idle is True


def test_idle_can_be_turned_off_in_the_config_file(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"imap": {"idle": false, "idle_timeout_seconds": 600}}')

    imap = load(config_path=path).imap

    assert imap.idle is False
    assert imap.idle_timeout_seconds == 600


# -- code and deployment must agree -------------------------------------------

COMPOSE = (DISPATCHER_PACKAGE.parents[1] / "docker-compose.yml").read_text(encoding="utf-8")


def test_compose_builds_the_tag_the_dispatcher_asks_for():
    """A drifted tag fails every scan with "No such image".

    ``EMAIL_GUARD_SCANNER_IMAGE`` in compose, the ``image:`` the scanner
    service builds, and the code default all name the same thing -- and there
    is nothing at runtime that would notice if they stopped.
    """
    image = load().container.image

    assert f"image: {image}" in COMPOSE, "compose does not build the default image tag"
    assert f'EMAIL_GUARD_SCANNER_IMAGE: "{image}"' in COMPOSE


def test_the_deployed_dispatcher_defaults_to_the_container_runner():
    """The code default is subprocess; the *deployment* opts into isolation."""
    assert 'EMAIL_GUARD_SCANNER_RUNNER: "container"' in COMPOSE
    assert load().scanner_runner == "subprocess"


def test_the_dispatcher_is_never_given_the_docker_socket():
    """Only the socket-proxy may see it -- that path is host-root-equivalent.

    Comments are stripped first: the socket-proxy's own explanation of why the
    dispatcher must not have the socket names the path, and prose is not
    configuration.
    """
    directives = "\n".join(
        line for line in COMPOSE.splitlines() if not line.lstrip().startswith("#")
    )
    dispatcher_block = directives.split("\n  dispatcher:", 1)[1].split(
        "\n  docker-socket-proxy:", 1
    )[0]

    assert "docker.sock" not in dispatcher_block
    assert "DOCKER_HOST" in dispatcher_block
    # And exactly one line in the whole file mounts it.
    mounts = [line for line in directives.splitlines() if "/var/run/docker.sock" in line]
    assert len(mounts) == 1
    assert mounts[0].strip().endswith(":ro")


def test_the_review_console_stays_on_loopback():
    """One character between "localhost only" and "on the LAN"."""
    assert '"127.0.0.1:8080:8080"' in COMPOSE


# -- the ground rule ----------------------------------------------------------


def test_the_dispatcher_still_imports_nothing_from_the_scanner():
    """The subprocess/container boundary has to be real, not nominal.

    The runner abstraction is the *only* seam. If the dispatcher ever imports
    ``email_guard``, the scanner has stopped being an opaque unit and the
    container it runs in has stopped being a boundary worth having.
    """
    offenders = []
    forbidden = re.compile(r"^\s*(?:from|import)\s+email_guard(?!_)", re.MULTILINE)
    for source in sorted(DISPATCHER_PACKAGE.rglob("*.py")):
        if forbidden.search(source.read_text(encoding="utf-8")):
            offenders.append(source.name)

    assert offenders == []
