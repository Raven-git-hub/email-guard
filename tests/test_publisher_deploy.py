"""Deployment facts about the acheron bridge that no function can express.

The hard rule of this feature is a *deployment* property: the sandbox never
touches the network partition. A host-side publisher is only a real boundary if
the containers genuinely cannot reach the share -- so the things asserted here
are the ones that would quietly undo it:

* the publisher is not a package root, so no image installs it;
* no Dockerfile copies it;
* no compose service mounts acheron, or is handed its path in an environment
  variable;
* the two systemd units run as a non-root user, read the shared
  ``EnvironmentFile``, and invoke the commands the package actually provides.

Parsing the files beats matching substrings, which is the same call
``tests/test_rules_sync_deploy.py`` makes for the compose assertions.
"""

from __future__ import annotations

import configparser
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PUBLISHER = PROJECT_ROOT / "publisher"
SYSTEMD = PUBLISHER / "systemd"
COMPOSE = PROJECT_ROOT / "docker-compose.yml"
IMAGES = ("scanner", "dispatcher", "webui", "rules_sync")

ACHERON = "/mnt/network/acheron"


def unit(name: str) -> configparser.ConfigParser:
    """One systemd unit, parsed.

    ``strict=False`` because systemd allows a directive to repeat (the path unit
    has three ``PathModified=`` lines); ``optionxform=str`` because unit
    directives are case-sensitive.
    """
    parser = configparser.ConfigParser(strict=False, empty_lines_in_values=False)
    parser.optionxform = str
    parser.read(SYSTEMD / name, encoding="utf-8")
    return parser


# --- the boundary ----------------------------------------------------------------


def test_the_publisher_is_not_a_declared_package_root():
    """No image installs it, because no image may have it.

    `pip install .` walks `packages.find.where`; adding `publisher` there would
    put the code that can reach acheron inside every image built from this
    repository. It is stdlib-only and runs from the checkout instead.
    """
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"where\s*=\s*\[([^\]]+)\]", pyproject)
    assert match, "could not find packages.find `where` in pyproject.toml"
    roots = re.findall(r'"([^"]+)"', match.group(1))

    assert "publisher" not in roots
    assert set(roots) == set(IMAGES)


def test_the_test_suite_still_imports_it():
    """It is not installed, so it is on the test path explicitly. Both must stay true."""
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert re.search(r'^pythonpath\s*=\s*\["publisher"\]', pyproject, re.MULTILINE)


def test_no_image_copies_the_publisher():
    for image in IMAGES:
        dockerfile = (PROJECT_ROOT / image / "Dockerfile").read_text(encoding="utf-8")
        assert not re.search(r"^COPY\s+publisher/", dockerfile, re.MULTILINE), (
            f"{image}/Dockerfile copies publisher/ -- that image could then reach acheron"
        )


def test_no_container_is_given_the_partition():
    """The rule, stated against the file that would break it.

    A volume line or an environment variable naming acheron is the only way a
    container could learn the path, let alone reach it.
    """
    compose = [
        line
        for line in COMPOSE.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]

    offenders = [line.strip() for line in compose if ACHERON in line]
    assert offenders == [], (
        "no compose service may mount or be told about the network partition: "
        f"{offenders}"
    )


def test_the_publisher_depends_on_nothing_outside_the_standard_library():
    """It runs on the host with no virtualenv, so a third-party import would break it."""
    third_party = {"requests", "yaml", "fastapi", "httpx", "pydantic", "uvicorn"}
    for source in sorted((PUBLISHER / "email_guard_publisher").glob("*.py")):
        text = source.read_text(encoding="utf-8")
        imported = set(re.findall(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", text, re.MULTILINE))
        roots = {name.split(".")[0] for name in imported}
        assert not (roots & third_party), f"{source.name} imports {roots & third_party}"
        assert "email_guard" not in roots, (
            f"{source.name} imports the scanner -- the publisher must stay standalone"
        )


# --- the units -------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "email-guard-publisher.path",
        "email-guard-publisher.service",
        "email-guard-publisher.timer",
        "email-guard-cleanup.service",
        "email-guard-cleanup.timer",
    ],
)
def test_the_unit_ships_in_the_repository(name):
    assert (SYSTEMD / name).is_file()


def test_the_environment_file_sample_ships_too():
    sample = (SYSTEMD / "publisher.env.sample").read_text(encoding="utf-8")

    assert "EMAIL_GUARD_OUTBOUND_DIR=" in sample
    assert "EMAIL_GUARD_PUBLISH_DEST=" in sample
    assert "EMAIL_GUARD_OUTBOUND_RETENTION_DAYS" in sample


def test_the_path_unit_watches_the_outbound_tree_and_starts_the_publisher():
    parsed = unit("email-guard-publisher.path")

    assert parsed["Path"]["Unit"] == "email-guard-publisher.service"
    # configparser keeps the last value of a repeated key; the raw text carries
    # all three, one per bucket.
    watched = re.findall(
        r"^PathModified=(.+)$",
        (SYSTEMD / "email-guard-publisher.path").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert len(watched) == 3
    assert all(path.endswith(("/cleared", "/flagged", "/rejected")) for path in watched)
    assert all("/data/outbound/" in path for path in watched)


@pytest.mark.parametrize(
    "name, command",
    [
        ("email-guard-publisher.service", "publish"),
        ("email-guard-cleanup.service", "cleanup"),
    ],
)
def test_each_service_runs_the_command_the_package_provides(name, command):
    service = unit(name)["Service"]

    assert service["Type"] == "oneshot"
    assert service["ExecStart"].endswith(f"-m email_guard_publisher {command}")
    assert "python3" in service["ExecStart"]


@pytest.mark.parametrize(
    "name", ["email-guard-publisher.service", "email-guard-cleanup.service"]
)
def test_each_service_runs_as_a_non_root_user(name):
    """Root is not needed: the user owns the outbound tree and can write the share."""
    service = unit(name)["Service"]

    assert service["User"] not in ("root", "0")
    assert service["User"] == "1000"
    assert service["Group"] == "1000"
    assert service["NoNewPrivileges"] == "true"


@pytest.mark.parametrize(
    "name", ["email-guard-publisher.service", "email-guard-cleanup.service"]
)
def test_both_services_read_one_environment_file(name):
    """One file, so the source tree and retention can never skew between them."""
    service = unit(name)["Service"]

    assert service["EnvironmentFile"] == "/etc/email-guard/publisher.env"
    # `Environment=` repeats, and configparser keeps only the last value -- read
    # the raw text for the one that makes the package importable.
    raw = (SYSTEMD / name).read_text(encoding="utf-8")
    assert re.search(r"^Environment=PYTHONPATH=.*publisher$", raw, re.MULTILINE)


def test_only_the_publisher_may_write_the_partition():
    """The cleanup sweep is not given acheron at all -- enforced by systemd, not code."""
    publisher = unit("email-guard-publisher.service")["Service"]["ReadWritePaths"]
    cleanup = unit("email-guard-cleanup.service")["Service"]["ReadWritePaths"]

    assert ACHERON in publisher
    assert ACHERON not in cleanup
    assert "data/outbound" in cleanup


def test_the_timers_are_installed_and_target_the_right_services():
    backstop = unit("email-guard-publisher.timer")
    daily = unit("email-guard-cleanup.timer")

    assert backstop["Timer"]["Unit"] == "email-guard-publisher.service"
    assert daily["Timer"]["Unit"] == "email-guard-cleanup.service"
    assert daily["Timer"]["OnCalendar"] == "daily"
    # The backstop exists because the path unit can fire a beat too early.
    assert "OnUnitActiveSec" in backstop["Timer"]
    assert backstop["Install"]["WantedBy"] == "timers.target"
    assert daily["Install"]["WantedBy"] == "timers.target"


def test_the_documentation_covers_the_install_and_the_contract():
    """The two things an operator cannot infer from the units themselves."""
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    validation = (PROJECT_ROOT / "VALIDATION.md").read_text(encoding="utf-8")

    for text in (readme, validation):
        assert ACHERON in text
        assert "email-guard-publisher.path" in text
    assert "EMAIL_GUARD_OUTBOUND_RETENTION_DAYS" in readme
    assert "/etc/email-guard/publisher.env" in validation
