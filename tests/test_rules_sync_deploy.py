"""Deployment facts about the rules updater that only compose can express.

Several guarantees in this feature are not properties of any Python function --
they are properties of the compose file and the Dockerfiles, and each one is a
real failure if it regresses:

* the updater must never acquire docker access;
* exactly one component may write the rules tree;
* the scanner's rules mount must stay read-only;
* the console must reach the updater over an internal network, not the host.

Parsing the YAML beats matching substrings, the same call
``tests/test_scanner_runner.py`` already makes for the socket-proxy and the
console's port publication.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("yaml", reason="compose assertions need PyYAML")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
COMPOSE = PROJECT_ROOT / "docker-compose.yml"
UPDATER = "rules-updater"


@pytest.fixture(scope="module")
def compose() -> dict:
    import yaml

    with COMPOSE.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def compose_text() -> str:
    """The file with comments stripped, for line-level assertions.

    The comments talk about the docker socket at length; only the real mount
    lines may be counted.
    """
    lines = [
        line for line in COMPOSE.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]
    return "\n".join(lines)


@pytest.fixture(scope="module")
def updater(compose: dict) -> dict:
    assert UPDATER in compose["services"], "the rules-updater service is missing"
    return compose["services"][UPDATER]


# --- no new docker exposure ------------------------------------------------------


def test_the_updater_never_sees_the_docker_socket(updater: dict):
    """It creates no containers, so it has no business being able to."""
    volumes = updater.get("volumes") or []

    assert not any("docker.sock" in str(volume) for volume in volumes)
    assert "DOCKER_HOST" not in (updater.get("environment") or {})
    assert "dockerproxy" not in (updater.get("networks") or [])


def test_the_socket_is_still_mounted_exactly_once_and_read_only(compose_text: str):
    """The stack-wide invariant, re-asserted now that a service was added."""
    mounts = [
        line.strip()
        for line in compose_text.splitlines()
        if "/var/run/docker.sock" in line
    ]

    assert len(mounts) == 1, f"expected exactly one socket mount, found {mounts}"
    assert mounts[0].endswith(":ro")


# --- exactly one writer of the rules tree -----------------------------------------


def _rules_mounts(service: dict) -> list[str]:
    return [
        str(volume)
        for volume in (service.get("volumes") or [])
        if "rules" in str(volume)
    ]


def test_only_the_updater_can_write_the_rules_tree(compose: dict):
    """Two writers racing for one symlink is the failure this prevents."""
    writable: list[tuple[str, str]] = []
    for name, service in compose["services"].items():
        for mount in _rules_mounts(service):
            if not mount.endswith(":ro"):
                writable.append((name, mount))

    assert [name for name, _ in writable] == [UPDATER], (
        f"exactly one service may write the rules tree, found {writable}"
    )


def test_the_updaters_seed_mount_is_read_only(updater: dict):
    """`rules/` is tracked. The updater reads it and never writes it."""
    seed = [m for m in _rules_mounts(updater) if m.startswith("./rules:")]

    assert seed == ["./rules:/app/rules:ro"]


def test_the_dispatchers_rules_mount_is_read_only(compose: dict):
    mounts = _rules_mounts(compose["services"]["dispatcher"])

    assert any(mount.endswith(":/app/rules:ro") for mount in mounts)


def test_the_updater_cannot_reach_the_personal_data_volume(updater: dict):
    """A rules update and a list edit are independent operations."""
    volumes = [str(volume) for volume in (updater.get("volumes") or [])]

    assert not any("email-guard-data" in volume for volume in volumes)
    assert not any("/app/data" in volume for volume in volumes)


# --- the mount cutover -------------------------------------------------------------


def test_the_default_wiring_is_todays_wiring(compose: dict):
    """A deploy that has not cut over must behave exactly as it did before.

    The variables are unset by default, so compose substitutes the fallbacks and
    the result is byte-for-byte the pre-auto-updater configuration.
    """
    dispatcher = compose["services"]["dispatcher"]
    environment = dispatcher["environment"]

    assert environment["EMAIL_GUARD_CONTAINER_RULES_DIR"] == (
        "/app/rules${EMAIL_GUARD_RULES_LIVE_POINTER:-}"
    )
    assert environment["EMAIL_GUARD_HOST_RULES_DIR"] == (
        "${EMAIL_GUARD_HOST_ROOT}/"
        "${EMAIL_GUARD_RULES_LIVE_NAME:-rules}${EMAIL_GUARD_RULES_LIVE_POINTER:-}"
    )
    assert (
        "./${EMAIL_GUARD_RULES_LIVE_NAME:-rules}:/app/rules:ro"
        in [str(volume) for volume in dispatcher["volumes"]]
    )


def test_the_dispatcher_binds_a_directory_never_the_symlink(compose: dict):
    """The subtlety that makes a promote visible without a restart.

    Binding `rules-live/current` would make the daemon resolve the symlink once,
    at container start, and mount the release it pointed at then -- this
    long-lived container would never see a later swap. Binding the directory
    mounts the directory's own inode, so `current` is an entry inside it and the
    next path walk sees the new target.
    """
    dispatcher = compose["services"]["dispatcher"]
    binds = [str(volume) for volume in dispatcher["volumes"] if "rules" in str(volume)]

    assert not any("/current:" in bind for bind in binds), (
        "the dispatcher must bind the live ROOT, not the current symlink"
    )
    # The pointer is applied to the CONTAINER path instead, inside the bind.
    assert "${EMAIL_GUARD_RULES_LIVE_POINTER:-}" in (
        dispatcher["environment"]["EMAIL_GUARD_CONTAINER_RULES_DIR"]
    )


def test_the_dispatcher_networks_are_unchanged(compose: dict):
    """Pinned elsewhere too; restated here because this change touched it."""
    assert sorted(compose["services"]["dispatcher"]["networks"]) == [
        "dockerproxy",
        "mail",
    ]


# --- the control path ---------------------------------------------------------------


def test_the_console_reaches_the_updater_over_an_internal_network(compose: dict):
    assert compose["networks"]["rulesctl"]["internal"] is True
    assert sorted(compose["services"]["webui"]["networks"]) == ["default", "rulesctl"]
    assert sorted(compose["services"][UPDATER]["networks"]) == ["egress", "rulesctl"]


def test_the_console_keeps_the_default_network(compose: dict):
    """Naming only `rulesctl` would silently unpublish the console's port."""
    assert "default" in compose["services"]["webui"]["networks"]
    assert compose["services"]["webui"]["ports"] == [
        "${EMAIL_GUARD_WEBUI_BIND:-127.0.0.1}:${EMAIL_GUARD_WEBUI_HOST_PORT:-8080}:8080"
    ]


def test_the_updater_publishes_no_host_port(updater: dict):
    """`expose`, not `ports`: reachable on rulesctl, not from the host."""
    assert "ports" not in updater
    assert updater.get("expose") == ["8090"]


def test_the_console_is_told_where_the_updater_is(compose: dict):
    environment = compose["services"]["webui"]["environment"]

    assert "rules-updater:8090" in environment["EMAIL_GUARD_RULES_CONTROL_URL"]


def test_both_sides_read_the_control_token_from_one_variable(compose: dict):
    """One .env line feeds both, so the two can never skew."""
    console = compose["services"]["webui"]["environment"]
    service = compose["services"][UPDATER]["environment"]

    assert console["EMAIL_GUARD_RULES_CONTROL_TOKEN"] == (
        "${EMAIL_GUARD_RULES_CONTROL_TOKEN:-}"
    )
    assert service["EMAIL_GUARD_RULES_CONTROL_TOKEN"] == (
        "${EMAIL_GUARD_RULES_CONTROL_TOKEN:-}"
    )


# --- hardening parity ----------------------------------------------------------------


def test_the_updater_is_hardened_like_every_other_service(updater: dict):
    assert updater["read_only"] is True
    assert updater["cap_drop"] == ["ALL"]
    assert updater["security_opt"] == ["no-new-privileges:true"]
    assert "/tmp" in updater["tmpfs"]
    assert updater["user"] == "${EMAIL_GUARD_UID:-1000}:${EMAIL_GUARD_GID:-1000}"


def test_the_updater_defaults_to_the_public_repository(updater: dict):
    environment = updater["environment"]

    assert environment["EMAIL_GUARD_RULES_REPO_URL"].endswith(
        "https://github.com/Raven-git-hub/email-guard}"
    )
    assert "main" in environment["EMAIL_GUARD_RULES_BRANCH"]
    assert "24h" in environment["EMAIL_GUARD_RULES_PULL_INTERVAL"]


# --- the image ------------------------------------------------------------------------


def test_the_updater_image_carries_git_and_a_ca_bundle():
    """Without ca-certificates an HTTPS fetch fails as an opaque TLS error."""
    dockerfile = (PROJECT_ROOT / "rules_sync" / "Dockerfile").read_text(encoding="utf-8")

    install = [line for line in dockerfile.splitlines() if "apt-get install" in line]
    assert install, "the updater image must install git"
    assert "git" in install[0]
    assert "ca-certificates" in install[0]
    assert "--no-install-recommends" in install[0]
    assert "rm -rf /var/lib/apt/lists/*" in dockerfile


def test_the_updater_image_has_no_docker_cli():
    dockerfile = (PROJECT_ROOT / "rules_sync" / "Dockerfile").read_text(encoding="utf-8")

    assert "docker:27-cli" not in dockerfile
    assert "COPY --from=dockercli" not in dockerfile


def _declared_roots() -> list[str]:
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"where\s*=\s*\[([^\]]+)\]", pyproject)
    assert match, "could not find packages.find `where` in pyproject.toml"
    return re.findall(r'"([^"]+)"', match.group(1))


def _copies(dockerfile: str, root: str) -> bool:
    return bool(re.search(rf"^COPY\s+{re.escape(root)}/", dockerfile, re.MULTILINE))


def _stubs(dockerfile: str, root: str) -> bool:
    return bool(
        re.search(rf"^RUN mkdir -p .*\b{re.escape(root)}\b", dockerfile, re.MULTILINE)
    )


def test_every_image_creates_every_declared_package_root():
    """A fifth `packages.find` root breaks `pip install .` in the other images.

    Each Dockerfile must COPY or `mkdir -p` all four, or the install fails on
    the missing ones. Asserted so the next root added cannot repeat it.
    """
    roots = _declared_roots()
    assert set(roots) == {"scanner", "dispatcher", "webui", "rules_sync"}

    for image in ("scanner", "dispatcher", "webui", "rules_sync"):
        dockerfile = (PROJECT_ROOT / image / "Dockerfile").read_text(encoding="utf-8")
        for root in roots:
            provided = _copies(dockerfile, root) or _stubs(dockerfile, root)
            assert provided, f"{image}/Dockerfile neither COPYs nor mkdirs {root!r}"


def test_each_image_carries_the_code_it_runs_and_stubs_the_rest():
    """Which roots are REAL in each image, not merely present.

    An empty stub satisfies `pip install .` and installs nothing, so "the root
    exists" says nothing about whether that package is importable at runtime.
    The updater is the case that matters: it stubbed `scanner/`, which made
    `email_guard` absent, which made the pack's own validator report every
    `func` rule as "failed to import" and reject every pull. See
    ``tests/test_rules_sync_validation_env.py`` for the behaviour itself.
    """
    real = {
        # image     -> the roots it genuinely installs
        "scanner": {"scanner"},
        "dispatcher": {"dispatcher", "scanner"},
        "webui": {"webui", "scanner", "dispatcher"},
        # rules_sync's OWN code imports nothing from the engine. `scanner` is
        # here for the validation SUBPROCESS, which loads the pulled pack's
        # `scan/*_funcs.py`, and those import `email_guard.links`.
        "rules_sync": {"rules_sync", "scanner"},
    }
    roots = set(_declared_roots())

    for image, installed in real.items():
        dockerfile = (PROJECT_ROOT / image / "Dockerfile").read_text(encoding="utf-8")
        for root in installed:
            assert _copies(dockerfile, root), (
                f"{image}/Dockerfile must COPY {root}/ -- an empty stub installs "
                "no code, and this image needs that package importable"
            )
        for root in roots - installed:
            assert _stubs(dockerfile, root) and not _copies(dockerfile, root), (
                f"{image}/Dockerfile should stub {root!r}, not copy it"
            )


def test_the_updater_installs_the_engine_rather_than_stubbing_it():
    """The regression, stated as the one line of Dockerfile it lives in.

    `rules/scan/level*_funcs.py` import `email_guard.links`, and `validate.py`
    proves a pack will run by exec'ing those modules. With `scanner/` stubbed,
    every pull was rejected with 11 "failed to import" errors and the updater
    fell back to the seed forever.
    """
    dockerfile = (PROJECT_ROOT / "rules_sync" / "Dockerfile").read_text(encoding="utf-8")

    assert _copies(dockerfile, "scanner")
    assert not _stubs(dockerfile, "scanner")
    # And the engine stays dependency-free, so this costs no third-party code.
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r"^dependencies = \[\]$", pyproject, re.MULTILINE), (
        "the updater image installs the engine on the strength of it having no "
        "runtime dependencies; that is no longer true"
    )


def test_the_updater_still_imports_nothing_from_the_engine_itself():
    """Installing the engine is for the SUBPROCESS, not for this package.

    `rules_sync` reaching into `email_guard` directly would couple the updater
    to the engine's API, and the pack (and its updater) are meant to stay
    independently movable to another repository.
    """
    package = PROJECT_ROOT / "rules_sync" / "email_guard_rules_sync"
    offenders = [
        f"{path.name}:{number}: {line.strip()}"
        for path in sorted(package.glob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if re.match(r"^\s*(from|import)\s+email_guard(\.|\s|$)", line)
    ]

    assert offenders == [], f"rules_sync imports the engine: {offenders}"


# --- repository hygiene ----------------------------------------------------------------


def test_the_live_root_is_gitignored_but_its_directory_is_kept():
    """Docker creates an absent bind source root-owned; uid 1000 then cannot write."""
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")

    assert "rules-live/**" in gitignore
    assert "!rules-live/.gitkeep" in gitignore
    assert (PROJECT_ROOT / "rules-live" / ".gitkeep").is_file()


def test_the_live_root_is_out_of_every_build_context():
    """`work/` carries a whole `.git`, which build contexts must not swallow."""
    dockerignore = (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8")

    assert "rules-live/" in dockerignore


def test_the_updater_settings_are_documented_in_the_env_sample():
    sample = (PROJECT_ROOT / ".env.sample").read_text(encoding="utf-8")

    for name in (
        "EMAIL_GUARD_RULES_REPO_URL",
        "EMAIL_GUARD_RULES_BRANCH",
        "EMAIL_GUARD_RULES_SUBPATH",
        "EMAIL_GUARD_RULES_PULL_INTERVAL",
        "EMAIL_GUARD_RULES_LIVE_NAME",
        "EMAIL_GUARD_RULES_LIVE_POINTER",
    ):
        assert name in sample, f"{name} is not documented in .env.sample"
    # The two values that make up the cutover, and the off switch.
    assert "rules-live" in sample
    assert "/current" in sample
    assert "off" in sample
