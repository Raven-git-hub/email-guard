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


def _published_console_entries() -> list[str]:
    """Every `ports:` entry in compose that publishes the console's 8080."""
    return [
        line.strip().lstrip("- ").strip('"')
        for line in COMPOSE.splitlines()
        if line.strip().startswith('- "') and ":8080" in line
    ]


def _render(entry: str) -> str:
    """Resolve `${VAR:-default}` the way compose does with NOTHING in the env.

    This is the property that matters and the one a reading of the file can get
    wrong: not "the line mentions 127.0.0.1 somewhere", but "with no `.env`, no
    exported variables, nothing, the published address is loopback".
    """
    return re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]*)\}", r"\1", entry)


def test_the_review_console_is_loopback_by_default():
    """The interface is configurable now; the DEFAULT must still be loopback.

    The bind address moved behind `EMAIL_GUARD_WEBUI_BIND` because the one
    deploy that wanted LAN access was hand-editing this tracked file and
    colliding with every `git pull`. Parameterising it is fine. What must never
    happen is the default drifting: a fresh clone, an unset variable or a
    missing `.env` has to stay loopback-only, because this console reads mail
    and edits the lists that decide what gets delivered, over plain HTTP, with
    no password unless one is configured.

    So this asserts the substitution, not the spelling: rendered with an empty
    environment, the published address is 127.0.0.1.
    """
    published = _published_console_entries()

    assert published == [
        "${EMAIL_GUARD_WEBUI_BIND:-127.0.0.1}:${EMAIL_GUARD_WEBUI_HOST_PORT:-8080}:8080"
    ]
    assert _render(published[0]) == "127.0.0.1:8080:8080"


def test_the_console_bind_default_is_a_loopback_literal():
    """Stated once more against the default alone, so a change to it is loud."""
    published = _published_console_entries()
    default = re.match(
        r"^\$\{EMAIL_GUARD_WEBUI_BIND:-([^}]*)\}:", published[0]
    )

    assert default, "the console bind must come from EMAIL_GUARD_WEBUI_BIND"
    assert default.group(1) == "127.0.0.1", (
        "the fallback bind must be loopback -- an unset variable may never "
        "expose the console on the LAN or the internet"
    )


def test_no_service_publishes_a_wildcard_address():
    """The regression this guards: `0.0.0.0` hardcoded back into a `ports:` line.

    `EMAIL_GUARD_WEBUI_HOST: 0.0.0.0` in the service ENVIRONMENT is a different
    thing and is correct -- it binds the interface INSIDE the container, which
    is what lets a published port reach the process at all. Only `ports:`
    entries decide who can see it, so only those are checked here.
    """
    published = [
        (name, str(entry))
        for name, service in _compose()["services"].items()
        for entry in (service.get("ports") or [])
    ]

    assert published, "no service publishes a port -- this test would pass vacuously"
    offenders = [
        (name, entry)
        for name, entry in published
        # A compose `ports:` entry is HOST[:CONTAINER] with an optional bind
        # address first. Two colons means the address is present; one means it
        # was omitted, which compose reads as every interface.
        if _render(entry).count(":") < 2
        or _render(entry).startswith(("0.0.0.0:", "*:", "::"))
    ]

    assert offenders == [], (
        f"a published port defaults to a wildcard address: {offenders}"
    )


def test_the_console_is_told_the_publication_it_cannot_observe():
    """The line that makes "LAN needs a token" enforceable instead of advisory.

    A container cannot see which HOST interface its port was published on -- it
    binds 0.0.0.0 inside its own namespace either way -- so compose passes the
    address in. The console refuses to start when that says LAN and no token is
    set (`email_guard_webui.config.reachable_beyond_this_host`).

    Both values must come from the SAME variable. Feeding them separately would
    let the publication and what the console believes about it drift apart,
    which is worse than not telling it at all: the guard would pass while the
    console sat on the LAN.
    """
    webui = _compose()["services"]["webui"]
    published = webui["environment"]["EMAIL_GUARD_WEBUI_PUBLISHED_BIND"]
    # The leading `${...}` of the ports entry -- not `split(":")`, which would
    # cut inside the `:-default`.
    bind = re.match(r"^(\$\{[^}]*\})", str(webui["ports"][0])).group(1)

    assert published == "${EMAIL_GUARD_WEBUI_BIND:-127.0.0.1}"
    assert published == bind, (
        "the published bind told to the container must be the same expression "
        f"as the one in `ports:` -- {published!r} vs {bind!r}"
    )


def test_the_console_still_requires_a_token_off_loopback():
    """Parameterising the bind must not touch the auth wiring it depends on.

    The rule is now enforced at startup, but enforcement only helps if an
    operator can satisfy it: the token still has to reach the container, and
    .env.sample still has to say the two go together.
    """
    environment = _compose()["services"]["webui"]["environment"]
    sample = (DISPATCHER_PACKAGE.parents[1] / ".env.sample").read_text(encoding="utf-8")

    assert environment["EMAIL_GUARD_WEBUI_TOKEN"] == "${EMAIL_GUARD_WEBUI_TOKEN:-}"
    assert "EMAIL_GUARD_WEBUI_BIND" in sample
    assert "EMAIL_GUARD_WEBUI_TOKEN" in sample
    # The two must be documented together: the whole point is that turning one
    # on obliges the other.
    bind_section = sample[sample.index("EMAIL_GUARD_WEBUI_BIND") :]
    assert "EMAIL_GUARD_WEBUI_TOKEN" in bind_section[:2000], (
        "the .env sample must state that exposing the console requires the token"
    )


# -- the compose topology a live bring-up corrected ---------------------------
#
# Each of these is a bug that cost a real bring-up. None of them is reachable
# without a daemon, so what is pinned here is the committed configuration --
# enough that a silent revert fails a test rather than a deployment.


def test_the_bridge_can_reach_proton():
    """`mail` is internal, so the bridge needs a second, non-internal network.

    On `mail` alone the bridge cannot resolve mail-api.proton.me, never
    authenticates, never opens its IMAP listener -- and the dispatcher's
    connection attempts return EOF, which reads like a dispatcher fault and is
    not one.
    """
    compose = _compose()

    assert compose["networks"]["mail"].get("internal") is True
    assert compose["networks"]["egress"].get("internal") is not True
    assert "egress" in compose["services"]["bridge"]["networks"]


def test_the_dispatcher_has_no_egress():
    """It needs the bridge and the socket-proxy. Nothing else."""
    networks = _compose()["services"]["dispatcher"]["networks"]

    assert sorted(networks) == ["dockerproxy", "mail"]


def test_the_dispatcher_uses_the_container_network_imap_port():
    """143 on the container network; 1143 is the in-container/published port.

    The shenxn image fronts the bridge with socat, so the number that works
    from another container is not the one the Proton Bridge docs quote.
    """
    port = _compose()["services"]["dispatcher"]["environment"]["EMAIL_GUARD_IMAP_PORT"]

    assert port == "${EMAIL_GUARD_IMAP_PORT:-143}"


def test_the_bridge_is_built_locally_so_it_survives_its_own_auto_update():
    """`shenxn/protonmail-bridge` updates the bridge binary inside the container.

    The build it now pulls links against `libfido2.so.1`, which that image does
    not ship, so the bridge dies at launch on the next restart -- and the
    symptom is a dispatcher getting EOF from `bridge:143`, which looks like a
    dispatcher fault and is not one. Reverting to `image:` would reintroduce a
    stack that breaks itself with no local change at all.
    """
    bridge = _compose()["services"]["bridge"]

    assert bridge.get("build") == "./bridge", "the bridge must be built, not pulled"
    assert bridge["image"] == "email-guard-bridge:0.1.0"

    dockerfile = (DISPATCHER_PACKAGE.parents[1] / "bridge" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    assert "FROM shenxn/protonmail-bridge" in dockerfile
    assert "libfido2-1" in dockerfile


def test_the_dispatcher_takes_a_webhook_url_from_the_environment():
    """Passthrough only: unset means no webhook sink is built and no egress.

    The URL cannot be baked in -- it names a downstream this repo knows nothing
    about -- but it has to be *reachable* from compose, or the deployed
    dispatcher can never deliver anything however it is configured.
    """
    environment = _compose()["services"]["dispatcher"]["environment"]

    assert environment["EMAIL_GUARD_WEBHOOK_URL"] == "${EMAIL_GUARD_WEBHOOK_URL:-}"
    assert load({}).webhook_url is None  # absent from the environment: no sink


def test_the_webhook_url_is_documented_in_the_env_sample():
    """Both delivery patterns, in the file an operator actually edits."""
    sample = (DISPATCHER_PACKAGE.parents[1] / ".env.sample").read_text(encoding="utf-8")

    assert "EMAIL_GUARD_WEBHOOK_URL" in sample
    assert "1010" in sample, "the Cloudflare bot-filter failure mode is the point"
    assert "egress" in sample


def test_the_socket_proxy_can_write_its_own_config():
    """haproxy renders /tmp/haproxy.cfg at startup; read_only alone crash-loops."""
    proxy = _compose()["services"]["docker-socket-proxy"]

    assert proxy["read_only"] is True
    assert "/tmp" in proxy["tmpfs"]
    assert "/run" in proxy["tmpfs"]


def _compose():
    yaml = pytest.importorskip("yaml", reason="compose assertions need PyYAML")
    return yaml.safe_load(COMPOSE)


# -- config resolution inside an image ----------------------------------------
#
# The bug these cover cost a live bring-up. Both config loaders fall back to
# `project_root()` = `Path(__file__).parents[2]`, which is the repo root from a
# checkout but the *install prefix* once pip-installed into site-packages. With
# no config file found there, every relative path in config.json resolves under
# that prefix: `/usr/local/lib/python3.11/data/lists`. The dispatcher's
# ContainerRunner self-check caught it; the web UI would have silently read an
# empty lists directory and shown nothing, which is worse.
#
# Naming the file -- EMAIL_GUARD_CONFIG, set as an ENV in both images -- is the
# fix. What these pin is the property that makes it work: paths resolve against
# the *config file's* directory, wherever the code itself happens to live.


def config_tree(root: Path) -> Path:
    """An /app-shaped layout: config/config.json with relative data paths."""
    (root / "config").mkdir(parents=True, exist_ok=True)
    path = root / "config" / "config.json"
    path.write_text(
        '{"lists_dir": "data/lists", "outbound_dir": "data/outbound",'
        ' "daily_brief_dir": "data/daily-brief", "rules_dir": "rules"}'
    )
    return path


def test_relative_paths_resolve_against_the_config_not_the_install_prefix(tmp_path):
    """The dispatcher's loader, pointed at a config far from both cwd and code."""
    app = tmp_path / "app"
    path = config_tree(app)

    container = load({"EMAIL_GUARD_CONFIG": str(path)}).container

    assert container.lists_dir == app / "data" / "lists"
    assert container.outbound_dir == app / "data" / "outbound"
    assert container.daily_brief_dir == app / "data" / "daily-brief"
    assert container.rules_dir == app / "rules"


def test_the_scanner_loader_resolves_the_same_way(tmp_path, monkeypatch):
    """The web UI reaches the data directories through this one."""
    import email_guard.config as scanner_config

    app = tmp_path / "app"
    path = config_tree(app)
    monkeypatch.setenv("EMAIL_GUARD_CONFIG", str(path))
    for stale in ("EMAIL_GUARD_LISTS_DIR", "EMAIL_GUARD_OUTBOUND_DIR",
                  "EMAIL_GUARD_DAILY_BRIEF_DIR", "EMAIL_GUARD_RULES_DIR"):
        monkeypatch.delenv(stale, raising=False)

    settings = scanner_config.load()

    assert settings.lists_dir == app / "data" / "lists"
    assert settings.outbound_dir == app / "data" / "outbound"


def test_resolved_paths_never_land_under_the_python_install_prefix(tmp_path):
    """The actual failure signature, asserted directly.

    `/usr/local/lib/python3.11/data/lists` is what a container produced before
    EMAIL_GUARD_CONFIG was set, and it is the shape to stay away from.
    """
    import sys

    path = config_tree(tmp_path / "app")
    container = load({"EMAIL_GUARD_CONFIG": str(path)}).container

    prefix = Path(sys.prefix).resolve()
    for name in ("lists_dir", "outbound_dir", "daily_brief_dir", "rules_dir", "data_dir"):
        resolved = getattr(container, name).resolve()
        assert prefix not in resolved.parents, f"{name} resolved under the install prefix"


def test_both_images_name_the_config_file_explicitly():
    """It belongs in the image, so it holds however the image is run."""
    root = DISPATCHER_PACKAGE.parents[1]
    for dockerfile in ("dispatcher/Dockerfile", "webui/Dockerfile"):
        text = (root / dockerfile).read_text(encoding="utf-8")
        assert "EMAIL_GUARD_CONFIG=/app/config/config.json" in text, dockerfile


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
