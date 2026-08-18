"""Web UI configuration, and the bind address it argues about.

The console has no authentication by default and no transport security at all;
"it is on loopback" is what stands in for both. So the interesting behaviour
here is not that a port can be configured -- it is what happens when someone
configures one that is reachable from elsewhere, and what happens when a shared
token is put somewhere it would be committed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="the web UI needs the 'webui' extra")

from email_guard_webui import config as webui_config  # noqa: E402
from email_guard_webui.__main__ import (  # noqa: E402
    EXIT_INSECURE,
    EXIT_OK,
    EXIT_USAGE,
    main,
)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A miniature project root: config/ beside data/, as the real one is laid out."""
    (tmp_path / "config").mkdir()
    for name in ("lists", "daily-brief", "outbound"):
        (tmp_path / "data" / name).mkdir(parents=True)
    return tmp_path


def write_config(project: Path, **sections) -> Path:
    path = project / "config" / "config.json"
    document = {
        "lists_dir": "data/lists",
        "daily_brief_dir": "data/daily-brief",
        "outbound_dir": "data/outbound",
    }
    document.update(sections)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


# --- defaults ------------------------------------------------------------------


def test_the_default_bind_is_loopback(project):
    config = webui_config.load(config_path=write_config(project), environ={})

    assert config.host == "127.0.0.1"
    assert config.port == 8080
    assert config.is_loopback
    assert config.auth_enabled is False


def test_the_data_directories_come_from_the_scanner_config(project):
    config = webui_config.load(config_path=write_config(project), environ={})

    assert config.lists_dir == (project / "data" / "lists").resolve()
    assert config.daily_brief_dir == (project / "data" / "daily-brief").resolve()
    assert config.outbound_dir == (project / "data" / "outbound").resolve()


def test_the_webui_section_is_read(project):
    path = write_config(project, webui={"host": "::1", "port": 9001, "frame_ancestors": "https://panel"})

    config = webui_config.load(config_path=path, environ={})

    assert (config.host, config.port) == ("::1", 9001)
    assert config.is_loopback
    assert "frame-ancestors https://panel" in config.content_security_policy


def test_flags_and_environment_win_in_that_order(project):
    path = write_config(project, webui={"host": "127.0.0.2", "port": 9001})
    env = {webui_config.ENV_HOST: "127.0.0.3", webui_config.ENV_PORT: "9002"}

    from_env = webui_config.load(config_path=path, environ=env)
    from_flag = webui_config.load(config_path=path, host="127.0.0.4", port=9003, environ=env)

    assert (from_env.host, from_env.port) == ("127.0.0.3", 9002)
    assert (from_flag.host, from_flag.port) == ("127.0.0.4", 9003)


@pytest.mark.parametrize("port", ["not-a-number", 0, 70000])
def test_an_unusable_port_is_an_error(project, port):
    path = write_config(project, webui={"port": port})

    with pytest.raises(webui_config.ConfigError):
        webui_config.load(config_path=path, environ={})


# --- the token -----------------------------------------------------------------


def test_the_token_comes_from_the_environment(project):
    path = write_config(project)

    config = webui_config.load(config_path=path, environ={webui_config.ENV_TOKEN: "s3cret"})

    assert config.auth_enabled
    assert config.auth_token == "s3cret"


def test_the_token_can_come_from_the_git_ignored_secrets_file(project):
    path = write_config(project)
    secrets = project / "config" / "secrets.json"
    secrets.write_text(json.dumps({"webui": {"token": "from-file"}}), encoding="utf-8")

    config = webui_config.load(config_path=path, environ={})

    assert config.auth_token == "from-file"
    # Environment still wins, as everywhere else in the project.
    assert webui_config.load(
        config_path=path, environ={webui_config.ENV_TOKEN: "from-env"}
    ).auth_token == "from-env"


def test_a_token_in_config_json_is_refused(project):
    """Refused, not ignored.

    ``config.json`` is committed. An operator who put a token there would
    otherwise believe the console was guarded while the secret sat in git, which
    is worse than having no token at all.
    """
    path = write_config(project, webui={"token": "committed-by-accident"})

    with pytest.raises(webui_config.ConfigError) as error:
        webui_config.load(config_path=path, environ={})

    assert "secrets.json" in str(error.value)


def test_the_token_never_appears_in_a_repr(project):
    config = webui_config.load(
        config_path=write_config(project), environ={webui_config.ENV_TOKEN: "s3cret"}
    )

    assert "s3cret" not in repr(config)


# --- the bind address ----------------------------------------------------------


@pytest.fixture
def uvicorn_calls(monkeypatch) -> list[dict]:
    """Capture what would have been served, without serving it."""
    calls: list[dict] = []
    monkeypatch.setattr(
        "email_guard_webui.__main__.uvicorn.run",
        lambda app, **kwargs: calls.append(kwargs),
    )
    return calls


def base_argv(project: Path) -> list[str]:
    return [
        "--config", str(write_config(project)),
        "--lists-dir", str(project / "data" / "lists"),
        "--daily-brief-dir", str(project / "data" / "daily-brief"),
        "--outbound-dir", str(project / "data" / "outbound"),
    ]


def test_a_loopback_bind_starts(project, uvicorn_calls):
    assert main(base_argv(project) + ["--port", "8123"]) == EXIT_OK
    assert uvicorn_calls == [
        {"host": "127.0.0.1", "port": 8123, "log_level": "info", "proxy_headers": False}
    ]


def test_a_non_loopback_bind_is_refused(project, uvicorn_calls, capsys):
    """Two mistakes required, not one.

    This process reads mail content and edits the lists that decide whether mail
    is delivered. A typo in a host must not be all that stands between that and
    the network.
    """
    assert main(base_argv(project) + ["--host", "0.0.0.0"]) == EXIT_USAGE

    assert uvicorn_calls == []
    assert "refusing to bind 0.0.0.0" in capsys.readouterr().err


def test_a_non_loopback_bind_can_be_asked_for_explicitly(project, uvicorn_calls, monkeypatch):
    """The container case: the published port is pinned to loopback on the host.

    That second half is now stated rather than assumed. A 0.0.0.0 bind on its
    own no longer starts without a token -- the process cannot tell a
    loopback-published container from a console on the LAN, so compose tells it
    (`EMAIL_GUARD_WEBUI_PUBLISHED_BIND`), and the untold case fails closed.
    """
    monkeypatch.setenv(webui_config.ENV_PUBLISHED_BIND, "127.0.0.1")

    assert main(base_argv(project) + ["--host", "0.0.0.0", "--allow-non-loopback"]) == EXIT_OK

    assert uvicorn_calls[0]["host"] == "0.0.0.0"


def test_the_environment_can_grant_the_same_permission(project, uvicorn_calls, monkeypatch):
    monkeypatch.setenv(webui_config.ENV_ALLOW_NON_LOOPBACK, "1")
    monkeypatch.setenv(webui_config.ENV_PUBLISHED_BIND, "127.0.0.1")

    assert main(base_argv(project) + ["--host", "0.0.0.0"]) == EXIT_OK

    assert uvicorn_calls[0]["host"] == "0.0.0.0"


# --- reachable off this host with no token: refuse, do not warn -------------------
#
# The console renders attacker-controlled mail and edits the lists that decide
# what is delivered. "It is on loopback" is what stands in for authentication;
# once that stops being true and no token has replaced it, the honest response
# is to not start. A warning was what this used to do, and a warning scrolls
# past in a container log while the console serves the LAN anyway.


def test_non_loopback_with_no_token_refuses_to_start(project, uvicorn_calls, capsys):
    """(a) The combination the guard exists for."""
    exit_code = main(base_argv(project) + ["--host", "0.0.0.0", "--allow-non-loopback"])

    assert exit_code == EXIT_INSECURE
    assert exit_code != EXIT_OK
    assert uvicorn_calls == [], "it must refuse BEFORE anything binds"
    error = capsys.readouterr().err
    assert "refusing to start" in error
    assert webui_config.ENV_TOKEN in error


def test_non_loopback_with_a_token_starts(project, uvicorn_calls, monkeypatch):
    """(b) A token is what makes the exposed case legitimate."""
    monkeypatch.setenv(webui_config.ENV_TOKEN, "s3cret")

    assert main(base_argv(project) + ["--host", "0.0.0.0", "--allow-non-loopback"]) == EXIT_OK

    assert uvicorn_calls[0]["host"] == "0.0.0.0"


def test_loopback_with_no_token_still_starts(project, uvicorn_calls):
    """(c) The development path. Only this host can reach it, so no token needed."""
    assert main(base_argv(project)) == EXIT_OK

    assert uvicorn_calls[0]["host"] == "127.0.0.1"


def test_a_token_from_the_secrets_file_satisfies_the_guard(project, uvicorn_calls):
    """The guard reads `auth_enabled`, not the env var -- the token has two homes.

    Keying on `EMAIL_GUARD_WEBUI_TOKEN` alone would refuse to start a correctly
    configured console whose token lives in the git-ignored secrets file.
    """
    (project / "config" / "secrets.json").write_text(
        json.dumps({"webui": {"token": "from-file"}}), encoding="utf-8"
    )

    assert main(base_argv(project) + ["--host", "0.0.0.0", "--allow-non-loopback"]) == EXIT_OK

    assert uvicorn_calls[0]["host"] == "0.0.0.0"


def test_a_lan_publication_with_no_token_refuses(project, uvicorn_calls, monkeypatch):
    """The compose case this whole change is about: BIND=0.0.0.0, empty token."""
    monkeypatch.setenv(webui_config.ENV_ALLOW_NON_LOOPBACK, "1")
    monkeypatch.setenv(webui_config.ENV_PUBLISHED_BIND, "0.0.0.0")

    assert main(base_argv(project) + ["--host", "0.0.0.0"]) == EXIT_INSECURE

    assert uvicorn_calls == []


def test_an_unknown_publication_fails_closed(project, uvicorn_calls, monkeypatch):
    """An older compose file against a newer image: no publication fact, no start.

    Refusing here is the deliberate choice. The alternative -- assume loopback
    when nobody said -- is the assumption that would have to be wrong only once.
    """
    monkeypatch.setenv(webui_config.ENV_ALLOW_NON_LOOPBACK, "1")
    monkeypatch.delenv(webui_config.ENV_PUBLISHED_BIND, raising=False)

    assert main(base_argv(project) + ["--host", "0.0.0.0"]) == EXIT_INSECURE

    assert uvicorn_calls == []


@pytest.mark.parametrize("published", ["127.0.0.1", "::1", "localhost", " 127.0.0.1 "])
def test_a_loopback_publication_is_recognised(project, uvicorn_calls, monkeypatch, published):
    monkeypatch.setenv(webui_config.ENV_PUBLISHED_BIND, published)

    assert main(base_argv(project) + ["--host", "0.0.0.0", "--allow-non-loopback"]) == EXIT_OK


@pytest.mark.parametrize("published", ["0.0.0.0", "192.168.1.42", "::", "10.0.0.5"])
def test_a_reachable_publication_is_recognised(project, uvicorn_calls, monkeypatch, published):
    monkeypatch.setenv(webui_config.ENV_PUBLISHED_BIND, published)

    assert main(base_argv(project) + ["--host", "0.0.0.0", "--allow-non-loopback"]) == EXIT_INSECURE


# --- the predicate on its own ------------------------------------------------------


def test_reachable_beyond_this_host_is_fail_closed(project):
    """Unit-level, so the three cases are visible without going through main()."""
    loopback = webui_config.load(config_path=write_config(project), environ={})
    exposed = webui_config.load(
        config_path=write_config(project), environ={webui_config.ENV_HOST: "0.0.0.0"}
    )

    # A loopback bind is unreachable from elsewhere whatever the environment says.
    assert webui_config.reachable_beyond_this_host(loopback, {}) is False
    assert (
        webui_config.reachable_beyond_this_host(
            loopback, {webui_config.ENV_ALLOW_NON_LOOPBACK: "1"}
        )
        is False
    )
    # A non-loopback bind is reachable unless the publication says otherwise.
    assert webui_config.reachable_beyond_this_host(exposed, {}) is True
    assert (
        webui_config.reachable_beyond_this_host(
            exposed, {webui_config.ENV_PUBLISHED_BIND: "127.0.0.1"}
        )
        is False
    )
    assert (
        webui_config.reachable_beyond_this_host(
            exposed, {webui_config.ENV_PUBLISHED_BIND: "0.0.0.0"}
        )
        is True
    )
