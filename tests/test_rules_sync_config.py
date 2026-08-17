"""Configuration, and the promise that no credential is ever reachable.

The updater pulls a PUBLIC repository. The tests here pin that as a property of
the code rather than a claim in a comment: every git invocation clears the
credential helper, and the environment handed to git is *built* rather than
inherited, so a credential helper configured on the host cannot leak in.

A private repository is therefore unsupported, and must fail with a sentence an
operator can act on rather than by hanging on a password prompt in a container
with no terminal.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from email_guard_rules_sync import git
from email_guard_rules_sync.config import (
    DEFAULT_BRANCH,
    DEFAULT_REPO_URL,
    DEFAULT_SUBPATH,
    ConfigError,
    load,
    parse_interval,
)

# --- intervals -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        pytest.param("24h", 86400.0, id="24h"),
        pytest.param("7d", 604800.0, id="7d"),
        pytest.param("weekly", 604800.0, id="weekly"),
        pytest.param("daily", 86400.0, id="daily"),
        pytest.param("hourly", 3600.0, id="hourly"),
        pytest.param("90m", 5400.0, id="90m"),
        pytest.param("  24H  ", 86400.0, id="whitespace-and-case"),
        pytest.param(None, 86400.0, id="unset-defaults-to-24h"),
        pytest.param("", 86400.0, id="empty-defaults-to-24h"),
    ],
)
def test_interval_parsing(text: str | None, seconds: float):
    assert parse_interval(text) == seconds


@pytest.mark.parametrize("text", ["off", "never", "manual", "OFF"])
def test_off_disables_scheduling(text: str):
    """`None` is a real value: manual refresh only, control endpoint still up."""
    assert parse_interval(text) is None


@pytest.mark.parametrize("text", ["soon", "24", "h", "-5h", "0h", "lots"])
def test_an_unparseable_interval_names_the_accepted_forms(text: str):
    with pytest.raises(ConfigError) as caught:
        parse_interval(text)

    message = str(caught.value)
    assert "off" in message
    assert "24h" in message


# --- the URL allow-list ---------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        pytest.param("ssh://git@github.com/Raven-git-hub/email-guard", id="ssh-scheme"),
        pytest.param("git@github.com:Raven-git-hub/email-guard.git", id="scp-style"),
        pytest.param("git://github.com/Raven-git-hub/email-guard", id="git-protocol"),
        pytest.param("http://example.invalid/repo", id="plain-http"),
    ],
)
def test_a_url_that_could_need_credentials_is_refused(url: str):
    with pytest.raises(ConfigError) as caught:
        load({"EMAIL_GUARD_RULES_REPO_URL": url})

    assert "EMAIL_GUARD_RULES_REPO_URL" in str(caught.value)


def test_an_empty_url_falls_back_to_the_default():
    """`FOO=` in a .env means "unset", the way compose's `${FOO:-}` does."""
    assert load({"EMAIL_GUARD_RULES_REPO_URL": "  "}).repo_url == DEFAULT_REPO_URL


def test_the_refusal_explains_that_private_repos_are_unsupported():
    """Requirement: fail with a clear message rather than prompting."""
    with pytest.raises(ConfigError) as caught:
        load({"EMAIL_GUARD_RULES_REPO_URL": "ssh://git@github.com/private/repo"})

    message = str(caught.value).lower()
    assert "public" in message
    assert "credential" in message


@pytest.mark.parametrize(
    "subpath", ["/etc", "../../etc", "rules/../../..", "  "]
)
def test_a_subpath_that_escapes_the_checkout_is_refused(subpath: str):
    with pytest.raises(ConfigError):
        load({"EMAIL_GUARD_RULES_SUBPATH": subpath})


# --- defaults -------------------------------------------------------------------


def test_the_defaults_match_the_repository_this_pack_lives_in():
    config = load({})

    assert config.repo_url == DEFAULT_REPO_URL == "https://github.com/Raven-git-hub/email-guard"
    assert config.branch == DEFAULT_BRANCH == "main"
    assert config.subpath == DEFAULT_SUBPATH == "rules"
    assert config.interval_seconds == 86400.0


def test_the_working_copy_is_derived_not_configurable():
    """One fewer way to aim the clone at the engine checkout or the data volume."""
    config = load({"EMAIL_GUARD_RULES_LIVE_DIR": "/srv/live"})

    assert config.work_dir == Path("/srv/live/work")
    assert "work_dir" not in {field for field in config.__dataclass_fields__}


def test_the_control_token_is_kept_out_of_the_repr():
    config = load({"EMAIL_GUARD_RULES_CONTROL_TOKEN": "s3cret"})

    assert config.control_token == "s3cret"
    assert "s3cret" not in repr(config)


@pytest.mark.parametrize("value", ["0", "-1", "many"])
def test_a_nonsense_keep_count_is_refused(value: str):
    with pytest.raises(ConfigError):
        load({"EMAIL_GUARD_RULES_KEEP_RELEASES": value})


# --- no credential path is reachable ---------------------------------------------


def test_the_git_environment_disables_every_prompt():
    env = git.build_env()

    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ASKPASS"] == "/bin/false"
    assert env["SSH_ASKPASS"] == "/bin/false"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_CONFIG_SYSTEM"] == os.devnull
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"


def test_the_git_environment_is_built_not_inherited(monkeypatch: pytest.MonkeyPatch):
    """A credential helper on the host must not reach the updater's git."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/host/.gitconfig")
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -i /host/id_rsa")
    monkeypatch.setenv("GIT_ASKPASS", "/host/askpass")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_notatoken")

    env = git.build_env()

    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert "/host/id_rsa" not in env["GIT_SSH_COMMAND"]
    assert env["GIT_ASKPASS"] == "/bin/false"
    assert "GITHUB_TOKEN" not in env


def test_home_is_a_throwaway_so_stored_credentials_are_not_even_present():
    env = git.build_env(home="/tmp/git-home")

    assert env["HOME"] == "/tmp/git-home"


@pytest.mark.parametrize(
    ("call", "kwargs"),
    [
        pytest.param(
            "clone", {"url": "https://example.invalid/r", "branch": "main", "subpath": "rules"},
            id="clone",
        ),
        pytest.param("ls_remote_sha", {"url": "https://example.invalid/r", "branch": "main"},
                     id="ls-remote"),
        pytest.param("fetch", {"branch": "main"}, id="fetch"),
    ],
)
def test_every_git_invocation_clears_the_credential_helper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, call: str, kwargs: dict
):
    seen: list[list[str]] = []

    def fake_run(argv, **_):
        seen.append(argv)
        raise AssertionError("stop after recording the argv")

    monkeypatch.setattr(git.subprocess, "run", fake_run)

    with pytest.raises(AssertionError):
        if call == "clone":
            git.clone(target=tmp_path / "work", timeout=5, **kwargs)
        elif call == "ls_remote_sha":
            git.ls_remote_sha(timeout=5, **kwargs)
        else:
            git.fetch(tmp_path, timeout=5, **kwargs)

    assert seen, "no git command was built"
    for argv in seen:
        assert argv[0] == "git"
        assert "credential.helper=" in argv
        assert "core.askPass=" in argv


# --- error translation ------------------------------------------------------------


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        pytest.param(
            "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
            "public",
            id="private-repo-prompt",
        ),
        pytest.param("remote: Authentication failed for 'https://…'", "public", id="auth-failed"),
        pytest.param(
            "remote: Repository not found.", "private", id="not-found-hints-private"
        ),
        pytest.param(
            "git@github.com: Permission denied (publickey).", "HTTPS", id="ssh-key"
        ),
        pytest.param(
            "fatal: unable to access '…': Could not resolve host: github.com",
            "egress",
            id="no-egress",
        ),
        pytest.param(
            "fatal: unable to access '…': SSL certificate problem: unable to get issuer",
            "ca-certificates",
            id="missing-ca-bundle",
        ),
        pytest.param(
            "fatal: couldn't find remote ref refs/heads/nope",
            "EMAIL_GUARD_RULES_BRANCH",
            id="bad-branch",
        ),
    ],
)
def test_git_failures_are_translated_into_something_actionable(stderr: str, expected: str):
    """Offline, and deterministic: canned stderr, no network involved.

    This is how "a private repo fails with a clear message" is tested without
    reaching for a real private repository.
    """
    assert expected in git.classify_error(stderr)


def test_an_unrecognised_failure_still_reports_something():
    assert git.classify_error("fatal: something new went wrong") == (
        "fatal: something new went wrong"
    )
    assert git.classify_error("") == "git failed with no output"
