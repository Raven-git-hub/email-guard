"""Configuration for the rules auto-updater.

Every setting is an environment variable, because the updater runs as a compose
service and has no config file of its own. Defaults are chosen so that an
operator who sets nothing at all gets the intended behaviour: pull this
repository's ``rules/`` subtree from ``main`` once a day.

The one setting with no safe default is the repository URL's *scheme*, and it is
enforced rather than defaulted -- see :func:`_check_url`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

ENV_REPO_URL = "EMAIL_GUARD_RULES_REPO_URL"
ENV_BRANCH = "EMAIL_GUARD_RULES_BRANCH"
ENV_SUBPATH = "EMAIL_GUARD_RULES_SUBPATH"
ENV_INTERVAL = "EMAIL_GUARD_RULES_PULL_INTERVAL"
ENV_LIVE_DIR = "EMAIL_GUARD_RULES_LIVE_DIR"
ENV_SEED_DIR = "EMAIL_GUARD_RULES_SEED_DIR"
ENV_KEEP_RELEASES = "EMAIL_GUARD_RULES_KEEP_RELEASES"
ENV_CONTROL_HOST = "EMAIL_GUARD_RULES_CONTROL_HOST"
ENV_CONTROL_PORT = "EMAIL_GUARD_RULES_CONTROL_PORT"
ENV_CONTROL_TOKEN = "EMAIL_GUARD_RULES_CONTROL_TOKEN"

# The repository the pack lives in today. The pack may move to its own
# repository later (root README, "Engine vs rules pack"), which is a change of
# this default and nothing else.
DEFAULT_REPO_URL = "https://github.com/Raven-git-hub/email-guard"
DEFAULT_BRANCH = "main"
DEFAULT_SUBPATH = "rules"
DEFAULT_INTERVAL = "24h"
DEFAULT_LIVE_DIR = "/app/rules-live"
DEFAULT_SEED_DIR = "/app/rules"
DEFAULT_KEEP_RELEASES = 3
DEFAULT_CONTROL_HOST = "127.0.0.1"
DEFAULT_CONTROL_PORT = 8090

DEFAULT_GIT_TIMEOUT = 180.0
DEFAULT_VALIDATE_TIMEOUT = 60.0

# `https` because that is how a public repository is fetched without credentials.
# `file` because it is credential-free by construction, and it is what lets the
# test suite exercise every real git path offline against a `git init` in a
# tmp_path. Everything else is refused: `ssh`/`git@host:path` need a key,
# `http` is unauthenticated *and* unencrypted, and `git://` is neither
# authenticated nor encrypted.
ALLOWED_SCHEMES = ("https://", "file://")

_INTERVALS: dict[str, float | None] = {
    "off": None,
    "never": None,
    "manual": None,
    "hourly": 3600.0,
    "daily": 86400.0,
    "24h": 86400.0,
    "weekly": 604800.0,
    "7d": 604800.0,
}

_UNITS = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0, "w": 604800.0}


class ConfigError(ValueError):
    """A setting is unusable. Raised at startup, never mid-pull."""


def parse_interval(value: str | None) -> float | None:
    """Seconds between pulls, or ``None`` for "off".

    Accepts the words the operator is likely to write (``off``, ``weekly``,
    ``daily``) as well as ``<number><unit>`` forms (``24h``, ``7d``, ``90m``).
    ``None`` is a real value here, not an error: "off" means manual refresh
    only, and the control endpoint keeps serving.
    """
    if value is None:
        value = DEFAULT_INTERVAL
    text = value.strip().lower()
    if not text:
        text = DEFAULT_INTERVAL

    if text in _INTERVALS:
        return _INTERVALS[text]

    unit = text[-1]
    if unit in _UNITS:
        try:
            amount = float(text[:-1])
        except ValueError:
            amount = -1.0
        if amount > 0:
            return amount * _UNITS[unit]

    raise ConfigError(
        f"{ENV_INTERVAL}={value!r} is not an interval. Use 'off' for manual-only, "
        "one of 'hourly'/'daily'/'weekly', or a number with a unit such as "
        "'24h', '7d' or '90m'."
    )


def _check_url(url: str) -> str:
    """Refuse any URL that could make git ask for a credential.

    The updater is built to pull a PUBLIC repository and never supplies
    credentials -- it does not read tokens, ssh keys or credential helpers from
    the environment, and :func:`~.git.build_env` actively scrubs them. A private
    repository therefore cannot work, and the honest failure is a clear message
    at startup rather than a git process blocking on a password prompt.
    """
    text = (url or "").strip()
    if not text.lower().startswith(ALLOWED_SCHEMES):
        raise ConfigError(
            f"{ENV_REPO_URL}={url!r} is not supported: the rules updater pulls "
            "public repositories over HTTPS only and never supplies credentials. "
            "Use an https:// URL. A private repository is not supported -- "
            "mirror its rules pack to a public repository, or update the pack by "
            "redeploying instead."
        )
    return text


def _check_subpath(subpath: str) -> str:
    """The subtree of the repo that holds the pack.

    Refused: absolute paths and any `..`, both of which would make the staged
    copy reach outside the sparse checkout.
    """
    raw = (subpath or "").strip()
    if not raw:
        raise ConfigError(f"{ENV_SUBPATH} is empty; use 'rules' or a subdirectory path")
    # Checked BEFORE any stripping: silently turning '/etc' into 'etc' would
    # accept a path the operator plainly did not mean.
    if raw.startswith("/") or ".." in Path(raw).parts:
        raise ConfigError(
            f"{ENV_SUBPATH}={subpath!r} must be a relative path inside the "
            "repository, with no '..' segments"
        )
    text = raw.rstrip("/")
    if not text:
        raise ConfigError(
            f"{ENV_SUBPATH}={subpath!r} must be a relative path inside the "
            "repository, with no '..' segments"
        )
    return text


@dataclass(frozen=True)
class SyncConfig:
    """Everything :func:`~.sync.pull_and_promote` needs to run.

    ``work_dir`` is deliberately *derived* rather than configurable: it is the
    git working copy, and the one thing that must never be pointed at the engine
    checkout or at the live data volume. Not offering the knob is the simplest
    way to guarantee that.
    """

    repo_url: str = DEFAULT_REPO_URL
    branch: str = DEFAULT_BRANCH
    subpath: str = DEFAULT_SUBPATH
    interval_seconds: float | None = 86400.0
    live_dir: Path = Path(DEFAULT_LIVE_DIR)
    seed_dir: Path = Path(DEFAULT_SEED_DIR)
    keep_releases: int = DEFAULT_KEEP_RELEASES
    git_timeout: float = DEFAULT_GIT_TIMEOUT
    validate_timeout: float = DEFAULT_VALIDATE_TIMEOUT
    control_host: str = DEFAULT_CONTROL_HOST
    control_port: int = DEFAULT_CONTROL_PORT
    control_token: str | None = field(default=None, repr=False)

    @property
    def work_dir(self) -> Path:
        return self.live_dir / "work"

    @property
    def releases_dir(self) -> Path:
        return self.live_dir / "releases"

    @property
    def current_link(self) -> Path:
        return self.live_dir / "current"

    @property
    def state_file(self) -> Path:
        return self.live_dir / "state.json"

    @property
    def lock_file(self) -> Path:
        return self.live_dir / ".lock"


def _int(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = (environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}={raw!r} is not a whole number") from exc
    if value < 1:
        raise ConfigError(f"{name}={raw!r} must be at least 1")
    return value


def load(environ: Mapping[str, str] | None = None) -> SyncConfig:
    """Build a config from the environment, validating as we go."""
    env = os.environ if environ is None else environ

    token = (env.get(ENV_CONTROL_TOKEN) or "").strip() or None

    return SyncConfig(
        repo_url=_check_url((env.get(ENV_REPO_URL) or "").strip() or DEFAULT_REPO_URL),
        branch=(env.get(ENV_BRANCH) or DEFAULT_BRANCH).strip() or DEFAULT_BRANCH,
        subpath=_check_subpath(env.get(ENV_SUBPATH) or DEFAULT_SUBPATH),
        interval_seconds=parse_interval(env.get(ENV_INTERVAL)),
        live_dir=Path(env.get(ENV_LIVE_DIR) or DEFAULT_LIVE_DIR),
        seed_dir=Path(env.get(ENV_SEED_DIR) or DEFAULT_SEED_DIR),
        keep_releases=_int(env, ENV_KEEP_RELEASES, DEFAULT_KEEP_RELEASES),
        control_host=(env.get(ENV_CONTROL_HOST) or DEFAULT_CONTROL_HOST).strip(),
        control_port=_int(env, ENV_CONTROL_PORT, DEFAULT_CONTROL_PORT),
        control_token=token,
    )
