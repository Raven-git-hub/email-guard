"""Web UI configuration: where the data lives, and how the server is exposed.

The data directories are *not* redefined here -- ``lists_dir``,
``daily_brief_dir`` and ``outbound_dir`` come from :mod:`email_guard.config`, so
the console reads exactly the directories the scanner and the dispatcher write.
This module adds only what serving introduces: bind address, port, the optional
shared token, and the one CSP knob.

Resolution order mirrors the scanner's, highest priority first:

    1. explicit CLI flag (``--host`` / ``--port`` / ``--config`` / the
       ``--*-dir`` flags)
    2. environment (``EMAIL_GUARD_WEBUI_HOST`` / ``EMAIL_GUARD_WEBUI_PORT`` /
       ``EMAIL_GUARD_WEBUI_TOKEN`` / ``EMAIL_GUARD_WEBUI_FRAME_ANCESTORS``)
    3. the ``webui`` section of ``config/config.json``
    4. built-in default

The token is the one exception: it is a secret, so it is read from the
environment or from the git-ignored ``config/secrets.json`` -- never from
``config.json``, which is committed. Same rule the dispatcher applies to the
bridge credentials.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from email_guard import config as scanner_config

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
# A single knob, deliberately: the side-panel host that will embed this console
# later needs `frame-ancestors` widened, and nothing else in the policy.
DEFAULT_FRAME_ANCESTORS = "'none'"
DEFAULT_SECRETS_FILE = "config/secrets.json"

ENV_HOST = "EMAIL_GUARD_WEBUI_HOST"
ENV_PORT = "EMAIL_GUARD_WEBUI_PORT"
ENV_TOKEN = "EMAIL_GUARD_WEBUI_TOKEN"
ENV_FRAME_ANCESTORS = "EMAIL_GUARD_WEBUI_FRAME_ANCESTORS"
ENV_ALLOW_NON_LOOPBACK = "EMAIL_GUARD_WEBUI_ALLOW_NON_LOOPBACK"
# The one fact this process cannot discover for itself: which HOST interface its
# port was published on. Inside a container it binds 0.0.0.0 and always has --
# that is what makes a published port reach it at all -- so its own bind address
# says nothing about who can connect. `docker-compose.yml` sets this from the
# same `EMAIL_GUARD_WEBUI_BIND` that decides the publication, which is what lets
# :func:`reachable_beyond_this_host` tell "loopback-published container" from
# "console on the LAN". Unset means unknown, and unknown is treated as exposed.
ENV_PUBLISHED_BIND = "EMAIL_GUARD_WEBUI_PUBLISHED_BIND"
ENV_SECRETS = "EMAIL_GUARD_SECRETS"

# Where the rules updater's control endpoint lives, and the token for it. The
# console has no git and no write access to the rules tree by design: it asks
# the updater instead, so exactly one component owns git and the write path.
# Unset means "no updater in this deployment", and the refresh endpoint says so.
ENV_RULES_CONTROL_URL = "EMAIL_GUARD_RULES_CONTROL_URL"
ENV_RULES_CONTROL_TOKEN = "EMAIL_GUARD_RULES_CONTROL_TOKEN"

# The header a client presents the shared token in, when one is configured.
AUTH_HEADER = "X-Email-Guard-Token"

# Same set the dispatcher trusts for the bridge connection: an address whose
# traffic cannot leave the host.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "localhost.localdomain"})

# Static assets live beside the package, not inside it: `webui/static/` is the
# approved UI mock's home and stays the served root.
STATIC_DIR = Path(__file__).resolve().parents[1] / "static"


class ConfigError(ValueError):
    """A configuration value is missing or unusable."""


@dataclass(frozen=True)
class WebUIConfig:
    """Everything the server needs to start and to find its data."""

    lists_dir: Path
    daily_brief_dir: Path
    outbound_dir: Path
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    # `repr=False`: a dataclass repr turns up in tracebacks, and a shared token
    # must not ride along -- the same reason the dispatcher hides its password.
    auth_token: str | None = field(default=None, repr=False)
    frame_ancestors: str = DEFAULT_FRAME_ANCESTORS
    static_dir: Path = STATIC_DIR
    config_path: Path | None = None
    rules_control_url: str | None = None
    # `repr=False` for the same reason `auth_token` has it.
    rules_control_token: str | None = field(default=None, repr=False)

    @property
    def is_loopback(self) -> bool:
        return self.host.strip("[]").lower() in LOOPBACK_HOSTS

    @property
    def auth_enabled(self) -> bool:
        return bool(self.auth_token)

    @property
    def content_security_policy(self) -> str:
        return content_security_policy(self.frame_ancestors)


def content_security_policy(frame_ancestors: str = DEFAULT_FRAME_ANCESTORS) -> str:
    """The policy sent on every response.

    ``default-src 'none'`` and an explicit allowance per directive, rather than
    a broad default with exceptions: a directive nobody thought about should
    deny, not inherit. ``script-src 'self'`` is what forbids inline script,
    which is why the UI's JavaScript lives in ``static/app.js`` and binds its
    handlers with ``addEventListener`` instead of ``onclick=``.

    ``style-src`` keeps ``'unsafe-inline'`` because the approved mock carries
    inline ``style`` attributes. A style attribute cannot execute; script is the
    capability worth spending strictness on.
    """
    return "; ".join(
        (
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "connect-src 'self'",
            "img-src 'none'",
            "base-uri 'none'",
            "form-action 'none'",
            f"frame-ancestors {frame_ancestors.strip()}",
        )
    )


def load(
    config_path: str | os.PathLike[str] | None = None,
    lists_dir: str | os.PathLike[str] | None = None,
    daily_brief_dir: str | os.PathLike[str] | None = None,
    outbound_dir: str | os.PathLike[str] | None = None,
    host: str | None = None,
    port: int | None = None,
    environ: dict[str, str] | None = None,
) -> WebUIConfig:
    """Build the effective web UI configuration.

    ``environ`` covers this module's own variables. The data directories are
    resolved by :func:`email_guard.config.load`, which reads
    ``EMAIL_GUARD_LISTS_DIR`` and friends from the process environment -- the
    console must find the same directories the scanner does, so that lookup
    stays where the scanner owns it.
    """
    env = os.environ if environ is None else environ

    scanner = scanner_config.load(
        config_path=config_path,
        lists_dir=lists_dir,
        daily_brief_dir=daily_brief_dir,
        outbound_dir=outbound_dir,
    )

    data = _webui_section(scanner.config_path)
    base = (
        scanner.config_path.resolve().parent.parent
        if scanner.config_path
        else scanner_config.project_root()
    )

    return WebUIConfig(
        lists_dir=scanner.lists_dir,
        daily_brief_dir=scanner.daily_brief_dir,
        outbound_dir=scanner.outbound_dir,
        host=str(host or env.get(ENV_HOST) or data.get("host") or DEFAULT_HOST),
        port=_port(port, env.get(ENV_PORT), data.get("port")),
        auth_token=_load_token(env, base),
        frame_ancestors=str(
            env.get(ENV_FRAME_ANCESTORS)
            or data.get("frame_ancestors")
            or DEFAULT_FRAME_ANCESTORS
        ),
        config_path=scanner.config_path,
        rules_control_url=(env.get(ENV_RULES_CONTROL_URL) or "").strip() or None,
        rules_control_token=(env.get(ENV_RULES_CONTROL_TOKEN) or "").strip() or None,
    )


def allow_non_loopback(environ: dict[str, str] | None = None) -> bool:
    """Has the operator opted into a non-loopback bind via the environment?

    The flag exists for exactly one case: inside a container, where the process
    must bind ``0.0.0.0`` for a published port to reach it. It says the bind is
    permitted -- NOT that the result is safe. Who can actually connect depends
    on the host publication, which is :func:`reachable_beyond_this_host`.
    """
    env = os.environ if environ is None else environ
    return str(env.get(ENV_ALLOW_NON_LOOPBACK, "")).strip().lower() in {"1", "true", "yes"}


def is_loopback_address(host: str) -> bool:
    """Is this a host nothing off this machine can reach?

    The same set :attr:`WebUIConfig.is_loopback` uses, applied to an address
    from the environment rather than to the configured bind.
    """
    return str(host).strip().strip("[]").lower() in LOOPBACK_HOSTS


def reachable_beyond_this_host(
    config: "WebUIConfig", environ: dict[str, str] | None = None
) -> bool:
    """Can anything other than this machine reach the console?

    **Fail-closed**: this answers True unless it can positively show otherwise.
    It is what the startup guard keys on, and getting it wrong in the permissive
    direction means an unauthenticated console -- one that renders
    attacker-controlled mail and edits the rules deciding what gets delivered --
    on somebody's LAN.

    Three cases, in the order they are decided:

    * **Bound to loopback.** Nothing off this machine can connect, whatever else
      is set -- including inside a container, where a loopback bind is precisely
      what a published port cannot reach. This is the plain ``python -m
      email_guard_webui`` development path, and it keeps working with no token.
    * **The publication address is known.** ``EMAIL_GUARD_WEBUI_PUBLISHED_BIND``
      is set by ``docker-compose.yml`` from ``EMAIL_GUARD_WEBUI_BIND``, so the
      container is *told* the one thing it cannot observe. A loopback value
      means the port is published to this host only, and a 0.0.0.0 bind inside
      the container is then no more reachable than loopback -- which is the
      whole point of that arrangement.
    * **Anything else.** A non-loopback bind with no publication information:
      assume it is reachable. That covers a hand-run ``--allow-non-loopback``,
      an old compose file against a new image, and every case not thought of.

    Note what this does NOT key on: :func:`allow_non_loopback`. That flag grants
    *permission* to bind off loopback; the bind itself is the fact. Keying on
    the flag would refuse a console that had been given the flag and then bound
    127.0.0.1 anyway -- reachable by nobody, and no reason to stop it.
    """
    env = os.environ if environ is None else environ

    if config.is_loopback:
        return False

    published = str(env.get(ENV_PUBLISHED_BIND, "")).strip()
    if published:
        return not is_loopback_address(published)

    return True


def _webui_section(path: Path | None) -> dict:
    if path is None or not path.is_file():
        return {}
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    section = data.get("webui") or {}
    if not isinstance(section, dict):
        raise ConfigError(f"{path}: 'webui' must be an object")
    if "token" in section:
        # Refused rather than ignored: an operator who put a token here would
        # otherwise believe the console was protected while the secret sat in a
        # committed file.
        raise ConfigError(
            f"{path}: the shared token must not live in config.json (it is "
            f"committed). Set {ENV_TOKEN}, or put it in "
            f"{DEFAULT_SECRETS_FILE} under 'webui'.'token' (git-ignored)."
        )
    return section


def _load_token(env: dict[str, str], base: Path) -> str | None:
    """Environment first, then the git-ignored secrets file. Absent = auth off."""
    token = (env.get(ENV_TOKEN) or "").strip()
    if token:
        return token

    secrets_path = env.get(ENV_SECRETS)
    path = Path(secrets_path) if secrets_path else base / DEFAULT_SECRETS_FILE
    if not path.is_file():
        if secrets_path:
            raise FileNotFoundError(f"secrets file not found: {path}")
        return None

    with path.open(encoding="utf-8") as handle:
        secrets = json.load(handle)
    section = secrets.get("webui") or {}
    if not isinstance(section, dict):
        raise ConfigError(f"{path}: 'webui' must be an object")
    return (section.get("token") or "").strip() or None


def _port(flag: int | None, from_env: str | None, from_file) -> int:
    for candidate in (flag, from_env, from_file):
        if candidate in (None, ""):
            continue
        try:
            number = int(candidate)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"port must be an integer, got {candidate!r}") from exc
        if not 1 <= number <= 65535:
            raise ConfigError(f"port must be between 1 and 65535, got {number}")
        return number
    return DEFAULT_PORT
