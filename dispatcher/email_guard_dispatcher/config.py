"""Dispatcher configuration: IMAP settings, secrets, state paths, webhook.

Resolution order mirrors the scanner's (``scanner/email_guard/config.py``),
highest priority first:

    1. explicit CLI flag (``--config`` / ``--mailbox``)
    2. environment
    3. the ``imap`` section of ``config/config.json``
    4. built-in default

This module deliberately does **not** import ``email_guard``. The dispatcher
reaches the scanner by running it as a subprocess, and keeping the import graph
empty is what makes that boundary real rather than nominal -- the dispatcher
cannot accidentally grow a dependency on scanner internals.

Secrets never live in git. The IMAP username and password are the
*bridge-generated* credentials (Proton Bridge mints a per-account pair that is
not the Proton account password), and they come from the environment or a
git-ignored secrets file. Everything else is non-secret and lives in
``config.json``.
"""

from __future__ import annotations

import json
import os
import ssl
from dataclasses import dataclass, field
from pathlib import Path

from .container_runner import (
    DEFAULT_CPUS,
    DEFAULT_IMAGE,
    DEFAULT_MEMORY,
    DEFAULT_PIDS_LIMIT,
    DEFAULT_TMPFS_SIZE,
    ContainerSettings,
)
from .scanner_runner import RUNNERS

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1143
DEFAULT_MAILBOX = "INBOX"
DEFAULT_POLL_INTERVAL_SECONDS = 30
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_CONCURRENCY = 4
DEFAULT_SCAN_TIMEOUT_SECONDS = 120

# IDLE is on by default because on-arrival processing is the point; it is a
# latency optimisation only, and the poll interval above remains the
# correctness guarantee whether IDLE works or not.
DEFAULT_IDLE = True
# Re-issue IDLE well inside the ~29 minutes RFC 2177 warns a server may allow
# before dropping an idle connection.
DEFAULT_IDLE_TIMEOUT_SECONDS = 1500

# The code default is the unsandboxed one: it needs no daemon, so a plain
# checkout and the test suite work untouched. Compose switches the *deployed*
# dispatcher to "container", which is where isolation is actually wanted.
DEFAULT_SCANNER_RUNNER = "subprocess"

# Scanner-side directories. The dispatcher normally has no opinion on these --
# the scanner resolves its own configuration. The container runner is the
# exception: it has to name them to mount them.
DEFAULT_LISTS_DIR = "data/lists"
DEFAULT_RULES_DIR = "rules"
DEFAULT_OUTBOUND_DIR = "data/outbound"
DEFAULT_DAILY_BRIEF_DIR = "data/daily-brief"
DEFAULT_DATA_DIR = "data"
DEFAULT_SPOOL_DIR = "data/dispatcher/scan-spool"

# Runtime stores. Both hold personal data -- the state file records which
# messages arrived, the quarantine log records who sent the ones that failed --
# so both are git-ignored, like data/outbound (root README, "Storage & privacy").
DEFAULT_STATE_FILE = "data/dispatcher/state.json"
DEFAULT_QUARANTINE_LOG = "data/dispatcher/quarantine.log"
DEFAULT_SECRETS_FILE = "config/secrets.json"

TLS_STARTTLS = "starttls"
TLS_SSL = "ssl"
TLS_NONE = "none"
TLS_MODES = (TLS_STARTTLS, TLS_SSL, TLS_NONE)

# Hosts where a self-signed bridge certificate is acceptable without a CA file:
# traffic never leaves the machine, so there is no network attacker to defend
# against. Anything else must present a verifiable certificate -- see
# ImapSettings.build_ssl_context.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "localhost.localdomain"})

ENV_CONFIG = "EMAIL_GUARD_CONFIG"
ENV_SECRETS = "EMAIL_GUARD_SECRETS"
ENV_USERNAME = "EMAIL_GUARD_IMAP_USERNAME"
ENV_PASSWORD = "EMAIL_GUARD_IMAP_PASSWORD"
ENV_WEBHOOK_URL = "EMAIL_GUARD_WEBHOOK_URL"
ENV_IDLE = "EMAIL_GUARD_IMAP_IDLE"

# Connection overrides. These exist for compose: under it the bridge is reached
# at a service name rather than 127.0.0.1, and the certificate to trust lives
# at a path only the deployment knows. config/config.json is shared with the
# host-run dispatcher and mounted read-only, so it is the wrong place to encode
# either. Same precedence as everything else: environment beats file.
ENV_IMAP_HOST = "EMAIL_GUARD_IMAP_HOST"
ENV_IMAP_PORT = "EMAIL_GUARD_IMAP_PORT"
ENV_IMAP_TLS = "EMAIL_GUARD_IMAP_TLS"
ENV_IMAP_CA_FILE = "EMAIL_GUARD_IMAP_CA_FILE"
ENV_IMAP_MAILBOX = "EMAIL_GUARD_IMAP_MAILBOX"
ENV_SCANNER_RUNNER = "EMAIL_GUARD_SCANNER_RUNNER"
ENV_SCANNER_IMAGE = "EMAIL_GUARD_SCANNER_IMAGE"
ENV_CONTAINER_USER = "EMAIL_GUARD_CONTAINER_USER"

# Both halves of each path mapping. Deliberately *not* named
# EMAIL_GUARD_RULES_DIR / EMAIL_GUARD_LISTS_DIR: those already belong to the
# scanner, and the container runner passes them into the scanner container with
# container-side values. Reusing the names would have the dispatcher's own
# mount configuration silently become the scanner's path configuration.
ENV_HOST_DATA_DIR = "EMAIL_GUARD_HOST_DATA_DIR"
ENV_CONTAINER_DATA_DIR = "EMAIL_GUARD_CONTAINER_DATA_DIR"
ENV_HOST_RULES_DIR = "EMAIL_GUARD_HOST_RULES_DIR"
ENV_CONTAINER_RULES_DIR = "EMAIL_GUARD_CONTAINER_RULES_DIR"


class ConfigError(ValueError):
    """A configuration value is missing or unusable."""


def project_root() -> Path:
    """``<root>/dispatcher/email_guard_dispatcher/config.py`` -> ``<root>``."""
    return Path(__file__).resolve().parents[2]


def default_config_path() -> Path:
    return project_root() / "config" / "config.json"


@dataclass(frozen=True)
class ImapSettings:
    """Everything needed to open one connection to the bridge.

    ``password`` is ``repr=False`` on purpose: a dataclass repr turns up in
    tracebacks and debug logs, and a bridge password must not ride along.
    """

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    mailbox: str = DEFAULT_MAILBOX
    tls: str = TLS_STARTTLS
    ca_file: Path | None = None
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    concurrency: int = DEFAULT_CONCURRENCY
    scan_timeout_seconds: float = DEFAULT_SCAN_TIMEOUT_SECONDS
    idle: bool = DEFAULT_IDLE
    idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS
    username: str | None = None
    password: str | None = field(default=None, repr=False)

    @property
    def is_loopback(self) -> bool:
        return self.host.strip("[]").lower() in LOOPBACK_HOSTS

    def require_credentials(self) -> tuple[str, str]:
        """The credentials, or a clear error naming where to put them."""
        if not self.username or not self.password:
            raise ConfigError(
                "IMAP credentials missing: set "
                f"{ENV_USERNAME} and {ENV_PASSWORD}, or write them to "
                f"{DEFAULT_SECRETS_FILE} (git-ignored). These are the "
                "bridge-generated credentials, not the Proton account password."
            )
        return self.username, self.password

    def build_ssl_context(self) -> ssl.SSLContext | None:
        """The TLS policy, in one place.

        Proton Bridge listens on loopback with a self-signed certificate it
        generates at install time, so there is nothing to verify it against.
        Accepting it *on loopback* is safe -- the connection never leaves the
        host. Accepting it anywhere else would not be, so a non-loopback host
        with no ``ca_file`` gets ordinary verification and is allowed to fail
        loudly rather than being silently downgraded.

        TODO(bridge-tls): there is currently no way to encrypt the hop when the
        bridge is reached by a *name* rather than by loopback, which is what
        compose does (``bridge:143`` over an internal network). The bridge's
        certificate is issued for ``localhost``/``127.0.0.1``, so it fails
        hostname verification against ``bridge`` no matter which ``ca_file`` is
        supplied, and there is deliberately no verify-off switch here. The
        compose deployment therefore runs that hop as ``tls=none`` on a network
        with no route off the host -- honest, and better than a downgrade
        pretending to verify. Closing this properly means a fourth mode:
        encrypt, pin/trust this specific certificate, skip the hostname check.
        """
        if self.tls == TLS_NONE:
            return None
        if self.tls not in TLS_MODES:
            raise ConfigError(f"unknown tls mode {self.tls!r}; expected one of {TLS_MODES}")
        if self.ca_file is not None:
            return ssl.create_default_context(cafile=str(self.ca_file))
        if self.is_loopback:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        return ssl.create_default_context()


@dataclass(frozen=True)
class DispatcherConfig:
    imap: ImapSettings
    state_file: Path
    quarantine_log: Path
    webhook_url: str | None = None
    config_path: Path | None = None
    scanner_runner: str = DEFAULT_SCANNER_RUNNER
    container: ContainerSettings = field(default_factory=ContainerSettings)


def load(
    config_path: str | os.PathLike[str] | None = None,
    mailbox: str | None = None,
    state_file: str | os.PathLike[str] | None = None,
    quarantine_log: str | os.PathLike[str] | None = None,
    environ: dict[str, str] | None = None,
) -> DispatcherConfig:
    """Build the effective dispatcher configuration."""
    env = os.environ if environ is None else environ

    chosen_config = config_path or env.get(ENV_CONFIG)
    path = Path(chosen_config) if chosen_config else default_config_path()

    data: dict = {}
    used_path: Path | None = None
    if path.is_file():
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        used_path = path
    elif chosen_config:
        # Same rule as the scanner: an explicitly requested config that is
        # absent is an error, a missing default one is not.
        raise FileNotFoundError(f"config file not found: {path}")

    # Relative entries in config.json hang off the project root, not the cwd,
    # so the dispatcher behaves the same however it is invoked.
    base = used_path.resolve().parent.parent if used_path else project_root()
    imap_data = data.get("imap") or {}
    if not isinstance(imap_data, dict):
        raise ConfigError("config.json: 'imap' must be an object")

    username, password = _load_credentials(env, base)

    tls = str(env.get(ENV_IMAP_TLS) or imap_data.get("tls", TLS_STARTTLS)).lower()
    if tls not in TLS_MODES:
        raise ConfigError(f"imap.tls must be one of {TLS_MODES}, got {tls!r}")

    ca_file = env.get(ENV_IMAP_CA_FILE) or imap_data.get("ca_file")
    imap = ImapSettings(
        host=str(env.get(ENV_IMAP_HOST) or imap_data.get("host", DEFAULT_HOST)),
        port=int(env.get(ENV_IMAP_PORT) or imap_data.get("port", DEFAULT_PORT)),
        mailbox=mailbox
        or env.get(ENV_IMAP_MAILBOX)
        or str(imap_data.get("mailbox", DEFAULT_MAILBOX)),
        tls=tls,
        ca_file=_resolve_path(ca_file, base) if ca_file else None,
        poll_interval_seconds=float(
            imap_data.get("poll_interval_seconds", DEFAULT_POLL_INTERVAL_SECONDS)
        ),
        max_attempts=_positive_int(imap_data.get("max_attempts"), DEFAULT_MAX_ATTEMPTS, "max_attempts"),
        concurrency=_positive_int(imap_data.get("concurrency"), DEFAULT_CONCURRENCY, "concurrency"),
        scan_timeout_seconds=float(
            imap_data.get("scan_timeout_seconds", DEFAULT_SCAN_TIMEOUT_SECONDS)
        ),
        idle=_bool(env.get(ENV_IDLE), imap_data.get("idle"), DEFAULT_IDLE),
        idle_timeout_seconds=float(
            imap_data.get("idle_timeout_seconds", DEFAULT_IDLE_TIMEOUT_SECONDS)
        ),
        username=username,
        password=password,
    )

    dispatcher_data = data.get("dispatcher") or {}
    if not isinstance(dispatcher_data, dict):
        raise ConfigError("config.json: 'dispatcher' must be an object")

    runner = str(
        env.get(ENV_SCANNER_RUNNER)
        or dispatcher_data.get("scanner_runner")
        or DEFAULT_SCANNER_RUNNER
    ).strip().lower()
    if runner not in RUNNERS:
        raise ConfigError(
            f"config.json: dispatcher.scanner_runner must be one of {RUNNERS}, got {runner!r}"
        )

    return DispatcherConfig(
        imap=imap,
        state_file=_pick_path(
            state_file, dispatcher_data.get("state_file"), DEFAULT_STATE_FILE, base
        ),
        quarantine_log=_pick_path(
            quarantine_log, dispatcher_data.get("quarantine_log"), DEFAULT_QUARANTINE_LOG, base
        ),
        webhook_url=env.get(ENV_WEBHOOK_URL) or dispatcher_data.get("webhook_url") or None,
        config_path=used_path,
        scanner_runner=runner,
        container=_load_container(data, dispatcher_data, env, base),
    )


def _load_container(
    data: dict, dispatcher_data: dict, env: dict[str, str], base: Path
) -> ContainerSettings:
    """The container runner's settings, including both halves of each path map.

    Built unconditionally, even under the subprocess runner: the settings are
    cheap, and constructing them always means a malformed ``container`` block is
    reported at startup rather than lying dormant until someone switches
    runners on a live host. Validation of the *values* is
    :meth:`ContainerSettings.validate`, which only the container runner calls --
    a subprocess deployment has no mounts to get wrong.

    The scanner's own directories are read from the *top level* of config.json
    -- the same keys the scanner reads. That is the one place the dispatcher
    looks at scanner configuration, and it is unavoidable: something has to
    name a directory in order to mount it. It is still only paths; nothing here
    knows what the scanner writes into them.
    """
    section = dispatcher_data.get("container") or {}
    if not isinstance(section, dict):
        raise ConfigError("config.json: 'dispatcher.container' must be an object")

    data_dir = _resolve_path(
        env.get(ENV_CONTAINER_DATA_DIR) or section.get("data_dir") or DEFAULT_DATA_DIR, base
    )
    rules_dir = _resolve_path(
        env.get(ENV_CONTAINER_RULES_DIR)
        or section.get("rules_dir")
        or data.get("rules_dir")
        or DEFAULT_RULES_DIR,
        base,
    )

    # Host paths default to the dispatcher's own: correct whenever the
    # dispatcher is NOT itself containerised, where the two are the same
    # filesystem. Compose overrides them, and getting that wrong is the failure
    # ContainerRunner's startup validation and VALIDATION.md exist to catch.
    host_data_dir = Path(env.get(ENV_HOST_DATA_DIR) or section.get("host_data_dir") or data_dir)
    host_rules_dir = Path(
        env.get(ENV_HOST_RULES_DIR) or section.get("host_rules_dir") or rules_dir
    )

    return ContainerSettings(
        image=env.get(ENV_SCANNER_IMAGE) or section.get("image") or DEFAULT_IMAGE,
        host_data_dir=host_data_dir,
        data_dir=data_dir,
        host_rules_dir=host_rules_dir,
        rules_dir=rules_dir,
        lists_dir=_resolve_path(data.get("lists_dir") or DEFAULT_LISTS_DIR, base),
        outbound_dir=_resolve_path(data.get("outbound_dir") or DEFAULT_OUTBOUND_DIR, base),
        daily_brief_dir=_resolve_path(
            data.get("daily_brief_dir") or DEFAULT_DAILY_BRIEF_DIR, base
        ),
        spool_dir=_resolve_path(section.get("spool_dir") or DEFAULT_SPOOL_DIR, base),
        user=str(
            env.get(ENV_CONTAINER_USER) or section.get("user") or _current_user()
        ),
        memory=str(section.get("memory") or DEFAULT_MEMORY),
        pids_limit=_positive_int(section.get("pids_limit"), DEFAULT_PIDS_LIMIT, "pids_limit"),
        cpus=str(section.get("cpus") or DEFAULT_CPUS),
        tmpfs_size=str(section.get("tmpfs_size") or DEFAULT_TMPFS_SIZE),
        docker_binary=str(section.get("docker_binary") or "docker"),
    )


def _current_user() -> str:
    """The dispatcher's own uid/gid.

    Inheriting it is what makes the spool files the scanner container writes
    readable by the dispatcher that has to move them afterwards -- and it means
    a dispatcher correctly running as non-root produces a non-root scanner for
    free. A dispatcher running as root is refused by
    :meth:`ContainerSettings.validate`, which is the intended nudge.
    """
    return f"{os.getuid()}:{os.getgid()}"


def _load_credentials(env: dict[str, str], base: Path) -> tuple[str | None, str | None]:
    """Environment first, then the git-ignored secrets file."""
    username = env.get(ENV_USERNAME)
    password = env.get(ENV_PASSWORD)
    if username and password:
        return username, password

    secrets_path = env.get(ENV_SECRETS)
    path = Path(secrets_path) if secrets_path else base / DEFAULT_SECRETS_FILE
    if not path.is_file():
        if secrets_path:
            raise FileNotFoundError(f"secrets file not found: {path}")
        return username, password

    with path.open(encoding="utf-8") as handle:
        secrets = json.load(handle)
    section = secrets.get("imap") or {}
    if not isinstance(section, dict):
        raise ConfigError(f"{path}: 'imap' must be an object")
    # Environment still wins over the file, per the documented order.
    return username or section.get("username"), password or section.get("password")


def _bool(env_value, file_value, fallback: bool) -> bool:
    """Environment first, then the file. ``"0"``/``"false"``/``"no"`` are false."""
    if env_value is not None and str(env_value).strip() != "":
        return str(env_value).strip().lower() not in ("0", "false", "no", "off")
    if file_value is not None:
        return bool(file_value)
    return fallback


def _positive_int(value, fallback: int, name: str) -> int:
    if value is None:
        return fallback
    number = int(value)
    if number < 1:
        raise ConfigError(f"config.json: imap.{name} must be at least 1, got {number}")
    return number


def _resolve_path(value: str | os.PathLike[str], base: Path) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    return candidate.resolve()


def _pick_path(flag, from_file, fallback: str, base: Path) -> Path:
    # A flag is user-supplied at the call site, so it resolves against the cwd;
    # config.json values hang off the project root. Same rule as the scanner.
    if flag:
        return Path(flag).expanduser().resolve()
    return _resolve_path(from_file or fallback, base)
