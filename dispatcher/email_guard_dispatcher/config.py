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

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1143
DEFAULT_MAILBOX = "INBOX"
DEFAULT_POLL_INTERVAL_SECONDS = 30
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_CONCURRENCY = 4
DEFAULT_SCAN_TIMEOUT_SECONDS = 120

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

    tls = str(imap_data.get("tls", TLS_STARTTLS)).lower()
    if tls not in TLS_MODES:
        raise ConfigError(f"config.json: imap.tls must be one of {TLS_MODES}, got {tls!r}")

    ca_file = imap_data.get("ca_file")
    imap = ImapSettings(
        host=str(imap_data.get("host", DEFAULT_HOST)),
        port=int(imap_data.get("port", DEFAULT_PORT)),
        mailbox=mailbox or str(imap_data.get("mailbox", DEFAULT_MAILBOX)),
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
        username=username,
        password=password,
    )

    dispatcher_data = data.get("dispatcher") or {}
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
    )


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
