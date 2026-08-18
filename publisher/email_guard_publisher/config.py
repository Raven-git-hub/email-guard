"""Configuration, entirely from the environment -- nothing hardcoded.

Both units read the same ``EnvironmentFile``
(``/etc/email-guard/publisher.env``, sample in ``publisher/systemd/``), so the
source tree, the destination and the retention window are set once and are
visible to an operator in one place, with ``systemctl cat`` and ``systemctl
show`` able to print exactly what a unit will run with.

Every value has a default that is either the repository's own layout
(``data/outbound``) or the agreed deployment path
(``/mnt/network/acheron/email-guard``); the file is where a host disagrees with
those, not where it repeats them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

#: The tree the scanner writes, as seen from the HOST. Under compose this is
#: the bind source of the `email-guard-data` volume -- `${EMAIL_GUARD_HOST_ROOT}/
#: data/outbound` -- never the `/app/data/outbound` path a container sees.
SOURCE_ENV = "EMAIL_GUARD_OUTBOUND_DIR"
DEFAULT_SOURCE = "data/outbound"

#: The mounted network partition. The only path in this system that leaves the
#: host, and the only one no container may ever be given.
DEST_ENV = "EMAIL_GUARD_PUBLISH_DEST"
DEFAULT_DEST = "/mnt/network/acheron/email-guard"

#: Which buckets are published. All three by default: the destination layout is
#: `<bucket>/<job>/`, so a consumer that only wants cleared mail can read one
#: subdirectory. Narrow it here if quarantined mail should not leave the host
#: at all.
BUCKETS_ENV = "EMAIL_GUARD_PUBLISH_BUCKETS"
DEFAULT_BUCKETS = ("cleared", "flagged", "rejected")

#: How long a PUBLISHED job stays on local disk. Unpublished jobs are never
#: touched by retention, however old they are -- see `cleanup`.
RETENTION_ENV = "EMAIL_GUARD_OUTBOUND_RETENTION_DAYS"
DEFAULT_RETENTION_DAYS = 14


class ConfigError(ValueError):
    """Bad configuration. Raised at startup, before anything is copied."""


@dataclass(frozen=True)
class Settings:
    """Where to read from, where to write to, and how long to keep the local copy."""

    source_dir: Path
    dest_dir: Path
    buckets: tuple[str, ...]
    retention_days: int

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ

        source = Path(env.get(SOURCE_ENV) or DEFAULT_SOURCE).expanduser()
        dest = Path(env.get(DEST_ENV) or DEFAULT_DEST).expanduser()
        buckets = _buckets(env.get(BUCKETS_ENV))
        retention = _retention_days(env.get(RETENTION_ENV))

        if not str(dest):
            raise ConfigError(f"{DEST_ENV} is empty")
        # The one configuration mistake that would be actively destructive:
        # publishing a tree into itself, which the retention sweep would then
        # be free to delete. Cheap to check, impossible to recover from.
        if _is_within(dest, source) or _is_within(source, dest):
            raise ConfigError(
                f"{DEST_ENV} ({dest}) and {SOURCE_ENV} ({source}) overlap; "
                "the destination must be a separate tree"
            )

        return cls(
            source_dir=source,
            dest_dir=dest,
            buckets=buckets,
            retention_days=retention,
        )


def _buckets(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return DEFAULT_BUCKETS
    names = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not names:
        raise ConfigError(f"{BUCKETS_ENV} is set but names no buckets")
    for name in names:
        # A bucket becomes a path component on both sides. It comes from an
        # operator rather than from mail, but the check costs one line.
        if name in (".", "..") or "/" in name or "\\" in name:
            raise ConfigError(f"{BUCKETS_ENV} contains an unusable bucket name: {name!r}")
    return names


def _retention_days(raw: str | None) -> int:
    if raw is None or not str(raw).strip():
        return DEFAULT_RETENTION_DAYS
    try:
        days = int(str(raw).strip())
    except ValueError:
        raise ConfigError(f"{RETENTION_ENV} must be a whole number of days, got {raw!r}") from None
    if days < 0:
        raise ConfigError(f"{RETENTION_ENV} cannot be negative, got {days}")
    return days


def _is_within(path: Path, root: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
    except ValueError:
        return False
    return True
