"""Rules pack auto-updater.

Pulls the rules pack from git on a schedule (or on demand from the review
console), validates it, and promotes it atomically so the *next* scan container
mounts the new tree. Nothing restarts: each message is scanned by a fresh
``docker run --rm`` that mounts the rules directory read-only at scan time, so
there is no long-lived process holding the old rules.

Deliberately self-contained: this package imports NOTHING from the scanner
engine, the same independence rule ``rules/validate.py`` follows. It talks to
the pack through two narrow contracts -- the pack's own ``validate.py`` (run as
a subprocess) and the on-disk layout of ``rules/reference/`` -- so the pack can
move to its own repository later without touching this code.

The failure split of the runtime is mirrored exactly, and must not be unified:

* **scan rules fail CLOSED** -- any validator error and the pull is *rejected*.
  The live pack is left exactly as it was and scanning continues on it.
* **the signature feed fails OPEN** -- a missing or malformed
  ``rules/reference/{injection,phishing}_signatures.json`` is a warning that
  still promotes. A truncated download must cost sensitivity, not stop the mail.

See the root README, "Engine vs rules pack".
"""

from __future__ import annotations

from .config import ConfigError, SyncConfig, load, parse_interval
from .lock import PullBusy, pull_lock
from .sync import PullResult, pull_and_promote

__all__ = [
    "ConfigError",
    "PullBusy",
    "PullResult",
    "SyncConfig",
    "load",
    "parse_interval",
    "pull_and_promote",
    "pull_lock",
]
