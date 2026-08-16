"""What has already been handled, so a restart does not redo it.

Two records, both git-ignored because both name real correspondents:

* the **state file** -- every ``(UIDVALIDITY, UID)`` the dispatcher has finished
  with, whether it scanned cleanly or was given up on.
* the **quarantine log** -- one JSON object per line for each message that
  exhausted its retries, so a poisoned message leaves a trail instead of just
  disappearing.

The IMAP ``\\Seen`` flag is the other half of this and is *not* sufficient on its
own: any client can clear it, and a mailbox the human occasionally opens will
have it set on messages that were never scanned. The state file is the
authority; ``\\Seen`` is a courtesy to whatever else looks at the mailbox.

Not thread-safe: ``add`` is a read-modify-write of one file, so two concurrent
calls would lose one of the updates. The runner only ever calls this from its
main thread -- see :mod:`.runner`.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

STATE_VERSION = 1


class StateError(RuntimeError):
    """The state file exists but cannot be understood."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProcessedState:
    """Processed-UID persistence plus the quarantine log.

    ``clock`` is injected rather than called inline, following the scanner's
    habit of taking ``now`` as a parameter (``pipeline.scan_and_write``) so the
    written records are assertable in tests.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        quarantine_log: str | os.PathLike[str] | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.path = Path(path)
        self.quarantine_log = (
            Path(quarantine_log)
            if quarantine_log is not None
            else self.path.with_name("quarantine.log")
        )
        self._clock = clock
        self._processed: dict[str, set[str]] = {}
        self._load()

    # -- queries --------------------------------------------------------------

    def has(self, uid_validity: str, uid: str) -> bool:
        return uid in self._processed.get(str(uid_validity), ())

    def count(self, uid_validity: str | None = None) -> int:
        if uid_validity is None:
            return sum(len(uids) for uids in self._processed.values())
        return len(self._processed.get(str(uid_validity), ()))

    # -- mutations ------------------------------------------------------------

    def add(self, uid_validity: str, uid: str) -> None:
        """Record one message as finished and persist immediately.

        Persisting per message rather than per drain is the point: a crash
        halfway through a batch must not replay the messages already scanned,
        because replaying them would re-fire their webhooks.
        """
        bucket = self._processed.setdefault(str(uid_validity), set())
        if uid in bucket:
            return
        bucket.add(uid)
        self._save()

    def quarantine(
        self,
        uid_validity: str,
        uid: str,
        *,
        attempts: int,
        exit_code: int | None = None,
        error: str = "",
        stderr: str = "",
        sender: str | None = None,
    ) -> dict[str, Any]:
        """Give up on one message: log why, then mark it finished.

        Marking it finished in the *state file* (not only ``\\Seen``) is what
        stops a restart -- or a mailbox whose flags were cleared by another
        client -- from picking the same poison message back up and burning
        ``max_attempts`` scans on it all over again.
        """
        record = {
            "timestamp": self._clock().isoformat(),
            "uid_validity": str(uid_validity),
            "uid": uid,
            "attempts": attempts,
            "exit_code": exit_code,
            "error": error,
            "stderr": stderr,
            "sender": sender,
        }
        self.quarantine_log.parent.mkdir(parents=True, exist_ok=True)
        with self.quarantine_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        log.error(
            "quarantined uid %s after %s attempts: %s", uid, attempts, error or exit_code
        )
        self.add(uid_validity, uid)
        return record

    def read_quarantine(self) -> list[dict[str, Any]]:
        """Every quarantine record, oldest first. Convenience for tests and ops."""
        if not self.quarantine_log.is_file():
            return []
        with self.quarantine_log.open(encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    # -- persistence ----------------------------------------------------------

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            with self.path.open(encoding="utf-8") as handle:
                data = json.load(handle)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            # Not transient, and not safe to ignore: starting from an empty
            # state would rescan and re-deliver the whole backlog. Stop and let
            # a human look at it.
            raise StateError(f"state file is not valid JSON: {self.path}: {exc}") from exc
        if not isinstance(data, dict):
            raise StateError(f"state file is not a JSON object: {self.path}")

        processed = data.get("processed") or {}
        if not isinstance(processed, dict):
            raise StateError(f"state file 'processed' is not an object: {self.path}")
        self._processed = {
            str(validity): {str(uid) for uid in uids}
            for validity, uids in processed.items()
        }

    def _save(self) -> None:
        payload = {
            "version": STATE_VERSION,
            "processed": {
                validity: sorted(uids, key=_uid_sort_key)
                for validity, uids in sorted(self._processed.items())
            },
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write a sibling then rename: os.replace is atomic on the same
        # filesystem, so a crash mid-write leaves the old state intact rather
        # than a truncated file that would fail to load on restart.
        handle = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.path.parent,
            prefix=self.path.name + ".",
            suffix=".tmp",
            delete=False,
        )
        try:
            with handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, self.path)
        except BaseException:
            try:
                os.unlink(handle.name)
            except OSError:
                pass
            raise


def _uid_sort_key(uid: str) -> tuple[int, int | str]:
    """Numeric where possible, so the file reads naturally rather than 1, 10, 2."""
    return (0, int(uid)) if uid.isdigit() else (1, uid)
