"""Run the scanner as a subprocess and read its verdict back.

This is the entire dispatcher->scanner interface, and it is intentionally thin.
The contract it codes against (``scanner/email_guard/cli.py``):

* ``python -m email_guard <path.eml>`` scans one message and files it.
* **stdout is the verdict JSON and nothing else** -- the human "wrote ..." trail
  goes to stderr precisely so stdout stays pipeable.
* exit ``0`` on success; ``1`` on a config/IO error; ``2`` on an invalid rules
  pack (and argparse's own usage errors); ``3`` on contradictory lists. Anything
  non-zero is a failure here, so codes can be added without touching this file.

Note what this module does *not* do: it passes no ``--lists-dir``,
``--rules-dir``, ``--outbound-dir`` or ``--daily-brief-dir``. The scanner
resolves its own configuration, which is what keeps the dispatcher ignorant of
the scanner's internals. ``extra_env`` is the one seam -- it lets a caller
(tests today, a container recipe later) steer the scanner through the
``EMAIL_GUARD_*`` environment the scanner already documents, without the
dispatcher knowing what those variables mean.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

SCANNER_MODULE = "email_guard"
STDERR_KEEP = 2000  # enough of the tail to diagnose, short enough to log


@dataclass(frozen=True)
class ScanOutcome:
    """One scanner run. ``ok`` means exit 0 *and* a parseable verdict."""

    ok: bool
    exit_code: int
    verdict: dict[str, Any] | None = None
    stderr: str = field(default="", repr=False)
    error: str = ""

    @property
    def bucket(self) -> str | None:
        return (self.verdict or {}).get("bucket")

    @property
    def final_level(self) -> int | None:
        return (self.verdict or {}).get("final_level")

    @property
    def sender(self) -> str | None:
        return (self.verdict or {}).get("sender")


class ScannerClient:
    """Invoke ``python -m email_guard`` on raw message bytes."""

    def __init__(
        self,
        python_executable: str | None = None,
        module: str = SCANNER_MODULE,
        extra_env: dict[str, str] | None = None,
        timeout: float = 120.0,
        cwd: str | os.PathLike[str] | None = None,
    ) -> None:
        self._python = python_executable or sys.executable
        self._module = module
        self._extra_env = dict(extra_env or {})
        self._timeout = timeout
        self._cwd = os.fspath(cwd) if cwd is not None else None

    def scan(self, raw: bytes) -> ScanOutcome:
        """Scan one message. Never raises for a scanner-side failure."""
        path = None
        try:
            path = self._write_temp(raw)
            return self._run(path)
        except OSError as exc:
            # Could not even stage the message -- retryable, like any other
            # failure, so it comes back as an outcome rather than an exception.
            return ScanOutcome(ok=False, exit_code=-1, error=f"cannot stage message: {exc}")
        finally:
            if path is not None:
                try:
                    os.unlink(path)
                except OSError:
                    log.warning("could not remove temp file %s", path)

    # -- internals ------------------------------------------------------------

    def _write_temp(self, raw: bytes) -> str:
        handle = tempfile.NamedTemporaryFile(
            prefix="email-guard-", suffix=".eml", delete=False
        )
        try:
            handle.write(raw)
        finally:
            handle.close()
        return handle.name

    def _run(self, path: str) -> ScanOutcome:
        env = {**os.environ, **self._extra_env}
        argv = [self._python, "-m", self._module, path]
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv,
                capture_output=True,
                timeout=self._timeout,
                env=env,
                cwd=self._cwd,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ScanOutcome(
                ok=False, exit_code=-1, error=f"scanner timed out after {self._timeout}s"
            )
        except OSError as exc:
            return ScanOutcome(ok=False, exit_code=-1, error=f"cannot run scanner: {exc}")

        stderr = _tail(completed.stderr)
        if completed.returncode != 0:
            return ScanOutcome(
                ok=False,
                exit_code=completed.returncode,
                stderr=stderr,
                error=f"scanner exited {completed.returncode}",
            )

        try:
            verdict = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            # Exit 0 with unreadable stdout is still a failure: without a
            # verdict there is nothing to deliver and nothing to record.
            return ScanOutcome(
                ok=False,
                exit_code=completed.returncode,
                stderr=stderr,
                error=f"scanner stdout is not valid JSON: {exc}",
            )
        if not isinstance(verdict, dict):
            return ScanOutcome(
                ok=False,
                exit_code=completed.returncode,
                stderr=stderr,
                error="scanner stdout is not a JSON object",
            )
        return ScanOutcome(ok=True, exit_code=0, verdict=verdict, stderr=stderr)


def _tail(stream: bytes | None) -> str:
    text = (stream or b"").decode("utf-8", errors="replace").strip()
    return text[-STDERR_KEEP:]
