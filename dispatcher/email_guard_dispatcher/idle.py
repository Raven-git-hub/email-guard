"""IMAP IDLE (RFC 2177), hand-rolled over the stdlib ``imaplib`` connection.

``imaplib`` has no IDLE support, so this module drives the exchange by hand:
send ``<tag> IDLE``, wait for the server to push an untagged response, send
``DONE``, read the tagged completion. That is the whole protocol.

Hand-rolled rather than pulled from a library on purpose. The dispatcher has
**zero runtime dependencies** (``pyproject.toml``), and IDLE here is only ever a
*latency* optimisation: :meth:`Runner.run_forever` guarantees a full drain every
``poll_interval_seconds`` whatever this module does, so a best-effort IDLE that
occasionally gives up costs a few seconds of latency and never a message. A
library would buy robustness this design does not need, at the cost of the one
property the scanner and dispatcher both advertise. If that calculus ever
changes -- attachments make scans expensive, or the poll interval grows to
minutes -- ``imapclient`` is the obvious swap, and this module is the only file
that would go.

Reaching into ``imaplib`` internals is the price, so it is confined to this one
file. Three of them are load-bearing and were read out of CPython 3.11's
``imaplib.py`` rather than assumed:

* ``_new_tag()`` (imaplib.py:1221) returns *bytes* and, as a side effect,
  registers ``tagged_commands[tag] = None``. Left behind, that is a phantom
  in-flight command that confuses the next real command, so it is popped in a
  ``finally``.
* ``readline()`` (imaplib.py:330) reads from ``self.file``, a ``BufferedReader``
  over ``sock.makefile('rb')`` (imaplib.py:316). A timeout raised *inside* a
  buffered read can leave that buffer inconsistent, which would corrupt every
  later command. So reads are gated on :func:`select.select` and a socket
  timeout is only ever a liveness backstop -- and if it does fire, the exchange
  is fatal to the connection rather than recovered in place. The runner then
  reconnects, which throws the suspect buffer away.
* ``capabilities`` is a tuple of upper-cased ``str``. ``starttls`` refreshes it
  (imaplib.py:835) but ``login`` does not, so a server advertising IDLE only
  after authentication would be misread -- :mod:`.mailsource` refreshes after
  LOGIN, and the check is advisory anyway: a ``BAD``/``NO`` to a real IDLE is
  what actually demotes a connection to polling.

Known and accepted: a wake announcement that the server coalesces into the same
TCP segment as the IDLE continuation can land in ``imaplib``'s buffer where
``select`` cannot see it, and then goes unnoticed until the next slice or the
poll deadline. That is a latency edge, not a lost message, which is exactly the
class of failure the poll backstop exists to absorb.
"""

from __future__ import annotations

import logging
import select
import time
from typing import Any, Callable

log = logging.getLogger(__name__)

# Untagged responses that mean "the mailbox changed, go and look". The drain
# that follows re-enumerates the mailbox from scratch, so this list only has to
# be good enough to trigger -- it never has to be complete, and nothing here
# ever parses a message count out of the line.
WAKE_TOKENS = (b"EXISTS", b"RECENT", b"EXPUNGE", b"FETCH")

# How long a single blocking read may take before the connection is judged
# dead. Only ever reached when the server has already been seen to be ready, or
# right after DONE, so it is generous on purpose.
READ_BACKSTOP_SECONDS = 30.0

# How long to block in one select() before checking the stop flag. Bounds how
# long SIGTERM waits behind an IDLE that would otherwise sit for 25 minutes.
DEFAULT_SLICE_SECONDS = 5.0
_MIN_SLICE_SECONDS = 0.01


class IdleUnsupported(RuntimeError):
    """The server refused IDLE. Demote this connection to polling."""


class IdleError(RuntimeError):
    """The IDLE exchange failed. The connection is suspect -- reconnect."""


def server_supports_idle(conn: Any) -> bool:
    """Advisory only: whether the server *advertises* IDLE."""
    return "IDLE" in (getattr(conn, "capabilities", ()) or ())


def idle_once(
    conn: Any,
    timeout: float,
    stop: Any = None,
    slice_seconds: float = DEFAULT_SLICE_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
) -> bool:
    """Run one IDLE/DONE cycle. ``True`` if the mailbox changed.

    Returns ``False`` on a clean timeout or a stop request. Raises
    :class:`IdleUnsupported` if the server rejects the command, and
    :class:`IdleError` if the exchange breaks down.
    """
    tag = conn._new_tag()
    previous = _get_timeout(conn)
    try:
        _set_timeout(conn, READ_BACKSTOP_SECONDS)
        conn.send(tag + b" IDLE\r\n")
        woke = _await_continuation(conn, tag)
        woke = _watch(conn, timeout, stop, slice_seconds, monotonic) or woke
        conn.send(b"DONE\r\n")
        # A notification can arrive between the decision to stop and the DONE
        # landing, so the completion drain counts as a wake source too.
        return _drain_to_tag(conn, tag) or woke
    except IdleUnsupported:
        raise
    except IdleError:
        raise
    except OSError as exc:
        raise IdleError(f"IDLE socket error: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - imaplib.IMAP4.error and friends
        raise IdleError(f"IDLE failed: {exc}") from exc
    finally:
        # _new_tag registered this; nothing else will ever retire it.
        try:
            conn.tagged_commands.pop(tag, None)
        except Exception:  # noqa: BLE001 - teardown must not mask the real error
            pass
        _set_timeout(conn, previous)


# -- the phases ---------------------------------------------------------------


def _await_continuation(conn: Any, tag: bytes) -> bool:
    """Read up to the ``+`` continuation. ``True`` if a wake arrived first."""
    woke = False
    for _ in range(_MAX_PREAMBLE_LINES):
        line = _read_line(conn)
        if line.startswith(b"+"):
            return woke
        if line.startswith(tag):
            # The server answered the command instead of continuing it: BAD
            # (no IDLE), or NO. Either way this connection cannot IDLE.
            raise IdleUnsupported(_describe(line))
        woke = _is_wake(line) or woke
    raise IdleError("no IDLE continuation from the server")


def _watch(
    conn: Any,
    timeout: float,
    stop: Any,
    slice_seconds: float,
    monotonic: Callable[[], float],
) -> bool:
    """Wait for a push. ``False`` on timeout or stop -- both mean "drain anyway"."""
    deadline = monotonic() + max(0.0, timeout)
    while True:
        if stop is not None and stop.is_set():
            return False
        remaining = deadline - monotonic()
        if remaining <= 0:
            return False
        # The floor matters: a zero-length slice would turn this into a spin.
        if not _readable(conn, min(remaining, max(_MIN_SLICE_SECONDS, slice_seconds))):
            continue
        if _is_wake(_read_line(conn)):
            return True


def _drain_to_tag(conn: Any, tag: bytes) -> bool:
    """Consume through the tagged completion, so the stream is clean again."""
    woke = False
    for _ in range(_MAX_COMPLETION_LINES):
        line = _read_line(conn)
        if line.startswith(tag):
            return woke
        woke = _is_wake(line) or woke
    raise IdleError("no tagged completion after DONE")


# -- socket plumbing ----------------------------------------------------------


def _readable(conn: Any, timeout: float) -> bool:
    """Whether a read can proceed without blocking."""
    sock = conn.sock
    # Bytes already decrypted inside the TLS layer are invisible to select().
    pending = getattr(sock, "pending", None)
    if callable(pending):
        try:
            if pending():
                return True
        except OSError:
            pass
    try:
        ready, _, _ = select.select([sock], [], [], timeout)
    except (OSError, ValueError) as exc:
        raise IdleError(f"select failed: {exc}") from exc
    return bool(ready)


def _read_line(conn: Any) -> bytes:
    """One CRLF-terminated line, via imaplib's own buffered reader."""
    try:
        line = conn.readline()
    except OSError as exc:
        # Includes socket.timeout. Fatal on purpose: a timeout inside the
        # BufferedReader can leave it inconsistent, so the connection is
        # discarded rather than reused. See the module docstring.
        raise IdleError(f"read failed during IDLE: {exc}") from exc
    if not line:
        raise IdleError("connection closed during IDLE")
    return line.strip()


def _get_timeout(conn: Any) -> float | None:
    try:
        return conn.sock.gettimeout()
    except Exception:  # noqa: BLE001 - restoring is best-effort
        return None


def _set_timeout(conn: Any, value: float | None) -> None:
    try:
        conn.sock.settimeout(value)
    except Exception:  # noqa: BLE001 - a dead socket fails the next read anyway
        pass


# -- line classification ------------------------------------------------------


def _is_wake(line: bytes) -> bool:
    if not line.startswith(b"*"):
        return False
    upper = line.upper()
    return any(token in upper for token in WAKE_TOKENS)


def _describe(line: bytes) -> str:
    return line.decode("ascii", errors="replace")


# Bounds on how much unsolicited chatter is tolerated before the exchange is
# called broken, so a misbehaving server cannot spin these loops forever.
_MAX_PREAMBLE_LINES = 64
_MAX_COMPLETION_LINES = 256
