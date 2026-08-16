"""Where messages come from: the bridge, or an in-memory fake.

The loop in :mod:`.runner` talks to this protocol and nothing else, so the whole
dispatcher is testable offline against :class:`FakeMailSource` -- no server, no
sockets, no credentials.

``uid_validity`` is part of the protocol because an IMAP UID is only unique
within a UIDVALIDITY generation. If the server ever renumbers a mailbox, UID 7
afterwards is a different message from UID 7 before, so the processed-state key
has to carry both (RFC 3501 s2.3.1.1).

``wait_for_activity`` is the on-arrival half. It is **optional** in the
protocol: the runner duck-types it and falls back to sleeping, so a source that
cannot push (the fake, or a server without IDLE) still works exactly as before.
It is a *trigger only* -- it reports "something happened", never *what*, so the
caller has nothing to act on but a full re-enumeration. That is deliberate. A
targeted fetch of the announced message would make the notification
load-bearing, and a dropped notification would then strand mail; as it is, the
durable queue is the mailbox and the done-list is the state file, exactly as
before.
"""

from __future__ import annotations

import imaplib
import logging
import re
import threading
import time
from typing import Protocol

from . import idle
from .config import TLS_NONE, TLS_SSL, TLS_STARTTLS, ImapSettings

log = logging.getLogger(__name__)

_UIDVALIDITY_RE = re.compile(rb"UIDVALIDITY\s+(\d+)", re.IGNORECASE)

# Consecutive IDLE failures tolerated before a connection is demoted to pure
# polling. Small, because the alternative is re-failing every cycle; a
# reconnect clears it, so the demotion is never permanent.
IDLE_FAILURES_BEFORE_POLLING = 3

# How often FakeMailSource re-checks its stop flag while pretending to idle.
_FAKE_SLICE_SECONDS = 0.01


class MailSourceError(RuntimeError):
    """The mail source could not serve a request."""


class MailSource(Protocol):
    """The dispatcher's whole view of a mailbox."""

    @property
    def uid_validity(self) -> str:
        """Identifies the current UID generation of the selected mailbox."""

    def fetch_new(self) -> list[tuple[str, bytes]]:
        """Return ``(uid, raw_rfc822_bytes)`` for every message awaiting a scan."""

    def mark_processed(self, uid: str) -> None:
        """Mark one message handled, so it is not served again."""


class SupportsIdle(Protocol):
    """The optional on-arrival half of :class:`MailSource`.

    Duck-typed by the runner rather than required, so nothing that cannot push
    has to pretend it can.
    """

    def wait_for_activity(self, timeout: float, stop: object = None) -> bool:
        """Block up to ``timeout``. ``True`` if the mailbox may have changed.

        Never raises: a source that cannot wait usefully returns ``False``
        having slept, so the caller drains on the ordinary poll schedule.
        """


class ImapMailSource:
    """The real one: an IMAP connection to the Proton Mail Bridge.

    Not thread-safe, and deliberately so -- ``imaplib.IMAP4`` multiplexes tagged
    commands over one socket with no locking, so two threads issuing commands
    concurrently interleave their tags and corrupt the protocol. The runner
    keeps every call to this class on one thread; only the scanner subprocesses
    run in parallel.
    """

    def __init__(self, settings: ImapSettings, timeout: float = 60.0) -> None:
        self._settings = settings
        self._timeout = timeout
        self._conn: imaplib.IMAP4 | None = None
        self._uid_validity: str = ""
        # Reset by connect(), so a reconnect always gives IDLE another chance.
        self._idle_enabled = bool(settings.idle)
        self._idle_failures = 0

    # -- connection lifecycle -------------------------------------------------

    def connect(self) -> None:
        """Open, secure, authenticate and select. Idempotent-ish: closes first."""
        self.close()
        settings = self._settings
        username, password = settings.require_credentials()
        context = settings.build_ssl_context()

        log.info(
            "connecting to bridge at %s:%s (tls=%s, mailbox=%s)",
            settings.host,
            settings.port,
            settings.tls,
            settings.mailbox,
        )
        if settings.tls == TLS_SSL:
            conn: imaplib.IMAP4 = imaplib.IMAP4_SSL(
                settings.host, settings.port, ssl_context=context, timeout=self._timeout
            )
        else:
            conn = imaplib.IMAP4(settings.host, settings.port, timeout=self._timeout)
            if settings.tls == TLS_STARTTLS:
                conn.starttls(ssl_context=context)
            elif settings.tls == TLS_NONE:
                # Only ever sane on loopback; the config comment spells out why.
                log.warning("IMAP running without TLS (tls=none) to %s", settings.host)

        conn.login(username, password)
        # imaplib refreshes capabilities after STARTTLS but not after LOGIN, and
        # servers routinely advertise more once authenticated -- IDLE among
        # them. Without this the capability check below reads the pre-auth
        # banner and can wrongly conclude the server cannot IDLE.
        self._refresh_capabilities(conn)
        self._check(*conn.select(_quote(settings.mailbox)), what="SELECT")
        self._conn = conn
        self._uid_validity = self._read_uid_validity(conn)
        self._idle_failures = 0
        self._idle_enabled = bool(settings.idle)
        if self._idle_enabled and not idle.server_supports_idle(conn):
            log.info("server does not advertise IDLE; polling every %ss", settings.poll_interval_seconds)
            self._idle_enabled = False
        log.info(
            "selected %s (uidvalidity=%s, idle=%s)",
            settings.mailbox,
            self._uid_validity,
            "on" if self._idle_enabled else "off",
        )

    def close(self) -> None:
        """Best-effort teardown; a failure here never matters to the caller."""
        conn, self._conn = self._conn, None
        if conn is None:
            return
        try:
            conn.close()
        except Exception:  # noqa: BLE001 - the mailbox may already be gone
            pass
        try:
            conn.logout()
        except Exception:  # noqa: BLE001 - so may the socket
            pass

    def reconnect(self) -> None:
        self.connect()

    # -- the protocol ---------------------------------------------------------

    @property
    def uid_validity(self) -> str:
        return self._uid_validity

    def fetch_new(self) -> list[tuple[str, bytes]]:
        conn = self._require_conn()
        typ, data = conn.uid("SEARCH", None, "UNSEEN")
        self._check(typ, data, what="SEARCH UNSEEN")
        uids = (data[0] or b"").split()

        messages: list[tuple[str, bytes]] = []
        for raw_uid in uids:
            uid = raw_uid.decode("ascii")
            body = self._fetch_one(conn, uid)
            if body is None:
                # A message can vanish between SEARCH and FETCH (moved or
                # deleted by another client). Skip it rather than fail the drain.
                log.warning("uid %s disappeared between SEARCH and FETCH", uid)
                continue
            messages.append((uid, body))
        return messages

    def mark_processed(self, uid: str) -> None:
        conn = self._require_conn()
        typ, data = conn.uid("STORE", uid, "+FLAGS", r"(\Seen)")
        self._check(typ, data, what=f"STORE \\Seen uid={uid}")

    # -- on-arrival -----------------------------------------------------------

    def wait_for_activity(self, timeout: float, stop=None) -> bool:
        """Hold IDLE for up to ``timeout``. ``True`` if the mailbox changed.

        Never raises. Every failure mode degrades to sleeping out the remaining
        time and returning ``False``, because the caller's next move either way
        is a full drain -- and a drain against a broken connection is what
        trips the runner's existing reconnect/backoff path. IDLE going wrong
        must cost latency, never a message.
        """
        deadline = time.monotonic() + max(0.0, timeout)
        while self._idle_enabled:
            if stop is not None and stop.is_set():
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                conn = self._require_conn()
                # Each stretch is re-issued well inside the ~29 minute window
                # RFC 2177 warns servers may enforce on an idle connection.
                stretch = min(remaining, self._settings.idle_timeout_seconds)
                if idle.idle_once(conn, stretch, stop):
                    return True
                self._idle_failures = 0
            except idle.IdleUnsupported as exc:
                log.info("server refused IDLE (%s); polling from here on", exc)
                self._idle_enabled = False
            except Exception as exc:  # noqa: BLE001 - never fail the loop
                self._idle_failures += 1
                log.warning(
                    "IDLE failed (%s/%s): %s; draining on the poll schedule meanwhile",
                    self._idle_failures,
                    IDLE_FAILURES_BEFORE_POLLING,
                    exc,
                )
                if self._idle_failures >= IDLE_FAILURES_BEFORE_POLLING:
                    # Stop retrying on this connection. A reconnect -- which the
                    # runner performs when a drain fails -- re-enables it.
                    log.warning("giving up on IDLE for this connection; reconnect re-enables it")
                    self._idle_enabled = False
                break

        return _sleep_out(deadline - time.monotonic(), stop)

    # -- internals ------------------------------------------------------------

    def _refresh_capabilities(self, conn: imaplib.IMAP4) -> None:
        try:
            conn._get_capabilities()
        except Exception as exc:  # noqa: BLE001 - advisory; IDLE self-demotes anyway
            log.debug("could not refresh capabilities after login: %s", exc)

    def _fetch_one(self, conn: imaplib.IMAP4, uid: str) -> bytes | None:
        # BODY.PEEK[] rather than BODY[]: plain BODY[] sets \Seen as a side
        # effect of reading, which would mark a message processed before its
        # scan had even started -- and a crash mid-scan would then lose it.
        typ, data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
        self._check(typ, data, what=f"FETCH uid={uid}")
        for part in data or []:
            if isinstance(part, tuple) and len(part) >= 2 and part[1]:
                return bytes(part[1])
        return None

    def _read_uid_validity(self, conn: imaplib.IMAP4) -> str:
        """From SELECT's untagged response, falling back to STATUS."""
        try:
            typ, data = conn.response("UIDVALIDITY")
            if typ == "UIDVALIDITY" and data and data[0]:
                return data[0].decode("ascii").strip()
        except Exception:  # noqa: BLE001 - fall through to STATUS
            pass

        typ, data = conn.status(_quote(self._settings.mailbox), "(UIDVALIDITY)")
        self._check(typ, data, what="STATUS UIDVALIDITY")
        match = _UIDVALIDITY_RE.search(data[0] or b"")
        if not match:
            raise MailSourceError(f"could not read UIDVALIDITY for {self._settings.mailbox}")
        return match.group(1).decode("ascii")

    def _require_conn(self) -> imaplib.IMAP4:
        if self._conn is None:
            raise MailSourceError("not connected: call connect() first")
        return self._conn

    @staticmethod
    def _check(typ, data, what: str) -> None:
        if typ != "OK":
            raise MailSourceError(f"{what} failed: {typ} {data!r}")


def _sleep_out(seconds: float, stop=None) -> bool:
    """Sleep the remainder of a wait window. Always ``False`` -- no push seen."""
    if seconds <= 0:
        return False
    if stop is not None:
        stop.wait(seconds)
    else:
        time.sleep(seconds)
    return False


def _quote(mailbox: str) -> str:
    """Quote a mailbox name; imaplib passes it through verbatim."""
    if mailbox.startswith('"') and mailbox.endswith('"'):
        return mailbox
    return '"' + mailbox.replace("\\", "\\\\").replace('"', '\\"') + '"'


class FakeMailSource:
    """An in-memory mailbox, so the loop can be tested without a server.

    ``fail_times`` makes the next N ``fetch_new`` calls raise a transient error,
    which is how the reconnect/backoff path gets exercised offline.

    ``notify`` is the IDLE half: set the event and the next
    ``wait_for_activity`` returns immediately, exactly as a server push would.
    Leave it unset and the call behaves like a server that never pushes, which
    is how the poll backstop gets tested. ``idle_failures`` makes the next N
    waits raise, standing in for a dropped IDLE connection.

    ``connect_failures`` makes the next N ``connect`` calls raise -- a bridge
    that is still starting up, which is the ordinary case under compose.
    """

    def __init__(
        self,
        messages: list[tuple[str, bytes]] | None = None,
        uid_validity: str = "1",
        fail_times: int = 0,
        idle_failures: int = 0,
        connect_failures: int = 0,
    ) -> None:
        self._messages = list(messages or [])
        self._uid_validity = uid_validity
        self.seen: set[str] = set()
        self.fail_times = fail_times
        self.connect_calls = 0
        self.connect_failures = connect_failures
        self.marked: list[str] = []
        self.notify = threading.Event()
        self.idle_failures = idle_failures
        self.waits: list[float] = []

    @property
    def uid_validity(self) -> str:
        return self._uid_validity

    def set_uid_validity(self, value: str) -> None:
        """Simulate a server renumbering the mailbox."""
        self._uid_validity = value

    def add(self, uid: str, raw: bytes) -> None:
        self._messages.append((uid, raw))

    def connect(self) -> None:
        self.connect_calls += 1
        if self.connect_failures > 0:
            self.connect_failures -= 1
            raise MailSourceError("simulated connection refused (bridge not ready)")

    def close(self) -> None:
        pass

    def reconnect(self) -> None:
        self.connect()

    def fetch_new(self) -> list[tuple[str, bytes]]:
        if self.fail_times > 0:
            self.fail_times -= 1
            raise MailSourceError("simulated transient IMAP failure")
        return [(uid, raw) for uid, raw in self._messages if uid not in self.seen]

    def mark_processed(self, uid: str) -> None:
        self.seen.add(uid)
        self.marked.append(uid)

    def wait_for_activity(self, timeout: float, stop=None) -> bool:
        """Stand in for IDLE: return on ``notify``, else time out like a poll.

        Honours ``stop`` the same way the real one does -- by checking it
        between short slices rather than sleeping through it. A fake that
        ignored it would hang any test whose loop is asked to shut down while
        waiting, which is precisely the case worth testing.
        """
        self.waits.append(timeout)
        if self.idle_failures > 0:
            self.idle_failures -= 1
            raise MailSourceError("simulated IDLE connection drop")

        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if stop is not None and stop.is_set():
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if self.notify.wait(min(remaining, _FAKE_SLICE_SECONDS)):
                self.notify.clear()
                return True
