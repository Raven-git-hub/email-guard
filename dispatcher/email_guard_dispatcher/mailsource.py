"""Where messages come from: the bridge, or an in-memory fake.

The loop in :mod:`.runner` talks to this protocol and nothing else, so the whole
dispatcher is testable offline against :class:`FakeMailSource` -- no server, no
sockets, no credentials.

``uid_validity`` is part of the protocol because an IMAP UID is only unique
within a UIDVALIDITY generation. If the server ever renumbers a mailbox, UID 7
afterwards is a different message from UID 7 before, so the processed-state key
has to carry both (RFC 3501 s2.3.1.1).

.. note::
   Poll-based for now: :class:`ImapMailSource` is asked for UNSEEN messages
   every ``poll_interval_seconds``. IMAP IDLE would cut latency from that
   interval to near-instant and is the intended later enhancement -- it needs
   connection keepalive, a re-IDLE timer (servers drop an idle connection after
   ~29 minutes) and a wakeup path, none of which is worth building before the
   poll loop has proven itself. Not built now.
"""

from __future__ import annotations

import imaplib
import logging
import re
from typing import Protocol

from .config import TLS_NONE, TLS_SSL, TLS_STARTTLS, ImapSettings

log = logging.getLogger(__name__)

_UIDVALIDITY_RE = re.compile(rb"UIDVALIDITY\s+(\d+)", re.IGNORECASE)


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
        self._check(*conn.select(_quote(settings.mailbox)), what="SELECT")
        self._conn = conn
        self._uid_validity = self._read_uid_validity(conn)
        log.info("selected %s (uidvalidity=%s)", settings.mailbox, self._uid_validity)

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

    # -- internals ------------------------------------------------------------

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


def _quote(mailbox: str) -> str:
    """Quote a mailbox name; imaplib passes it through verbatim."""
    if mailbox.startswith('"') and mailbox.endswith('"'):
        return mailbox
    return '"' + mailbox.replace("\\", "\\\\").replace('"', '\\"') + '"'


class FakeMailSource:
    """An in-memory mailbox, so the loop can be tested without a server.

    ``fail_times`` makes the next N ``fetch_new`` calls raise a transient error,
    which is how the reconnect/backoff path gets exercised offline.
    """

    def __init__(
        self,
        messages: list[tuple[str, bytes]] | None = None,
        uid_validity: str = "1",
        fail_times: int = 0,
    ) -> None:
        self._messages = list(messages or [])
        self._uid_validity = uid_validity
        self.seen: set[str] = set()
        self.fail_times = fail_times
        self.connect_calls = 0
        self.marked: list[str] = []

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
