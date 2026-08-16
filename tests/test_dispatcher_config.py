"""Dispatcher configuration, secrets handling, sinks and state persistence.

Offline throughout: the webhook sink is driven through an injected transport, so
nothing here opens a socket.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from email_guard_dispatcher import config as dispatcher_config
from email_guard_dispatcher.config import ConfigError, ImapSettings
from email_guard_dispatcher.sinks import LoggingSink, WebhookSink, build_sinks
from email_guard_dispatcher.state import ProcessedState, StateError

from tests.conftest import PROJECT_ROOT

IMAP_ENV = (dispatcher_config.ENV_USERNAME, dispatcher_config.ENV_PASSWORD)


def write_config(tmp_path: Path, payload: dict) -> Path:
    """A config.json in a project-root-shaped layout (``<root>/config/``)."""
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# -- config.json -------------------------------------------------------------


def test_defaults_match_the_bridge(tmp_path):
    settings = dispatcher_config.load(
        config_path=write_config(tmp_path, {}), environ={}
    )
    imap = settings.imap

    assert imap.host == "127.0.0.1"
    assert imap.port == 1143
    assert imap.mailbox == "INBOX"
    assert imap.tls == "starttls"
    assert imap.max_attempts == 3
    assert imap.concurrency == 4


def test_imap_section_is_read(tmp_path):
    path = write_config(
        tmp_path,
        {
            "imap": {
                "host": "bridge.internal",
                "port": 993,
                "mailbox": "Intake",
                "tls": "ssl",
                "poll_interval_seconds": 5,
                "max_attempts": 7,
                "concurrency": 2,
            }
        },
    )
    imap = dispatcher_config.load(config_path=path, environ={}).imap

    assert (imap.host, imap.port, imap.mailbox, imap.tls) == (
        "bridge.internal",
        993,
        "Intake",
        "ssl",
    )
    assert imap.poll_interval_seconds == 5
    assert imap.max_attempts == 7
    assert imap.concurrency == 2


def test_mailbox_flag_beats_the_file(tmp_path):
    path = write_config(tmp_path, {"imap": {"mailbox": "INBOX"}})
    settings = dispatcher_config.load(config_path=path, mailbox="Intake", environ={})
    assert settings.imap.mailbox == "Intake"


def test_relative_runtime_paths_hang_off_the_project_root(tmp_path):
    path = write_config(tmp_path, {})
    settings = dispatcher_config.load(config_path=path, environ={})

    assert settings.state_file == (tmp_path / "data/dispatcher/state.json").resolve()
    assert settings.quarantine_log == (tmp_path / "data/dispatcher/quarantine.log").resolve()


def test_bad_values_are_rejected(tmp_path):
    with pytest.raises(ConfigError):
        dispatcher_config.load(
            config_path=write_config(tmp_path, {"imap": {"tls": "carrier-pigeon"}}),
            environ={},
        )
    with pytest.raises(ConfigError):
        dispatcher_config.load(
            config_path=write_config(tmp_path, {"imap": {"concurrency": 0}}), environ={}
        )


def test_missing_explicit_config_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        dispatcher_config.load(config_path=tmp_path / "nope.json", environ={})


def test_repo_config_carries_an_imap_section():
    """The shipped config.json is what the README documents."""
    data = json.loads((PROJECT_ROOT / "config" / "config.json").read_text(encoding="utf-8"))

    assert data["imap"]["host"] == "127.0.0.1"
    assert data["imap"]["port"] == 1143
    assert data["imap"]["tls"] == "starttls"
    # ...and it stays readable by the scanner, whose keys sit alongside it.
    assert data["lists_dir"] == "data/lists"


# -- secrets -----------------------------------------------------------------


def test_credentials_come_from_the_environment(tmp_path):
    settings = dispatcher_config.load(
        config_path=write_config(tmp_path, {}),
        environ={
            dispatcher_config.ENV_USERNAME: "bridge-user",
            dispatcher_config.ENV_PASSWORD: "bridge-pass",
        },
    )
    assert settings.imap.require_credentials() == ("bridge-user", "bridge-pass")


def test_credentials_fall_back_to_the_secrets_file(tmp_path):
    path = write_config(tmp_path, {})
    (tmp_path / "config" / "secrets.json").write_text(
        json.dumps({"imap": {"username": "file-user", "password": "file-pass"}}),
        encoding="utf-8",
    )
    settings = dispatcher_config.load(config_path=path, environ={})
    assert settings.imap.require_credentials() == ("file-user", "file-pass")


def test_environment_beats_the_secrets_file(tmp_path):
    path = write_config(tmp_path, {})
    (tmp_path / "config" / "secrets.json").write_text(
        json.dumps({"imap": {"username": "file-user", "password": "file-pass"}}),
        encoding="utf-8",
    )
    settings = dispatcher_config.load(
        config_path=path,
        environ={
            dispatcher_config.ENV_USERNAME: "env-user",
            dispatcher_config.ENV_PASSWORD: "env-pass",
        },
    )
    assert settings.imap.require_credentials() == ("env-user", "env-pass")


def test_missing_credentials_say_where_to_put_them(tmp_path):
    settings = dispatcher_config.load(config_path=write_config(tmp_path, {}), environ={})
    with pytest.raises(ConfigError) as excinfo:
        settings.imap.require_credentials()

    message = str(excinfo.value)
    assert dispatcher_config.ENV_USERNAME in message
    assert dispatcher_config.ENV_PASSWORD in message
    assert "secrets.json" in message


def test_password_never_appears_in_a_repr():
    """A dataclass repr lands in tracebacks and debug logs; the password must not."""
    settings = ImapSettings(username="bridge-user", password="hunter2-bridge")

    assert "hunter2-bridge" not in repr(settings)
    assert "bridge-user" in repr(settings)  # the username is not a secret
    assert settings.password == "hunter2-bridge"


def test_no_secrets_file_is_committed():
    """The sample is tracked; a filled-in secrets.json must never be."""
    tracked = subprocess.run(
        ["git", "ls-files"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()

    assert "config/secrets.sample.json" in tracked
    assert "config/secrets.json" not in tracked
    assert not any(name.startswith("data/dispatcher/") and name.endswith(".json") for name in tracked)

    sample = json.loads(
        (PROJECT_ROOT / "config" / "secrets.sample.json").read_text(encoding="utf-8")
    )
    assert sample["imap"]["username"].startswith("REPLACE_ME")
    assert sample["imap"]["password"].startswith("REPLACE_ME")


# -- TLS policy --------------------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_accepts_the_self_signed_bridge_certificate(host):
    import ssl

    context = ImapSettings(host=host).build_ssl_context()

    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


@pytest.mark.parametrize("host", ["bridge.internal", "203.0.113.9", "mail.example.com"])
def test_remote_hosts_are_never_silently_unverified(host):
    """The dangerous case: a non-loopback host must still verify."""
    import ssl

    context = ImapSettings(host=host).build_ssl_context()

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_a_ca_file_is_honoured_even_on_loopback(tmp_path):
    import ssl

    ca = tmp_path / "bridge-ca.pem"
    ca.write_text("not a certificate\n", encoding="utf-8")
    # A loopback host with an explicit ca_file must load that file rather than
    # take the self-signed shortcut -- an unusable bundle raising here is the
    # proof it was read at all.
    with pytest.raises(ssl.SSLError):
        ImapSettings(host="127.0.0.1", ca_file=ca).build_ssl_context()


def test_tls_none_has_no_context():
    assert ImapSettings(tls="none").build_ssl_context() is None


# -- ImapMailSource response handling ----------------------------------------
#
# No server involved: a stub stands in for imaplib.IMAP4 so the response
# parsing -- which is the only real logic in ImapMailSource -- is covered.


class StubIMAP:
    """Just enough of imaplib.IMAP4 to drive fetch_new / mark_processed."""

    def __init__(self, uids=b"1 2", bodies=None, search_typ="OK"):
        self.uids = uids
        self.bodies = bodies if bodies is not None else {"1": b"raw-one", "2": b"raw-two"}
        self.search_typ = search_typ
        self.commands: list[tuple] = []

    def uid(self, command, *args):
        self.commands.append((command, *args))
        if command == "SEARCH":
            return self.search_typ, [self.uids]
        if command == "FETCH":
            uid = args[0]
            body = self.bodies.get(uid)
            if body is None:
                return "OK", [None]  # vanished between SEARCH and FETCH
            return "OK", [(f"{uid} (BODY[] {{{len(body)}}}".encode(), body), b")"]
        if command == "STORE":
            return "OK", [b"1 (FLAGS (\\Seen))"]
        raise AssertionError(f"unexpected command {command}")


def make_source(stub) -> object:
    from email_guard_dispatcher.mailsource import ImapMailSource

    source = ImapMailSource(ImapSettings())
    source._conn = stub  # noqa: SLF001 - standing in for a live connection
    source._uid_validity = "99"  # noqa: SLF001
    return source


def test_fetch_new_reads_bodies_by_uid():
    stub = StubIMAP()
    messages = make_source(stub).fetch_new()

    assert messages == [("1", b"raw-one"), ("2", b"raw-two")]
    # BODY.PEEK[], never BODY[]: reading must not set \Seen on its own.
    fetches = [c for c in stub.commands if c[0] == "FETCH"]
    assert all(c[2] == "(BODY.PEEK[])" for c in fetches)


def test_fetch_new_skips_a_message_that_vanished():
    stub = StubIMAP(uids=b"1 2 3")  # uid 3 has no body
    assert make_source(stub).fetch_new() == [("1", b"raw-one"), ("2", b"raw-two")]


def test_empty_mailbox_is_not_an_error():
    assert make_source(StubIMAP(uids=b"")).fetch_new() == []


def test_failed_search_raises():
    from email_guard_dispatcher.mailsource import MailSourceError

    with pytest.raises(MailSourceError):
        make_source(StubIMAP(search_typ="NO")).fetch_new()


def test_mark_processed_stores_the_seen_flag():
    stub = StubIMAP()
    make_source(stub).mark_processed("7")

    assert ("STORE", "7", "+FLAGS", r"(\Seen)") in stub.commands


def test_using_the_source_before_connecting_is_an_error():
    from email_guard_dispatcher.mailsource import ImapMailSource, MailSourceError

    with pytest.raises(MailSourceError):
        ImapMailSource(ImapSettings()).fetch_new()


# -- sinks -------------------------------------------------------------------


VERDICT = {"sender": "sam@unknown-sender.example", "final_level": 3, "bucket": "flagged"}


def test_default_sink_is_logging_only():
    sinks = build_sinks(None)
    assert len(sinks) == 1
    assert isinstance(sinks[0], LoggingSink)


def test_webhook_is_added_when_configured():
    sinks = build_sinks("https://hooks.example/inbound")
    assert isinstance(sinks[1], WebhookSink)


def test_webhook_posts_the_verdict_json():
    posted: list[tuple[str, bytes]] = []

    def transport(url: str, payload: bytes) -> int:
        posted.append((url, payload))
        return 200

    WebhookSink("https://hooks.example/inbound", transport=transport).deliver(VERDICT, "42")

    assert len(posted) == 1
    url, payload = posted[0]
    assert url == "https://hooks.example/inbound"
    assert json.loads(payload.decode("utf-8")) == VERDICT


def test_webhook_retries_then_gives_up_without_raising():
    attempts: list[int] = []
    slept: list[float] = []

    def transport(url: str, payload: bytes) -> int:
        attempts.append(1)
        return 500

    sink = WebhookSink(
        "https://hooks.example/inbound",
        transport=transport,
        attempts=3,
        backoff=1.0,
        sleep=slept.append,
    )
    sink.deliver(VERDICT, "42")  # must not raise: a dead webhook is not a failed scan

    assert len(attempts) == 3
    assert slept == [1.0, 2.0]  # exponential, and no sleep after the last try


def test_webhook_stops_retrying_once_it_succeeds():
    codes = iter([500, 204])
    calls: list[int] = []

    def transport(url: str, payload: bytes) -> int:
        calls.append(1)
        return next(codes)

    WebhookSink(
        "https://hooks.example/x", transport=transport, attempts=3, sleep=lambda _: None
    ).deliver(VERDICT, "42")

    assert len(calls) == 2


def test_webhook_survives_a_transport_exception():
    def transport(url: str, payload: bytes) -> int:
        raise OSError("connection refused")

    WebhookSink(
        "https://hooks.example/x", transport=transport, attempts=2, sleep=lambda _: None
    ).deliver(VERDICT, "42")


# -- state -------------------------------------------------------------------


def test_state_round_trips(tmp_path):
    path = tmp_path / "state.json"
    state = ProcessedState(path, tmp_path / "quarantine.log")
    state.add("1", "7")
    state.add("1", "8")

    assert ProcessedState(path, tmp_path / "quarantine.log").has("1", "7")
    assert not ProcessedState(path, tmp_path / "quarantine.log").has("2", "7")


def test_state_is_written_atomically_and_readably(tmp_path):
    path = tmp_path / "state.json"
    state = ProcessedState(path, tmp_path / "quarantine.log")
    for uid in ("10", "2", "1"):
        state.add("42", uid)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == 1
    assert payload["processed"]["42"] == ["1", "2", "10"]  # numeric order, not "1,10,2"
    assert not list(tmp_path.glob("*.tmp"))  # no leftover temp files


def test_corrupt_state_refuses_to_start(tmp_path):
    """Starting empty would rescan and re-deliver the backlog -- fail instead."""
    path = tmp_path / "state.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(StateError):
        ProcessedState(path, tmp_path / "quarantine.log")


def test_quarantine_records_and_marks_processed(tmp_path):
    from datetime import datetime, timezone

    pinned = datetime(2026, 5, 15, 9, 0, tzinfo=timezone.utc)
    state = ProcessedState(
        tmp_path / "state.json", tmp_path / "quarantine.log", clock=lambda: pinned
    )
    state.quarantine("1", "7", attempts=3, exit_code=2, error="boom", stderr="trace")

    assert state.has("1", "7")  # marked done, so it cannot block the queue
    records = state.read_quarantine()
    assert records == [
        {
            "timestamp": pinned.isoformat(),
            "uid_validity": "1",
            "uid": "7",
            "attempts": 3,
            "exit_code": 2,
            "error": "boom",
            "stderr": "trace",
            "sender": None,
        }
    ]
