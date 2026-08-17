"""A very small HTTP control surface, so the console can ask for a pull.

**Why the console does not do this itself.** Exactly one component owns git and
the write path to the live tree. Giving the review console its own git binary,
its own egress and a read-write rules mount would put three new powers on the
process that renders hostile mail, and would mean two writers racing for one
symlink. Instead the console asks this service, and every pull in the system --
scheduled or manual -- funnels through the one flock in this one process.

Stdlib ``http.server`` on purpose: the updater's image would otherwise need a
web framework to answer one POST, and this repo's zero-runtime-dependency
posture is worth more than the convenience.

Exposure: bound to an ``internal: true`` compose network with two containers on
it and no route off the host, plus a shared-token check. Same reasoning the
dispatcher<->bridge hop already uses for plaintext IMAP.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .config import SyncConfig
from .sync import pull_and_promote, status_snapshot

log = logging.getLogger(__name__)

AUTH_HEADER = "X-Email-Guard-Rules-Token"
NO_STORE = "no-store"


def build_server(
    config: SyncConfig,
    *,
    pull: Callable[[SyncConfig], Any] | None = None,
) -> ThreadingHTTPServer:
    """A configured, not-yet-serving control server.

    ``pull`` is injectable so tests can drive the transport without a git remote.
    """
    do_pull = pull if pull is not None else pull_and_promote

    class Handler(BaseHTTPRequestHandler):
        server_version = "EmailGuardRulesUpdater/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            log.debug("control: " + fmt, *args)

        # -- helpers ---------------------------------------------------------
        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", NO_STORE)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _authorised(self) -> bool:
            """Constant-time comparison, so a wrong guess leaks no timing."""
            token = config.control_token
            if not token:
                return True
            supplied = self.headers.get(AUTH_HEADER) or ""
            return hmac.compare_digest(supplied, token)

        def _drain(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 0:
                self.rfile.read(length)

        # -- routes ----------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
            if self.path == "/healthz":
                healthy = _pack_is_servable(config)
                self._send(200 if healthy else 503, {"ok": healthy})
                return
            if self.path == "/rules/status":
                if not self._authorised():
                    self._send(401, {"detail": f"missing or invalid {AUTH_HEADER}"})
                    return
                self._send(200, status_snapshot(config))
                return
            self._send(404, {"detail": "no such endpoint"})

        def do_POST(self) -> None:  # noqa: N802
            self._drain()
            if self.path != "/rules/refresh":
                self._send(404, {"detail": "no such endpoint"})
                return
            if not self._authorised():
                self._send(401, {"detail": f"missing or invalid {AUTH_HEADER}"})
                return

            result = do_pull(config)
            # 200 for every outcome, including `rejected`, `busy` and `error`.
            # Those are *results* of a pull that ran, not transport failures --
            # the console branches on `status`, and a 5xx would make a correctly
            # refused bad pack look like a broken button.
            self._send(200, result.as_dict())

    server = ThreadingHTTPServer((config.control_host, config.control_port), Handler)
    server.daemon_threads = True
    return server


def _pack_is_servable(config: SyncConfig) -> bool:
    """Health is "a scan container starting now would find a pack"."""
    try:
        return (config.current_link / "scan" / "level2.json").is_file()
    except OSError:
        return False


def serve_in_background(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, name="rules-control", daemon=True)
    thread.start()
    log.info("rules control endpoint listening on %s:%s", *server.server_address[:2])
    return thread
