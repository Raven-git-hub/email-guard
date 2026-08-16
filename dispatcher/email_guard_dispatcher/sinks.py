"""Where a verdict goes once the scan succeeds.

The scanner has already filed the message into ``outbound/<bucket>/<job>/`` by
the time a sink sees it, so a sink is about *notification*, not storage. The
default logs; an optional webhook POSTs the verdict JSON.

TODO(webhook): delivery is best-effort -- a few immediate retries, then the
event is dropped with an error logged. The README's Components section promises
the dispatcher "owns webhook delivery + retries so an offline downstream never
loses an event", which needs a durable queue: persist undelivered verdicts
beside the state file, drain them on a timer, and only then call the event
delivered. Not built here; the retry/backoff below is the interim.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Protocol

log = logging.getLogger(__name__)

DEFAULT_WEBHOOK_ATTEMPTS = 3
DEFAULT_WEBHOOK_BACKOFF = 1.0
DEFAULT_WEBHOOK_TIMEOUT = 10.0


class Sink(Protocol):
    def deliver(self, verdict: dict[str, Any], uid: str) -> None:
        """Hand one verdict onward. Must not raise: a sink is not the point."""


class LoggingSink:
    """The default: one line per verdict, at the level the message earned."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._log = logger or log

    def deliver(self, verdict: dict[str, Any], uid: str) -> None:
        written = verdict.get("written") or {}
        self._log.info(
            "uid=%s sender=%s level=%s bucket=%s job=%s",
            uid,
            verdict.get("sender"),
            verdict.get("final_level"),
            verdict.get("bucket"),
            written.get("job"),
        )


def urllib_transport(
    url: str, payload: bytes, timeout: float = DEFAULT_WEBHOOK_TIMEOUT
) -> int:
    """POST ``payload`` as JSON and return the status code."""
    request = urllib.request.Request(  # noqa: S310 - url comes from local config
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return int(getattr(response, "status", 0) or 0)


class WebhookSink:
    """POST the verdict JSON, with a short retry and backoff.

    ``transport`` and ``sleep`` are injected so the tests can drive this against
    a stub with no socket and no real delay -- the whole suite stays offline.
    """

    def __init__(
        self,
        url: str,
        transport: Callable[[str, bytes], int] | None = None,
        attempts: int = DEFAULT_WEBHOOK_ATTEMPTS,
        backoff: float = DEFAULT_WEBHOOK_BACKOFF,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.url = url
        self._transport = transport or (lambda u, body: urllib_transport(u, body))
        self._attempts = max(1, attempts)
        self._backoff = backoff
        self._sleep = sleep

    def deliver(self, verdict: dict[str, Any], uid: str) -> None:
        payload = json.dumps(verdict, ensure_ascii=False).encode("utf-8")
        delay = self._backoff
        for attempt in range(1, self._attempts + 1):
            try:
                status = self._transport(self.url, payload)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                last_error: str | Exception = exc
            else:
                if 200 <= status < 300:
                    log.debug("webhook delivered uid=%s status=%s", uid, status)
                    return
                last_error = f"HTTP {status}"
            log.warning(
                "webhook attempt %s/%s for uid=%s failed: %s",
                attempt,
                self._attempts,
                uid,
                last_error,
            )
            if attempt < self._attempts:
                self._sleep(delay)
                delay *= 2
        # Deliberately swallowed: the scan succeeded and the message is already
        # filed, so a dead webhook must not fail the message. See TODO(webhook).
        log.error("webhook giving up on uid=%s after %s attempts", uid, self._attempts)


def build_sinks(webhook_url: str | None, logger: logging.Logger | None = None) -> list[Sink]:
    """The configured sinks: always the log, plus a webhook when one is set."""
    sinks: list[Sink] = [LoggingSink(logger)]
    if webhook_url:
        sinks.append(WebhookSink(webhook_url))
    return sinks
