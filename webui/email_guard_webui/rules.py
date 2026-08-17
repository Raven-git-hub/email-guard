"""Talking to the rules updater.

The console does not pull the rules itself, and that is a design decision worth
stating plainly: doing so would mean giving the process that renders hostile
mail a git binary, egress to the internet, and a read-write mount of the tree
the scanner reads -- and it would create a second writer racing the scheduled
pull for one symlink.

Instead the console asks the `rules-updater` service, over a compose network
declared ``internal: true``. Exactly one component owns git and the write path,
so every pull in the system funnels through that one process's lock and
"scheduled pull and manual pull cannot race" is true by construction rather than
by careful coordination.

stdlib ``urllib`` rather than ``httpx``: the console's dependency set is an
optional extra that a deployment has to opt into, and one POST does not justify
growing it.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Callable

log = logging.getLogger(__name__)

AUTH_HEADER = "X-Email-Guard-Rules-Token"

# A pull does real work -- clone or fetch, copy the tree, run the validator in a
# subprocess -- so the refresh timeout is generous. The status read touches only
# a JSON file and a readlink, so it is short: the panel should not hang when the
# updater is gone.
REFRESH_TIMEOUT = 180.0
STATUS_TIMEOUT = 5.0


class UpdaterUnreachable(RuntimeError):
    """The updater is not configured, or did not answer."""


class UpdaterClient:
    """A tiny JSON client for the updater's control endpoint.

    ``opener`` is injectable so tests exercise the endpoints without opening a
    socket -- the same seam ``create_app`` uses for ``today`` and
    ``ContainerRunner`` uses for ``docker``.
    """

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        refresh_timeout: float = REFRESH_TIMEOUT,
        status_timeout: float = STATUS_TIMEOUT,
        opener: Callable[[urllib.request.Request, float], bytes] | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._refresh_timeout = refresh_timeout
        self._status_timeout = status_timeout
        self._opener = opener or _urlopen

    def refresh(self) -> dict[str, Any]:
        """Trigger a pull. Returns the updater's structured result verbatim."""
        return self._call("/rules/refresh", method="POST", timeout=self._refresh_timeout)

    def status(self) -> dict[str, Any]:
        """What is live now. No pull, no lock."""
        return self._call("/rules/status", method="GET", timeout=self._status_timeout)

    def _call(self, path: str, *, method: str, timeout: float) -> dict[str, Any]:
        request = urllib.request.Request(f"{self._base}{path}", method=method)
        if method == "POST":
            # An explicit empty body: urllib decides POST vs GET from `data`,
            # and a Request with method="POST" and no data still sends no
            # Content-Length, which some servers reject.
            request.data = b""
        if self._token:
            request.add_header(AUTH_HEADER, self._token)

        try:
            raw = self._opener(request, timeout)
        except urllib.error.HTTPError as exc:
            detail = _detail(exc.read())
            raise UpdaterUnreachable(
                f"the rules updater refused the request (HTTP {exc.code}): {detail}"
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise UpdaterUnreachable(
                f"could not reach the rules updater at {self._base}: {exc}"
            ) from exc

        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise UpdaterUnreachable(
                "the rules updater returned something that is not JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise UpdaterUnreachable("the rules updater returned an unexpected document")
        return payload


def _urlopen(request: urllib.request.Request, timeout: float) -> bytes:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _detail(body: bytes) -> str:
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "no detail"
    if isinstance(payload, dict) and isinstance(payload.get("detail"), str):
        return payload["detail"]
    return "no detail"


def client_for(config: Any) -> UpdaterClient:
    """Build a client, or explain why there is not one.

    An unconfigured updater is a legitimate deployment -- the console just has
    to say so rather than appear broken.
    """
    if not getattr(config, "rules_control_url", None):
        raise UpdaterUnreachable(
            "no rules updater is configured for this console "
            "(EMAIL_GUARD_RULES_CONTROL_URL is unset), so rules cannot be "
            "refreshed from here"
        )
    return UpdaterClient(config.rules_control_url, config.rules_control_token)
