"""The control endpoint the review console calls.

Bound to loopback on port 0 and driven with stdlib urllib, so these tests need
no network and no fixed port. The pull itself is injected: this file is about
the transport, the auth and the status mapping, not about git.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterator

import pytest

from email_guard_rules_sync import store
from email_guard_rules_sync.config import SyncConfig
from email_guard_rules_sync.control import AUTH_HEADER, build_server
from email_guard_rules_sync.lock import pull_lock
from email_guard_rules_sync.sync import PullResult

RESULT = PullResult(
    status="updated",
    old_commit="a" * 40,
    new_commit="b" * 40,
    timestamp="2026-08-17T00:00:00+00:00",
    message="promoted bbbbbbbbbbbb from main",
)


@pytest.fixture
def config(tmp_path: Path, rules_dir: Path) -> SyncConfig:
    return SyncConfig(
        live_dir=tmp_path / "rules-live",
        seed_dir=rules_dir,
        control_host="127.0.0.1",
        control_port=0,
    )


def serve(config: SyncConfig, **kwargs) -> Iterator[str]:
    server = build_server(config, **kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def base_url(config: SyncConfig) -> Iterator[str]:
    store.ensure_live_root(config.live_dir, config.seed_dir)
    yield from serve(config, pull=lambda cfg: RESULT)


def call(
    url: str, method: str = "GET", token: str | None = None
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, method=method)
    if method == "POST":
        request.data = b""
    if token is not None:
        request.add_header(AUTH_HEADER, token)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def test_refresh_returns_the_structured_result(base_url: str):
    status, payload = call(f"{base_url}/rules/refresh", "POST")

    assert status == 200
    assert payload["status"] == "updated"
    assert payload["old_commit"] == "a" * 40
    assert payload["new_commit"] == "b" * 40
    assert payload["validation_errors"] == []
    assert payload["timestamp"]
    assert payload["message"]


def test_status_reports_the_promoted_release(base_url: str):
    status, payload = call(f"{base_url}/rules/status")

    assert status == 200
    assert payload["current_commit"] == "seed"
    assert payload["current_target"] == "releases/seed/rules"


def test_status_does_not_need_the_lock(config: SyncConfig, base_url: str):
    """The console must be able to show state while a pull is running."""
    with pull_lock(config.lock_file):
        status, payload = call(f"{base_url}/rules/status")

    assert status == 200
    assert payload["current_commit"] == "seed"


@pytest.mark.parametrize(
    ("status_name", "expected"),
    [
        pytest.param("rejected", "rejected", id="rejected"),
        pytest.param("busy", "busy", id="busy"),
        pytest.param("error", "error", id="error"),
    ],
)
def test_every_outcome_is_an_http_200(config: SyncConfig, status_name: str, expected: str):
    """A refused bad pack is the updater working, not a broken button.

    The console branches on `status`; a 5xx here would make a correct rejection
    indistinguishable from an outage.
    """
    store.ensure_live_root(config.live_dir, config.seed_dir)
    outcome = PullResult(status=status_name, timestamp="2026-08-17T00:00:00+00:00")

    for url in serve(config, pull=lambda cfg: outcome):
        status, payload = call(f"{url}/rules/refresh", "POST")
        break

    assert status == 200
    assert payload["status"] == expected


def test_healthz_is_ok_once_the_pack_is_servable(base_url: str):
    status, payload = call(f"{base_url}/healthz")

    assert status == 200
    assert payload["ok"] is True


def test_healthz_fails_when_nothing_is_promoted(config: SyncConfig):
    config.live_dir.mkdir(parents=True)

    for url in serve(config, pull=lambda cfg: RESULT):
        status, payload = call(f"{url}/healthz")
        break

    assert status == 503
    assert payload["ok"] is False


def test_an_unknown_path_is_a_404(base_url: str):
    assert call(f"{base_url}/rules/promote", "POST")[0] == 404
    assert call(f"{base_url}/nope")[0] == 404


# --- auth -----------------------------------------------------------------------


@pytest.fixture
def guarded(config: SyncConfig, tmp_path: Path) -> Iterator[str]:
    with_token = SyncConfig(
        live_dir=config.live_dir,
        seed_dir=config.seed_dir,
        control_host="127.0.0.1",
        control_port=0,
        control_token="s3cret",
    )
    store.ensure_live_root(with_token.live_dir, with_token.seed_dir)
    yield from serve(with_token, pull=lambda cfg: RESULT)


def test_a_configured_token_guards_refresh_and_status(guarded: str):
    assert call(f"{guarded}/rules/refresh", "POST")[0] == 401
    assert call(f"{guarded}/rules/status")[0] == 401
    assert call(f"{guarded}/rules/refresh", "POST", token="wrong")[0] == 401

    assert call(f"{guarded}/rules/refresh", "POST", token="s3cret")[0] == 200
    assert call(f"{guarded}/rules/status", token="s3cret")[0] == 200


def test_a_refused_call_does_not_run_a_pull(config: SyncConfig):
    calls: list[int] = []
    with_token = SyncConfig(
        live_dir=config.live_dir,
        seed_dir=config.seed_dir,
        control_host="127.0.0.1",
        control_port=0,
        control_token="s3cret",
    )
    store.ensure_live_root(with_token.live_dir, with_token.seed_dir)

    def pull(cfg: SyncConfig) -> PullResult:
        calls.append(1)
        return RESULT

    for url in serve(with_token, pull=pull):
        assert call(f"{url}/rules/refresh", "POST", token="nope")[0] == 401
        break

    assert calls == []


def test_healthz_needs_no_token(guarded: str):
    """Docker's HEALTHCHECK has no way to carry one."""
    assert call(f"{guarded}/healthz")[0] == 200


def test_api_responses_are_not_cacheable(base_url: str):
    request = urllib.request.Request(f"{base_url}/rules/status")
    with urllib.request.urlopen(request, timeout=10) as response:
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
