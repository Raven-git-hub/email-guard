"""The console's "Refresh rules" endpoint.

The console deliberately owns no part of the pull: it has no git, no egress and
no write access to the rules tree. It asks the rules-updater service, which is
the single owner of both. These tests drive that seam with an injected client,
so nothing here opens a socket.

The status mapping is the interesting part. A pull that ran and *refused* a bad
pack is the system working exactly as designed, so it comes back 200 with a
``status`` the UI branches on. Only "there was nobody to ask" is an error.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi", reason="the web UI needs the 'webui' extra")

from fastapi.testclient import TestClient  # noqa: E402

from email_guard_webui.app import create_app  # noqa: E402
from email_guard_webui.config import AUTH_HEADER, WebUIConfig  # noqa: E402
from email_guard_webui.rules import UpdaterUnreachable  # noqa: E402

DAY = date(2026, 5, 15)

REFRESHED = {
    "status": "updated",
    "old_commit": "a" * 40,
    "new_commit": "b" * 40,
    "validation_errors": [],
    "warnings": [],
    "timestamp": "2026-08-17T00:00:00+00:00",
    "message": "promoted bbbbbbbbbbbb from main",
}

LIVE = {
    "current_commit": "b" * 40,
    "current_target": "releases/" + "b" * 40 + "/rules",
    "branch": "main",
    "last_pull_at": "2026-08-17T00:00:00+00:00",
    "last_status": "updated",
    "validation_errors": [],
    "warnings": [],
}


class FakeUpdater:
    """Stands in for the rules-updater service."""

    def __init__(self, refresh_result: Any = None, status_result: Any = None) -> None:
        self._refresh = refresh_result if refresh_result is not None else REFRESHED
        self._status = status_result if status_result is not None else LIVE
        self.refresh_calls = 0

    def refresh(self) -> dict[str, Any]:
        self.refresh_calls += 1
        if isinstance(self._refresh, Exception):
            raise self._refresh
        return self._refresh

    def status(self) -> dict[str, Any]:
        if isinstance(self._status, Exception):
            raise self._status
        return self._status


@pytest.fixture
def lists_dir(tmp_path: Path) -> Path:
    path = tmp_path / "lists"
    path.mkdir()
    for name in ("whitelist", "greylist", "blacklist"):
        (path / f"{name}.json").write_text(json.dumps({name: []}), encoding="utf-8")
    return path


@pytest.fixture
def config(tmp_path: Path, lists_dir: Path) -> WebUIConfig:
    brief = tmp_path / "daily-brief"
    brief.mkdir()
    return WebUIConfig(
        lists_dir=lists_dir,
        daily_brief_dir=brief,
        outbound_dir=tmp_path / "outbound",
        rules_control_url="http://rules-updater:8090",
    )


def client_with(config: WebUIConfig, updater: FakeUpdater | None, **kwargs) -> TestClient:
    """Build a console whose updater client is the fake."""
    import email_guard_webui.app as app_module

    app = create_app(config, today=lambda: DAY)
    if updater is not None:
        app_module.rules_module.client_for = lambda cfg: updater  # type: ignore[assignment]
    return TestClient(app, **kwargs)


@pytest.fixture(autouse=True)
def restore_client_for():
    """`client_for` is monkeypatched by name; put the real one back."""
    import email_guard_webui.app as app_module
    from email_guard_webui import rules as rules_real

    original = rules_real.client_for
    yield
    app_module.rules_module.client_for = original


# --- the happy paths ---------------------------------------------------------------


def test_refresh_returns_the_updaters_structured_result(config: WebUIConfig):
    updater = FakeUpdater()
    client = client_with(config, updater)

    response = client.post("/api/rules/refresh")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "updated"
    assert payload["old_commit"] == "a" * 40
    assert payload["new_commit"] == "b" * 40
    assert payload["validation_errors"] == []
    assert payload["timestamp"]
    assert updater.refresh_calls == 1


def test_status_reports_what_is_live(config: WebUIConfig):
    client = client_with(config, FakeUpdater())

    response = client.get("/api/rules/status")

    assert response.status_code == 200
    assert response.json()["current_commit"] == "b" * 40
    assert response.json()["branch"] == "main"


def test_a_status_read_triggers_no_pull(config: WebUIConfig):
    updater = FakeUpdater()
    client = client_with(config, updater)

    client.get("/api/rules/status")

    assert updater.refresh_calls == 0


# --- outcomes that are results, not failures ----------------------------------------


def test_a_rejected_pull_is_a_200_carrying_the_validation_errors(config: WebUIConfig):
    """A refused bad pack is the validator doing its job.

    A 5xx here would make a correct refusal look identical to an outage, and the
    reviewer needs to see *which* rules failed, not just that something did.
    """
    errors = ["scan/level2.json: invalid JSON", "assess/level3.py: failed to import"]
    client = client_with(
        config,
        FakeUpdater(
            refresh_result={
                "status": "rejected",
                "old_commit": "a" * 40,
                "new_commit": "a" * 40,
                "validation_errors": errors,
                "warnings": [],
                "timestamp": "2026-08-17T00:00:00+00:00",
                "message": "the pulled pack is invalid (2 error(s))",
            }
        ),
    )

    response = client.post("/api/rules/refresh")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "rejected"
    assert payload["validation_errors"] == errors
    # The live pack did not move.
    assert payload["old_commit"] == payload["new_commit"]


def test_busy_is_reported_without_an_error(config: WebUIConfig):
    """A double-clicked button must be a non-event."""
    client = client_with(
        config,
        FakeUpdater(
            refresh_result={
                "status": "busy",
                "old_commit": "a" * 40,
                "new_commit": "a" * 40,
                "validation_errors": [],
                "warnings": [],
                "timestamp": "2026-08-17T00:00:00+00:00",
                "message": "another rules pull is already running",
            }
        ),
    )

    response = client.post("/api/rules/refresh")

    assert response.status_code == 200
    assert response.json()["status"] == "busy"
    assert response.json()["validation_errors"] == []


def test_no_change_is_a_200(config: WebUIConfig):
    client = client_with(
        config,
        FakeUpdater(refresh_result={**REFRESHED, "status": "no_change"}),
    )

    response = client.post("/api/rules/refresh")

    assert response.status_code == 200
    assert response.json()["status"] == "no_change"


def test_a_promote_with_feed_warnings_is_still_a_success(config: WebUIConfig):
    """The fail-open half, surfaced to the reviewer without blocking anything."""
    client = client_with(
        config,
        FakeUpdater(
            refresh_result={
                **REFRESHED,
                "warnings": ["reference/injection_signatures.json: invalid JSON"],
            }
        ),
    )

    response = client.post("/api/rules/refresh")

    assert response.status_code == 200
    assert response.json()["status"] == "updated"
    assert response.json()["warnings"]


# --- the one real error -------------------------------------------------------------


def test_an_unreachable_updater_is_a_503(config: WebUIConfig):
    client = client_with(
        config, FakeUpdater(refresh_result=UpdaterUnreachable("connection refused"))
    )

    response = client.post("/api/rules/refresh")

    assert response.status_code == 503
    assert "connection refused" in response.json()["detail"]
    assert response.json()["errors"]


def test_an_unconfigured_updater_is_a_503(tmp_path: Path, lists_dir: Path):
    """A console in a deployment that runs no updater must say so plainly."""
    brief = tmp_path / "daily-brief"
    brief.mkdir()
    unconfigured = WebUIConfig(
        lists_dir=lists_dir,
        daily_brief_dir=brief,
        outbound_dir=tmp_path / "outbound",
        rules_control_url=None,
    )
    client = TestClient(create_app(unconfigured, today=lambda: DAY))

    response = client.post("/api/rules/refresh")

    assert response.status_code == 503
    assert "EMAIL_GUARD_RULES_CONTROL_URL" in response.json()["detail"]


def test_an_unreachable_updater_does_not_break_the_rest_of_the_console(config: WebUIConfig):
    client = client_with(
        config, FakeUpdater(status_result=UpdaterUnreachable("nope"))
    )

    assert client.get("/api/rules/status").status_code == 503
    assert client.get("/api/candidates").status_code == 200


# --- auth ---------------------------------------------------------------------------


def test_the_rules_endpoints_inherit_the_console_token(tmp_path: Path, lists_dir: Path):
    """They are declared inside `api_router()`, so the guard is not optional."""
    brief = tmp_path / "daily-brief"
    brief.mkdir()
    guarded = WebUIConfig(
        lists_dir=lists_dir,
        daily_brief_dir=brief,
        outbound_dir=tmp_path / "outbound",
        auth_token="s3cret",
        rules_control_url="http://rules-updater:8090",
    )
    updater = FakeUpdater()
    client = client_with(guarded, updater)

    assert client.post("/api/rules/refresh").status_code == 401
    assert client.get("/api/rules/status").status_code == 401
    assert client.post(
        "/api/rules/refresh", headers={AUTH_HEADER: "wrong"}
    ).status_code == 401

    assert client.post(
        "/api/rules/refresh", headers={AUTH_HEADER: "s3cret"}
    ).status_code == 200


def test_a_refused_request_never_reaches_the_updater(tmp_path: Path, lists_dir: Path):
    brief = tmp_path / "daily-brief"
    brief.mkdir()
    guarded = WebUIConfig(
        lists_dir=lists_dir,
        daily_brief_dir=brief,
        outbound_dir=tmp_path / "outbound",
        auth_token="s3cret",
        rules_control_url="http://rules-updater:8090",
    )
    updater = FakeUpdater()
    client = client_with(guarded, updater)

    client.post("/api/rules/refresh")

    assert updater.refresh_calls == 0


def test_the_control_token_stays_out_of_the_config_repr(config: WebUIConfig):
    with_token = WebUIConfig(
        lists_dir=config.lists_dir,
        daily_brief_dir=config.daily_brief_dir,
        outbound_dir=config.outbound_dir,
        rules_control_url="http://rules-updater:8090",
        rules_control_token="updater-s3cret",
    )

    assert "updater-s3cret" not in repr(with_token)


# --- serving --------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/api/rules/status", "/api/rules/refresh"])
def test_the_csp_is_on_the_rules_responses(config: WebUIConfig, path: str):
    client = client_with(config, FakeUpdater())

    response = client.get(path) if path.endswith("status") else client.post(path)

    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


# --- the button -------------------------------------------------------------------------


def test_the_refresh_button_is_wired_without_inline_script():
    """CSP is `script-src 'self'`, so the handler cannot be an attribute.

    The global no-inline-handler and no-``innerHTML`` guards already live in
    ``test_webui.py`` and cover this file too; what is pinned here is that the
    new control exists and is bound from app.js rather than from markup.
    """
    static = Path(__file__).resolve().parent.parent / "webui" / "static"
    markup = (static / "index.html").read_text(encoding="utf-8")
    script = (static / "app.js").read_text(encoding="utf-8")

    assert 'id="refreshRules"' in markup
    assert 'id="rulesStatus"' in markup
    assert "byId('refreshRules').addEventListener" in script


def test_the_other_config_controls_stay_inert():
    """This change adds the rules control and nothing else.

    SAVE stays disabled rather than lying about writing a config nobody reads.
    """
    static = Path(__file__).resolve().parent.parent / "webui" / "static"
    markup = (static / "index.html").read_text(encoding="utf-8")
    script = (static / "app.js").read_text(encoding="utf-8")

    assert 'id="saveConfig" disabled' in markup
    assert "byId('saveConfig').addEventListener" not in script
