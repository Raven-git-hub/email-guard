"""The server: a single-page console plus the JSON API behind it.

Phase 1 wires two panels to real data -- Review and List Data. Event Log and
Config are present but inert; they need the event store and the dispatcher
config wiring, which are Phase 2.

Shape of the thing:

    GET  /                      the console (static shell, no data in it)
    GET  /static/...            app.css / app.js
    GET  /api/candidates        the review queue
    POST /api/decisions         one decision -> the applier -> the live lists
    GET  /api/lists/{name}      entries for the List Data panel
    POST /api/lists/{name}/add  a manual add, down the same applier path

Three things are load-bearing rather than stylistic:

* **Every response carries the CSP** (:func:`email_guard_webui.config.content_security_policy`),
  errors included -- a middleware, so no handler can forget it.
* **The API is the only thing behind the token.** The shell is a static file
  with no mail content in it; a browser cannot attach a header to a top-level
  navigation, so guarding the shell would only push the token into a URL. Every
  byte of mail content and every write goes through a guarded route.
* **The applier is the only writer.** Both write endpoints build a decisions
  document and hand it to :func:`email_guard.apply.apply_decisions`. There is no
  second path into ``data/lists/*.json``, and no validation logic here that
  could drift from the applier's.
"""

from __future__ import annotations

import hmac
from datetime import date
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from email_guard.apply import InvalidDecisions, apply_decisions
from email_guard.lists import LIST_NAMES, InvalidLists, Lists

from . import candidates as candidates_module
from . import decisions as decisions_module
from . import listing
from .config import AUTH_HEADER, WebUIConfig

INDEX_NAME = "index.html"

# The API returns mail content and list state. Neither belongs in a disk cache
# or a proxy, however local.
NO_STORE = "no-store"


# --- request bodies ------------------------------------------------------------
#
# Deliberately permissive: these models keep unknown keys out of a list file,
# and stop there. Whether an action exists, whether an entry names exactly one
# of email/domain, whether a greylist entry keyed on an address is legal -- all
# of that is the applier's, and answering it twice is how two answers start
# disagreeing.


class EntryBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str | None = None
    domain: str | None = None
    friendly_name: str | None = None
    tags: list[str] = Field(default_factory=list)


class StructureBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    key_phrases: list[str] = Field(default_factory=list)
    disposition: str | None = None
    tags: list[str] = Field(default_factory=list)


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate: str
    action: str
    entry: EntryBody | None = None
    structure: StructureBody | None = None


class AddBody(BaseModel):
    """A manual add from the List Data panel.

    No ``action``: the list is in the URL, and no ``candidate`` because there is
    no staged proposal behind it -- the entry key stands in, which is exactly
    the "<job-or-domain>" the decisions contract allows.
    """

    model_config = ConfigDict(extra="forbid")

    entry: EntryBody
    structure: StructureBody | None = None


# --- the app -------------------------------------------------------------------


def create_app(
    config: WebUIConfig,
    *,
    today: Callable[[], date] | None = None,
) -> FastAPI:
    """Build the application.

    ``today`` is injected rather than read from the clock in the handlers, the
    same way :mod:`email_guard.propose` takes its day: a decision applied in a
    test must stamp a date the test chose.
    """
    # No docs, no schema endpoint, and deliberately no CORS middleware: the only
    # client is the page this process serves. Adding CORS would hand every other
    # origin the browser is pointed at a way to drive these endpoints -- without
    # it, a cross-origin write cannot even get past its preflight.
    app = FastAPI(
        title="Email Guard",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.config = config
    app.state.today = today or date.today

    static_dir = Path(config.static_dir)
    index = static_dir / INDEX_NAME

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = config.content_security_policy
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = NO_STORE
        return response

    @app.exception_handler(InvalidDecisions)
    async def invalid_decisions(request: Request, exc: InvalidDecisions) -> JSONResponse:
        """A rejected document is the reviewer's problem to fix, so 4xx.

        Every error, not the first: the applier collects them all precisely so
        the person holding the card can see the whole story.
        """
        return JSONResponse(status_code=400, content={"detail": str(exc), "errors": exc.errors})

    @app.exception_handler(InvalidLists)
    async def invalid_lists(request: Request, exc: InvalidLists) -> JSONResponse:
        """The lists on disk are already in a state the engine refuses.

        503, not 500: nothing the console did caused it and nothing it can do
        will fix it -- a human has to repair the files the scanner is equally
        refusing to run on.
        """
        return JSONResponse(
            status_code=503,
            content={
                "detail": "the live lists are invalid; the scanner refuses them too",
                "errors": exc.errors,
            },
        )

    app.include_router(api_router())

    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def console() -> FileResponse:
        if not index.is_file():
            raise HTTPException(status_code=500, detail=f"UI not found at {index}")
        # `no-store` on the shell too: it costs one request on reload and means
        # a rebuilt app.js can never be shadowed by a cached shell.
        return FileResponse(index, media_type="text/html", headers={"Cache-Control": NO_STORE})

    return app


def require_token(request: Request) -> None:
    """Shared-token auth, off unless a token is configured.

    Compared with :func:`hmac.compare_digest`, so a wrong guess costs the same
    time whatever it got right.
    """
    token = request.app.state.config.auth_token
    if not token:
        return
    supplied = request.headers.get(AUTH_HEADER) or ""
    if not hmac.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail=f"missing or invalid {AUTH_HEADER}")


def api_router() -> APIRouter:
    router = APIRouter(prefix="/api", dependencies=[Depends(require_token)])

    @router.get("/candidates")
    async def get_candidates(request: Request) -> dict[str, Any]:
        """The unreviewed queue, oldest first.

        The lists are loaded once for the whole queue and every card's
        membership computed against that snapshot, so a card cannot disagree
        with the card above it about where a domain currently lives.
        """
        config = _config(request)
        lists = _lists(config)
        cards = [
            candidates_module.card(candidate, lists)
            for candidate in candidates_module.queue(config.daily_brief_dir)
        ]
        return {"candidates": cards, "count": len(cards)}

    @router.post("/decisions")
    async def post_decision(request: Request, body: DecisionBody) -> dict[str, Any]:
        """Apply one decision, then consume the candidate behind it.

        Order matters: the applier runs first and is all-or-nothing, so a
        rejected decision leaves the candidate in the queue where the reviewer
        can try again. A re-post of an already-applied decision is harmless --
        the applier is idempotent and the candidate is simply no longer there to
        consume -- which is what makes a double-clicked Confirm a non-event.
        """
        config = _config(request)
        decision = decisions_module.build_decision(
            candidate=body.candidate,
            action=body.action,
            entry=body.entry.model_dump() if body.entry else None,
            structure=body.structure.model_dump() if body.structure else None,
        )
        document = decisions_module.build_document(decision, today=request.app.state.today())
        report = apply_decisions(document, config.lists_dir)

        path = candidates_module.resolve(config.daily_brief_dir, body.candidate)
        if path is not None:
            candidates_module.mark_reviewed(path)

        return {
            "candidate": body.candidate,
            "consumed": path is not None,
            "report": report,
        }

    @router.get("/lists/{list_name}")
    async def get_list(request: Request, list_name: str) -> dict[str, Any]:
        config = _config(request)
        _require_list(list_name)
        entries = listing.entries(_lists(config), list_name)
        return {"list": list_name, "entries": entries, "count": len(entries)}

    @router.post("/lists/{list_name}/add")
    async def post_list_add(request: Request, list_name: str, body: AddBody) -> dict[str, Any]:
        """A manual add is a decision like any other.

        Same applier, same validation, same mutual-exclusivity rule -- so an
        address typed into the Add box moves off whichever list it was on,
        exactly as it would had it come from a review card. A second door into
        the lists is precisely what this endpoint is not.
        """
        config = _config(request)
        _require_list(list_name)
        entry = body.entry.model_dump()
        decision = decisions_module.build_decision(
            # No staged proposal behind a manual add, so the subject names
            # itself -- the "<job-or-domain>" the contract allows.
            candidate=(entry.get("email") or entry.get("domain") or "").strip() or "manual entry",
            action=list_name,
            entry=entry,
            structure=body.structure.model_dump() if body.structure else None,
        )
        document = decisions_module.build_document(decision, today=request.app.state.today())
        return {"list": list_name, "report": apply_decisions(document, config.lists_dir)}

    return router


def _config(request: Request) -> WebUIConfig:
    return request.app.state.config


def _lists(config: WebUIConfig) -> Lists:
    """The live lists, validated -- the same load the scanner performs.

    Failing here on a contradictory pair of lists is the point: the console must
    not offer a review built on a state the engine has already refused to run on.
    """
    return Lists.load(config.lists_dir)


def _require_list(list_name: str) -> None:
    if list_name not in LIST_NAMES:
        raise HTTPException(
            status_code=404,
            detail=f"unknown list {list_name!r} (expected one of {', '.join(LIST_NAMES)})",
        )
