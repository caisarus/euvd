# SPDX-License-Identifier: EUPL-1.2
"""The FastAPI dashboard app (Step 6.2): read-mostly, HTTP Basic auth on every route,
server-rendered Jinja2, no SPA. `euvd-watch web serve` (cli.py) imports this module
lazily - only `web_serve`'s code path needs the `[web]` extra installed.

Route -> template map:
  GET  /                          overview.html    (name="overview")
  GET  /findings                  findings.html     (name="findings_list")
  GET  /findings/{hash}/{euvd_id} finding_detail.html (name="finding_detail")
  GET  /cra                       cra_events.html   (name="cra_events_list")
  GET  /cra/{url_id}              cra_event_detail.html (name="cra_event_detail")
  POST /cra/{url_id}/mark         -> redirect        (name="cra_event_mark")
  GET  /cra/{url_id}/draft        cra_event_draft.html (name="cra_event_draft")
  GET  /audit                     audit_log.html    (name="audit_log_page")

`{url_id}` is `dashboard.event_url_id(event_id)` - a hash, not the real event_id.
Real CRA event_ids are `f"{component.dedupe_key}|{euvd_id}"`, and `dedupe_key` is
purl-derived (e.g. `purl:pkg:pypi/jinja2@3.1.6`), so it routinely contains '/' and
would break a plain `{event_id}` path segment. Routes resolve `url_id` back to the
real event_id server-side via `dashboard.resolve_event_id` before touching the store.

Every route requires HTTP Basic credentials (test_plan §6.2: 401 without credentials
on all routes) via a single `dependencies=[Depends(...)]` on the FastAPI app - a route
added later can't accidentally skip auth.
"""

# Deliberately NO `from __future__ import annotations` here: FastAPI resolves route
# parameter annotations at import time via `typing.get_type_hints`, which cannot see
# closure-local names (like `security`/`get_store` below) if those annotations were
# stringified by the future import - it silently falls back to treating the
# dependencies as query parameters instead. Python 3.11 (this project's floor)
# supports `X | None` natively at runtime, so nothing here needs the future import.

import hmac
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from euvd_watch.config import Settings
from euvd_watch.cra.actions import UnknownStageError, validate_stage_name
from euvd_watch.cra.actions import mark as cra_mark_action
from euvd_watch.cra.audit import AuditError, AuditLog
from euvd_watch.cra.report import DraftError, render_markdown
from euvd_watch.cra.state import EventStore, StateError
from euvd_watch.web import dashboard as dash
from euvd_watch.web.auth import verify_password
from euvd_watch.web.store import Store

_PACKAGE_DIR = Path(__file__).parent
_WWW_AUTHENTICATE = 'Basic realm="euvd-watch dashboard"'


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials.",
        headers={"WWW-Authenticate": _WWW_AUTHENTICATE},
    )


def create_app(settings: Settings, *, sbom_path: str, host: str, port: int) -> FastAPI:
    """Build the dashboard app bound to one SBOM's watch snapshot and one state dir.

    `settings.web.password_hash` must already be set (`web_serve` in cli.py checks
    this before calling here) - a dashboard with no credential configured would
    otherwise construct successfully and serve unauthenticated.
    """
    security = HTTPBasic(realm="euvd-watch dashboard", auto_error=True)
    templates = Jinja2Templates(directory=str(_PACKAGE_DIR / "templates"))
    templates.env.filters["pill"] = dash.pill_for

    def require_auth(
        credentials: Annotated[HTTPBasicCredentials, Depends(security)],
    ) -> str:
        expected_hash = settings.web.password_hash
        user_ok = hmac.compare_digest(credentials.username, settings.web.username)
        pass_ok = expected_hash is not None and verify_password(credentials.password, expected_hash)
        if not (user_ok and pass_ok):
            raise _unauthorized()
        return credentials.username

    def get_store() -> Iterator[Store]:
        store = Store(settings.state_dir)
        store.migrate()
        try:
            yield store
        finally:
            store.close()

    app = FastAPI(
        title="euvd-watch dashboard",
        docs_url=None,
        redoc_url=None,
        dependencies=[Depends(require_auth)],
    )
    app.state.settings = settings
    app.state.sbom_path = sbom_path
    app.mount("/static", StaticFiles(directory=str(_PACKAGE_DIR / "static")), name="static")

    def base_context(request: Request, store: Store, active_page: str) -> dict[str, object]:
        try:
            findings, _generated_at = dash.load_findings(store, sbom_path)
            exploited_badge = sum(1 for f in findings if f.record.exploited)
        except dash.NoSnapshotError:
            exploited_badge = 0
        return {
            "request": request,
            "active_page": active_page,
            "state_dir": str(settings.state_dir),
            "rendered_at": datetime.now(UTC).strftime("%H:%M:%S UTC"),
            "username": settings.web.username,
            "host": host,
            "port": port,
            "exploited_badge": exploited_badge,
        }

    def render_error(
        request: Request,
        store: Store,
        active_page: str,
        *,
        status_code: int,
        title: str,
        message: str,
        hint: str | None = None,
    ) -> Any:
        context = base_context(request, store, active_page)
        context.update({"title": title, "message": message, "hint": hint})
        return templates.TemplateResponse(request, "error.html", context, status_code=status_code)

    @app.get("/", name="overview")
    def overview(request: Request, store: Annotated[Store, Depends(get_store)]) -> Any:
        try:
            view = dash.build_overview(settings, store, sbom_path)
        except dash.NoSnapshotError as exc:
            return render_error(
                request,
                store,
                "overview",
                status_code=200,
                title="No findings yet",
                message=str(exc),
            )
        context = base_context(request, store, "overview")
        context["view"] = view
        return templates.TemplateResponse(request, "overview.html", context)

    @app.get("/findings", name="findings_list")
    def findings_list(
        request: Request,
        store: Annotated[Store, Depends(get_store)],
        confidence: str = "any",
        exploited: str = "any",
        vex_status: str = "any",
        page: int = 1,
    ) -> Any:
        try:
            view = dash.build_findings(
                settings,
                store,
                sbom_path,
                confidence=confidence,
                exploited=exploited,
                vex_status=vex_status,
                page=page,
            )
        except dash.NoSnapshotError as exc:
            return render_error(
                request,
                store,
                "findings",
                status_code=200,
                title="No findings yet",
                message=str(exc),
            )
        context = base_context(request, store, "findings")
        context["view"] = view
        return templates.TemplateResponse(request, "findings.html", context)

    @app.get("/findings/{comp_hash}/{euvd_id}", name="finding_detail")
    def finding_detail(
        request: Request,
        comp_hash: str,
        euvd_id: str,
        store: Annotated[Store, Depends(get_store)],
    ) -> Any:
        try:
            view = dash.build_finding_detail(settings, store, sbom_path, comp_hash, euvd_id)
        except dash.NoSnapshotError as exc:
            return render_error(
                request,
                store,
                "findings",
                status_code=200,
                title="No findings yet",
                message=str(exc),
            )
        if view is None:
            raise HTTPException(status_code=404, detail="No such finding in the current scan.")
        context = base_context(request, store, "findings")
        context["view"] = view
        return templates.TemplateResponse(request, "finding_detail.html", context)

    @app.get("/cra", name="cra_events_list")
    def cra_events_list(request: Request, store: Annotated[Store, Depends(get_store)]) -> Any:
        rows = dash.build_cra_events(settings, store)
        context = base_context(request, store, "cra")
        context["rows"] = rows
        return templates.TemplateResponse(request, "cra_events.html", context)

    @app.get("/cra/{url_id}", name="cra_event_detail")
    def cra_event_detail(
        request: Request, url_id: str, store: Annotated[Store, Depends(get_store)]
    ) -> Any:
        event_id = dash.resolve_event_id(store, url_id)
        view = (
            dash.build_cra_event_detail(settings, store, event_id) if event_id is not None else None
        )
        if view is None:
            raise HTTPException(status_code=404, detail="No CRA event with that id.")
        context = base_context(request, store, "cra")
        context["view"] = view
        return templates.TemplateResponse(request, "cra_event_detail.html", context)

    @app.post("/cra/{url_id}/mark", name="cra_event_mark")
    def cra_event_mark(
        request: Request,
        url_id: str,
        store: Annotated[Store, Depends(get_store)],
        stage: Annotated[str, Form()] = "",
        note: Annotated[str, Form()] = "",
        remediation_available: Annotated[str | None, Form()] = None,
    ) -> Any:
        event_id = dash.resolve_event_id(store, url_id)
        if event_id is None:
            raise HTTPException(status_code=404, detail="No CRA event with that id.")

        stage_name = stage or None
        note_value = note or None
        remediation = remediation_available is not None

        if stage_name is None and not remediation:
            return render_error(
                request,
                store,
                "cra",
                status_code=400,
                title="Nothing to record",
                message="Choose a stage to mark complete and/or check remediation available.",
            )
        if stage_name is not None:
            try:
                validate_stage_name(stage_name, settings.cra_stages)
            except UnknownStageError as exc:
                return render_error(
                    request, store, "cra", status_code=400, title="Unknown stage", message=str(exc)
                )

        event_store = EventStore(store.path)
        log = AuditLog(settings.state_dir / "cra-audit.jsonl")
        try:
            cra_mark_action(
                event_store,
                log,
                event_id,
                stage=stage_name,
                note=note_value,
                remediation_available=remediation,
                now=datetime.now(UTC),
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="No CRA event with that id.") from None
        except (StateError, AuditError) as exc:
            return render_error(
                request,
                store,
                "cra",
                status_code=500,
                title="Could not record action",
                message=str(exc),
            )
        finally:
            event_store.close()

        return RedirectResponse(
            request.url_for("cra_event_detail", url_id=url_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/cra/{url_id}/draft", name="cra_event_draft")
    def cra_event_draft(
        request: Request, url_id: str, store: Annotated[Store, Depends(get_store)]
    ) -> Any:
        event_id = dash.resolve_event_id(store, url_id)
        if event_id is None:
            raise HTTPException(status_code=404, detail="No CRA event with that id.")
        event_store = EventStore(store.path)
        try:
            event = event_store.get(event_id)
        finally:
            event_store.close()
        if event is None:
            raise HTTPException(status_code=404, detail="No CRA event with that id.")
        try:
            text = render_markdown(event, settings, datetime.now(UTC).isoformat())
        except DraftError as exc:
            return render_error(
                request,
                store,
                "cra",
                status_code=400,
                title="Cannot render a draft",
                message=str(exc),
            )
        context = base_context(request, store, "cra")
        context["url_id"] = url_id
        context["event_id"] = event_id
        context["draft_text"] = text
        return templates.TemplateResponse(request, "cra_event_draft.html", context)

    @app.get("/audit", name="audit_log_page")
    def audit_log_page(request: Request, store: Annotated[Store, Depends(get_store)]) -> Any:
        view = dash.build_audit_log(settings)
        context = base_context(request, store, "audit")
        context["view"] = view
        return templates.TemplateResponse(request, "audit_log.html", context)

    return app


def run_server(app: FastAPI, *, host: str, port: int) -> None:
    """Blocking uvicorn run - `web_serve` (cli.py) calls this; Ctrl+C stops it."""
    uvicorn.run(app, host=host, port=port, log_level="warning")
