"""FastAPI composition root for the read-only foundation API."""

from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from asca import __version__
from asca.api.dependencies import get_provenance_service, register_provenance_error_handlers
from asca.api.export_routes import build_export_router
from asca.api.legacy import legacy_trace_from_graph
from asca.api.provenance_routes import build_provenance_router
from asca.api.schemas import (
    CapabilitiesResponse,
    Capability,
    CapabilityState,
    IdentityStatusResponse,
    LiveResponse,
    ReadyResponse,
    TraceResponse,
)
from asca.application.demo import DEMO_DECISION_ID, DEMO_PROJECT_ID, seed_synthetic_demo
from asca.application.ports import Clock, IdFactory
from asca.application.provenance import ProvenanceService
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository
from asca.infrastructure.system import SystemClock, Uuid4IdFactory


async def add_security_headers(request: Request, call_next: object) -> Response:
    """Add baseline headers; production deployment will require more controls."""
    # This middleware does not interpret or authorize requests.
    from collections.abc import Awaitable, Callable
    from typing import cast

    typed_handler = cast(Callable[[Request], Awaitable[Response]], call_next)
    response = await typed_handler(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


def _mount_routes(app: FastAPI, router: APIRouter) -> None:
    """Add a router's routes to the app as plain ``APIRoute`` entries.

    ``include_router`` in current FastAPI wraps an included router in one lazy route
    object, which would hide its operations from route-allowlist checks that enumerate
    ``app.routes``. Mounting the route objects directly keeps every operation visible.
    """
    app.router.routes.extend(router.routes)


def create_app(
    *,
    seed_demo: bool = True,
    clock: Clock | None = None,
    ids: IdFactory | None = None,
) -> FastAPI:
    """Create a deterministic application without external side effects.

    Interim composition: provenance lives in an in-memory repository. Everything is
    built eagerly; no environment variable or file is read.
    """
    repository = InMemoryProvenanceRepository()
    service = ProvenanceService(repository, clock or SystemClock(), ids or Uuid4IdFactory())
    if seed_demo:
        seed_synthetic_demo(repository)
    app = FastAPI(
        title="ATLAS Scientific Code Assistant",
        version=__version__,
        summary="Foundation API — integrations are not configured",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=False,
        allow_methods=["GET", "OPTIONS"],
        allow_headers=["Content-Type"],
    )
    app.add_middleware(BaseHTTPMiddleware, dispatch=add_security_headers)
    app.state.provenance_service = service
    register_provenance_error_handlers(app)

    @app.get("/api/v1/health/live", response_model=LiveResponse, tags=["health"])
    def live() -> LiveResponse:
        return LiveResponse(status="ok")

    @app.get("/api/v1/health/ready", response_model=ReadyResponse, tags=["health"])
    def ready() -> ReadyResponse:
        return ReadyResponse(status="ready", version=__version__)

    @app.get(
        "/api/v1/system/capabilities",
        response_model=CapabilitiesResponse,
        tags=["system"],
    )
    def capabilities() -> CapabilitiesResponse:
        return CapabilitiesResponse(
            items=[
                Capability(
                    id="foundation_api",
                    label="Foundation API",
                    status=CapabilityState.AVAILABLE,
                ),
                Capability(
                    id="provenance",
                    label="Provenance inspector",
                    status=CapabilityState.DEMO_ONLY,
                ),
                Capability(
                    id="provenance_store",
                    label="Persisted provenance store and exports",
                    status=CapabilityState.AVAILABLE,
                ),
                Capability(
                    id="cern_sso",
                    label="CERN single sign-on",
                    status=CapabilityState.NOT_IMPLEMENTED,
                ),
                Capability(
                    id="chatlas",
                    label="chATLAS retrieval",
                    status=CapabilityState.NOT_IMPLEMENTED,
                ),
                Capability(
                    id="codegen",
                    label="Scientific code generation",
                    status=CapabilityState.NOT_IMPLEMENTED,
                ),
                Capability(
                    id="execution",
                    label="Sandboxed execution",
                    status=CapabilityState.NOT_IMPLEMENTED,
                ),
            ]
        )

    @app.get("/api/v1/identity/status", response_model=IdentityStatusResponse, tags=["identity"])
    def identity_status() -> IdentityStatusResponse:
        """Disclose that CERN login is not yet configured or available."""
        return IdentityStatusResponse()

    @app.get("/api/v1/demo/trace", response_model=TraceResponse, tags=["demo"], deprecated=True)
    def demo_trace(
        provenance: Annotated[ProvenanceService, Depends(get_provenance_service)],
    ) -> TraceResponse:
        """Legacy synthetic trace, served from the stored demonstration project."""
        return legacy_trace_from_graph(provenance.load(DEMO_PROJECT_ID), DEMO_DECISION_ID)

    _mount_routes(app, build_provenance_router())
    _mount_routes(app, build_export_router())
    return app
