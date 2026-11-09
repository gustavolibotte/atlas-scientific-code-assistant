"""FastAPI composition root for the read-only foundation API."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from asca import __version__
from asca.api.schemas import (
    CapabilitiesResponse,
    Capability,
    CapabilityState,
    DecisionDTO,
    EvidenceDTO,
    LiveResponse,
    ReadyResponse,
    SymbolDTO,
    TraceResponse,
    VerificationDTO,
)
from asca.application.demo import create_synthetic_trace


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


def create_app() -> FastAPI:
    """Create a deterministic application without external side effects."""
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

    @app.get("/api/v1/demo/trace", response_model=TraceResponse, tags=["demo"])
    def demo_trace() -> TraceResponse:
        trace = create_synthetic_trace()
        return TraceResponse(
            is_synthetic=trace.is_synthetic,
            disclaimer="Synthetic UI demonstration; no CERN source, code, or test was consulted.",
            decision=DecisionDTO.model_validate(trace.decision, from_attributes=True),
            evidence=[
                EvidenceDTO.model_validate(item, from_attributes=True) for item in trace.evidence
            ],
            symbols=[
                SymbolDTO.model_validate(item, from_attributes=True) for item in trace.symbols
            ],
            verifications=[
                VerificationDTO.model_validate(item, from_attributes=True)
                for item in trace.verifications
            ],
        )

    return app
