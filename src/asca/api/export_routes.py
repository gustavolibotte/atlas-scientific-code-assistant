"""Export download route (placeholder until Workstream B; not mounted in Phase 1)."""

from fastapi import APIRouter
from fastapi.responses import Response

from asca.api.dependencies import ProjectIdPath
from asca.application.exports import ExportArtifact
from asca.domain.provenance import AccessClass


def build_export_router() -> APIRouter:
    router = APIRouter(tags=["provenance"])

    @router.get(
        "/api/v1/projects/{project_id}/exports/{artifact}",
        responses={200: {"content": {"application/json": {"schema": {"type": "object"}}}}},
    )
    def export_artifact(
        project_id: ProjectIdPath,
        artifact: ExportArtifact,
        audience: AccessClass = AccessClass.PUBLIC,
    ) -> Response:
        return Response(status_code=501)

    return router
