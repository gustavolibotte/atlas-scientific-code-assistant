"""Read-only download route for reproducible, audience-filtered export documents."""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import Response

import asca
from asca.api.dependencies import ProjectIdPath, get_provenance_service
from asca.application.exports import ExportArtifact, build_export, canonical_json
from asca.application.provenance import ProvenanceService
from asca.contracts import schema_id
from asca.domain.provenance import AccessClass, ProjectId


def build_export_router() -> APIRouter:
    router = APIRouter(tags=["provenance"])

    @router.get(
        "/api/v1/projects/{project_id}/exports/{artifact}",
        response_class=Response,
        responses={200: {"content": {"application/json": {"schema": {"type": "object"}}}}},
    )
    def export_artifact(
        project_id: ProjectIdPath,
        artifact: ExportArtifact,
        service: Annotated[ProvenanceService, Depends(get_provenance_service)],
        audience: AccessClass = AccessClass.PUBLIC,
    ) -> Response:
        """Download one export document of a project, filtered for ``audience``."""
        graph = service.load(ProjectId(project_id))
        document = build_export(
            graph, artifact, audience=audience, generator_version=asca.__version__
        )
        return Response(
            content=canonical_json(document),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{artifact.value}.json"',
                "X-ASCA-Schema": schema_id(artifact.value),
            },
        )

    return router
