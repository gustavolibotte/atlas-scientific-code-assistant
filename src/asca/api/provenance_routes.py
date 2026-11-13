"""Read-only provenance routes: project list, symbol list and the function inspector."""

from typing import Annotated

from fastapi import APIRouter, Depends

from asca.api.dependencies import ProjectIdPath, SymbolIdPath, get_provenance_service
from asca.api.presenters import (
    function_inspection_response,
    project_list_response,
    symbol_list_response,
)
from asca.api.provenance_schemas import (
    FunctionInspectionResponse,
    ProjectListResponse,
    SymbolListResponse,
)
from asca.application.inspection import inspect_function
from asca.application.provenance import ProvenanceService
from asca.domain.provenance import ProjectId

Service = Annotated[ProvenanceService, Depends(get_provenance_service)]


def build_provenance_router() -> APIRouter:
    router = APIRouter(tags=["provenance"])

    @router.get("/api/v1/projects", response_model=ProjectListResponse)
    def list_projects(service: Service) -> ProjectListResponse:
        """List stored projects with their current revision."""
        return project_list_response(service.list_projects())

    @router.get("/api/v1/projects/{project_id}/symbols", response_model=SymbolListResponse)
    def list_project_symbols(project_id: ProjectIdPath, service: Service) -> SymbolListResponse:
        """List the symbols of the project's latest workspace revision."""
        return symbol_list_response(service.load(ProjectId(project_id)))

    @router.get(
        "/api/v1/projects/{project_id}/symbols/{symbol_id}/inspection",
        response_model=FunctionInspectionResponse,
    )
    def inspect_symbol(
        project_id: ProjectIdPath, symbol_id: SymbolIdPath, service: Service
    ) -> FunctionInspectionResponse:
        """Show the decisions, evidence, tests and reviews behind one code symbol."""
        graph = service.load(ProjectId(project_id))
        # Local single-user mode: every access class is returned.
        # M10: filter by viewer before any non-loopback deployment
        return function_inspection_response(graph, inspect_function(graph, symbol_id))

    return router
