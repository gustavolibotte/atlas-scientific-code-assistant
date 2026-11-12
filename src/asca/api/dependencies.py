"""Shared FastAPI dependencies and provenance error mapping."""

from typing import Annotated

from fastapi import FastAPI, Path, Request
from fastapi.responses import JSONResponse

from asca.application.errors import ProjectNotFoundError, StoredGraphIntegrityError
from asca.application.provenance import ProvenanceService
from asca.domain.provenance import RecordNotFoundError

ProjectIdPath = Annotated[str, Path(pattern=r"^prj_[0-9a-f]{32}$", min_length=36, max_length=36)]
SymbolIdPath = Annotated[str, Path(pattern=r"^sym_[0-9a-f]{32}$", min_length=36, max_length=36)]


def get_provenance_service(request: Request) -> ProvenanceService:
    service: ProvenanceService = request.app.state.provenance_service
    return service


async def _not_found(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": "Not found"})


async def _integrity_error(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": "Provenance store integrity error"})


def register_provenance_error_handlers(app: FastAPI) -> None:
    """Map provenance errors to bodies that never echo input, ids, SQL or URLs."""
    app.add_exception_handler(ProjectNotFoundError, _not_found)
    app.add_exception_handler(RecordNotFoundError, _not_found)
    app.add_exception_handler(StoredGraphIntegrityError, _integrity_error)
