"""In-memory provenance repository for tests and interim composition."""

import threading
from collections.abc import Sequence

from asca.application.errors import (
    ConcurrentModificationError,
    DuplicateProjectError,
    ProjectNotFoundError,
)
from asca.application.ports import ProjectSummary
from asca.domain.provenance import Project, ProjectId, ProvenanceGraph, ProvenanceRecord


class InMemoryProvenanceRepository:
    """Holds one immutable graph per project; appends are compare-and-set."""

    def __init__(self) -> None:
        self._graphs: dict[str, ProvenanceGraph] = {}
        self._lock = threading.Lock()

    def create_project(self, project: Project) -> None:
        with self._lock:
            if project.id in self._graphs:
                raise DuplicateProjectError("project already exists")
            self._graphs[project.id] = ProvenanceGraph.empty(project)

    def list_projects(self) -> list[ProjectSummary]:
        with self._lock:
            graphs = list(self._graphs.values())
        return [
            ProjectSummary(project=graph.project, revision=graph.revision)
            for graph in sorted(graphs, key=lambda item: (item.project.created_at, item.project.id))
        ]

    def load(self, project_id: ProjectId) -> ProvenanceGraph:
        with self._lock:
            graph = self._graphs.get(project_id)
        if graph is None:
            raise ProjectNotFoundError("project not found")
        return graph

    def append(
        self,
        project_id: ProjectId,
        expected_revision: int,
        records: Sequence[ProvenanceRecord],
    ) -> int:
        with self._lock:
            graph = self._graphs.get(project_id)
            if graph is None:
                raise ProjectNotFoundError("project not found")
            if graph.revision != expected_revision:
                raise ConcurrentModificationError("project revision changed")
            updated = graph.append(records)
            self._graphs[project_id] = updated
            return updated.revision
