from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

# ==========================================
# 1. MODELOS DE CODEQL (Scanner / Tarea 3)
# ==========================================


class Finding(BaseModel):
    rule_id: str
    severity: str
    description: str
    file_path: str
    start_line: int


class RepositoryReport(BaseModel):
    name: str
    url: str
    status: str
    languages: List[str] = []
    findings: List[Finding] = []
    error_reason: Optional[str] = None


class Summary(BaseModel):
    repositories: int = 0
    analyzed: int = 0
    unsupported: int = 0
    failed: int = 0
    findings: int = 0


class OrganizationReport(BaseModel):
    organization: str
    summary: Summary
    repositories: List[RepositoryReport]

    def sort_results(self):
        """Ordena los repositorios por nombre de manera alfabética y estable."""
        self.repositories.sort(key=lambda r: r.name)


# ==========================================
# 2. MODELOS DE SBOM (Syft / Tarea 4)
# ==========================================


class RepositorySbomReport(BaseModel):
    name: str
    full_name: str
    commit_hash: str
    generated_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
    syft_version: str
    status: str  # "success", "failed", "no_components"
    components_count: int = 0
    sbom_path: Optional[str] = None
    error_reason: Optional[str] = None


class SbomSummary(BaseModel):
    total_repositories: int
    analyzed: int
    failed: int
    total_components_identified: int


class OrganizationSbomReport(BaseModel):
    organization: str
    summary: SbomSummary
    repositories: List[RepositorySbomReport]

    def sort_results(self):
        """Ordena los repositorios por nombre de manera alfabética y estable."""
        self.repositories.sort(key=lambda r: r.name)