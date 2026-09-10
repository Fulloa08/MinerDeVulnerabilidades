from typing import List, Optional
from pydantic import BaseModel, Field

class Finding(BaseModel):
    rule_id: str
    severity: str
    message: str
    file: str
    start_line: int

class RepositoryReport(BaseModel):
    name: str
    url: str
    status: str  # 'analyzed', 'failed', 'unsupported', etc.
    languages: List[str] = Field(default_factory=list)
    error_reason: Optional[str] = None
    findings: List[Finding] = Field(default_factory=list)

class Summary(BaseModel):
    repositories: int = 0
    analyzed: int = 0
    failed: int = 0
    unsupported: int = 0
    findings: int = 0

class OrganizationReport(BaseModel):
    organization: str
    summary: Summary
    repositories: List[RepositoryReport]

    def sort_results(self):
        """Ordena repositorios y hallazgos para asegurar resultados reproducibles."""
        self.repositories.sort(key=lambda repo: repo.name)
        for repo in self.repositories:
            repo.findings.sort(key=lambda f: (f.file, f.start_line, f.rule_id))