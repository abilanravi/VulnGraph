from pydantic import BaseModel

from app.schemas.finding import FindingRead


class DashboardSummary(BaseModel):
    total_repositories: int
    total_open_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    recent_findings: list[FindingRead]
