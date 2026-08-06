from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_db
from app.db.models import Finding, FindingStatus, Repository, Severity, User
from app.schemas.dashboard import DashboardSummary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_OPEN_STATUSES = (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(
    current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)
) -> DashboardSummary:
    owned_findings = db.query(Finding).join(Repository).filter(Repository.owner_id == current_user.id)

    total_repositories = db.query(Repository).filter(Repository.owner_id == current_user.id).count()
    total_open_findings = owned_findings.filter(Finding.status.in_(_OPEN_STATUSES)).count()

    severity_counts = dict(
        owned_findings.filter(Finding.status.in_(_OPEN_STATUSES))
        .with_entities(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )

    recent_findings = owned_findings.order_by(Finding.detected_at.desc()).limit(10).all()

    return DashboardSummary(
        total_repositories=total_repositories,
        total_open_findings=total_open_findings,
        critical_findings=severity_counts.get(Severity.CRITICAL, 0),
        high_findings=severity_counts.get(Severity.HIGH, 0),
        medium_findings=severity_counts.get(Severity.MEDIUM, 0),
        low_findings=severity_counts.get(Severity.LOW, 0),
        recent_findings=recent_findings,
    )
