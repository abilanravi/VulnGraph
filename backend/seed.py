"""Seeds the database with a demo user, repositories, and findings for local development."""

from app.core.security import hash_password
from app.db.base import Base, SessionLocal, engine
from app.db.models import (
    Finding,
    FindingStatus,
    FindingType,
    Repository,
    Scanner,
    Severity,
    User,
    Vulnerability,
)
from app.services.fingerprint import compute_fingerprint

DEMO_EMAIL = "demo@vulngraph.dev"
DEMO_PASSWORD = "password123"


def seed() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == DEMO_EMAIL).first()
        if user is None:
            user = User(email=DEMO_EMAIL, hashed_password=hash_password(DEMO_PASSWORD))
            db.add(user)
            db.flush()

        repo_specs = [
            {"name": "webapp", "owner": "acme-corp", "url": "https://github.com/acme-corp/webapp"},
            {"name": "payments-service", "owner": "acme-corp", "url": "https://github.com/acme-corp/payments-service"},
        ]
        repos = {}
        for spec in repo_specs:
            repo = (
                db.query(Repository)
                .filter(Repository.owner_id == user.id, Repository.name == spec["name"])
                .first()
            )
            if repo is None:
                repo = Repository(owner_id=user.id, **spec)
                db.add(repo)
                db.flush()
            repos[spec["name"]] = repo

        vuln_specs = [
            {
                "cve": "CVE-2021-23337",
                "severity": Severity.HIGH,
                "description": "Lodash command injection via template function.",
            },
            {
                "cve": "CVE-2022-29078",
                "severity": Severity.CRITICAL,
                "description": "ejs template engine remote code execution via settings[view options][outputFunctionName].",
            },
            {
                "cve": "CVE-2023-45853",
                "severity": Severity.CRITICAL,
                "description": "MiniZip buffer overflow via a crafted ZIP archive.",
            },
        ]
        vulns = {}
        for spec in vuln_specs:
            vuln = db.query(Vulnerability).filter(Vulnerability.cve == spec["cve"]).first()
            if vuln is None:
                vuln = Vulnerability(**spec)
                db.add(vuln)
                db.flush()
            vulns[spec["cve"]] = vuln

        finding_specs = [
            ("webapp", "CVE-2021-23337", FindingStatus.OPEN),
            ("webapp", "CVE-2022-29078", FindingStatus.OPEN),
            ("payments-service", "CVE-2023-45853", FindingStatus.RESOLVED),
        ]
        for repo_name, cve, status in finding_specs:
            repo = repos[repo_name]
            vuln = vulns[cve]
            fingerprint = compute_fingerprint(repo.id, Scanner.MANUAL, cve=cve)
            finding = (
                db.query(Finding)
                .filter(Finding.repository_id == repo.id, Finding.fingerprint == fingerprint)
                .first()
            )
            if finding is None:
                db.add(
                    Finding(
                        repository_id=repo.id,
                        vulnerability_id=vuln.id,
                        scanner=Scanner.MANUAL,
                        finding_type=FindingType.MANUAL,
                        severity=vuln.severity,
                        title=cve,
                        description=vuln.description,
                        cve=cve,
                        fingerprint=fingerprint,
                        status=status,
                    )
                )

        # A sample Semgrep (SAST) finding, illustrating the scanner-origin shape.
        semgrep_fingerprint = compute_fingerprint(
            repos["webapp"].id,
            Scanner.SEMGREP,
            rule_id="python.flask.security.audit.debug-enabled",
            file_path="app/main.py",
            line_start=12,
        )
        if (
            db.query(Finding)
            .filter(Finding.repository_id == repos["webapp"].id, Finding.fingerprint == semgrep_fingerprint)
            .first()
            is None
        ):
            db.add(
                Finding(
                    repository_id=repos["webapp"].id,
                    scanner=Scanner.SEMGREP,
                    finding_type=FindingType.SAST,
                    severity=Severity.MEDIUM,
                    title="python.flask.security.audit.debug-enabled",
                    description="Flask app run with debug=True, which can leak a Werkzeug debugger RCE.",
                    file_path="app/main.py",
                    line_start=12,
                    rule_id="python.flask.security.audit.debug-enabled",
                    fingerprint=semgrep_fingerprint,
                    status=FindingStatus.OPEN,
                )
            )

        db.commit()
        print(f"Seed complete. Demo login: {DEMO_EMAIL} / {DEMO_PASSWORD}")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
