import pytest


@pytest.fixture()
def repository(auth_client):
    return auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()


def test_create_manual_finding(auth_client, repository):
    resp = auth_client.post(
        f"/api/repositories/{repository['id']}/findings",
        json={"cve": "CVE-2024-12345", "severity": "HIGH", "description": "test vuln"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["cve"] == "CVE-2024-12345"
    assert body["scanner"] == "MANUAL"
    assert body["finding_type"] == "MANUAL"
    assert body["status"] == "OPEN"
    assert body["title"] == "CVE-2024-12345"


def test_duplicate_manual_finding_does_not_create_second_row(auth_client, repository):
    payload = {"cve": "CVE-2024-12345", "severity": "HIGH", "description": "test vuln"}
    first = auth_client.post(f"/api/repositories/{repository['id']}/findings", json=payload)
    second = auth_client.post(f"/api/repositories/{repository['id']}/findings", json=payload)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] == second.json()["id"]

    findings = auth_client.get(f"/api/repositories/{repository['id']}/findings").json()
    assert len(findings) == 1


def test_update_finding_status_lifecycle(auth_client, repository):
    created = auth_client.post(
        f"/api/repositories/{repository['id']}/findings",
        json={"cve": "CVE-2024-1", "severity": "LOW", "description": "x"},
    ).json()

    resp = auth_client.patch(
        f"/api/repositories/{repository['id']}/findings/{created['id']}", json={"status": "IN_PROGRESS"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "IN_PROGRESS"

    resp = auth_client.patch(
        f"/api/repositories/{repository['id']}/findings/{created['id']}", json={"status": "RESOLVED"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "RESOLVED"
    assert resp.json()["resolved_at"] is not None


def test_findings_require_auth(client):
    resp = client.get("/api/repositories/00000000-0000-0000-0000-000000000000/findings")
    assert resp.status_code == 401
