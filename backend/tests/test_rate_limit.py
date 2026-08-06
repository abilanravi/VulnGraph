from app.core.rate_limit import reset_rate_limits


def test_login_rate_limited_after_threshold(client):
    reset_rate_limits()
    client.post("/api/auth/signup", json={"email": "bruteforce@example.com", "password": "password123"})

    responses = [
        client.post("/api/auth/login", json={"email": "bruteforce@example.com", "password": "wrong"})
        for _ in range(15)
    ]
    assert any(r.status_code == 429 for r in responses)
    assert responses[0].status_code == 401


def test_signup_rate_limited_after_threshold(client):
    reset_rate_limits()
    responses = [
        client.post("/api/auth/signup", json={"email": f"spam{i}@example.com", "password": "password123"})
        for i in range(10)
    ]
    assert any(r.status_code == 429 for r in responses)


def test_scan_trigger_rate_limited_after_threshold(auth_client):
    reset_rate_limits()
    repo = auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()

    responses = [
        auth_client.post(f"/api/repositories/{repo['id']}/scans/semgrep", json={"path": "/no/such/path"})
        for _ in range(25)
    ]
    assert any(r.status_code == 429 for r in responses)
