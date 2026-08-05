def test_signup_and_login(client):
    resp = client.post("/api/auth/signup", json={"email": "a@example.com", "password": "password123"})
    assert resp.status_code == 201
    assert "access_token" in resp.json()

    resp = client.post("/api/auth/login", json={"email": "a@example.com", "password": "password123"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_signup_duplicate_email_rejected(client):
    client.post("/api/auth/signup", json={"email": "a@example.com", "password": "password123"})
    resp = client.post("/api/auth/signup", json={"email": "a@example.com", "password": "password123"})
    assert resp.status_code == 400


def test_login_wrong_password_rejected(client):
    client.post("/api/auth/signup", json={"email": "a@example.com", "password": "password123"})
    resp = client.post("/api/auth/login", json={"email": "a@example.com", "password": "wrong-password"})
    assert resp.status_code == 401


def test_protected_endpoint_requires_auth(client):
    resp = client.get("/api/repositories")
    assert resp.status_code == 401


def test_me_returns_current_user(auth_client):
    resp = auth_client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.json()["email"] == "test@example.com"
