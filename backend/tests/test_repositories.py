def test_create_and_list_repository(auth_client):
    resp = auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"})
    assert resp.status_code == 201
    repo = resp.json()
    assert repo["name"] == "webapp"

    resp = auth_client.get("/api/repositories")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_get_repository_not_found(auth_client):
    resp = auth_client.get("/api/repositories/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


def test_repository_isolated_per_user(client):
    client.post("/api/auth/signup", json={"email": "owner@example.com", "password": "password123"})
    owner_token = client.post(
        "/api/auth/login", json={"email": "owner@example.com", "password": "password123"}
    ).json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {owner_token}"})
    repo = client.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()

    client.post("/api/auth/signup", json={"email": "other@example.com", "password": "password123"})
    other_token = client.post(
        "/api/auth/login", json={"email": "other@example.com", "password": "password123"}
    ).json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {other_token}"})

    resp = client.get(f"/api/repositories/{repo['id']}")
    assert resp.status_code == 404
    assert client.get("/api/repositories").json() == []
