def test_api_response_has_baseline_security_headers(client):
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "Permissions-Policy" in resp.headers


def test_api_response_has_strict_csp(client):
    resp = client.get("/health")
    assert resp.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_docs_route_is_exempt_from_strict_csp(client):
    resp = client.get("/docs")
    assert "Content-Security-Policy" not in resp.headers


def test_hsts_not_sent_outside_production(client):
    resp = client.get("/health")
    assert "Strict-Transport-Security" not in resp.headers
