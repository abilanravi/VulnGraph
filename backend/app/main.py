from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import audit, auth, dashboard, findings, repositories, scans, users
from app.core.config import settings

app = FastAPI(title="VulnGraph API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Baseline security headers for a JSON API.

    `Content-Security-Policy` is scoped to `default-src 'none'` since every real response here is
    JSON, not HTML — nothing should ever need to load a script/style/frame from this origin. The
    interactive docs (`/docs`, `/redoc`) are the one legitimate exception: Swagger/ReDoc's UI
    loads its own scripts/styles, so they're excluded from that policy rather than being served
    broken. `Strict-Transport-Security` is only sent when `environment=production`, since it's
    only correct to promise HTTPS-only access once HTTPS is actually guaranteed in front of this
    service — sending it in local HTTP development would be actively wrong.
    """
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

    if settings.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    return response


app.include_router(auth.router, prefix="/api")
app.include_router(repositories.router, prefix="/api")
app.include_router(findings.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(audit.router, prefix="/api")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
