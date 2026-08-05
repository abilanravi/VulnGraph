# VulnGraph

Software Vulnerability Intelligence Platform. Phase 1 MVP: a full-stack app with authentication,
manual repository tracking, and manual vulnerability/finding entry. Scanner integrations (Semgrep,
OSV Scanner), GitHub import, and Docker Compose are planned for later phases.

## Stack

- **Frontend**: Next.js (App Router) + TypeScript + Tailwind CSS — `frontend/`
- **Backend**: FastAPI + SQLAlchemy + Alembic — `backend/`
- **Database**: PostgreSQL
- **Auth**: FastAPI issues JWTs; the Next.js server stores the token in an httpOnly cookie and
  forwards it as a Bearer token when calling the API.

## Prerequisites

- Python 3.10+
- Node.js 20+
- PostgreSQL running locally (native install, or a standalone container:
  `docker run -d --name vulngraph-postgres -e POSTGRES_USER=svip -e POSTGRES_PASSWORD=svip -e POSTGRES_DB=svip -p 5432:5432 postgres`)

## Backend setup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux
pip install -r requirements.txt

cp .env.example .env          # edit DATABASE_URL / JWT_SECRET if needed
alembic upgrade head
python seed.py                # creates demo@vulngraph.dev / password123 with sample data

uvicorn app.main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

## Frontend setup

```bash
cd frontend
npm install
cp .env.local.example .env.local   # BACKEND_URL=http://localhost:8000
npm run dev
```

App: http://localhost:3000

## Verifying the app works

1. Visit http://localhost:8000/docs and confirm the `auth`, `repositories`, and `findings`
   endpoints are listed.
2. Visit http://localhost:3000 — you should be redirected to `/login`.
3. Sign up (or log in with the seeded demo account: `demo@vulngraph.dev` / `password123`).
4. On the dashboard, confirm the seeded repositories (`acme-corp/webapp`,
   `acme-corp/payments-service`) are listed.
5. Open a repository and confirm its findings (CVEs, severities) are listed.
6. Add a new repository, then add a finding to it (CVE, severity, description) and confirm it
   appears in the list.
7. Log out and confirm you're redirected to `/login`, and that visiting `/dashboard` directly
   while logged out also redirects to `/login`.

## Project layout

```
backend/
  app/
    core/       # settings, password hashing, JWT
    db/         # SQLAlchemy engine/session, models
    schemas/    # Pydantic request/response models
    api/        # routes + auth dependency
  alembic/      # migrations
  seed.py

frontend/
  app/          # routes (login, signup, dashboard, ...)
  lib/
    api.ts        # typed backend client (server-only)
    session.ts     # httpOnly JWT cookie helpers
    actions/         # Server Actions (login, signup, add repository, add finding)
  proxy.ts      # route guard for /dashboard/*
```

## Roadmap

- **Phase 2**: integrate Semgrep (SAST) and OSV Scanner (SCA); store their findings against the
  existing `findings`/`vulnerabilities` schema instead of manual entry.
- **Phase 3**: GitHub integration for repository import, automated scanning, and Docker Compose.
