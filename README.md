# VulnGraph

Software Vulnerability Intelligence Platform. Authentication, repository tracking, and a
scanning pipeline that runs Semgrep (SAST) and OSV Scanner (SCA) against a local path,
normalizes their output into a common Finding model, and dedupes findings across repeated
scans. GitHub import and Docker Compose are planned for later phases.

## Stack

- **Frontend**: Next.js (App Router) + TypeScript + Tailwind CSS — `frontend/`
- **Backend**: FastAPI + SQLAlchemy + Alembic — `backend/`
- **Database**: PostgreSQL
- **Scanners**: [Semgrep](https://semgrep.dev) (SAST), [OSV Scanner](https://github.com/google/osv-scanner) (SCA) — invoked as external CLIs
- **Auth**: FastAPI issues JWTs; the Next.js server stores the token in an httpOnly cookie and
  forwards it as a Bearer token when calling the API.

## Prerequisites

- Python 3.10+
- Node.js 20+
- PostgreSQL running locally (native install, or a standalone container:
  `docker run -d --name vulngraph-postgres -e POSTGRES_USER=svip -e POSTGRES_PASSWORD=svip -e POSTGRES_DB=svip -p 5432:5432 postgres`)
- [Semgrep](https://semgrep.dev/docs/getting-started/) on `PATH` to run SAST scans (`pip install semgrep`)
- [OSV Scanner](https://google.github.io/osv-scanner/installation/) on `PATH` to run SCA scans

Semgrep and OSV Scanner are optional at install time — the backend runs without them, but
triggering a scan without the corresponding CLI installed returns a `FAILED` scan with an
explanatory error message instead of crashing.

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

### Running tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

Tests run against an in-memory SQLite database (schema created directly from the SQLAlchemy
models) rather than Postgres, so they don't require a running database. They cover: Semgrep/OSV
result parsing, scan ingestion/dedup (new/unchanged/resolved/reopened findings), auth, repository
access control, and manual finding creation/lifecycle.

## Frontend setup

```bash
cd frontend
npm install
cp .env.local.example .env.local   # BACKEND_URL=http://localhost:8000
npm run dev
```

App: http://localhost:3000

## Verifying the app works

1. Visit http://localhost:8000/docs and confirm the `auth`, `repositories`, `findings`,
   `scans`, and `dashboard` endpoints are listed.
2. Visit http://localhost:3000 — you should be redirected to `/login`.
3. Sign up (or log in with the seeded demo account: `demo@vulngraph.dev` / `password123`).
4. On the dashboard, confirm the summary tiles (repositories, open/critical/high/medium/low
   findings) and the seeded repositories (`acme-corp/webapp`, `acme-corp/payments-service`) are
   listed.
5. Open a repository and confirm its findings (manual CVEs and the seeded Semgrep finding) are
   listed with severity, scanner, and location.
6. With Semgrep or OSV Scanner installed, enter a local path in the "Run scan" forms and confirm
   a scan record appears with a findings summary, and that re-running the same scan doesn't
   duplicate findings (only reports what changed).
7. Change a finding's status (Start / Resolve / False positive / Reopen) and confirm it updates.
8. Add a new repository, then add a manual finding to it (CVE, severity, description) and confirm
   it appears in the list.
9. Log out and confirm you're redirected to `/login`, and that visiting `/dashboard` directly
   while logged out also redirects to `/login`.

## Project layout

```
backend/
  app/
    core/       # settings, password hashing, JWT
    db/         # SQLAlchemy engine/session, models (User, Repository, Vulnerability, Scan, Finding)
    schemas/    # Pydantic request/response models
    api/        # routes (auth, repositories, findings, scans, dashboard) + auth dependency
    services/
      fingerprint.py     # dedup fingerprint shared by manual entry and both scanners
      scan_service.py    # orchestrates a scan run and reconciles findings (new/unchanged/resolved/reopened)
      scanners/           # semgrep.py, osv.py — subprocess invocation + result parsing
  alembic/      # migrations
  tests/        # pytest suite (SQLite-backed)
  seed.py

frontend/
  app/          # routes (login, signup, dashboard, repository detail, ...)
  lib/
    api.ts        # typed backend client (server-only)
    session.ts     # httpOnly JWT cookie helpers
    actions/         # Server Actions (login, signup, repositories, findings, scans)
  proxy.ts      # route guard for /dashboard/*
```

## How scanning works

1. `POST /api/repositories/{id}/scans/semgrep` or `/scans/osv` with `{"path": "<local path>"}` —
   a path on the backend host to scan (no GitHub cloning; that's a later milestone).
2. The backend runs the corresponding CLI, parses its JSON output into a normalized shape
   (severity, title, description, file/line or package/version, raw scanner output), and
   reconciles it against existing findings for that repository + scanner using a fingerprint:
   - Semgrep: `rule_id + file_path + line`
   - OSV: `package_name + package_version + CVE/GHSA id`
   - Manual entries: `CVE` (unchanged from before)
3. Findings not seen before are created (`OPEN`); findings seen again are refreshed in place
   (no duplicates); previously `OPEN`/`IN_PROGRESS` findings no longer reported by that scanner
   are marked `RESOLVED`; a `RESOLVED` finding that reappears is reopened. Findings a user marked
   `FALSE_POSITIVE` are left alone even if the scanner still reports them.
4. Each finding keeps a `status` lifecycle (`OPEN` → `IN_PROGRESS` → `RESOLVED`/`FALSE_POSITIVE`,
   with manual reopen back to `OPEN`) independent of the scan reconciliation above.

## Known limitations / not verified end-to-end

- A live PostgreSQL/Docker environment was not available in this environment, so the Alembic
  migration was verified with an offline `--sql` dry-run (both upgrade and downgrade) rather than
  against a real database. Its data-backfill step (populating `title`/`cve`/`fingerprint` on
  pre-existing findings) only runs with a live connection, by design.
- Neither Semgrep nor OSV Scanner is installed in this environment (disk space constraints), so
  the scanner CLIs themselves were not exercised end-to-end. What *is* verified: subprocess
  invocation gracefully fails with a `FAILED` scan record when the CLI is missing (tested for
  real, since neither binary is present here), and the JSON parsers are unit-tested against
  representative sample output from each tool's documented schema.
- Backend tests run against SQLite, not Postgres — sufficient for application logic, but not a
  substitute for a full Postgres integration run.

## Roadmap

- **Milestone 4**: GitHub integration for repository import, automated scanning, and Docker Compose.
