# VulnGraph

Software Vulnerability Intelligence Platform. Authentication, GitHub repository import, and a
scanning pipeline that runs Semgrep (SAST) and OSV Scanner (SCA) against a repository (either a
shallow clone of a public GitHub URL, or a local path), normalizes their output into a common
Finding model, and dedupes findings across repeated scans. Access is governed by role-based
access control (RBAC) with server-enforced resource ownership, and security-sensitive actions are
recorded to an audit log — see "Security" below.

## Stack

- **Frontend**: Next.js (App Router) + TypeScript + Tailwind CSS — `frontend/`
- **Backend**: FastAPI + SQLAlchemy + Alembic — `backend/`
- **Database**: PostgreSQL
- **Scanners**: [Semgrep](https://semgrep.dev) (SAST), [OSV Scanner](https://github.com/google/osv-scanner) (SCA) — invoked as external CLIs
- **Repository access**: public GitHub repositories are shallow-cloned (`git clone --depth 1`)
  into a temporary directory for the duration of a scan, then deleted
- **Auth**: FastAPI issues JWTs; the Next.js server stores the token in an httpOnly cookie and
  forwards it as a Bearer token when calling the API.
- **CI**: GitHub Actions runs backend tests, frontend typecheck/lint/build, and lightweight
  security checks (secret scanning, dependency vulnerability scanning) on every push/PR — see
  `.github/workflows/ci.yml`.

## Quickest way to run everything: Docker Compose

```bash
cp .env.example .env   # edit JWT_SECRET at minimum
docker compose up --build
```

This starts PostgreSQL (persisted in a named volume), the backend (runs Alembic migrations on
startup, then serves the API on :8000 — includes Semgrep and OSV Scanner in the image), and the
frontend (:3000). Set `SEED_DB=true` in `.env` before first startup to also load demo data.

**Not verified in this environment** — see "Known limitations" below; Docker itself wasn't
available here, so the Compose stack was reviewed but never actually built/started.

## Prerequisites (running natively, without Docker)

- Python 3.10+
- Node.js 20+
- [Git](https://git-scm.com/) on `PATH` — required to clone GitHub repositories for scanning
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
models) rather than Postgres, so they don't require a running database. 107 tests cover:
Semgrep/OSV result parsing, scan ingestion/dedup (new/unchanged/resolved/reopened findings), auth,
manual finding creation/lifecycle, and (Milestone 5) RBAC, cross-user resource isolation, JWT/auth
hardening, rate limiting, audit logging, and input-validation/subprocess-safety.

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
   findings) and the seeded repositories (`acme-corp/webapp`, `acme-corp/payments-service`,
   `octocat/Hello-World`) are listed.
5. Open a repository and confirm its findings (manual CVEs and the seeded Semgrep finding) are
   listed with severity, scanner, and location.
6. Click "Add repository" → "From GitHub" and import a public repo by URL (e.g.
   `https://github.com/octocat/Hello-World`); confirm it's created with a "GitHub import" badge.
   Click "Run Scan" on it (no path needed) and confirm VulnGraph clones it and runs both
   scanners — with Semgrep/OSV Scanner installed, a findings summary appears; without them, both
   scans record `FAILED` with a clear error message (not a crash).
7. For a manually-added repository, enter a local path in the "Run Scan" form instead and confirm
   the same scan/findings flow, and that re-running the same scan doesn't duplicate findings
   (only reports what changed).
8. Change a finding's status (Start / Resolve / False positive / Reopen) and confirm it updates.
9. Add a manual finding (CVE, severity, description) to a repository and confirm it appears.
10. Log out and confirm you're redirected to `/login`, and that visiting `/dashboard` directly
    while logged out also redirects to `/login`.

## Project layout

```
backend/
  app/
    core/       # settings, password hashing, JWT, RBAC permissions, rate limiting
    db/         # SQLAlchemy engine/session, models (User, Repository, ..., AuditLog)
    schemas/    # Pydantic request/response models
    api/        # routes (auth, repositories, findings, scans, dashboard, users, audit) + deps
    services/
      fingerprint.py     # dedup fingerprint shared by manual entry and both scanners
      github.py          # GitHub URL parsing/validation
      repo_fetch.py       # shallow git clone into a temp dir, with cleanup
      scan_service.py    # orchestrates a scan run and reconciles findings (new/unchanged/resolved/reopened)
      scanners/           # semgrep.py, osv.py — subprocess invocation + result parsing
      audit.py            # writes AuditLog rows for security-sensitive actions
  alembic/      # migrations
  tests/        # pytest suite (SQLite-backed)
  Dockerfile, docker-entrypoint.sh
  seed.py

frontend/
  app/          # routes (login, signup, dashboard, repository detail, dashboard/admin, ...)
  lib/
    api.ts        # typed backend client (server-only)
    session.ts     # httpOnly JWT cookie helpers
    actions/         # Server Actions (login, signup, repositories, findings, scans, users)
  proxy.ts      # route guard for /dashboard/*
  Dockerfile

docker-compose.yml    # postgres + backend + frontend, for local/demo use
.github/workflows/ci.yml   # backend tests, frontend typecheck/lint/build, security checks
```

## How GitHub import works

`POST /api/repositories` with `{"url": "https://github.com/<owner>/<repo>"}` validates the URL,
extracts `owner`/`repo`, and stores the repository with `source=GITHUB`. Only
`https://github.com/<owner>/<repo>` URLs (public repositories) are accepted — no SSH URLs, no
other Git hosts. (Repositories can still be added without a URL — `{"name": ..., "owner": ...}`
— for scanning via a local path instead; these get `source=MANUAL`.)

## How scanning works

1. `POST /api/repositories/{id}/scans/run` runs both Semgrep and OSV Scanner in one pass.
   Individual `/scans/semgrep` and `/scans/osv` endpoints are still available if you only want
   one. All three accept an optional `{"path": "<local path>"}` body:
   - If `path` is given, that directory on the backend host is scanned directly.
   - If omitted, the repository must have been added via a GitHub URL (`source=GITHUB`) —
     VulnGraph shallow-clones it (`git clone --depth 1`) into a temporary directory, scans that,
     and deletes it afterward (`app/services/repo_fetch.py`). `/scans/run` shares a single clone
     across both scanners rather than cloning twice.
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

## Security

VulnGraph is a case study in authentication, authorization, and audit — not just feature count.

### Roles & permissions

Three roles (`app/db/models.py: UserRole`), server-enforced on every route via FastAPI
dependencies (`app/core/permissions.py`), never inferred from the frontend:

| | ADMIN | DEVELOPER | VIEWER |
|---|---|---|---|
| View own repositories/findings/scans | ✓ | ✓ | ✓ |
| Create/import repositories, run scans, update findings | ✓ | ✓ | ✗ |
| View **any** user's repositories/findings/scans | ✓ | ✗ | ✗ |
| Manage users (list, change role, activate/deactivate) | ✓ | ✗ | ✗ |
| View audit log | ✓ | ✗ | ✗ |

New accounts always default to `DEVELOPER` and are always `is_active=True` — `role`/`is_active`
are not fields on the signup request (`app/schemas/user.py: UserCreate`), so a client cannot
self-elevate at signup. Changing another user's role or active status requires ADMIN
(`PATCH /api/users/{id}/role`, `PATCH /api/users/{id}/active}` in `app/api/routes/users.py`), and
neither endpoint permits acting on your own account — an admin can't self-promote-by-accident or
lock themselves out.

### Authorization & resource isolation

Repositories, scans, and findings are owned by a single user (`Repository.owner_id`). Every route
that takes a `repository_id` resolves it through `_get_owned_repository`
(`app/api/routes/repositories.py`), which filters by `owner_id` unless the caller is ADMIN — a
repository you don't own doesn't exist as far as the API is concerned, both for lookups and for
scan/finding sub-resources beneath it. Non-owned resources return `404`, not `403`, so a request
can't be used to fingerprint which repository ids exist. This is why VIEWER accounts have no
built-in path to owning a repository of their own in this MVP (they can't create one, and
ownership isn't currently shareable) — an admin account is the practical way to give a VIEWER
something to look at; see "Explicitly out of scope" for why sharing/teams wasn't built.
`tests/test_resource_isolation.py` and `tests/test_rbac.py` cover cross-user access attempts and
the ADMIN bypass.

### Authentication hardening

- Passwords are hashed with bcrypt (`passlib`, `app/core/security.py`) — verified never stored in
  plaintext (`tests/test_auth_hardening.py::test_password_is_hashed_not_stored_plaintext`).
- JWTs carry a server-set expiry (`jwt_expire_minutes`, default 60m); expired, malformed, or
  wrong-signature tokens are all rejected with `401` (`tests/test_auth_hardening.py`).
- A JWT for a deactivated account is rejected immediately via `get_current_active_user`
  (`app/api/deps.py`), even if the token itself hasn't expired — deactivation takes effect without
  waiting for the token to expire.
- Login failure (wrong password, unknown email, and deactivated account) all return the same
  `401 Invalid email or password` — the response never confirms whether an email is registered.
- The session cookie is set by the Next.js server (`frontend/lib/session.ts`): `httpOnly`,
  `sameSite=lax`, and `secure` when `NODE_ENV=production` — the JWT itself is never exposed to
  client-side JavaScript.

### Rate limiting

In-memory, per-process fixed-window limiter (`app/core/rate_limit.py`): login and signup are
limited per client IP (login also factors in the attempted email, so one IP can't exhaust the
budget for every account), and scan triggering is limited per authenticated user. This is
explicitly an MVP-appropriate choice, documented in code: **it does not coordinate across
multiple backend processes/instances** — a horizontally scaled deployment would need a shared
store (e.g. Redis) instead, which is out of scope for this milestone.
`tests/test_rate_limit.py` exercises all three limits.

### Audit logging

`AuditLog` (`app/db/models.py`) records `login_success` / `login_failed` / `signup`,
`repository_created` / `repository_imported`, `scan_triggered`, `finding_status_changed`,
`role_changed`, and `user_deactivated` / `user_reactivated`, each with the acting user, an IP,
and a small non-secret metadata blob — never a password, JWT, cookie, or GitHub token
(`app/services/audit.py`, verified by
`tests/test_audit_log.py::test_audit_log_never_contains_password_or_token`). Visible to ADMIN only
via `GET /api/audit-logs` and the `/dashboard/admin` page.

### Security headers

- **Backend** (`app/main.py`, a JSON-only API): `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
  `Permissions-Policy`, and `Content-Security-Policy: default-src 'none'` on every response
  except `/docs`/`/redoc` (which need their own CSP to render Swagger/ReDoc's UI).
  `Strict-Transport-Security` is only sent when `ENVIRONMENT=production`, since promising
  HTTPS-only access is only correct once HTTPS is actually guaranteed in front of the service.
- **Frontend** (`next.config.ts`): the same first four headers, plus a same-origin
  `Content-Security-Policy`. That policy uses `'unsafe-inline'` for `script-src` rather than a
  per-request nonce — a nonce-based CSP was tried first and reverted after finding (via
  `npm run build && npm run start` and inspecting the rendered HTML) that Next.js only stamps
  nonces onto *dynamically* rendered pages, and `/login`/`/signup` here are statically
  prerendered; forcing every route into dynamic rendering just for CSP nonces would trade away
  Next's static optimization for a benefit this app doesn't need (no `dangerouslySetInnerHTML`
  anywhere, no third-party scripts). `default-src 'self'` plus the frame/object/form restrictions
  still hold. See the comment in `next.config.ts` for the full reasoning.

### Input validation & subprocess safety

- GitHub URLs are matched against a strict `https://github.com/<owner>/<repo>` pattern
  (`app/services/github.py`) — no SSH URLs, no other hosts, no shell metacharacters can survive
  into a clone URL.
- Every external process invocation (`git clone`, `semgrep`, `osv-scanner`) is called with
  `subprocess.run([...])` argument arrays, never a shell string — there is no code path where
  user input is interpolated into a shell command (verified in
  `tests/test_input_validation.py`, which asserts `shell=` doesn't appear in any of the three
  invocation call sites).
- A local scan `path` must resolve (via `os.path.realpath`) to an existing directory, and — when
  the optional `SCAN_ROOT_DIR` setting is configured — must stay inside that root, rejecting
  `..`-style traversal and pointing the scanner at arbitrary server paths
  (`app/api/routes/scans.py: _resolve_scan_path`, tested in `tests/test_input_validation.py`).
  `SCAN_ROOT_DIR` is unset by default for local/single-operator use; **set it in any deployment
  where the backend host also holds data other than what's meant to be scanned.**

## Known limitations / not verified end-to-end

- **Docker**: not available in this environment (`docker` isn't installed), so
  `docker-compose.yml`, `backend/Dockerfile`, and `frontend/Dockerfile` were written and
  reviewed but never actually built or run. Verify with `docker compose up --build` before
  relying on them.
- **Semgrep / OSV Scanner**: not installed in this development environment (only ~390MB of disk
  was free, too little to safely install them here — both are included in `backend/Dockerfile`
  for the containerized path). What *is* verified for real: subprocess invocation gracefully
  fails with a `FAILED` scan record when the CLI is missing, and the JSON parsers are unit-tested
  against representative sample output from each tool's documented schema.
- **GitHub cloning**: verified for real — `git` is installed locally, and
  `backend/tests/test_repo_fetch.py::test_clone_real_public_repository` performs an actual
  `git clone --depth 1` of a small public GitHub repo (`octocat/Hello-World`) over the network as
  part of the test suite. The rest of that file's tests mock `subprocess` for deterministic,
  network-independent coverage of the error paths (missing `git`, timeout, non-zero exit).
- A live PostgreSQL environment was not available, so both Alembic migrations were verified with
  an offline `--sql` dry-run (upgrade and downgrade) rather than against a real database.
  Migration `0002`'s data-backfill step only runs with a live connection, by design.
- Backend tests run against SQLite, not Postgres — sufficient for application logic, but not a
  substitute for a full Postgres integration run.
- `pip-audit` (run in CI) currently flags `starlette` (fix requires a FastAPI major-version bump)
  and `ecdsa` (no fix version published yet) as having open advisories; both are transitive
  dependencies, so the CI step is advisory (`continue-on-error`) rather than blocking.
  `python-jose` and `python-multipart` were bumped to their latest versions to close the
  vulnerabilities `pip-audit` found in them. Unchanged in Milestone 5 (re-ran `pip-audit`; same
  two advisories, no new ones from any Milestone 5 code — no new dependencies were added).
  `npm audit --audit-level=high` reports zero frontend vulnerabilities.
- Migration `0004_rbac_audit` (roles, `is_active`, `audit_logs`) was verified the same way as the
  others: an offline `alembic upgrade head --sql` / `downgrade ... --sql` dry-run against
  Postgres DDL, plus the full pytest suite against SQLite. It was **not** run against a live
  Postgres database, for the same reason as before (none available in this environment).
- The rate limiter (`app/core/rate_limit.py`) is in-memory and per-process by design (see
  "Security" above) — correct for this MVP's single-instance deployment, wrong for a
  horizontally scaled one without a shared store.
- A full browser-based click-through of the RBAC UI (role badge, hidden buttons, `/dashboard/admin`)
  wasn't possible without a real browser in this environment, but was verified end-to-end via a
  local smoke test: a real backend (SQLite-backed) and a production Next.js build (`npm run
  build && npm run start`) running together, exercised with `curl` using an ADMIN and a VIEWER
  session cookie — confirmed the admin page renders live user/audit data, and that the VIEWER
  session correctly has "Add repository" hidden from the rendered HTML.

## Dogfooding

Since GitHub import now exists, you can point VulnGraph at its own repository: add
`https://github.com/<your-fork>/VulnGraph` and click "Run Scan". This exercises the exact same
clone → Semgrep → OSV → normalize → dedupe → dashboard pipeline as any other repository.

## Roadmap

- **Milestone 4**: GitHub repository import, real automated scanning (clone → scan → dedupe),
  Docker Compose, and CI.
- **Milestone 5** (this phase): RBAC (ADMIN/DEVELOPER/VIEWER), server-enforced authorization and
  resource isolation, minimal user management, audit logging, in-memory rate limiting, security
  headers, and input-validation/subprocess-safety hardening. See "Security" above for what was
  built and "Known limitations" for what wasn't independently verified in this environment.
  Explicitly out of scope for this milestone (see task spec): OAuth/SSO/MFA, distributed rate
  limiting (Redis), multi-tenant repository sharing/teams, and any cloud infrastructure.
