# SentinelScope — Web Security Scanner

> For authorised, non-destructive security assessment only.

SentinelScope is a production-oriented Flask + React security assessment platform backed entirely by SQLite. It combines safe target validation, a persistent scan worker queue, explainable findings, team access control, reporting, recurring scans, ownership verification and operational tooling in a responsive desktop/mobile PWA.

## Product capabilities

### Identity and account security
- Sign up, login and logout
- PBKDF2-SHA256 password hashing
- HttpOnly session cookies
- CSRF protection
- Login throttling and temporary lockout
- Email verification with expiring one-time links
- Forgot/reset-password links
- TOTP MFA (Google/Microsoft Authenticator, 1Password and compatible apps)
- Password change with other-session revocation
- Active-session history
- Workspace switching
- Account deletion
- SMTP delivery in production and development links when SMTP is intentionally not configured

### Teams and access control
- Isolated organisations/workspaces
- Owner, Admin, Analyst and Viewer roles
- Team invitations with expiring links
- Role updates
- Member activate/deactivate/remove
- Audit log for privileged and security-relevant actions

### Projects, targets and authorisation
- Multiple projects and targets
- Explicit ownership/permission acknowledgement
- DNS TXT ownership verification
- Well-known-file ownership verification
- Verified-target requirement for Lab profile
- Target and project lifecycle management

### Scanner
- Quick, Standard and verified Lab profiles
- SSRF-aware URL validation
- Loopback/private/link-local/reserved/metadata blocking by default
- Redirect destination re-validation
- Restricted HTTP(S) schemes/ports
- Request timeout and response-size caps
- Same-origin bounded crawler
- TLS/HTTPS checks
- Security headers and HSTS/CSP checks
- Cookie Secure/HttpOnly/SameSite checks
- CORS heuristic review
- Mixed-content checks
- Form transport, password-method and CSRF heuristics
- External script integrity heuristic
- Technology disclosure/developer-comment checks
- Evidence, severity, confidence, impact, remediation and standards mapping
- Security score and finding fingerprints
- Scan-history comparison (new/fixed/unchanged)

### Queue, live updates and schedules
- SQLite WAL-mode persistent job queue
- Separate worker process
- Job retry state
- API restarts do not lose queued scans
- Server-Sent Events for live scan progress
- Recurring scans
- Schedule pause/resume/delete
- Scan-complete/failed in-app notifications
- Optional email notification when SMTP is configured

### Reports and integrations
- PDF report
- HTML report
- JSON report
- OWASP ZAP JSON import
- ZAP/scanner overlap comparison
- Workspace JSON export
- SQLite backup creation/download
- Validated SQLite restore
- Prometheus-style operational metrics

### UI
- React + TypeScript + Vite
- Responsive enterprise dashboard
- Android/mobile-friendly design
- PWA manifest
- Project/target management UI
- Live findings and remediation UI
- Team/RBAC UI
- Notification center
- Backup/restore and account-security UI

## Verification and quality gates

GitHub Actions validates:
1. Python backend test suite
2. Strict TypeScript + Vite production build
3. Playwright browser E2E on Desktop Chrome and Pixel 7 emulation

The E2E flow validates real signup, authenticated workspace loading and project creation.

A bounded non-destructive load smoke utility is included at `tools/load_smoke.py`.

## Development

### Backend
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
python backend/run.py
```

### Worker
In another terminal:
```bash
python backend/worker.py
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Open: `http://127.0.0.1:5173`

## Production-style Docker deployment
```bash
docker compose up --build -d
```

Open: `http://localhost:8080`

The Compose stack includes:
- Nginx frontend/reverse proxy
- Gunicorn Flask API
- separate SQLite scan worker
- shared persistent SQLite volume

For a public deployment, terminate HTTPS at a trusted reverse proxy/load balancer and set values based on `.env.example`, especially:

```env
PUBLIC_APP_URL=https://scanner.example.com
CORS_ORIGINS=https://scanner.example.com
SESSION_COOKIE_SECURE=1
TRUST_PROXY_HEADERS=1
SMTP_HOST=...
SMTP_USERNAME=...
SMTP_PASSWORD=...
```

Store the SQLite volume on encrypted storage with restrictive OS/container permissions and protect backups equivalently.

## Controlled demo targets
```bash
python demo-sites/demo_server.py
```

The bundled demo server is only for controlled local evaluation. Private targets remain blocked by default unless `SCANNER_ALLOW_PRIVATE=1` is explicitly enabled for that isolated demo environment.

## Load smoke test
Against your own deployment only:

```bash
python tools/load_smoke.py http://127.0.0.1:5000/health --requests 100 --concurrency 10
```

The utility has built-in request/concurrency safety caps.

## Security model
SentinelScope intentionally does **not** implement destructive exploitation, credential attacks, brute-force against target applications, persistence, data extraction or denial-of-service behavior. Automated scanning cannot prove complete application security or reliably identify all business-logic and authorization flaws.

See:
- `SECURITY.md`
- `docs/ARCHITECTURE.md`
- `docs/API.md`
- `docs/SCANNER_CHECKS.md`
- `docs/EVALUATION.md`
- `docs/DEPLOYMENT.md`

## Dedicated system administration

SentinelScope has a separate global control center at:

```text
/admin
```

Workspace `Owner/Admin` permissions do not automatically grant system-administrator access. Bootstrap system administrators explicitly:

```env
SYSTEM_ADMIN_EMAILS=admin@example.com
```

An existing user can also be promoted from the operator CLI:

```bash
python backend/manage.py promote-admin admin@example.com
python backend/manage.py list-admins
```

The system-admin control center includes:

- global platform overview and health metrics
- all users, verification/MFA state and account enable/disable
- grant/revoke system-admin access with last-admin protection
- all workspaces with suspend/reactivate controls
- all scans with cooperative cancellation
- persistent SQLite job queue: retry, cancel and cleanup
- worker heartbeat and online/offline visibility
- recent login attempts and locked-user security events
- global audit trail
- public-registration and maintenance-mode controls
- platform name, maintenance message and admin banner settings
- global in-app broadcast notifications
- SMTP diagnostic email
- platform SQLite backup creation/download
- runtime, database and Prometheus-style metrics

System-admin access is checked by the API, not only hidden in the interface.

## Deep assessment workflows

SentinelScope now treats assessment data as a continuing security-management workflow rather than a one-off scan.

### Project scan policy
Each project stores a real scan policy that is snapshotted into every queued scan:
- maximum in-scope pages
- crawl depth
- request delay/rate pacing
- include-path regular expressions
- exclude-path regular expressions
- individually disabled check IDs

Safety caps are enforced by the scanner even if a client requests larger values.

### Asset inventory and baseline
Every scan persists discovered in-scope assets with:
- URL and discovery source
- crawl depth
- HTTP status
- content type
- page title
- response size
- server/cache metadata
- redirect chain
- response timing
- response-truncation evidence

Successive completed scans produce asset drift:
- added assets
- removed assets
- changed status/content type/title/size

### Finding lifecycle
Findings persist across individual scan runs by target + stable fingerprint. A finding can move through:
- OPEN
- ACKNOWLEDGED
- IN_PROGRESS
- ACCEPTED_RISK
- FALSE_POSITIVE
- REMEDIATED

The lifecycle record also stores:
- first seen / last seen
- occurrence count
- assignee
- due date
- severity override
- risk/triage reason
- analyst comments
- detection timeline across scans

When an active finding disappears in a later scan, it is automatically marked REMEDIATED unless it is already in an explicit terminal triage state.

### Remediation verification
Analysts can request **Verify remediation** on a persistent finding. SentinelScope:
1. queues a fresh standards-configured scan,
2. links it to the finding state,
3. checks the stable fingerprint after completion,
4. records `VERIFIED_FIXED` or `STILL_PRESENT`,
5. updates the persistent finding state.

### Standards coverage
Each result calculates standards-mapping summaries with mapped checks and pass/warning/fail/error counts for references such as OWASP ASVS and OWASP WSTG.

### Scoped API keys
Users can issue expiring bearer API keys. Raw tokens are displayed only once and stored only as SHA-256 hashes.

Scopes:
- `read`
- `scan`
- `write`
- system-admin keys may additionally use `admin`

CSRF is required for cookie sessions; bearer keys use scope enforcement instead.

### Quotas and retention
System administrators can configure:
- scans per workspace per 24 hours
- concurrent queued/running scans per workspace
- completed-scan retention period

Retention removes old scan instances and their per-scan assets/findings/events while preserving continuing security-management state such as current finding lifecycle records.

### Enterprise security operations

The authenticated product now includes a portfolio-level security operations workflow rather than only per-scan review:

- executive risk dashboard with severity debt, remediation health, scan posture trend and recurring-assessment health
- issue inbox with search, severity/state/owner/SLA filters
- private and workspace-shared saved issue views
- multi-select and governed bulk triage
- CSV export of filtered issue portfolios
- severity-based remediation SLA policy and automatic due dates
- optional Owner-only accepted-risk approval
- durable issue activity history for creation, reopen, triage, comments and automatic remediation
- asset provenance drilldown with first/last seen, redirect evidence and scan-by-scan response history
- per-workspace notification preferences for in-app and email channels

### Public product website

The unauthenticated site explains the complete product before signup:

- `/product`
- `/features`
- `/solutions`
- `/enterprise`
- `/workflow`
- `/security`
- `/standards`
- `/research`
- `/responsible-use`
- `/deployment`
- `/docs`
- `/about`

Desktop and mobile use intentionally different information layouts. Mobile uses a compact context header, bottom navigation dock, stacked operational cards and sheet-style detail/modals rather than scaling the desktop console down.
