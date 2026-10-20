# SentinelScope Enterprise Completion Audit

## Purpose

This audit records the enterprise-product hardening applied to SentinelScope. The goal is not to imitate a commercial platform or claim unlimited scale. The goal is to make every implemented capability connected, explainable, testable and operationally useful within the project's SQLite-first deployment scope.

## Product operating model

SentinelScope follows one continuous workflow:

1. establish an authorised workspace and governed scope;
2. create projects and accountable targets;
3. verify ownership where stronger scan modes require it;
4. use reusable versioned scan profiles and bounded policies;
5. discover the in-scope application surface;
6. run non-destructive, evidence-first security checks;
7. normalise repeated detections into persistent issues;
8. prioritise issues using technical severity plus business context;
9. assign owners, due dates and triage decisions;
10. verify remediation with linked re-assessment;
11. retain report/export provenance and audit history;
12. automate approved workflows with schedules, API keys and signed webhooks;
13. operate the platform through worker health, queue controls, backups, retention and system administration.

## Enterprise workflow depth completed

### Identity and account lifecycle

- secure signup/login/logout
- PBKDF2 password hashing
- HttpOnly session cookie
- CSRF enforcement for interactive sessions
- login throttling and temporary lockout
- email verification
- password reset
- TOTP MFA and one-time recovery codes
- active-session history and revocation
- workspace switching
- workspace-scoped membership disable/removal
- account deletion
- scoped expiring API keys
- system-admin boundary separate from workspace Owner/Admin

### Workspace governance

- Owner/Admin/Analyst/Viewer RBAC
- invitation lifecycle including resend/revoke
- access-review workflow with persisted review items and decisions
- global audit events
- member security posture including verification, MFA and last login
- workspace security policy
- scan quotas, concurrency and retention controls

### Projects and targets

- editable project metadata and archive/reactivate lifecycle
- target authorisation acknowledgement
- DNS TXT / well-known-file ownership verification
- environment, criticality, tags, accountable owner and notes
- archive-aware assessment controls
- cascade-safe deletion for dependent scan/lifecycle data

### Assessment governance

- project base policy
- named reusable scan profiles
- profile version history
- immutable profile version + policy snapshot on each scan
- quick / standard / verified lab modes
- crawl depth/page/pacing controls
- include/exclude path regex controls
- individually disabled checks
- scheduled scans pinned to profile/version context
- manual run-now and schedule history
- schedule drift visibility/recovery

### Scanner and evidence

- SSRF/private/link-local/metadata protection
- safe redirect re-validation
- bounded response size and crawl scope
- same-origin asset discovery
- transport/TLS evidence
- security headers
- CSP directive quality
- HSTS policy strength
- cookies
- CORS reflection observation
- form and sensitive-GET heuristics
- mixed content and browser security signals
- advertised HTTP methods
- technology/developer disclosure
- security.txt observation
- stable finding fingerprints
- response timing, redirect and truncation metadata

### Security operations

- portfolio issue inbox
- effective severity and contextual risk score
- stable finding lifecycle
- first/last seen and occurrence count
- assignee
- due date
- severity override
- risk reason and review/expiry date
- comments
- bulk triage
- saved personal/shared views
- CSV export
- overdue SLA escalation with daily deduplication
- remediation verification
- detection timeline
- risk-acceptance expiry signal
- scan comparison

### Asset and exposure management

- latest completed-scan asset inventory
- target/project/business context
- asset first/last seen history
- added/removed/changed baselines
- response metadata and provenance
- contextual Exposure Map connecting:
  - Project
  - Target
  - Discovered asset
  - Active persistent issue
  - Accountable owner
- top-risk target summary derived from persisted lifecycle risk scores

The Exposure Map deliberately represents only SentinelScope's governed and discovered data. It does not claim internet-wide external attack-surface discovery.

### Integrations and evidence portability

- signed webhooks with workspace-managed secret
- delivery attempts and retry evidence
- scoped API keys
- OWASP ZAP result comparison
- PDF / HTML / JSON reports
- report export history
- SHA-256 report digest header/provenance
- workspace JSON export

### Operations and administration

- SQLite WAL persistence
- durable job queue
- separate worker process
- retries and cancellation
- stale-job recovery
- worker heartbeats
- scan progress with SSE
- system-admin control center
- users/workspaces/scans/jobs/security-events/global-audit controls
- maintenance and registration controls
- SMTP diagnostic
- backup/download/validated restore
- retention execution
- Prometheus-style metrics
- public-safe health/status surface

## UX / design completion

### Public product site

Public information architecture now includes:

- Home
- Product
- Features
- Solutions
- Enterprise
- Exposure Management
- Asset Inventory
- Scan Profiles
- Vulnerability Management
- Continuous Monitoring
- Governance
- Integrations
- Workflow
- Security
- Trust
- Standards
- Methodology
- Research
- Reports
- Deployment
- Architecture
- Scanner Checks
- API
- Developers
- Getting Started
- Documentation
- Responsible Use
- Platform Status
- About

The public site describes implemented behavior and avoids fabricated customer logos, false coverage numbers or claims that automated scanning proves total security.

### Authenticated desktop UX

- grouped information architecture
- workspace context and breadcrumbs
- global command/search surface
- desktop side navigation
- portfolio dashboard
- priority action views
- risk/coverage summaries
- deep project/target cards
- issue operations workspace
- asset inventory
- exposure map
- report center
- integrations
- team/access governance
- settings and account security
- dedicated system-admin console
- light/dark theme
- loading, offline, empty, error and recovery states

### Mobile UX

Mobile is intentionally not a shrunken desktop:

- bottom navigation dock for primary workflows
- drawer for full information architecture
- touch-sized actions
- stacked issue and exposure contexts
- responsive tables/cards
- full-screen complex configuration modals where needed
- safe-area / viewport support
- installable PWA metadata
- maskable app identity
- production service worker caching static application shell only
- API, authentication and health responses are never service-worker cached

## External design principles adopted

A review of current security-platform patterns reinforced five design decisions:

1. prioritise context over raw alert count;
2. connect inventory, risk and ownership;
3. keep remediation as part of the product workflow;
4. expose reusable policy/configuration rather than one-off scan buttons;
5. present public pages around the operating model, not an undifferentiated feature list.

SentinelScope implements these ideas only with data and capabilities it actually owns.

## Release gates

A change is not considered complete until relevant gates pass:

- backend pytest suite
- TypeScript strict build
- Vite production build
- desktop Chromium E2E
- Pixel 7 emulation E2E
- authentication/workspace browser flow
- project/profile governance browser flow
- system-admin browser flow
- public-site browser routes
- tenant-isolation regression tests
- scanner safety tests

## Deliberate boundaries

These are not defects.

- SentinelScope remains non-destructive.
- It does not brute-force credentials.
- It does not perform denial-of-service testing.
- It does not extract protected data.
- It does not silently scan unauthorised targets.
- Automated checks cannot prove the absence of business-logic or complex authorisation vulnerabilities.
- SQLite is used intentionally for the defined deployment scope; it is not presented as a horizontally distributed database.
- Discovered assets are bounded scanner inventory, not internet-wide attack-surface discovery.
- Standards references are mappings to relevant checks, not a blanket compliance certification.

## Production environment dependencies

Software support is implemented, but a real deployment still needs operator-provided infrastructure values:

- public domain
- TLS certificate / HTTPS termination
- SMTP credentials
- system-admin bootstrap identity
- encrypted persistent storage / backup protection
- monitoring destination if Prometheus metrics are collected externally

Those values cannot be safely invented or embedded in source control.
