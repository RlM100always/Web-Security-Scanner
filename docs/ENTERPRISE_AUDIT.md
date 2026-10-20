# Enterprise Product Audit & Feature Maturity

This document records the current SentinelScope product architecture, the workflow depth expected from each major feature, and the automated validation gates used to prevent surface-only functionality.

## Product principles

1. **Authorised and non-destructive by default.** Assessment features must preserve SSRF protections, bounded crawling, redirect revalidation, response-size limits, request timeouts and explicit target authorisation.
2. **Persist important state.** Findings, assets, schedules, jobs, audit events, policies, notifications and remediation decisions are stored in SQLite rather than existing only in browser state.
3. **API enforcement before UI enforcement.** Role, system-admin, API-key, target-verification, project-state and safety boundaries are server-side controls.
4. **Evidence before claims.** Findings carry evidence, confidence, standards references and remediation. Standards mappings do not claim blanket compliance.
5. **Lifecycle over snapshots.** Security work is managed across scans: discovered assets drift, findings recur or remediate, schedules retain run health, and decisions remain auditable.

## Feature maturity matrix

| Domain | Enterprise workflow depth |
| --- | --- |
| Public product experience | Home, Product, Features, Security, Standards, Docs and About routes; responsive product narrative; explicit responsible-use boundary |
| Authentication | Signup/login, email verification, password reset, PBKDF2 password hashing, login throttling, HttpOnly session cookies, CSRF, TOTP MFA, one-time recovery codes, session/device revocation |
| Secret storage | API/session/token hashes; optional Fernet encryption for MFA secrets using deployment-managed APP_ENCRYPTION_KEY |
| Workspace isolation | Active per-workspace memberships, Owner/Admin/Analyst/Viewer roles, workspace switching, suspended-workspace enforcement, workspace-scoped member deactivation, member email/MFA/last-login posture and member-level audit activity drilldown |
| Invitations | Expiring invitations, resend/revoke lifecycle, role assignment, pending-invitation UI |
| System administration | Separate system-admin privilege, users/workspaces/scans/jobs/workers/security events/audit/settings/backups/retention/quotas/maintenance/broadcast/SMTP diagnostics |
| Projects | Editable name/description/tags, active/archive lifecycle, archived-project scan/target enforcement, retained history, safer archive-before-delete workflow |
| Targets | Explicit authorisation, ownership verification, business criticality, environment, tags, metadata editing, SSRF-safe URL validation |
| Scan policy | Project policy plus per-scan bounded overrides, include/exclude regex, disabled checks, request pacing, depth/page caps and immutable per-scan policy snapshot |
| Scan creation | Three-step target/profile/scope/review wizard with target business context and explicit final authorisation confirmation |
| Scanner | TLS/certificate/protocol/cipher/expiry, HTTPS/HSTS, CSP quality, browser headers, cookies, CORS reflection, forms, mixed content, methods, disclosure, security.txt and same-origin asset discovery |
| Asset inventory | Persisted URL/status/type/title/depth/size/source/timing/redirect/truncation metadata; portfolio inventory; latest-target view; added/removed/changed baseline analysis; first/last seen and scan-by-scan provenance drilldown |
| Findings | Stable fingerprint, first/last seen, occurrence count, effective severity, target criticality context, risk score, assignee, SLA due date, comments, scan detection timeline and immutable workflow activity |
| Risk decisions | OPEN/ACKNOWLEDGED/IN_PROGRESS/ACCEPTED_RISK/FALSE_POSITIVE/REMEDIATED; saved/private/shared issue views; portfolio filters; bulk triage; rationale requirement; risk-review expiry; optional Owner-only acceptance approval; expired acceptance priority signal |
| Remediation verification | Queued re-assessment linked to the persistent issue; VERIFIED_FIXED/STILL_PRESENT history |
| Standards | Check-level references and scan-level mapped PASS/WARNING/FAIL/ERROR summary; no blanket certification claim |
| Reports | Executive summary, scope, policy, target context, standards evidence, findings, assets, drift, methodology and limitations in PDF/HTML/JSON |
| ZAP comparison | Imported JSON baseline comparison stored with scan evidence |
| Schedules | Named recurring assessments, cadence/profile, failure notification preference, pause/resume, run-now, run count, failure count, last/next run and persisted execution history |
| Job processing | Persistent SQLite queue, retries, cancellation, worker heartbeat, status telemetry |
| Notifications | Personal/workspace/global notifications, unread summary, mark-one/read-all workflow, scheduled failure delivery |
| Audit | Actor/resource/IP/details/timestamp evidence, search/filter UI and JSON export |
| API access | Expiring one-time-displayed bearer tokens, hashed storage, read/scan/write/admin scopes and central scope enforcement |
| Backups | SQLite online backup, integrity validation, restore workflow, workspace/system-admin history |
| Retention & quotas | Daily scan quota, concurrent scan limit, retention policy and admin-triggered cleanup |
| Responsive UX | Premium desktop security console with condensed sidebar, command palette, executive risk dashboard and dense evidence views; mobile uses a separate compact shell with bottom dock, stacked operational cards, safe-area spacing and sheet-style modals instead of shrinking the desktop layout |
| Accessibility | Semantic public navigation, page headings, keyboard command palette, labelled inputs, focusable controls and high-contrast light/dark design tokens |

## Security boundaries

SentinelScope intentionally does **not** provide:

- destructive exploitation;
- credential stuffing or brute force;
- credential theft;
- persistence or malware deployment;
- destructive data modification;
- denial-of-service testing;
- unrestricted internal-network scanning;
- claims that automated checks prove full application security or regulatory compliance.

The Lab profile may only be queued for an ownership-verified target. Verification does not remove the non-destructive scanner boundary.

## Responsive product model

### Laptop / desktop

- condensed persistent workspace sidebar;
- breadcrumb scope and current view in the header;
- Ctrl/Cmd + K command search for navigation, projects, targets and active issues;
- dense evidence tables and multi-column panels;
- dedicated system-admin control center.

### Mobile

- compact context header;
- bottom navigation for Dashboard, Assets, Issues, Scans and Settings;
- off-canvas full navigation for secondary workflows;
- stacked workflow cards and modal sections;
- horizontally scrollable evidence tables only where column comparison is materially useful;
- touch-friendly action targets.

## Validation gates

GitHub Actions must run:

1. backend pytest suite;
2. TypeScript/Vite production build;
3. Playwright browser E2E on Desktop Chrome;
4. Playwright browser E2E using a Pixel 7 device profile.

Regression coverage includes authentication, system administration, public product pages, deep scan policy persistence, API-key creation, multi-workspace isolation, MFA recovery codes, target risk scoring, schedule history, notifications and report generation.

## Remaining architectural constraint

The project intentionally remains **SQLite-based** for the current academic/product scope. SQLite WAL plus a persistent job queue can support this deployment model, but it is not presented as a substitute for a horizontally distributed multi-region database/queue architecture. The UI/API design keeps domain boundaries explicit so those infrastructure components can be replaced later without changing the product model.

## Public information architecture

The unauthenticated product site now provides dedicated routes for:

- Product
- Features
- Solutions
- Enterprise workflows
- End-to-end workflow
- Security model
- Standards mapping
- Research & evaluation
- Responsible use
- Deployment model
- Documentation
- About

The public experience intentionally explains what the scanner does, what it does not do, how evidence moves through remediation, how SQLite deployment is operated, and why automated standards mapping is not equivalent to certification.

## Portfolio operating model

The enterprise issue inbox now supports:

1. search plus lifecycle/severity/assignee/SLA filtering;
2. private and workspace-shared saved views;
3. multi-select operations;
4. bulk assignment/state/due-date changes;
5. CSV export of the current filtered view;
6. workspace severity-based remediation SLAs;
7. automatic due dates when an issue is first created;
8. optional Owner-only risk acceptance;
9. durable workflow activity history for creation, reopen, comments, triage and automatic remediation.

The dashboard also exposes executive portfolio signals for active security debt, overdue/unassigned issues, expired risk acceptances, remediation rate, posture trend, schedule health and critical-target coverage.
