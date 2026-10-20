# SentinelScope REST API

All authenticated mutation endpoints use the HttpOnly session cookie plus `X-CSRF-Token`.

## Authentication
- `POST /api/v1/auth/signup`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`
- `POST /api/v1/auth/password`
- `GET /api/v1/auth/sessions`
- `DELETE /api/v1/auth/account`
- `POST /api/v1/auth/email-verification/request`
- `POST /api/v1/auth/email-verification/confirm`
- `POST /api/v1/auth/forgot-password`
- `POST /api/v1/auth/reset-password`
- `POST /api/v1/auth/mfa/setup`
- `POST /api/v1/auth/mfa/confirm`
- `POST /api/v1/auth/mfa/disable`
- `POST /api/v1/auth/workspace`
- `POST /api/v1/auth/invitations/accept`

## Dashboard and projects
- `GET /api/v1/dashboard`
- `GET|POST /api/v1/projects`
- `PATCH /api/v1/projects/:id`
- `DELETE /api/v1/projects/:id`
- `GET|POST /api/v1/targets`
- `PATCH /api/v1/targets/:id`
- `DELETE /api/v1/targets/:id`

Target metadata includes business criticality, environment, tags, accountable `owner_user_id` and operational notes.

## Target preflight

- `GET /api/v1/targets/:id/preflight` — latest and recent diagnostic history
- `POST /api/v1/targets/:id/preflight` — run a bounded non-destructive setup diagnostic for `quick`, `standard` or `lab`

Preflight validates the target safety policy, DNS, HTTP reachability, safe redirects, assessable content, HTTPS/TLS evidence, selected-profile eligibility and the bounded response budget. HTTP 401/403/429/503 conditions are surfaced as warnings rather than bypassed. Lab remains blocked until ownership verification succeeds.

Manual scan creation reuses a compatible recent preflight or runs one server-side before queueing. A `BLOCKED` result prevents queue creation.

## Ownership verification
- `POST /api/v1/targets/:id/verification`
- `POST /api/v1/verifications/:id/check`

## Scans
- `GET|POST /api/v1/scans`
- `GET /api/v1/scans/:id`
- `GET /api/v1/scans/:id/events` (SSE)
- `GET /api/v1/scans/:id/report.pdf`
- `GET /api/v1/scans/:id/report.html`
- `GET /api/v1/scans/:id/report.json`
- `POST /api/v1/scans/:id/zap`

## Schedules
- `GET|POST /api/v1/schedules`
- `PATCH /api/v1/schedules/:id`
- `DELETE /api/v1/schedules/:id`

## Team
- `GET /api/v1/team`
- `POST /api/v1/team` (direct member creation for controlled/admin workflows)
- `PATCH /api/v1/team/:user_id`
- `PATCH /api/v1/team/:user_id/active`
- `DELETE /api/v1/team/:user_id`
- `POST /api/v1/team/invitations`
- `GET /api/v1/team/invitations`

## Notifications and audit
- `GET /api/v1/notifications`
- `POST /api/v1/notifications/:id/read`
- `GET /api/v1/audit`

## Backup, export and operations
- `GET /api/v1/export/workspace.json` — Owner-only, tenant-scoped JSON portability
- `GET /health` — public-safe service health

The legacy workspace routes under `/api/v1/backups*` and `/api/v1/metrics*` return **403**. Raw SQLite backups/restores and platform-wide operational metrics are global resources and therefore belong to the System Admin boundary, not a workspace Owner/Admin boundary.

Lab scans require a verified target.

## System administration

All routes below require `system_admin=1` on the authenticated user.

- `GET /api/v1/admin/overview`
- `GET /api/v1/admin/users`
- `PATCH /api/v1/admin/users/:user_id`
- `GET /api/v1/admin/organizations`
- `PATCH /api/v1/admin/organizations/:organization_id`
- `GET /api/v1/admin/scans`
- `POST /api/v1/admin/scans/:scan_id/cancel`
- `GET /api/v1/admin/jobs`
- `POST /api/v1/admin/jobs/:job_id/retry`
- `POST /api/v1/admin/jobs/:job_id/cancel`
- `DELETE /api/v1/admin/jobs/completed`
- `GET /api/v1/admin/workers`
- `GET /api/v1/admin/security-events`
- `GET /api/v1/admin/audit`
- `GET /api/v1/admin/settings`
- `PUT /api/v1/admin/settings`
- `POST /api/v1/admin/broadcast`
- `POST /api/v1/admin/email-test`
- `GET /api/v1/admin/backups`
- `POST /api/v1/admin/backups`
- `GET /api/v1/admin/backups/:filename`
- `POST /api/v1/admin/backups/restore`
- `GET /api/v1/admin/metrics`
- `GET /api/v1/admin/metrics/prometheus`

Database restore is deliberately gated. The System Admin must first enable maintenance mode, stop every worker process, and leave no `RUNNING` or `QUEUED` persistent jobs. Restore uploads are size-capped and integrity-checked before the database file is replaced.

## Deep assessment workflow APIs

### Scan policy
- `GET /api/v1/projects/:project_id/policy`
- `PUT /api/v1/projects/:project_id/policy`

Policy fields:
`max_pages`, `max_depth`, `request_delay_ms`, `include_paths`, `exclude_paths`, `disabled_checks`.

### Reusable scan profiles
- `GET|POST /api/v1/projects/:project_id/scan-profiles`
- `PATCH /api/v1/projects/:project_id/scan-profiles/:profile_id`
- `POST /api/v1/projects/:project_id/scan-profiles/:profile_id/clone`
- `DELETE /api/v1/projects/:project_id/scan-profiles/:profile_id`

Profiles are project-scoped, named, versioned and reusable by manual scans and schedules. Profile fields include `name`, `description`, `scan_mode`, `is_default`, `active` and the same bounded policy fields as the project base policy. Updating a profile increments its version for future runs. A scan stores immutable `scan_profile_name`, `scan_profile_version` and exact `policy` snapshot.

### Scan result depth
`GET /api/v1/scans/:scan_id` now includes:
- `findings`
- `assets`
- `asset_comparison`
- `standards_summary`
- `policy`
- `comparison`
- optional `zap` comparison

### Finding lifecycle
- `GET /api/v1/finding-states`
- `GET /api/v1/finding-states/:state_id`
- `PATCH /api/v1/finding-states/:state_id`
- `GET|POST /api/v1/finding-states/:state_id/comments`
- `POST /api/v1/finding-states/:state_id/verify`

The detail response includes comments, remediation verification history and the scan-by-scan detection timeline.

### API keys
- `GET|POST /api/v1/api-keys`
- `DELETE /api/v1/api-keys/:key_id`

Use the one-time raw token as:

```http
Authorization: Bearer wss_...
```

### Admin lifecycle controls
- `POST /api/v1/admin/retention/run`

Platform settings also include `scan_quota_per_day`, `max_concurrent_scans_per_org` and `scan_retention_days`.

## Enterprise issue operations

### Workspace remediation governance
- `GET /api/v1/workspace/security-policy`
- `PUT /api/v1/workspace/security-policy`

Workspace policy currently governs:
- severity-based remediation SLA days
- automatic due dates for newly created persistent issues
- optional Owner-only approval for `ACCEPTED_RISK`

### Saved issue views
- `GET|POST /api/v1/issue-views`
- `PATCH|DELETE /api/v1/issue-views/:view_id`

A saved view persists issue filters. Admins can create shared workspace views; users can keep private views.

### Bulk issue triage
- `POST /api/v1/finding-states/bulk`

Up to 250 selected persistent issues can be updated in one governed operation. Supported fields include lifecycle state, severity override, assignee, due date, risk reason and risk-review expiry. The same validation rules used by single-issue triage still apply.

### Issue activity history
`GET /api/v1/finding-states/:state_id` includes `activity` in addition to comments, scan-detection timeline and remediation-verification history.

Activity captures events such as issue creation, reopen, automatic remediation, comments and triage changes.

## Asset provenance

- `GET /api/v1/assets/history?target_id=:target_id&url=:url`

Returns workspace-scoped target context, the latest observation, scan-by-scan asset history and summary counts for first/last seen, status-code changes and content-type changes.

## Notification preferences

- `GET /api/v1/notification-preferences`
- `PUT /api/v1/notification-preferences`

Preferences are stored per user **and per workspace**. Supported channels currently cover in-app/email delivery for scan completion, scan failure and recurring-assessment failure.

### Member security activity
- `GET /api/v1/team/:user_id/activity`

Workspace Admin/Owner users can review member-scoped audit activity together with membership security posture exposed by `GET /api/v1/team`, including email-verification state, MFA state and last-login timestamp.


## Enterprise integrations and access governance

### Signed outbound webhooks

Workspace Admin or Owner:

- `GET /api/v1/integrations/webhooks`
- `POST /api/v1/integrations/webhooks`
- `PATCH /api/v1/integrations/webhooks/:endpoint_id`
- `DELETE /api/v1/integrations/webhooks/:endpoint_id`
- `GET /api/v1/integrations/webhooks/deliveries`
- `POST /api/v1/integrations/webhooks/:endpoint_id/test`
- `POST /api/v1/integrations/webhooks/deliveries/:delivery_id/retry`

Supported event families include scan completion/failure, finding lifecycle updates, remediation verification requests, risk acceptance, recurring-assessment changes and access-review completion.

Webhook requests include:

- `X-SentinelScope-Event`
- `X-SentinelScope-Delivery`
- `X-SentinelScope-Signature: sha256=<HMAC>`

Endpoint URLs are validated when configured and revalidated again before delivery. Redirects are not followed. Delivery state and response metadata are persisted and retryable.

### Workspace access certification

Workspace Admin or Owner:

- `GET|POST /api/v1/access-reviews`
- `GET /api/v1/access-reviews/:review_id`
- `PATCH /api/v1/access-reviews/:review_id/items/:item_id`
- `POST /api/v1/access-reviews/:review_id/complete`

Reviews snapshot current workspace membership. Every member must receive an APPROVE or REVOKE decision before completion. Workspace Owner access cannot be revoked by this workflow. Applied revocations disable workspace membership and revoke active sessions for that workspace.

### Report export provenance

- `GET /api/v1/reports/history`

Every PDF, HTML or JSON report export records actor, scan, format, byte size, timestamp and SHA-256 digest. Report responses also include `X-SentinelScope-SHA256`.

### Public service health

- `GET /health`

The endpoint exposes only public-safe service, database-engine and queue-engine status. Detailed workers, jobs, audit records and security telemetry remain authenticated.


### SLA escalation operations

- `GET /api/v1/portfolio/escalations`

The worker evaluates overdue active issues and creates daily-deduplicated escalation evidence. In-app/email delivery respects user preferences. Signed webhook subscribers may receive `finding.overdue`.


## Workspace readiness
- `GET /api/v1/onboarding`
- `POST /api/v1/onboarding/dismiss`

Readiness is derived from persisted account/workspace state: email verification, active project, authorised target, target owner, active scan profile and first completed scan. The endpoint also exposes optional Lab readiness through verified-target counts.
