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
- `DELETE /api/v1/projects/:id`
- `GET|POST /api/v1/targets`
- `DELETE /api/v1/targets/:id`

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
- `POST /api/v1/backups`
- `GET /api/v1/backups`
- `GET /api/v1/backups/:filename`
- `POST /api/v1/backups/restore`
- `GET /api/v1/export/workspace.json`
- `GET /api/v1/metrics`
- `GET /api/v1/metrics/prometheus`
- `GET /health`

Lab scans require a verified target. Backup/restore/export are owner-only; metrics require Admin or Owner.

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
- `GET /api/v1/admin/metrics`
- `GET /api/v1/admin/metrics/prometheus`

## Deep assessment workflow APIs

### Scan policy
- `GET /api/v1/projects/:project_id/policy`
- `PUT /api/v1/projects/:project_id/policy`

Policy fields:
`max_pages`, `max_depth`, `request_delay_ms`, `include_paths`, `exclude_paths`, `disabled_checks`.

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
