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
