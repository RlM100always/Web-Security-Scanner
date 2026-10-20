# Bug-Fix Audit — 2026-10-21

This audit records the regression and security fixes applied during the current stabilization pass. It is intentionally concise and exists so the final CI run is tied to the complete fixed state rather than to an older queued commit.

## Fixed

- MFA management no longer renders a blank modal before recovery codes exist.
- Workspace switching clears tenant-scoped UI state and handles failed switches without showing stale data.
- Unknown unauthenticated routes render a real 404 instead of falling through to sign-in.
- Reset/invitation/verification links handle missing tokens and loading/error states safely.
- ZAP import surfaces JSON/server/upload errors instead of failing silently.
- Toast timers no longer race and clear newer notifications.
- Explicit Bearer API-key authentication takes precedence over session cookies, preventing scope bypass.
- Cancelled scans keep persistent scan and worker-job states aligned.
- SQLite backup filenames are collision-safe; restore removes stale WAL/SHM state after integrity validation.
- Raw SQLite backup/restore and platform-wide metrics are System-Admin-only; workspace Owners receive tenant-scoped JSON export.
- System database restore requires maintenance mode, no online workers, an idle queue, and a bounded upload.
- Login throttling separates account and shared-network failure limits.
- Password recovery responses are account-existence neutral.
- Invitation acceptance is atomic and account-aware; existing workspace members cannot be re-invited to alter roles.
- Workspace Owner role is protected from downgrade through membership APIs.
- Webhook pause/retry/delete lifecycle preserves durable delivery state.
- Webhook response evidence is bounded while preserving an explicit truncation marker.
- Scan-producing rerun/schedule/remediation paths enforce the same authorization, preflight, quota, and API-key scope governance as normal scans.
- Regression fixtures were aligned to the current report-export schema.

## Validation gates

The repository CI is expected to validate:

1. dependency consistency;
2. Python compilation;
3. full backend pytest suite;
4. strict TypeScript/Vite production build;
5. Playwright E2E on desktop Chromium and Pixel 7 emulation;
6. CodeQL security analysis.

The final stabilization status should be based on the CI/CodeQL run attached to this audit commit or a direct descendant that contains no further code changes.
