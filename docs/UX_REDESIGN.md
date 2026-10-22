# SentinelScope UX audit and redesign notes

## Product UX goal

Optimise for the user's next decision, not the number of controls on screen. SentinelScope serves five recurring jobs:

1. **First-time setup:** create a workspace, organise a project, add an authorised target, assign an owner, configure a scan profile, and run the first baseline.
2. **Daily security triage:** identify the highest-risk active issues, overdue work, unassigned issues and expired risk decisions.
3. **Investigation:** move from a persistent issue to its evidence, target, history, comments and remediation verification.
4. **Assessment operations:** understand queued/running/failed scans, inspect the policy used, compare asset baselines and rerun safely.
5. **Governance:** manage workspace access, integrations, audit history, API keys, retention and platform operations.

## UX issues found in the current implementation

- The dashboard's large score looked like an overall portfolio score even though it represented a single latest scan.
- The first dashboard metrics focused on project/team counts rather than the risks or tasks most likely to need action.
- In-app navigation lived only in React state. Refreshing, sharing a view or using browser back/forward could lose the current workspace view.
- Scan detail was a transient view with no scan identifier in the URL.
- The mobile layout hid the command/search control entirely.
- The mobile drawer lacked a clear scrim interaction and a consistent close affordance.
- Issues, assets and scan tables retained desktop-style multi-column layouts on narrow screens, forcing horizontal scanning/scrolling.
- The public product preview used plausible sample metrics without a clear in-preview sample label.
- UI layers had accumulated over several CSS files; the redesign therefore uses a final, narrowly scoped UX layer instead of risky wholesale deletion of the established styles.

## Changes implemented

### Dashboard and information hierarchy
- Reframed the dashboard around “Know what needs attention”.
- Replaced the first metrics row with critical/high issues, overdue remediation, discovered assets and assessments in progress.
- Replaced the ambiguous score hero with a **Latest completed assessment** card that names the target and completion time.
- Added context-sensitive primary action: create a project, add a target, or run an authorised assessment depending on workspace readiness.
- Sorted priority actions by persisted risk score and improved the zero-issues / no-baseline next step.
- Kept portfolio distribution, remediation health, posture trend, automation health and queue details below the primary action area.

### Navigation and orientation
- Workspace views now use hash-based deep links and browser history.
- Scan details include the scan ID in the URL and can be restored after a refresh.
- The Scans navigation item stays active while viewing scan details.
- Added an accessible, icon-only mobile search trigger rather than hiding search.
- Added a notification shortcut with an unread count.
- Added a mobile drawer scrim and Escape-to-close behaviour.

### Mobile task layouts
- On narrow screens, issue rows become stacked issue cards with target/project, state, owner and remediation SLA.
- Asset rows become cards with status, type, depth and latency context.
- Scan rows become cards with status, profile, score, diff and actions.
- Filters, saved views, bulk actions, finding details and modals use touch-friendly controls and narrow-screen layouts.
- The bottom navigation respects safe-area insets and keeps the five most-used mobile destinations within thumb reach.

### Public product clarity
- Added Features to the top-level public navigation.
- Kept Security Model accessible in the public proof/trust links.
- Replaced implementation-centric homepage proof-strip labels with user-facing value.
- Labelled the dashboard preview as **illustrative data** so sample figures cannot be mistaken for a live customer environment.

### Accessibility and interaction quality
- Preserved a screen-reader dashboard landmark for existing assistive-technology and browser tests.
- Added a descriptive accessible name to mobile search.
- Strengthened visible keyboard focus, tap targets, form sizing, reduced-motion handling and modal scrolling.
- Added Playwright coverage for browser history, mobile drawer/search, and viewport overflow.

## Design decisions

- **Desktop:** persistent grouped sidebar, contextual header, high-information-density tables and portfolio panels.
- **Mobile:** thumb-friendly bottom navigation, off-canvas grouped navigation, compact action header and card-first data views.
- **Visual hierarchy:** one primary action per task area; supporting actions are secondary; risk severity and due-date urgency remain visible but not colour-only.
- **Trust:** distinguish a single-scan score from portfolio metrics, label sample data, and keep scan provenance visible.
- **Safe defaults:** assessment actions remain explicitly authorised and non-destructive.

## Verification

The repository's Playwright configuration runs Desktop Chrome and Pixel 7 emulation. The new UX test checks:
- dashboard content and accessible landmark,
- navigation hash and browser back,
- mobile drawer open/close,
- mobile dock navigation,
- command search and Escape-to-close,
- document width not exceeding viewport width.

The deep-workflow test separately checks policy persistence and API-key creation.

## Remaining product-quality work

This pass improves the user journey and responsive information architecture, but visual polish is not the same as a full usability certification. A release candidate should still receive:
- a real-device visual review on common Android sizes and small laptops,
- keyboard-only and screen-reader testing,
- moderated usability sessions with first-time analysts and security leads,
- extraction of the very large App component into tested feature modules and a shared component library,
- performance/accessibility audits against production-like data volumes.

Do not describe the application as “100% production-ready” solely because CI passes; security tooling needs ongoing validation against real authorised environments and an explicit release checklist.
