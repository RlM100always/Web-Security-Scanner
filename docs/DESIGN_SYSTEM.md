# SentinelScope Product UI & Interaction System

This document defines the interface rules that keep SentinelScope consistent as the product grows.

## Product UX principles

1. **Security work is contextual.** Every issue, asset, scan and schedule should preserve project, target and workspace context.
2. **Navigation follows the workflow.** Top-level navigation is grouped around Overview, Security operations, Assessment and Governance rather than exposing every feature as an unrelated menu item.
3. **Actions disclose impact.** Destructive or security-sensitive actions use in-product dialogs that explain consequences. Permanent project/target deletion requires explicit typed confirmation.
4. **Evidence stays close to action.** Findings show evidence, remediation, owner, lifecycle, history and verification without forcing the user through unrelated screens.
5. **Mobile is a different shell, not a squeezed desktop.** Primary workflows use a bottom dock, stacked cards, full-screen/sheet dialogs and safe-area spacing.
6. **Dense where comparison matters.** Tables are retained for issue, asset and scan comparison on larger screens; compact mobile layouts prioritize identity, severity, state and the next action.
7. **Accessibility is a primitive.** Dialogs expose role/aria semantics, trap focus, restore focus and support Escape. Keyboard command search is available with Ctrl/Cmd+K.
8. **Dark mode is first-class.** Components use shared surface, text, border and semantic-state tokens rather than page-specific hard-coded backgrounds.

## Design tokens

The application uses layered CSS token sets in `premium.css` and `enterprise.css`.

Core semantic categories:
- canvas/background
- primary and secondary surfaces
- strong/subtle borders
- primary text / muted text
- brand action
- success / warning / danger
- soft and elevated shadows
- compact and standard radii

Product components should reference semantic tokens whenever possible instead of introducing isolated page colors.

## Layout model

### Desktop / wide laptop

- persistent 244–252 px sidebar
- sticky 70–72 px context header
- max content width around 1540 px
- multi-column overview and comparison layouts
- command search visible in the header
- dense enterprise tables for issues/assets/scans
- side-by-side evidence and workflow panels where useful

### Compact laptop / tablet

- narrower sidebar
- reduced horizontal content padding
- filters collapse progressively
- low-value comparison columns may hide
- evidence tables may scroll horizontally

### Mobile

- off-canvas full navigation
- fixed five-destination bottom dock
- compact header with icon actions
- no desktop sidebar
- stacked cards and operational panels
- full-width or full-height modal workflows
- touch targets should remain approximately 44 px where practical
- use safe-area padding for bottom navigation

## Navigation

Workspace navigation is intentionally condensed:

### Overview
- Dashboard

### Security operations
- Issues
- Assets
- Exposure
- Reports

### Assessment
- Projects
- Scans
- Schedules

### Governance
- Team
- Notifications
- Integrations (Admin)
- Audit (Admin)
- Settings

System administration remains separate at `/admin`.

The global command palette should search/jump to:
- product areas
- projects
- targets
- active findings

## Public information architecture

The public site explains the product before asking a visitor to create an account.

Primary path:
1. What SentinelScope is
2. How the operating workflow works
3. What technical/security controls exist
4. How assets/findings/remediation connect
5. Trust, standards and responsible-use boundaries
6. Developer/automation/deployment information
7. Create workspace / sign in

Public routes include Product, Features, Solutions, Enterprise, Workflow, Security, Standards, Research, Responsible Use, Deployment, Docs, About, Trust, Integrations, API, Architecture, Scanner Checks, Reports, Developers, Status, Asset Inventory, Scan Profiles, Vulnerability Management, Continuous Monitoring, Governance, Getting Started and Methodology.

## Interaction patterns

### Destructive actions

Never use browser-native `confirm()` or `prompt()`.

Use an in-product dialog with:
- exact resource name
- consequence summary
- cancel action
- clearly styled destructive action
- typed `DELETE` confirmation for project/target destruction

Lower-impact removals such as saved views, schedules, members and webhooks use the shared governed confirmation component.

### One-time secrets

API keys, webhook signing-secret rotation and MFA recovery codes:
- display raw secret only after creation/rotation
- explain that it will not be shown again
- provide a copy action
- require an explicit acknowledgement before closing where practical

### Loading and failure

- preserve currently loaded workspace data during refresh
- use dedicated initial workspace loading state
- show user-actionable API errors rather than silently implying success
- offline mode must clearly indicate that mutations and scans require connectivity

### Empty states

Every empty state should explain:
- what is absent
- why it matters
- the next permitted action

## Visual hierarchy

The interface intentionally avoids “hacker neon” styling.

Use:
- neutral surfaces
- restrained blue brand emphasis
- semantic severity colors
- thin borders
- minimal, soft shadows
- compact labels
- strong information hierarchy
- consistent typography rhythm

Security severity color is reserved for security meaning, not decoration.

## Product references

The UI direction is informed by established enterprise security products that use:
- condensed grouped navigation
- workspace/scope switching
- breadcrumb context
- command search
- issue and asset drill-down
- saved views
- configurable analytics
- dark-mode support

SentinelScope applies these patterns to its own authorised web-assessment workflow rather than copying another product's visual identity.

## Regression gates

UI changes are not complete until:
- TypeScript production build passes
- desktop Playwright workflows pass
- Pixel 7 Playwright workflows pass
- public product routes remain reachable
- auth/workspace isolation tests pass
- destructive-action tests pass
- CodeQL completes without introducing blocking security findings
