# Architecture

The platform separates UI, REST API, persistence, target safety, crawling, security checks, normalization and reporting. Scanner checks do not directly own persistence, making them independently testable.

```text
React/PWA -> Flask API -> Repository (SQLite/PostgreSQL-ready boundary)
                         -> Scan Orchestrator
                            -> Target Safety / SSRF Guard
                            -> Safe HTTP Client / Redirect Revalidation
                            -> Same-origin Crawler
                            -> Plugin-style Check Functions
                            -> Finding Normalization / Scoring
                         -> PDF / HTML / JSON Reports
```

## Safety boundary
Targets are normalized, restricted to HTTP(S), checked for credentials/ports, DNS-resolved, and rejected when they resolve to loopback, private, link-local, multicast, reserved or known cloud metadata addresses. Redirect destinations are revalidated before following them.

`SCANNER_ALLOW_PRIVATE=1` exists only for controlled local evaluation.
