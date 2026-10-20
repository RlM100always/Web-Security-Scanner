# Scanner Check Catalogue

SentinelScope intentionally prioritizes repeatable, explainable and non-destructive observations. Each result stores evidence, confidence, affected URL, remediation and standards references where appropriate. Standards mapping does **not** imply complete OWASP, ASVS, WSTG or regulatory compliance.

## Transport and TLS

- HTTPS usage
- HTTP to HTTPS upgrade behavior
- certificate and hostname validated TLS handshake
- negotiated TLS protocol version
- negotiated cipher evidence
- certificate expiry / near-expiry warning
- HSTS presence
- HSTS max-age quality

## Browser and response security

- Content-Security-Policy presence
- CSP directive quality, including risky unsafe-eval / unsafe-inline / wildcard signals
- frame embedding protection
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy
- mixed-content subresources
- external-script Subresource Integrity heuristic
- sensitive page Cache-Control heuristic

## Cookies and forms

- Secure cookie attribute
- HttpOnly cookie attribute
- SameSite cookie attribute
- insecure HTTP form actions
- password forms using GET
- password autocomplete semantics
- POST-form anti-CSRF token heuristic
- sensitive-looking data submitted by GET
- cross-origin sensitive-form action heuristic

## CORS and HTTP configuration

- coarse Access-Control-Allow-Origin / credential review
- benign synthetic Origin reflection behavior
- OPTIONS-advertised HTTP methods
- unexpected TRACE / CONNECT advertisement warning

## Information disclosure and governance

- Server / X-Powered-By technology banner exposure
- rendered developer TODO / FIXME marker heuristic
- standardized /.well-known/security.txt availability and Contact metadata
- security.txt Expires metadata evidence

## Asset discovery evidence

For every discovered in-scope asset SentinelScope can persist:

- canonical URL
- discovery source
- crawl depth
- HTTP status
- content type
- page title
- response size
- response timing
- redirect chain
- response truncation signal
- selected server/cache metadata

Successive completed scans produce asset baseline analysis for added, removed and materially changed assets.

## Scanner safety boundary

The scanner does not implement destructive exploitation, credential stuffing, brute force, credential theft, persistence, destructive data modification, data extraction or denial-of-service testing. Same-origin crawling, target validation, redirect re-validation, response-size limits, request timeouts, crawl/page caps and request pacing remain part of the scanner boundary.

The Lab profile requires verified target ownership, but verification does not remove the non-destructive safety model.
