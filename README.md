# Web Security Scanner

> For authorised security testing only.

A standards-mapped, non-destructive web vulnerability assessment platform built with Flask and React. It is designed around safe-by-default target validation, explainable findings, scan history, reporting, and responsive/PWA UX.

## Highlights
- Project and target management
- Authorisation confirmation and verified-target flag
- SSRF-aware URL validation (private/loopback/link-local/metadata blocked by default)
- Quick, Standard and Lab scan profiles
- Limited same-origin crawler with page/depth caps
- 20+ passive/heuristic checks for TLS, headers, cookies, CORS, forms, mixed content and disclosure
- Structured findings: status, severity, confidence, evidence, remediation, standards mapping
- Security score, scan history and finding fingerprints
- JSON, HTML and PDF reports
- Responsive React dashboard and installable PWA manifest
- Secure/insecure local demo server for controlled evaluation
- pytest tests, Docker files and GitHub Actions CI

## Safety
The scanner is intentionally non-destructive. It does not perform exploitation, credential attacks, data extraction, denial of service, or invasive payload delivery. Private and local targets are blocked unless `SCANNER_ALLOW_PRIVATE=1`, intended only for the bundled local demo environment.

## Local development
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python backend/run.py

cd frontend
npm install
npm run dev
```

API: `http://127.0.0.1:5000/api/v1`  
Frontend: `http://127.0.0.1:5173`

## Demo evaluation
```bash
python demo-sites/demo_server.py
SCANNER_ALLOW_PRIVATE=1 python backend/run.py
```
Use `http://127.0.0.1:8090/secure` and `http://127.0.0.1:8090/insecure` only for local controlled evaluation.

## Architecture
See `docs/ARCHITECTURE.md`, `docs/SCANNER_CHECKS.md`, `docs/ETHICS.md`, and `docs/API.md`.
