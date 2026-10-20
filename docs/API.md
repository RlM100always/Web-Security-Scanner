# REST API

- `GET /health`
- `GET /api/v1/dashboard`
- `GET|POST /api/v1/projects`
- `GET|POST /api/v1/targets`
- `GET|POST /api/v1/scans`
- `GET /api/v1/scans/:id`
- `GET /api/v1/scans/:id/report.json`
- `GET /api/v1/scans/:id/report.html`
- `GET /api/v1/scans/:id/report.pdf`

Creating a target requires `authorized: true`. Lab-profile scans additionally require `verified: true`.
