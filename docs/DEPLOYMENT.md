# Deployment

For a production-style deployment, run the Flask API behind a reverse proxy, use PostgreSQL instead of local SQLite, move scanning to isolated workers/queues, define strict egress controls, and persist reports in object storage. Keep private-network access disabled unless an explicitly isolated enterprise deployment requires it.
