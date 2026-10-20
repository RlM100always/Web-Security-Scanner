# Deployment

SentinelScope is currently designed as a **production-style single-node SQLite deployment**. The application does not require PostgreSQL, Redis or Celery to use the implemented feature set.

## Recommended topology

```text
Internet
  |
Reverse proxy / TLS termination
  |
  +--> React static application
  |
  +--> Flask API
          |
          +--> SQLite database (WAL mode)
          |
          +--> persistent SQLite-backed job queue
                     |
                     +--> dedicated scanner worker
```

Run the API and scanner worker as separate operating-system processes even though they share the same SQLite database. This keeps request handling isolated from scan execution while preserving the project's SQLite-only requirement.

## SQLite production settings

The repository enables:

- WAL journal mode;
- foreign-key enforcement;
- busy timeout for lock contention;
- short database transactions;
- persistent scan/job state;
- online SQLite backups;
- integrity-aware restore workflow;
- stale worker lease recovery.

Place the SQLite database on **local persistent storage**. Do not place a live WAL database on an unreliable network filesystem.

Back up the database through SentinelScope's backup workflow or SQLite's online backup API rather than copying a busy database file blindly.

## API and reverse proxy

Run Flask behind a production WSGI server and reverse proxy. Terminate TLS at the reverse proxy and configure:

- secure session cookies;
- trusted proxy headers only when the reverse proxy is controlled;
- request/body size limits;
- API timeouts;
- access logs;
- process restart supervision;
- a restrictive outbound network policy for scanner workers.

The development Flask server is for local development only.

## Scanner worker

Run at least one dedicated worker process. Worker state is visible through the system-admin control center.

The queue supports:

- persistent queued jobs;
- cooperative scan cancellation;
- retry attempts;
- worker heartbeat;
- stale lease recovery;
- scan lifecycle events;
- schedule-triggered jobs.

For this SQLite deployment model, keep worker concurrency intentionally bounded. The system-admin setting `max_concurrent_scans_per_org` limits assessment concurrency at workspace level.

## Files and backups

Persist:

- the SQLite database;
- backup files;
- any deployment-specific SMTP/outbox state if used.

Reports are generated from persisted scan evidence and do not require object storage for the current architecture.

## Security boundary

Keep `SCANNER_ALLOW_PRIVATE=0` for normal internet-facing deployments. Private, loopback, link-local, reserved and cloud-metadata destinations are blocked by default and redirect destinations are revalidated.

Only enable private-network scanning inside an explicitly isolated environment where the operator understands the egress implications.

## Availability and recovery

Recommended operational controls:

1. supervise API and worker processes;
2. monitor worker heartbeat and failed jobs;
3. create scheduled database backups;
4. periodically verify backup restore procedures;
5. retain the database on durable local storage;
6. monitor free disk space;
7. use system-admin retention controls to remove expired scan instances;
8. keep the application and dependencies patched.

## Scaling boundary

SQLite WAL is intentionally retained for the current product requirement and is suitable for a well-managed single-node deployment with bounded worker concurrency.

A future horizontally distributed or multi-region architecture would require replacing the database/queue/storage infrastructure. That is a **future scaling boundary**, not a missing dependency for the current implemented feature set. The API and domain model keep those responsibilities separated so such a migration can happen later without redesigning the user workflow.
