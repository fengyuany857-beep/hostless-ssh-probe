# VCW Remote Runner

This repository is being upgraded from a Hostless SSH connectivity probe into **VCW Remote Runner v1**.

Target architecture:

```text
GPT
  -> Front MCP
  -> Execution Director
  -> VCW V2 Gateway
  -> VCW Remote Runner (this repository, hosted on Hostless)
  -> SSH/SFTP
  -> target VPS project
```

The Runner is deliberately **not an agent**. It performs deterministic, policy-checked actions and returns deterministic state. Bug diagnosis, code design, semantic repair decisions and strategy remain above this layer.

## RPC v1

Methods:

- `read_file`
- `write_file`
- `apply_patch`
- `exec`
- `start_job`
- `job_status`
- `cancel_job`
- `transfer`
- `reconcile`

States:

- `VERIFIED`
- `FAILED`
- `OUTCOME_UNKNOWN`
- `DENIED`
- `RATE_LIMITED`

See `docs/rpc-v1.md` for the contract.

## Required environment

- `RUNNER_TOKEN`
- `VCW_SERVER_ID`
- `TARGET_HOST`
- `TARGET_PORT` (default `22`)
- `TARGET_USER`
- `VCW_PROJECT_ROOT`
- `SSH_PRIVATE_KEY` or `SSH_PRIVATE_KEY_B64`
- `SSH_HOST_KEY_SHA256`

Optional:

- `VCW_ALLOWED_TOOLS`
- `VCW_ALLOWED_EXEC`
- `VCW_EXEC_PATH` (fixed executable search path; default `/usr/local/bin:/usr/bin:/bin`)
- `VCW_BACKEND_TIMEOUT_S`
- `VCW_MAX_FILE_BYTES`
- `VCW_MAX_OUTPUT_BYTES`
- `VCW_MAX_INFLIGHT`
- `VCW_LEDGER_DATABASE_URL` (recommended for Hostless production; PostgreSQL)
- `VCW_LEDGER_DB` (SQLite fallback for local/dev only)
- `VCW_RUNNER_BUILD_REVISION` (optional deployment provenance)
- `PORT` from Hostless

## Endpoints

- `GET /health`: process liveness
- `GET /v1/info`: authenticated Runner/backend capability check, including idempotency-ledger backend/durability
- `GET /probe`: authenticated compatibility probe
- `POST /v1/rpc`: authenticated Runner RPC

The RPC never accepts a host, port or username from the caller.

Optional `session_id` is correlation-only metadata supplied by Gateway. Runner does not use it as authorization or session lease authority. Unknown envelope and method-parameter fields are denied rather than silently ignored.

For side effects, `request_id` is bound to a canonical fingerprint of fixed server identity + method + params. Reusing it with changed action semantics is denied. Existing incomplete claims are never re-executed. The ledger stores only minimal reconciliation hints such as desired file SHA/path or deterministic job id, not task state or file bodies.

## Security boundary

The target SSH account is part of the isolation model. Runner argv filtering is not a complete host filesystem sandbox. Use a dedicated Unix account whose permissions expose only the intended project and required toolchain. Runner startup rejects `TARGET_USER=root` and `VCW_PROJECT_ROOT=/`.

Writes support compare-before-write CAS semantics, SFTP temp files, atomic `posix_rename`, read-back SHA256 verification, and file-mode verification. Existing regular-file mode is preserved; new files default to `0644`. Caller-facing file APIs refuse `.git` and `.vcw-runner` control metadata. SSH server identity is pinned with `SSH_HOST_KEY_SHA256`.

Caller executable paths are not accepted: `argv[0]` must be a bare name in `VCW_ALLOWED_EXEC`, resolved only through deployment-fixed `VCW_EXEC_PATH`. Exec/job cwd is canonically checked against the configured project root. This still does not replace least-privileged target-account isolation.

For production idempotency across Hostless redeploys, link a managed PostgreSQL database and inject its connection string as `VCW_LEDGER_DATABASE_URL`. PostgreSQL ledger statements run inside explicit transactions with transaction-local lock/statement timeouts; the connection avoids startup `options` so it remains compatible with Hostless's PgBouncer path. The Runner stores only request-ledger metadata and serialized RPC responses there. If that variable is absent, the Runner falls back to `VCW_LEDGER_DB` SQLite; the default `/tmp/vcw-runner-ledger.sqlite3` is restart-local and must not be used for a frozen production Runner.

Authenticated `GET /v1/info` reports ledger durability and a SHA256 runtime build fingerprint over packaged Runner source/requirements so real-host evidence can be bound to the deployed build. `connection_generation` is a successful SSH connection epoch and increments once per new established connection.

## Current status

Hostless -> target VPS TCP/22 reachability has already been proven. This branch upgrades the probe into the formal Runner API implementation.

Before freezing `vcw.runner.v1`, perform real Hostless SSH/SFTP acceptance against the target VPS, including durable PostgreSQL ledger replay across redeploy, wrong host-key rejection, CAS conflict, mode preservation, timeout/reconnect, job cancellation races, local 429 saturation, audit leak checks, transfer integrity and `OUTCOME_UNKNOWN` reconciliation cases.
