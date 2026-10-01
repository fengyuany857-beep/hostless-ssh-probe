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
- `VCW_BACKEND_TIMEOUT_S`
- `VCW_MAX_FILE_BYTES`
- `VCW_MAX_OUTPUT_BYTES`
- `VCW_MAX_INFLIGHT`
- `VCW_STATE_DATABASE_URL` (recommended for Hostless production; PostgreSQL)
- `VCW_STATE_DB` (SQLite fallback for local/dev only)
- `PORT` from Hostless

## Endpoints

- `GET /health`: process liveness
- `GET /v1/info`: authenticated Runner/backend capability check, including state-store backend/durability
- `GET /probe`: authenticated compatibility probe
- `POST /v1/rpc`: authenticated Runner RPC

The RPC never accepts a host, port or username from the caller.

## Security boundary

The target SSH account is part of the isolation model. Runner argv filtering is not a complete host filesystem sandbox. Use a dedicated Unix account whose permissions expose only the intended project and required toolchain.

Writes support CAS, SFTP temp files, atomic `posix_rename` and read-back SHA256 verification. SSH server identity is pinned with `SSH_HOST_KEY_SHA256`.

For production idempotency across Hostless redeploys, link a managed PostgreSQL database and inject its connection string as `VCW_STATE_DATABASE_URL`. The Runner stores only request-ledger metadata and serialized RPC responses there. If that variable is absent, the Runner falls back to `VCW_STATE_DB` SQLite; the default `/tmp/vcw-runner.sqlite3` is restart-local and must not be used for a frozen production Runner.

## Current status

Hostless -> target VPS TCP/22 reachability has already been proven. This branch upgrades the probe into the formal Runner API implementation.

Before freezing `vcw.runner.v1`, perform real Hostless SSH/SFTP acceptance against the target VPS, including host-key rejection, CAS conflict, timeout/reconnect, job cancel, connection-generation change, transfer integrity and `OUTCOME_UNKNOWN` reconciliation cases.
