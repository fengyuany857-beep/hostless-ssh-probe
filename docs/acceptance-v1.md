# VCW Remote Runner v1 acceptance gate

Do not freeze `vcw.runner.v1` or connect VCW V2 Gateway to this Runner until every required item below passes on the real Hostless deployment and target VPS.

## Identity and transport

- HTTPS endpoint is reachable only with the expected bearer token.
- Wrong bearer token is rejected.
- Wrong `server_id` is `DENIED`.
- RPC input cannot select an arbitrary host, port or username.
- Correct pinned SSH host key connects.
- Deliberately wrong SSH host-key fingerprint is rejected before authentication.
- Reconnect increments `connection_generation`.

## Path and policy

- relative path inside `VCW_PROJECT_ROOT` succeeds.
- `../` traversal is denied.
- absolute path outside the root is denied.
- symlink resolving outside the root is denied.
- overwrite of an existing symlink is denied.
- executable outside `VCW_ALLOWED_EXEC` is denied.
- default policy denies `sh` / `bash` caller execution.

The target SSH account must also be manually verified as least-privileged. Runner argv policy alone is not a host filesystem sandbox.

## File/CAS integrity

- `read_file` SHA256 matches an independently computed digest on the VPS.
- `write_file` with the correct expected SHA succeeds.
- `write_file` with a stale expected SHA returns `FAILED/CAS_MISMATCH` and leaves the file unchanged.
- successful write is read back and digest-verified.
- upload/download `transfer` round-trip has identical SHA256.
- oversized input is rejected.

## Patch

- valid patch passes `git apply --check` and applies.
- invalid patch returns `FAILED/PATCH_CHECK_FAILED` with no mutation.
- patch path escape is denied.
- patch failure after the check is treated conservatively and requires reconciliation.

## Exec and jobs

- allowlisted argv command exit 0 maps to `VERIFIED`.
- non-zero exit maps to `FAILED/NONZERO_EXIT`.
- backend timeout maps to `OUTCOME_UNKNOWN` and the connection is reset.
- `start_job` returns a deterministic job id.
- repeated start with the same request id does not create a second job.
- `job_status` observes RUNNING then SUCCEEDED/FAILED.
- `cancel_job` terminates the process group.
- missing exit record after process disappearance maps to `OUTCOME_UNKNOWN`.

## Idempotency and reconciliation

- concurrent use of the same side-effect `request_id` produces one owner and no duplicate mutation.
- reusing one request id for a different method is denied.
- a terminal cached response is replayed without repeating the action.
- `reconcile(kind=file)` verifies desired SHA.
- `reconcile(kind=job)` returns observed durable job state.
- `reconcile(kind=request)` does not turn a stored `OUTCOME_UNKNOWN` into a false `VERIFIED`.

Production Hostless acceptance must use a durable PostgreSQL request ledger via `VCW_STATE_DATABASE_URL`. SQLite via `VCW_STATE_DB` is retained only for local/dev use; the default `/tmp/vcw-runner.sqlite3` is restart-local and is not acceptable for a frozen production Runner. After switching to PostgreSQL, create a terminal side-effect request, redeploy the Hostless app, and verify that `reconcile(kind=request)` still observes the stored terminal response without repeating the action.

## Rate limiting and audit

- forced local saturation returns HTTP 429.
- response includes `Retry-After`.
- response code is `RUNNER_INFLIGHT_LIMIT`, distinguishable from upstream ChatGPT/Tunnel throttling.
- audit contains request id, method, status, duration and connection generation.
- audit does not contain bearer token, SSH private key or file contents.

## Freeze criteria

Freeze Runner v1 only when:

1. all required real-host cases above pass;
2. unresolved P0/P1 findings are zero;
3. exact RPC request/response schemas are recorded;
4. Hostless environment and secret names are final;
5. target SSH account isolation is verified;
6. state persistence behavior is explicitly documented;
7. the release commit is tagged before VCW V2 Gateway integration starts.
