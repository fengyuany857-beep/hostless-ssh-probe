# VCW Remote Runner v1 acceptance gate

Do not freeze `vcw.runner.v1` or connect VCW V2 Gateway to this Runner until every required item below passes on the exact real Hostless deployment and target VPS.

The deployed build must be bound by the authenticated `/v1/info.build.fingerprint_sha256` value and, when configured, `build.revision`.

## Identity and transport

- HTTPS endpoint is reachable.
- protected endpoints require the expected bearer token.
- wrong bearer token is rejected.
- wrong `server_id` is `DENIED`.
- unknown RPC envelope fields are denied; caller cannot select host, port, username, SSH key or project root.
- optional `session_id` is syntax-checked correlation only and does not create authorization.
- correct pinned SSH host key connects.
- deliberately wrong SSH host-key fingerprint is rejected before authentication and is never auto-accepted.
- reconnect increments `connection_generation`.

## Path and executable policy

- relative path inside `VCW_PROJECT_ROOT` succeeds.
- `../` traversal is denied.
- absolute path outside the root is denied.
- symlink resolving outside the root is denied.
- overwrite of an existing symlink is denied.
- executable outside `VCW_ALLOWED_EXEC` is denied.
- caller executable path such as `/tmp/fake/git` is denied even when basename is allowlisted.
- executable resolution uses deployment-fixed `VCW_EXEC_PATH`.
- exec/start_job cwd is canonically resolved inside the project root.
- default policy denies caller `sh` / `bash`.

The target SSH account must be manually verified as least-privileged. Runner argv/path policy is not a host filesystem sandbox.

## Request identity and idempotency

- side-effect `request_id` is bound to canonical server_id + method + params fingerprint.
- equivalent JSON key ordering produces the same fingerprint.
- `session_id` changes do not change the action fingerprint.
- reusing one request id for a different method is denied.
- reusing one request id with different params is denied.
- concurrent use of the same side-effect request id produces one owner and no duplicate mutation.
- a terminal cached response is replayed without repeating the action.
- legacy pre-fingerprint records are reconcile-only, never blindly replayed.
- injected terminal ledger commit failure after backend action maps to `OUTCOME_UNKNOWN/LEDGER_COMMIT_FAILED`.

## File/CAS integrity

- `read_file` SHA256 matches an independently computed digest on the VPS.
- `write_file` with correct expected SHA succeeds.
- stale expected SHA returns `FAILED/CAS_MISMATCH` and leaves the file unchanged.
- successful write is read back and digest-verified.
- upload/download `transfer` round-trip has identical SHA256.
- malformed or mixed-case SHA preconditions have deterministic normalization/rejection.
- oversized input is rejected.
- SFTP failure after atomic rename begins maps to `OUTCOME_UNKNOWN`, never a false deterministic failure.
- readback failure or final digest mismatch after rename maps to `OUTCOME_UNKNOWN`.

Current v1 durability claim is atomic replacement plus successful remote readback. Power-loss durability via a proven remote file+directory fsync sequence is not currently claimed and must remain documented as a known limit unless such a mechanism is added and tested.

## Patch

- valid patch passes `git apply --check`, applies and then passes `git apply --reverse --check`.
- invalid patch returns `FAILED/PATCH_CHECK_FAILED` with no mutation.
- patch path escape is denied.
- apply exit 0 with failed reverse-check maps to `OUTCOME_UNKNOWN/PATCH_POSTCONDITION_UNVERIFIED`.
- patch failure after the check is treated conservatively and requires reconciliation.
- staged temporary patch is best-effort cleaned up.

## Exec and jobs

- allowlisted argv command exit 0 maps to `VERIFIED`.
- non-zero exit maps to `FAILED/NONZERO_EXIT`.
- `timeout_s` rejects zero, negative, NaN and infinity and is capped at 300 seconds.
- backend timeout maps to `OUTCOME_UNKNOWN/BACKEND_TIMEOUT` and the connection is reset.
- stdout/stderr are drained while the command runs; output bounds do not deadlock on a full remote channel.
- `start_job` returns deterministic job id.
- repeated start with same request id does not create a second job.
- job identity records PID + boot ID + process start ticks.
- `job_status` observes RUNNING then SUCCEEDED/FAILED/CANCELLED as applicable.
- PID identity mismatch is `OUTCOME_UNKNOWN/JOB_IDENTITY_UNKNOWN`.
- `cancel_job` refuses to signal a PID that cannot be proven to be the original job.
- VERIFIED cancel requires the process group to be observed gone before the cancellation marker is committed.
- missing exit record after process disappearance maps to `OUTCOME_UNKNOWN`.

## Reconciliation

- `reconcile(kind=file)` verifies desired SHA.
- `reconcile(kind=job)` returns observed durable job state without inventing task state.
- `reconcile(kind=request)` does not turn stored `OUTCOME_UNKNOWN` into false `VERIFIED`.
- a RUNNING/incomplete ledger record remains uncertain until method-specific evidence resolves it.

## Durable idempotency ledger

Production Hostless acceptance must use durable PostgreSQL via `VCW_LEDGER_DATABASE_URL`.

SQLite via `VCW_LEDGER_DB` is local/dev fallback only; default `/tmp/vcw-runner-ledger.sqlite3` is restart-local and is not acceptable for a frozen production Runner.

Required real acceptance:

1. authenticated `/v1/info` reports `idempotency_ledger.backend=postgresql` and `durable=true`;
2. create a terminal side-effect request;
3. record build fingerprint and response;
4. redeploy/restart the Hostless Runner;
5. `reconcile(kind=request)` still observes the terminal result;
6. replay of the same request id returns the cached terminal response without repeating the side effect;
7. final target state independently proves no duplicate mutation.

Use `tools/ledger_persistence_acceptance.py prepare` and `verify` for this gate.

## Rate limiting and audit

- forced local saturation returns HTTP 429.
- response includes `Retry-After`.
- status is `RATE_LIMITED`.
- error code is `RUNNER_INFLIGHT_LIMIT`, distinguishable from upstream proxy/tunnel throttling.
- audit contains request id, method, status, duration and connection generation for completed RPCs.
- correlation session id may be present only as validated opaque metadata.
- audit does not contain bearer token, SSH private key/base64 key, request file contents or response file contents.

## Target-account isolation

Verify on the actual VPS:

- dedicated `vcwrunner` account exists;
- no root login is used by Runner;
- account is not in docker/admin-equivalent groups;
- no broad sudo permission;
- authorized key is restricted as intended;
- project root ownership/mode permits only intended effects;
- no unintended secret directories are readable/writable through account privileges;
- Runner policy is not misrepresented as a full filesystem sandbox.

## Contract and release

- `docs/rpc-v1-request.schema.json` matches accepted request envelope and method params.
- `docs/rpc-v1-response.schema.json` matches response envelope.
- method-specific result semantics in `docs/rpc-v1.md` match implementation.
- JSON schemas parse successfully in CI.
- CI unit/integration suite is green against PostgreSQL.
- authenticated live `/v1/info` build fingerprint is captured with real-host acceptance evidence.

## Freeze criteria

Freeze Runner v1 only when:

1. all required real-host cases above pass on the bound build;
2. unresolved P0/P1 findings are zero;
3. RPC request/response contract is recorded and regression-tested;
4. Hostless environment and secret names are final;
5. target SSH account isolation is verified;
6. ledger persistence behavior and durability limits are explicitly documented;
7. full regression is green at the release commit;
8. release commit is tagged before VCW V2 Gateway integration starts.

A frozen Runner remains a deterministic execution boundary. Freeze must not add Gateway authorization, session authority, project locks, task orchestration or model reasoning.
