# VCW Remote Runner RPC v1

The Runner is an execution boundary, not an agent.

It accepts deterministic actions from VCW V2 Gateway and returns deterministic state. It does not diagnose bugs, choose code designs, invent fixes, or change policy.

## Transport

`POST /v1/rpc`

Authentication:

`Authorization: Bearer <RUNNER_TOKEN>`

Envelope:

```json
{
  "server_id": "prod-vps-1",
  "request_id": "gw-01J...",
  "method": "read_file",
  "params": {}
}
```

`server_id` is fixed by deployment configuration. Arbitrary hosts are never accepted in RPC input.

Response:

```json
{
  "rpc_version": "vcw.runner.v1",
  "request_id": "gw-01J...",
  "server_id": "prod-vps-1",
  "connection_generation": 4,
  "status": "VERIFIED",
  "result": {},
  "error": null
}
```

Terminal Runner statuses:

- `VERIFIED`
- `FAILED`
- `OUTCOME_UNKNOWN`
- `DENIED`
- `RATE_LIMITED`

Runner-generated rate limiting uses HTTP 429, `Retry-After`, and `error.code=RUNNER_INFLIGHT_LIMIT` so it can be distinguished from upstream ChatGPT/Tunnel throttling.

## Methods

- `read_file(path, encoding?)`
- `write_file(path, content, encoding?, expected_sha256?)`
- `apply_patch(patch)`
- `exec(argv, cwd?, timeout_s?)`
- `start_job(argv, cwd?)`
- `job_status(job_id, max_log_bytes?)`
- `cancel_job(job_id)`
- `transfer(direction, ...)`
- `reconcile(kind, ...)`

### Writes and CAS

`write_file` and upload transfer stage data through SFTP temporary files, use OpenSSH `posix_rename`, read the result back, and verify SHA256. `expected_sha256` provides compare-and-swap semantics. A mismatch is `FAILED/CAS_MISMATCH`.

### Patch

Patch paths are pre-screened for root escape. The Runner stages the patch under `.vcw-runner/tmp`, runs `git apply --check`, then applies it. It does not invent a repair when a patch fails.

### Exec

Caller input is argv, not a shell string. `argv[0]` must be in `VCW_ALLOWED_EXEC`. The default list excludes `sh` and `bash`.

This is not a filesystem sandbox. The target SSH account must itself be least-privileged and unable to access host secrets outside the intended project.

### Jobs

`start_job` creates metadata under `.vcw-runner/jobs/<job_id>`, starts a detached process group and returns a deterministic job id derived from `request_id`.

`job_status` reports `RUNNING`, `SUCCEEDED`, `FAILED`, or `OUTCOME_UNKNOWN` if a process disappears without an exit record.

### Reconciliation

Supported v1 forms:

- `kind=request` + `target_request_id`
- `kind=file` + `path` + `sha256`
- `kind=job` + `job_id`

Unknown side effects are never blindly retried.

## Policy boundary

Runner enforces:

- fixed `VCW_SERVER_ID`
- fixed `TARGET_HOST` / `TARGET_PORT` / `TARGET_USER`
- pinned SSH host-key SHA256
- one configured project root
- RPC tool allowlist
- executable allowlist
- path root checks plus SFTP canonical-path checks
- symlink overwrite refusal
- CAS and post-write digest verification
- bounded file/output sizes
- bounded Runner concurrency
- backend timeouts and connection generation
- structured audit events without file contents or credentials

VCW V2 Gateway remains responsible for authorization, 25-minute session lease, project binding, queue/lock policy, and whether a deterministic Runner call is permitted.

Execution Director/GPT remains responsible for diagnosis and semantic decisions.
