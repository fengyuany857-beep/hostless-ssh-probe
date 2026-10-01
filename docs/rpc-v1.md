# VCW Remote Runner RPC v1

The Runner is a deterministic execution boundary, not an agent, Gateway, Execution Director, task planner, project selector, or authorization authority.

Machine-readable schemas:

- `docs/rpc-v1-request.schema.json`
- `docs/rpc-v1-response.schema.json`

## Transport and authentication

`POST /v1/rpc`

Authentication:

`Authorization: Bearer <RUNNER_TOKEN>`

The Runner-to-Gateway credential is distinct from the Runner-to-VPS SSH credential.

## Request envelope

```json
{
  "server_id": "prod-vps-1",
  "request_id": "gw-01J...",
  "session_id": "ses_xxx",
  "method": "write_file",
  "params": {
    "path": "src/a.py",
    "content": "...",
    "expected_sha256": "..."
  }
}
```

Required envelope fields are `server_id`, `request_id`, `method`, and `params`. `session_id` is optional.

Unknown envelope fields are denied. In particular, RPC input cannot select or override `host`, `ip`, `port`, `username`, `ssh_private_key`, or project root.

`session_id` is opaque correlation metadata only. Runner validates its syntax and may echo/audit it, but does not authorize it, enforce Gateway lease/TTL, acquire project locks, or infer permission from it.

## Request identity and idempotency

For side-effect methods, `request_id` is bound to a canonical request fingerprint over:

- fixed `server_id`
- method
- method params

`session_id` is deliberately excluded from the action fingerprint so the same uncertain action can be reconciled/replayed across a Gateway session renewal without changing its semantic identity.

Reusing a `request_id` with another method or different params is `DENIED`. A terminal cached response is replayed without repeating the side effect. Any existing claim without a terminal response remains `OUTCOME_UNKNOWN` and is never re-executed. Legacy ledger rows that predate fingerprints are reconcile-only and cannot be blindly replayed.

Before execution, the ledger stores only a minimal reconciliation hint when one can be derived without retaining payload content: desired file SHA/path for writes/uploads, deterministic job id for start/cancel, or patch digest/touched paths. It does not store task DAGs, approval state, GPT reasoning, or file bodies.

Side-effect methods are:

- `write_file`
- `apply_patch`
- `exec`
- `start_job`
- `cancel_job`
- upload `transfer`

Download `transfer` is read-only and does not claim the side-effect ledger. Upload `transfer` does.

## Response envelope

```json
{
  "rpc_version": "vcw.runner.v1",
  "request_id": "gw-01J...",
  "session_id": "ses_xxx",
  "server_id": "prod-vps-1",
  "connection_generation": 4,
  "status": "VERIFIED",
  "result": {},
  "error": null
}
```

`session_id` is present only when supplied and validated. It is attached at response time and is not persisted as part of the cached action result.

Runner statuses:

- `VERIFIED`: the method-specific post-condition was observed.
- `FAILED`: the Runner has evidence that the requested action did not reach the required success condition.
- `OUTCOME_UNKNOWN`: a consequential outcome cannot be safely classified and must be reconciled before retry.
- `DENIED`: request violates Runner policy or contract.
- `RATE_LIMITED`: local Runner concurrency limit rejected the request before execution.

Runner-generated saturation uses HTTP 429, `Retry-After`, and `error.code=RUNNER_INFLIGHT_LIMIT`.

## Methods

### read_file

Request params:

```json
{"path":"src/a.py","encoding":"utf-8"}
```

`encoding` is optional: `utf-8` or `base64`.

VERIFIED result:

```json
{
  "path": "/fixed/project/src/a.py",
  "encoding": "utf-8",
  "content": "...",
  "sha256": "64-hex",
  "bytes": 123
}
```

### write_file

Request params:

```json
{
  "path": "src/a.py",
  "content": "...",
  "encoding": "utf-8",
  "expected_sha256": "64-hex"
}
```

`expected_sha256` is optional. When supplied it is a compare-and-swap precondition.

Success path:

1. caller path check, including refusal of Runner/Git control metadata;
2. canonical parent confinement;
3. existing leaf symlink and non-regular-file refusal;
4. bounded current-file read, SHA256 and existing mode capture;
5. CAS comparison;
6. SFTP temporary write and close/flush;
7. existing mode preservation, or `0644` for a new file;
8. atomic OpenSSH `posix_rename`;
9. target readback;
10. final SHA256 and mode verification.

VERIFIED result includes:

```json
{
  "path": "/fixed/project/src/a.py",
  "ok": true,
  "sha256": "new-64-hex",
  "previous_sha256": "old-64-hex-or-null",
  "bytes": 123,
  "mode": "0755"
}
```

A stale precondition is `FAILED/CAS_MISMATCH` and does not rename the target.

If rename has begun but the rename/readback/final-digest outcome cannot be proven, the request is `OUTCOME_UNKNOWN/BACKEND_OUTCOME_UNKNOWN`; reconcile the target file before retrying.

Current v1 durability claim is atomic replacement plus successful remote readback. Existing file mode is preserved; new files are created as `0644`. It does not claim power-loss durability equivalent to a proven remote file+directory fsync sequence.

The CAS check and replace are serialized inside one Runner process. Gateway project locking and the dedicated target-account boundary remain required to prevent uncoordinated writers outside that execution path; v1 does not claim a filesystem-wide transactional CAS against hostile external writers.

### apply_patch

Request params:

```json
{"patch":"unified diff text"}
```

Runner:

1. pre-screens every diff path for project-root escape;
2. stages the patch under Runner internal project metadata;
3. runs `git apply --check`;
4. runs `git apply --whitespace=nowarn`;
5. verifies the applied post-condition with `git apply --reverse --check`;
6. best-effort removes the temporary patch.

A pre-check failure is `FAILED/PATCH_CHECK_FAILED`. A successful apply whose post-condition cannot be verified is `OUTCOME_UNKNOWN/PATCH_POSTCONDITION_UNVERIFIED`.

VERIFIED result:

```json
{
  "touched": ["src/a.py"],
  "patch_sha256": "64-hex",
  "postcondition": "reverse_apply_check"
}
```

Runner never invents a repair when a patch fails.

### exec

Request params:

```json
{
  "argv": ["pytest", "-q"],
  "cwd": ".",
  "timeout_s": 30
}
```

Caller input is argv, never an arbitrary shell command string. `argv[0]` must be a bare executable name and must be in `VCW_ALLOWED_EXEC`; an absolute/relative executable path such as `/tmp/fake/git` is denied even if its basename is allowlisted.

Executable resolution uses deployment-fixed `VCW_EXEC_PATH`. `cwd` is resolved canonically and must remain inside the configured project root. `timeout_s` must be finite and positive and is capped at 300 seconds.

Result:

```json
{
  "argv": ["pytest", "-q"],
  "cwd": "/fixed/project",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "..."
}
```

Exit code 0 maps to `VERIFIED`. A non-zero exit maps to `FAILED/NONZERO_EXIT`. A backend deadline maps to `OUTCOME_UNKNOWN/BACKEND_TIMEOUT` and resets the SSH connection.

Runner never infers test success from stdout text.

The executable allowlist is not a host filesystem sandbox. Target-account OS permissions remain part of the security boundary.

### start_job

Request params:

```json
{"argv":["python3","worker.py"],"cwd":"."}
```

The deterministic `job_id` derives from `request_id`. Runner records:

- PID
- Linux process start ticks from `/proc/<pid>/stat`
- boot ID
- exit record
- log
- cancellation marker

PID alone is never treated as sufficient process identity.

A VERIFIED start result includes:

```json
{
  "job_id": "job_...",
  "pid": 1234,
  "state": "RUNNING",
  "argv": ["python3","worker.py"],
  "cwd": "/fixed/project"
}
```

A very short job may already be observed in another terminal job state.

### job_status

Request params:

```json
{"job_id":"job_...","max_log_bytes":32768}
```

Method result state is one of:

- `RUNNING`
- `SUCCEEDED`
- `FAILED`
- `CANCELLED`
- `UNKNOWN`

If PID/boot/start identity cannot be safely tied to the original job, Runner returns `OUTCOME_UNKNOWN/JOB_IDENTITY_UNKNOWN`. If a process disappeared without a terminal record it returns `OUTCOME_UNKNOWN/JOB_STATE_UNKNOWN`.

### cancel_job

Request params:

```json
{"job_id":"job_..."}
```

Runner verifies PID + boot ID + process start ticks before signaling the process group. It refuses to kill a process whose identity no longer matches the recorded job.

Before signaling, Runner first observes current job state. An already SUCCEEDED/FAILED job returns `FAILED/JOB_ALREADY_TERMINAL`; an already CANCELLED job returns VERIFIED without signaling again; an uncertain identity/state returns `OUTCOME_UNKNOWN` and no signal is sent.

A VERIFIED cancellation means the recorded process identity matched, the process group was no longer observed after TERM/KILL, and the cancellation marker was written. The cancellation marker is authoritative over a racing exit record.

### transfer

Upload:

```json
{
  "direction":"upload",
  "path":"artifact.bin",
  "encoding":"base64",
  "content":"...",
  "content_sha256":"64-hex",
  "expected_sha256":"64-hex"
}
```

`content_sha256` and `expected_sha256` are optional. Upload uses the same CAS, atomic rename, readback and uncertainty semantics as `write_file`.

Download:

```json
{"direction":"download","path":"artifact.bin"}
```

VERIFIED download returns base64 content, SHA256 and byte count.

### reconcile

Request form for an idempotency record:

```json
{"kind":"request","target_request_id":"gw-01J..."}
```

A stored terminal non-unknown result is reported as observed. A stored `OUTCOME_UNKNOWN` remains `OUTCOME_UNKNOWN`; reconciliation never upgrades it merely because a ledger row exists. Incomplete/unknown records expose only their minimal `reconcile_hint` so the caller can issue an explicit file/job reconciliation instead of replaying the side effect.

File post-condition:

```json
{"kind":"file","path":"src/a.py","sha256":"64-hex"}
```

Job observation:

```json
{"kind":"job","job_id":"job_...","max_log_bytes":32768}
```

Unknown side effects are never blindly retried.

## Ledger failure semantics

The idempotency ledger is intentionally not the VCW task/session state machine.

If an action returns from the backend but the terminal ledger commit fails, Runner returns:

- `status=OUTCOME_UNKNOWN`
- `error.code=LEDGER_COMMIT_FAILED`
- the backend-observed action status/result as evidence

The caller must reconcile before any retry.

Production Hostless deployments use `VCW_LEDGER_DATABASE_URL` for durable PostgreSQL idempotency state. SQLite via `VCW_LEDGER_DB` is local/dev fallback only.

## Fixed execution identity

Deployment fixes:

- `VCW_SERVER_ID`
- `TARGET_HOST`
- `TARGET_PORT`
- `TARGET_USER`
- SSH private credential
- pinned SSH host-key SHA256
- `VCW_PROJECT_ROOT`
- `VCW_ALLOWED_TOOLS`
- `VCW_ALLOWED_EXEC`
- `VCW_EXEC_PATH`

Caller-facing file paths cannot address `.vcw-runner` or `.git` control metadata. `TARGET_USER=root` and filesystem-root `VCW_PROJECT_ROOT=/` are rejected at startup.

Caller input cannot alter these connection facts.

`GET /v1/info` exposes a runtime build SHA256 fingerprint over the packaged Runner source/requirements and may expose `VCW_RUNNER_BUILD_REVISION` when the deployment supplies it. This is provenance only, not authorization.

## Authority boundary

VCW V2 Gateway owns authorization, approval, session validity/TTL, project binding, queue/lock policy and Runner routing.

Execution Director/GPT owns task decomposition, diagnosis, semantic decisions, retry/backoff policy and next-step choice.

Runner owns deterministic action validation, execution evidence, post-condition verification, idempotency and reconciliation only.

`connection_generation` is a successful SSH connection epoch: it increments once when a new SSH connection is successfully established, not merely when a stale connection is reset.
