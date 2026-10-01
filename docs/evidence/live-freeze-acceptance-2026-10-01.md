# VCW Remote Runner live freeze acceptance evidence

Evidence date: 2026-10-01
Runner endpoint: `https://sb2.hostless.app`
Server identity: `test-vps-1`
Acceptance run id: `1790851200`
Verification tier: real Hostless -> real SSH/SFTP target VPS
Source branch at evidence consolidation: `vcw-remote-runner-v1`

## Build binding

Authenticated live `/v1/info` reported:

```text
build.fingerprint_sha256 = 5d51352d8b5897992e915cd6367d5853e57bd9ea4ba66dd97a71e8d0536dee25
build.revision = null
```

GitHub Actions independently computed the exact same build fingerprint from the packaged runtime inputs:

- `app.py`
- `vcw_runner.py`
- `channel_exec.py`
- `requirements.txt`

CI run for commit `cc69504cf078c85228a68824fae59fd6049595af` printed the same SHA256 fingerprint. The workflow-only commit does not affect the runtime fingerprint inputs.

Result: PASS for runtime-source build-content binding.

## Automated live harness summary

```text
passed = 21
total  = 22
failed = durable_postgres_ledger
```

PASS cases:

- authenticated backend/info
- runtime build fingerprint presence
- wrong bearer rejection
- audit canary write
- unknown RPC envelope rejection
- caller denial for `.git/config`
- caller denial for `.vcw-runner/jobs/*`
- executable path injection denial
- atomic write preserves mode
- stale CAS leaves file unchanged
- symlink overwrite denial
- idempotent terminal replay uses current session correlation
- request-id fingerprint mismatch denial
- transfer upload/download round-trip integrity
- patch reverse-check post-condition
- exec timeout -> `OUTCOME_UNKNOWN/BACKEND_TIMEOUT`
- request reconciliation preserves unknown outcome
- connection generation advances by exactly one successful connection epoch
- job start/status/cancel terminal consistency
- already terminal job cancellation refusal
- local saturation -> HTTP 429 + Retry-After + `RUNNER_INFLIGHT_LIMIT`

## Durable ledger result

Live `/v1/info` reported:

```json
{"backend":"sqlite","durable":false}
```

Result: FAIL for production freeze.

This is the only failure in the one-shot live harness. The current Hostless deployment still uses restart-local SQLite idempotency state and therefore cannot satisfy cross-redeploy request replay/reconciliation.

## Audit redaction canary

The harness wrote a unique file-body canary:

```text
VCW_AUDIT_CANARY_8482aa849e87bdf0fdfd
```

The canary write itself was VERIFIED.

The Hostless runtime-log scan has not yet been performed. Any occurrence of this canary in Hostless logs is a redaction failure.

## External gates still open

The live harness intentionally did not claim to test:

1. deliberately wrong SSH host-key pin on a real Hostless deployment;
2. Hostless runtime-log canary/redaction scan;
3. PostgreSQL idempotency persistence across a Hostless redeploy.

The PostgreSQL persistence gate must run:

```text
tools/ledger_persistence_acceptance.py prepare
<Hostless redeploy of the same build>
tools/ledger_persistence_acceptance.py verify
```

The helper binds prepare/verify to the same runtime build fingerprint unless explicitly placed in migration-only mode.

## Overall evidence state

The current real-host execution surface is strong enough for continued acceptance work, but Runner v1 is not frozen.

Current terminal state for this evidence set: PARTIAL.

Primary blocker: durable Hostless PostgreSQL ledger not active.
Secondary external gates: host-key negative injection and runtime-log canary scan.
