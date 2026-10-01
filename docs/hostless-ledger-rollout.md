# Hostless durable ledger rollout

Scope: VCW Remote Runner only.

Goal: replace restart-local SQLite idempotency state with Hostless managed PostgreSQL through `VCW_LEDGER_DATABASE_URL`.

This is not a VCW task/session database. The database stores only Runner request-idempotency records and minimal reconciliation hints.

## Preconditions

- branch: `vcw-remote-runner-v1`
- current Runner source CI is green
- target-account SSH hardening is already verified
- the Hostless app is `sb2`
- do not expose the database connection string in chat, logs, Git, or acceptance reports

## Database configuration

Recommended Hostless resource:

```text
Name: vcw-runner-ledger
Type: PostgreSQL
Version: 16 or latest stable
CPU: default
Memory: default
Storage: 256 MB
Linked app: sb2
Environment variable name: VCW_LEDGER_DATABASE_URL
```

The database is intentionally small. The Runner ledger contains request metadata and serialized terminal RPC responses, not project files or task history.

## Deployment behavior

Linking the database to `sb2` injects the PostgreSQL connection string as `VCW_LEDGER_DATABASE_URL` and causes an app redeploy.

The Runner:

1. recognizes `postgresql://` / `postgres://`;
2. opens Psycopg with prepared statements disabled for pooling compatibility;
3. uses explicit PostgreSQL transactions;
4. applies `SET LOCAL lock_timeout='5s'` and `statement_timeout='10s'` inside each ledger transaction;
5. creates/updates only table `vcw_runner_idempotency_v1`;
6. reports `idempotency_ledger.backend=postgresql` and `durable=true` from authenticated `/v1/info`.

No Gateway or Director state belongs in this table.

## Immediate post-deploy gate

After Hostless reports the database RUNNING and the app deployment healthy:

```bash
python3 /tmp/vcw_ledger_persistence_acceptance.py prepare
```

Expected first-phase output includes:

```text
PASS durable_postgres_active
PASS build_identity_captured
PASS side_effect_verified
```

The tool records the exact authenticated Runner build fingerprint and one CAS-protected side effect.

If this phase fails, do not retry the side effect with a new request id. Inspect the reported failure first.

## Redeploy persistence gate

Redeploy the same Runner build without changing source/runtime inputs, then run:

```bash
python3 /tmp/vcw_ledger_persistence_acceptance.py verify
```

Required result:

```text
PASS durable_postgres_active
PASS build_identity_bound
PASS reconcile_survived_redeploy
PASS cached_terminal_response_replayed
PASS side_effect_not_reexecuted
PASS final_file_proof
LEDGER_PERSISTENCE_ACCEPTANCE=PASS
```

The helper refuses a build change between prepare and verify unless explicitly placed in migration-only mode.

## Rollback

If PostgreSQL integration prevents the new deployment from becoming healthy:

1. remove/unlink `VCW_LEDGER_DATABASE_URL` from `sb2`;
2. redeploy the previous known-good Runner configuration;
3. confirm public `/health`;
4. authenticated `/v1/info` should report SQLite / non-durable again;
5. do not call that fallback state frozen or production-ready.

Do not delete the PostgreSQL database until any acceptance evidence you need has been captured. Database deletion is not required to roll the app back.

## Security notes

- Treat the connection string as a secret.
- Do not write it into GitHub Actions, files under the project root, screenshots, chat, or Runner audit logs.
- Hostless PostgreSQL uses TLS and PgBouncer on the managed connection path.
- Runner request/reconcile APIs never expose the database URL.
- `/v1/info` exposes only backend type and durability, never database credentials.

## Remaining freeze gates after persistence PASS

1. wrong SSH host-key deployment injection and recovery;
2. Hostless runtime-log scan for the live audit canary;
3. final live acceptance on the release-bound build;
4. zero open P0/P1;
5. release tag `vcw.runner.v1`.
