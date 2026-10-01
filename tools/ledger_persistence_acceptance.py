#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

RUNNER_URL = os.environ.get("RUNNER_URL", "https://sb2.hostless.app").rstrip("/")
SERVER_ID = os.environ.get("VCW_SERVER_ID", "test-vps-1")
HEADER_FILE = os.environ.get("VCW_RUNNER_HEADER_FILE", "/run/vcw-runner.header")
PROJECT_ROOT = Path(os.environ.get("VCW_PROJECT_ROOT", "/srv/vcw-runner-test"))
STATE_FILE = Path(os.environ.get("VCW_LEDGER_ACCEPTANCE_STATE", "/tmp/vcw-ledger-acceptance.json"))


def curl_json(path: str, body: dict | None = None) -> dict:
    cmd = ["curl", "-sS", "--max-time", "30", "-H", "@" + HEADER_FILE]
    payload = None
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
        payload = json.dumps(body, separators=(",", ":"))
    cmd.append(RUNNER_URL + path)
    proc = subprocess.run(cmd, input=payload, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"curl failed rc={proc.returncode}: {proc.stderr[-500:]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"non-JSON response: {proc.stdout[:500]!r}") from exc


def rpc(method: str, params: dict, request_id: str) -> dict:
    return curl_json("/v1/rpc", {
        "server_id": SERVER_ID,
        "request_id": request_id,
        "method": method,
        "params": params,
    })


def require_durable_postgres() -> dict:
    info = curl_json("/v1/info")
    ledger = info.get("idempotency_ledger") or {}
    if ledger.get("backend") != "postgresql" or ledger.get("durable") is not True:
        raise RuntimeError(f"durable PostgreSQL ledger is not active: {ledger!r}")
    return info


def build_identity(info: dict) -> dict:
    build = info.get("build") or {}
    fingerprint = build.get("fingerprint_sha256")
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise RuntimeError(f"Runner build fingerprint is missing or invalid: {build!r}")
    return {"fingerprint_sha256": fingerprint, "revision": build.get("revision")}


def prepare() -> None:
    info = require_durable_postgres()
    build = build_identity(info)

    run = str(int(time.time()))
    rel = f"ledger-persistence-{run}.txt"
    path = PROJECT_ROOT / rel
    baseline = f"BASE-{run}\n"
    final = f"FINAL-{run}\n"
    baseline_sha = hashlib.sha256(baseline.encode()).hexdigest()
    final_sha = hashlib.sha256(final.encode()).hexdigest()

    setup_rid = f"ledger-{run}-setup"
    setup = rpc("write_file", {"path": rel, "content": baseline}, setup_rid)
    if setup.get("status") != "VERIFIED":
        raise RuntimeError(f"baseline write failed: {setup}")

    side_effect_rid = f"ledger-{run}-side-effect"
    side_effect_body = {
        "server_id": SERVER_ID,
        "request_id": side_effect_rid,
        "method": "write_file",
        "params": {
            "path": rel,
            "content": final,
            "expected_sha256": baseline_sha,
        },
    }
    original = curl_json("/v1/rpc", side_effect_body)
    result = original.get("result") or {}
    if original.get("status") != "VERIFIED" or result.get("sha256") != final_sha:
        raise RuntimeError(f"side-effect write failed: {original}")
    if path.read_bytes() != final.encode():
        raise RuntimeError("local target file does not contain the expected final bytes")

    state = {
        "run": run,
        "path": rel,
        "final": final,
        "final_sha256": final_sha,
        "side_effect_request_id": side_effect_rid,
        "side_effect_body": side_effect_body,
        "original_response": original,
        "build": build,
        "ledger": info.get("idempotency_ledger"),
    }
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))

    print("PASS durable_postgres_active")
    print("PASS build_identity_captured")
    print("PASS side_effect_verified")
    print(f"REQUEST_ID={side_effect_rid}")
    print(f"STATE_FILE={STATE_FILE}")
    print("NEXT=redeploy Hostless app, then run this tool with 'verify'")


def verify() -> None:
    info = require_durable_postgres()
    current_build = build_identity(info)
    if not STATE_FILE.exists():
        raise RuntimeError(f"acceptance state file not found: {STATE_FILE}")
    state = json.loads(STATE_FILE.read_text())
    prepared_build = state.get("build") or {}
    allow_build_change = os.environ.get("VCW_LEDGER_ACCEPTANCE_ALLOW_BUILD_CHANGE", "").strip() == "1"
    if current_build != prepared_build and not allow_build_change:
        raise RuntimeError(
            "Runner build changed between prepare and verify; "
            f"prepared={prepared_build} current={current_build}. "
            "Repeat prepare/verify on one release build or explicitly set "
            "VCW_LEDGER_ACCEPTANCE_ALLOW_BUILD_CHANGE=1 for a migration-only test."
        )

    target_rid = state["side_effect_request_id"]
    reconcile = rpc(
        "reconcile",
        {"kind": "request", "target_request_id": target_rid},
        f"ledger-{state['run']}-reconcile-after-redeploy",
    )
    observed = (reconcile.get("result") or {}).get("observed_status")
    if reconcile.get("status") != "VERIFIED" or observed != "VERIFIED":
        raise RuntimeError(f"request ledger did not survive redeploy: {reconcile}")

    replay = curl_json("/v1/rpc", state["side_effect_body"])
    if replay != state["original_response"]:
        raise RuntimeError(
            "same request_id did not replay the exact cached terminal response; "
            f"original={state['original_response']} replay={replay}"
        )

    readback = rpc(
        "read_file",
        {"path": state["path"]},
        f"ledger-{state['run']}-readback-after-redeploy",
    )
    rr = readback.get("result") or {}
    if (
        readback.get("status") != "VERIFIED"
        or rr.get("sha256") != state["final_sha256"]
        or rr.get("content") != state["final"]
    ):
        raise RuntimeError(f"final file proof failed: {readback}")

    print("PASS durable_postgres_active")
    print("PASS build_identity_bound")
    print("PASS reconcile_survived_redeploy")
    print("PASS cached_terminal_response_replayed")
    print("PASS side_effect_not_reexecuted")
    print("PASS final_file_proof")
    print("LEDGER_PERSISTENCE_ACCEPTANCE=PASS")

    try:
        (PROJECT_ROOT / state["path"]).unlink(missing_ok=True)
        STATE_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["prepare", "verify"])
    args = parser.parse_args()
    if args.phase == "prepare":
        prepare()
    else:
        verify()


if __name__ == "__main__":
    main()
