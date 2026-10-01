#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

RUNNER_URL = os.environ.get("RUNNER_URL", "https://sb2.hostless.app").rstrip("/")
SERVER_ID = os.environ.get("VCW_SERVER_ID", "test-vps-1")
HEADER_FILE = os.environ.get("VCW_RUNNER_HEADER_FILE", "/run/vcw-runner.header")
PROJECT_ROOT = Path(os.environ.get("VCW_PROJECT_ROOT", "/srv/vcw-runner-test"))
REPORT = Path(os.environ.get("VCW_LIVE_ACCEPTANCE_REPORT", "/tmp/vcw-live-acceptance-report.json"))
RUN = str(int(time.time()))
RESULTS = []
ARTIFACTS: list[Path] = []


def curl_call(path: str, body: dict | None = None, auth: str = "good", timeout: int = 30) -> dict:
    with tempfile.NamedTemporaryFile(prefix="vcw-headers-", delete=False) as tmp:
        header_path = tmp.name
    try:
        cmd = ["curl", "-sS", "--max-time", str(timeout), "-D", header_path]
        if auth == "good":
            cmd += ["-H", "@" + HEADER_FILE]
        elif auth == "bad":
            cmd += ["-H", "Authorization: Bearer definitely-wrong"]
        payload = None
        if body is not None:
            cmd += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
            payload = json.dumps(body, separators=(",", ":"))
        cmd += ["-w", "\n__VCW_HTTP__:%{http_code}", RUNNER_URL + path]
        proc = subprocess.run(cmd, input=payload, text=True, capture_output=True)
        raw, marker, code_raw = proc.stdout.rpartition("\n__VCW_HTTP__:")
        code = int(code_raw) if marker and code_raw.isdigit() else 0
        headers = {}
        try:
            for line in Path(header_path).read_text(errors="replace").splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
        except Exception:
            pass
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"_raw": raw}
        return {
            "curl_rc": proc.returncode,
            "http": code,
            "headers": headers,
            "json": parsed,
            "stderr": proc.stderr[-500:],
        }
    finally:
        try:
            Path(header_path).unlink()
        except Exception:
            pass


def rpc(method: str, params: dict, tag: str, *, request_id: str | None = None, session_id: str | None = None, timeout: int = 30) -> dict:
    body = {
        "server_id": SERVER_ID,
        "request_id": request_id or f"live-{RUN}-{tag}",
        "method": method,
        "params": params,
    }
    if session_id is not None:
        body["session_id"] = session_id
    return curl_call("/v1/rpc", body, timeout=timeout)


def payload(call: dict) -> dict:
    value = call.get("json")
    return value if isinstance(value, dict) else {}


def is_status(call: dict, status: str, code: str | None = None) -> bool:
    p = payload(call)
    ok = p.get("status") == status
    if code is not None:
        ok = ok and (p.get("error") or {}).get("code") == code
    return ok


def record(name: str, ok: bool, evidence=None, note: str | None = None):
    row = {"name": name, "pass": bool(ok)}
    if note is not None:
        row["note"] = note
    if evidence is not None:
        row["evidence"] = evidence
    RESULTS.append(row)
    print(("PASS " if ok else "FAIL ") + name, flush=True)


def local_bytes(rel: str) -> bytes | None:
    try:
        return (PROJECT_ROOT / rel).read_bytes()
    except Exception:
        return None


def local_mode(rel: str) -> int | None:
    try:
        return stat.S_IMODE((PROJECT_ROOT / rel).lstat().st_mode)
    except Exception:
        return None


def cleanup():
    for path in ARTIFACTS:
        try:
            if path.is_symlink() or path.is_file():
                path.unlink(missing_ok=True)
        except Exception:
            pass


def main():
    if not Path(HEADER_FILE).exists():
        raise SystemExit(f"missing auth header file: {HEADER_FILE}")
    if not PROJECT_ROOT.is_dir():
        raise SystemExit(f"missing project root: {PROJECT_ROOT}")

    # Identity / durable ledger / provenance.
    info = curl_call("/v1/info")
    ip = payload(info)
    build = ip.get("build") or {}
    ledger = ip.get("idempotency_ledger") or {}
    record(
        "info_backend",
        info["http"] == 200 and ip.get("ok") is True and (ip.get("backend") or {}).get("ok") is True,
        info,
    )
    record(
        "build_fingerprint",
        isinstance(build.get("fingerprint_sha256"), str) and len(build.get("fingerprint_sha256")) == 64,
        build,
    )
    record(
        "durable_postgres_ledger",
        ledger.get("backend") == "postgresql" and ledger.get("durable") is True,
        ledger,
        note="required for freeze; configure VCW_LEDGER_DATABASE_URL if this fails",
    )
    generation0 = ip.get("connection_generation")

    wrong = curl_call("/v1/info", auth="bad")
    record("wrong_bearer_rejected", wrong["http"] == 401, {"http": wrong["http"]})

    # Unique body canary for later Hostless log redaction scan.
    audit_canary = "VCW_AUDIT_CANARY_" + hashlib.sha256((RUN + build.get("fingerprint_sha256", "")).encode()).hexdigest()[:20]
    audit_rel = f"live-audit-canary-{RUN}.txt"
    audit_path = PROJECT_ROOT / audit_rel
    ARTIFACTS.append(audit_path)
    audit_write = rpc("write_file", {"path": audit_rel, "content": audit_canary + "\n"}, "audit-canary")
    record(
        "audit_canary_write",
        is_status(audit_write, "VERIFIED") and local_bytes(audit_rel) == (audit_canary + "\n").encode(),
        {"status": payload(audit_write).get("status"), "path": audit_rel},
        note="later search Hostless logs for audit_canary; any hit is a redaction failure",
    )

    injected = curl_call("/v1/rpc", {
        "server_id": SERVER_ID,
        "request_id": f"live-{RUN}-envelope",
        "method": "read_file",
        "params": {"path": "sample.txt"},
        "host": "127.0.0.1",
    })
    record("unknown_envelope_denied", is_status(injected, "DENIED", "POLICY_DENIED"), injected)

    for rel in (".git/config", ".vcw-runner/jobs/anything"):
        x = rpc("read_file", {"path": rel}, "control-" + hashlib.sha256(rel.encode()).hexdigest()[:6])
        record("control_path_denied:" + rel, is_status(x, "DENIED", "POLICY_DENIED"), x)

    x = rpc("exec", {"argv": ["/usr/bin/git", "status", "--short"]}, "exec-path")
    record("executable_path_denied", is_status(x, "DENIED", "POLICY_DENIED"), x)

    # File mode + CAS.
    mode_rel = f"live-mode-{RUN}.sh"
    mode_path = PROJECT_ROOT / mode_rel
    ARTIFACTS.append(mode_path)
    mode_path.write_text("#!/bin/sh\necho OLD\n")
    os.chmod(mode_path, 0o755)
    before = mode_path.read_bytes()
    before_sha = hashlib.sha256(before).hexdigest()
    new_content = "#!/bin/sh\necho NEW\n"
    new_sha = hashlib.sha256(new_content.encode()).hexdigest()

    x = rpc("write_file", {
        "path": mode_rel,
        "content": new_content,
        "expected_sha256": before_sha,
    }, "mode-write")
    xr = payload(x).get("result") or {}
    record(
        "write_preserves_mode",
        is_status(x, "VERIFIED")
        and xr.get("sha256") == new_sha
        and xr.get("mode") == "0755"
        and local_mode(mode_rel) == 0o755
        and local_bytes(mode_rel) == new_content.encode(),
        x,
    )

    stale = rpc("write_file", {
        "path": mode_rel,
        "content": "STALE MUST NOT WIN\n",
        "expected_sha256": before_sha,
    }, "mode-stale")
    record(
        "cas_stale_preserves_file",
        is_status(stale, "FAILED", "CAS_MISMATCH") and local_bytes(mode_rel) == new_content.encode(),
        stale,
    )

    # Symlink overwrite refusal.
    symlink_target_rel = f"live-symlink-target-{RUN}.txt"
    symlink_rel = f"live-symlink-{RUN}.txt"
    symlink_target = PROJECT_ROOT / symlink_target_rel
    symlink = PROJECT_ROOT / symlink_rel
    ARTIFACTS.extend([symlink, symlink_target])
    symlink_target.write_text("ORIGINAL\n")
    symlink.symlink_to(symlink_target.name)
    x = rpc("write_file", {"path": symlink_rel, "content": "MUTATED\n"}, "symlink-write")
    record(
        "symlink_overwrite_denied",
        is_status(x, "DENIED", "POLICY_DENIED") and symlink_target.read_text() == "ORIGINAL\n",
        x,
    )

    # Request fingerprint mismatch and session-correlation replay.
    idem_rel = f"live-idem-{RUN}.txt"
    idem_path = PROJECT_ROOT / idem_rel
    ARTIFACTS.append(idem_path)
    idem_rid = f"live-{RUN}-idem"
    first = rpc("write_file", {"path": idem_rel, "content": "A\n"}, "unused", request_id=idem_rid, session_id="ses-a")
    replay = rpc("write_file", {"path": idem_rel, "content": "A\n"}, "unused2", request_id=idem_rid, session_id="ses-b")
    changed = rpc("write_file", {"path": idem_rel, "content": "B\n"}, "unused3", request_id=idem_rid, session_id="ses-c")
    record(
        "idempotent_replay_current_session",
        is_status(first, "VERIFIED")
        and payload(replay).get("status") == "VERIFIED"
        and payload(replay).get("session_id") == "ses-b"
        and local_bytes(idem_rel) == b"A\n",
        {"first": first, "replay": replay},
    )
    record("request_fingerprint_mismatch_denied", is_status(changed, "DENIED", "POLICY_DENIED"), changed)

    # Transfer round trip.
    tx_rel = f"live-transfer-{RUN}.bin"
    tx_path = PROJECT_ROOT / tx_rel
    ARTIFACTS.append(tx_path)
    blob = b"VCW-LIVE-" + RUN.encode() + bytes(range(32))
    blob_sha = hashlib.sha256(blob).hexdigest()
    up = rpc("transfer", {
        "direction": "upload",
        "path": tx_rel,
        "encoding": "base64",
        "content": base64.b64encode(blob).decode(),
        "content_sha256": blob_sha,
    }, "tx-up")
    down = rpc("transfer", {"direction": "download", "path": tx_rel}, "tx-down")
    try:
        decoded = base64.b64decode((payload(down).get("result") or {}).get("content", ""), validate=True)
    except Exception:
        decoded = b""
    record(
        "transfer_roundtrip",
        is_status(up, "VERIFIED")
        and is_status(down, "VERIFIED")
        and decoded == blob
        and (payload(down).get("result") or {}).get("sha256") == blob_sha,
        {"upload": up, "download": down},
    )

    # Patch + post-condition.
    patch_rel = f"live-patch-{RUN}.txt"
    patch_path = PROJECT_ROOT / patch_rel
    ARTIFACTS.append(patch_path)
    patch = (
        f"diff --git a/{patch_rel} b/{patch_rel}\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        f"+++ b/{patch_rel}\n"
        "@@ -0,0 +1 @@\n"
        f"+PATCH-{RUN}\n"
    )
    x = rpc("apply_patch", {"patch": patch}, "patch")
    record(
        "patch_verified_postcondition",
        is_status(x, "VERIFIED")
        and (payload(x).get("result") or {}).get("postcondition") == "reverse_apply_check"
        and local_bytes(patch_rel) == f"PATCH-{RUN}\n".encode(),
        x,
    )

    # Timeout + one new connection epoch.
    timeout_rid = f"live-{RUN}-timeout"
    timed = rpc("exec", {
        "argv": ["python3", "-c", "import time;time.sleep(2)"],
        "timeout_s": 0.2,
    }, "timeout", request_id=timeout_rid, timeout=10)
    record("exec_timeout_unknown", is_status(timed, "OUTCOME_UNKNOWN", "BACKEND_TIMEOUT"), timed)

    rec = rpc("reconcile", {"kind": "request", "target_request_id": timeout_rid}, "timeout-rec")
    record("timeout_request_stays_unknown", is_status(rec, "OUTCOME_UNKNOWN", "REQUEST_OUTCOME_UNKNOWN"), rec)

    info2 = curl_call("/v1/info")
    generation1 = payload(info2).get("connection_generation")
    record(
        "connection_generation_new_epoch",
        isinstance(generation0, int) and isinstance(generation1, int) and generation1 == generation0 + 1,
        {"before": generation0, "after": generation1},
    )

    # Job start/cancel/status.
    job = rpc("start_job", {
        "argv": ["python3", "-c", "import time;print('START',flush=True);time.sleep(20)"],
    }, "job-start")
    job_id = (payload(job).get("result") or {}).get("job_id")
    if job_id:
        time.sleep(0.3)
        pre = rpc("job_status", {"job_id": job_id, "max_log_bytes": 1024}, "job-pre")
        cancel = rpc("cancel_job", {"job_id": job_id}, "job-cancel")
        post = rpc("job_status", {"job_id": job_id, "max_log_bytes": 1024}, "job-post")
        record(
            "job_cancel_terminal_consistency",
            is_status(job, "VERIFIED")
            and (payload(pre).get("result") or {}).get("state") == "RUNNING"
            and is_status(cancel, "VERIFIED")
            and (payload(post).get("result") or {}).get("state") == "CANCELLED",
            {"start": job, "before": pre, "cancel": cancel, "after": post},
        )
    else:
        record("job_cancel_terminal_consistency", False, job)

    # Already-terminal cancel must not signal.
    short = rpc("start_job", {"argv": ["python3", "-c", "print('DONE')"]}, "job-short")
    short_id = (payload(short).get("result") or {}).get("job_id")
    terminal = None
    if short_id:
        for i in range(20):
            time.sleep(0.15)
            terminal = rpc("job_status", {"job_id": short_id, "max_log_bytes": 1024}, f"job-short-status-{i}")
            if (payload(terminal).get("result") or {}).get("state") != "RUNNING":
                break
        cancel_terminal = rpc("cancel_job", {"job_id": short_id}, "job-short-cancel")
        record(
            "cancel_terminal_job_refused",
            (payload(terminal).get("result") or {}).get("state") == "SUCCEEDED"
            and is_status(cancel_terminal, "FAILED", "JOB_ALREADY_TERMINAL"),
            {"terminal": terminal, "cancel": cancel_terminal},
        )
    else:
        record("cancel_terminal_job_refused", False, short)

    # Local saturation. Accepted execs serialize on the SSH backend lock and keep slots occupied.
    def slow(index: int):
        return rpc(
            "exec",
            {"argv": ["python3", "-c", "import time;time.sleep(1)"], "timeout_s": 5},
            f"rate-{index}",
            timeout=15,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        saturated = list(pool.map(slow, range(8)))
    limited = [x for x in saturated if x.get("http") == 429]
    record(
        "local_rate_limit_429",
        bool(limited)
        and all(is_status(x, "RATE_LIMITED", "RUNNER_INFLIGHT_LIMIT") for x in limited)
        and all(x.get("headers", {}).get("retry-after") == "1" for x in limited),
        {"limited_count": len(limited), "responses": limited},
    )

    cleanup()

    summary = {
        "run": RUN,
        "runner_url": RUNNER_URL,
        "server_id": SERVER_ID,
        "build": build,
        "ledger": ledger,
        "audit_canary": audit_canary,
        "passed": sum(1 for x in RESULTS if x["pass"]),
        "total": len(RESULTS),
        "failed": [x["name"] for x in RESULTS if not x["pass"]],
        "external_gates_not_tested_here": [
            "wrong SSH host-key deployment injection",
            "Hostless audit-log canary/redaction scan",
            "PostgreSQL ledger persistence across Hostless redeploy (use ledger_persistence_acceptance.py)",
        ],
        "results": RESULTS,
    }
    REPORT.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print("=== SUMMARY ===")
    print(json.dumps({k: summary[k] for k in ("passed", "total", "failed")}, ensure_ascii=False))
    print("REPORT=" + str(REPORT))


if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
