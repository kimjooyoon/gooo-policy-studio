#!/usr/bin/env python3
"""Exercise the actual local gate binary using fresh synthetic state/credentials.

Only localhost is contacted. Credentials and outgoing headers are never recorded.
"""
import argparse
import hashlib
import json
import select
import signal
import stat
import subprocess
import tempfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    project = Path(__file__).resolve().parents[1]
    client = build_opener(ProxyHandler({}), NoRedirect())
    observations = []
    with tempfile.TemporaryDirectory(prefix="gooo-gate-proof-") as temporary:
        directory = Path(temporary)
        state = directory / "state"
        credential = directory / "private.token"
        init = subprocess.run(
            [str(binary), "-init", str(project / "examples/automation-gate/bootstrap.json"),
             "-state", str(state), "-token-file", str(credential)],
            capture_output=True, text=True, timeout=15,
        )
        assert init.returncode == 0, "initialization failed"
        token = credential.read_text().strip()
        assert len(token) == 64 and token not in init.stdout + init.stderr
        assert stat.S_IMODE(credential.stat().st_mode) == 0o600
        assert stat.S_IMODE(state.stat().st_mode) == 0o700
        assert stat.S_IMODE((state / "snapshot.json").stat().st_mode) == 0o600

        def start():
            process = subprocess.Popen(
                [str(binary), "-state", str(state), "-addr", "127.0.0.1:0"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                ready, _, _ = select.select([process.stdout], [], [], 10)
                assert ready, "listener did not become ready"
                line = process.stdout.readline().strip()
                assert line.startswith("Gooo machine request gate: http://127.0.0.1:"), "listener failed"
                return process, line.split(": ", 1)[1]
            except BaseException:
                process.kill()
                process.communicate()
                raise

        def stop(process):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise
            assert process.returncode == 0, "gate did not stop cleanly"
            assert token not in stdout + stderr, "credential was logged"

        def call(base, method, path, body=None, authenticated=True, raw=None):
            headers = {"Content-Type": "application/json"}
            if authenticated:
                headers["Authorization"] = "Bearer " + token
            data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
            request = Request(base + path, data=data, headers=headers, method=method)
            try:
                with client.open(request, timeout=10) as response:
                    status, payload = response.status, response.read()
            except HTTPError as error:
                status, payload = error.code, error.read()
            assert token.encode() not in payload
            return status, json.loads(payload)

        process, base = start()
        try:
            status, _ = call(base, "GET", "/api/state", authenticated=False)
            assert status == 401
            observations.append({"case": "missing_credential", "status": status})
            status, view = call(base, "GET", "/api/state")
            assert status == 200 and "token_sha256" not in json.dumps(view)
            version = view["policy_version"]
            assert all(row["status"] == "pending" and row["revision"] == 1 for row in view["requests"])
            command = {"request_id": "req-export-1", "expected_revision": 1,
                       "policy_version": version, "idempotency_key": "proof-admit-1"}
            stale_version = "sha256:" + ("0" * 64 if version != "sha256:" + "0" * 64 else "1" * 64)
            status, _ = call(base, "POST", "/api/admit", {**command, "policy_version": stale_version})
            assert status == 409
            observations.append({"case": "stale_policy", "status": status})
            status, _ = call(base, "POST", "/api/admit", {**command, "policy": {"limit": 9000000000000}})
            assert status == 400
            observations.append({"case": "caller_policy_override", "status": status})
            duplicate = json.dumps(command).encode().replace(b'"request_id": "req-export-1"', b'"request_id":"req-export-1","request_id":"other"')
            status, _ = call(base, "POST", "/api/admit", raw=duplicate)
            assert status == 400
            observations.append({"case": "duplicate_JSON_key", "status": status})
            status, unchanged = call(base, "GET", "/api/state")
            assert status == 200 and unchanged == view
            status, approved = call(base, "POST", "/api/admit", command)
            assert status == 200 and approved["outcome"]["committed"] and not approved["replayed"]
            assert approved["outcome"]["receipt"]["result"]["after"]["approved"]
            assert approved["outcome"]["receipt"]["input"]["request"]["amount"] == 750000
            observations.append({"case": "authenticated_Gooo_approval", "status": status,
                                 "outcome_id": approved["outcome"]["id"]})
            status, retry = call(base, "POST", "/api/admit", command)
            assert status == 200 and retry["replayed"] and retry["outcome"] == approved["outcome"]
            observations.append({"case": "same_intent_retry", "status": status, "same_outcome": True})
            status, _ = call(base, "POST", "/api/admit", {**command, "expected_revision": 2})
            assert status == 409
            observations.append({"case": "key_reused_for_changed_intent", "status": status})
            status, _ = call(base, "POST", "/api/admit", {**command, "idempotency_key": "other-key"})
            assert status == 409
            observations.append({"case": "stale_request_with_new_key", "status": status})
            denied_command = {**command, "request_id": "req-export-over-limit", "idempotency_key": "proof-deny-1"}
            status, denied = call(base, "POST", "/api/admit", denied_command)
            outcome = denied["result"]["outcome"]
            assert status == 403 and not outcome["committed"]
            assert outcome["receipt"]["result"]["after"]["reason"] == "OVER_LIMIT"
            observations.append({"case": "Gooo_over_limit_denial", "status": status, "outcome_id": outcome["id"]})
            second_writer = subprocess.run([str(binary), "-state", str(state), "-addr", "127.0.0.1:0"], capture_output=True, timeout=10)
            assert second_writer.returncode != 0 and token.encode() not in second_writer.stdout + second_writer.stderr
            observations.append({"case": "second_process_writer", "startup_rejected": True})
        finally:
            stop(process)
        process, base = start()
        try:
            status, retry = call(base, "POST", "/api/admit", command)
            assert status == 200 and retry["replayed"] and retry["outcome"] == approved["outcome"]
            observations.append({"case": "approved_retry_after_process_restart", "status": status, "same_outcome": True})
            status, retry_denial = call(base, "POST", "/api/admit", denied_command)
            assert status == 403 and retry_denial["result"]["replayed"]
            assert retry_denial["result"]["outcome"] == denied["result"]["outcome"]
            observations.append({"case": "denied_retry_after_process_restart", "status": status, "same_outcome": True})
            status, final_view = call(base, "GET", "/api/state")
            assert status == 200
            states = {row["request"]["key"]: (row["status"], row["revision"]) for row in final_view["requests"]}
            assert states == {"req-export-1": ("approved", 2), "req-export-over-limit": ("pending", 1)}
        finally:
            stop(process)
    proof = {"schema": "policy-studio/machine-gate-observation/v1", "passed": True,
             "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "policy_version": version,
             "observations": observations, "cases": len(observations),
             "final_request_states": states, "raw_credentials_recorded": False,
             "scope": "Fresh synthetic trusted local state, actual native binary and loopback HTTP. One local state transition; no external effect, all-input proof or customer deployment."}
    encoded = json.dumps(proof, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        output = Path(args.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded)
    print(json.dumps({"passed": True, "cases": len(observations), "local_state_transitions": 1,
                      "external_effects": 0, "raw_credentials_recorded": False}))


if __name__ == "__main__":
    main()
