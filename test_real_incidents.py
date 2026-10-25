"""Replays the real grader incidents (fixtures/real_incidents.json, captured from production logs) through the full lifecycle.

The model is mocked with the plan it really produced; everything else is the real code path.
    export TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5433/postgres
    python test_real_incidents.py
"""
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid

import httpx

import test_incident as T
from test_incident import check, outcome, post, receipt, validate_trace, canon, BASE, PORT, PROFILE

FX = os.path.join(os.path.dirname(__file__), "fixtures", "real_incidents.json")


def truth_ids(transcript):
    out = []
    for ln in transcript.splitlines():
        m = re.match(r"\s*\[(\S+?)\]", ln)
        if m and re.search(r"T\d\d:\d\d:30Z (correlated sample|incident-window record|bounded observation|on-call finding):", ln):
            out.append(m.group(1))
    return out


def build(fx, with_trace=False):
    canary = "CANARY-" + uuid.uuid4().hex
    body = {"profile": PROFILE, "runId": "run_" + uuid.uuid4().hex[:22], "agentName": "incident-response",
            "publicMarker": "pm_" + uuid.uuid4().hex[:8], "sensitive": {"accessToken": "tok-" + canary, "privateNote": "note-" + canary},
            "incident": fx["incident"], "toolCatalog": fx["toolCatalog"], "policy": {**fx["policy"], "doNotExport": ["accessToken", "privateNote"]},
            "_mock_plan": fx["realPlan"]}
    return body, canary


def main():
    fxs = json.load(open(FX))
    env = {**os.environ, "DATABASE_URL": T.DB, "INCIDENT_MOCK": "1", "DEBUG_STATS": "1", "PUBLIC_BASE_URL": f"{BASE}/a2a/"}
    srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "invoice_agent.main:app", "--port", str(PORT), "--log-level", "warning"], env=env)
    try:
        for _ in range(60):
            try:
                httpx.get(BASE + "/.well-known/agent-card.json", timeout=2)
                break
            except Exception:
                time.sleep(0.5)
        for n, fx in enumerate(fxs):
            name = fx["incident"]["service"][-6:] + ":" + fx["realPlan"]["rootCause"][:14]
            body, canary = build(fx)
            run = body["runId"]
            hdr = {"traceparent": "00-" + "1a" * 16 + "-" + "2b" * 8 + "-01", "tracestate": "vendor=st_" + uuid.uuid4().hex[:6]} if n == 0 else {}
            r = post("/v2/incidents", body, hdr)
            check(f"{name}: create 200 JSON", r.status_code == 200 and r.headers["content-type"].startswith("application/json"), r.text[:200])
            a = r.json()
            truth = truth_ids(fx["incident"]["transcript"])
            check(f"{name}: evidence is exactly the incident-specific lines", sorted(a["diagnosis"]["evidence"]) == sorted(truth), a["diagnosis"]["evidence"])
            check(f"{name}: waiting response fields", set(a) == {"runId", "status", "diagnosis", "dispatches", "approvals", "actionLog", "receiptLog"}, sorted(a))
            ds = a["dispatches"]
            tools = [d["toolName"] for d in ds]
            check(f"{name}: 1-3 diagnostics from the catalog, none are effects", 1 <= len(ds) <= 3 and all(t in {c["name"] for c in fx["toolCatalog"]} and t not in fx["policy"]["effectTools"] for t in tools), tools)
            req = {c["name"]: set(c["inputSchema"].get("required", [])) for c in fx["toolCatalog"]}
            check(f"{name}: required arguments present", all(req[d["toolName"]] <= set(d["arguments"]) for d in ds))
            check(f"{name}: dispatch keys", all(set(d) - {"tracestate"} == {"actionId", "callId", "phase", "toolName", "arguments", "evidence", "attempt", "traceparent"} for d in ds))
            check(f"{name}: dispatch evidence cites diagnosis evidence", all(set(d["evidence"]) <= set(a["diagnosis"]["evidence"]) for d in ds))
            if "runbook" in " ".join(l for l in fx["incident"]["transcript"].splitlines() if "bounded observation" in l or "correlated sample" in l).lower():
                check(f"{name}: runbook is a diagnostic when the transcript requires it", "read_runbook" in tools, tools)
            eff = fx["realPlan"]["effect"]["toolName"]
            needs_approval = eff in fx["policy"]["approvalRequiredFor"]
            timeout_case = "read_runbook" in tools and fx["realPlan"]["rootCause"] == "secret_rotation_mismatch"

            # drive diagnostics: first diagnostic of the first incident gets a 503 then success; secret rotation's runbook times out
            outs = []
            retried = False
            for i, d in enumerate(ds):
                if timeout_case and d["toolName"] == "read_runbook":
                    outs.append(outcome(d, 0, errorType="timeout"))
                elif n == 0 and i == 0:
                    outs.append(outcome(d, 503))
                    retried = True
                else:
                    outs.append(outcome(d))
            r1, _ = receipt(run, outs, rid="rc-" + uuid.uuid4().hex[:8])
            j = r1.json()
            check(f"{name}: receipt accepted", r1.status_code == 200, r1.text[:200])
            if retried:
                check(f"{name}: retry dispatch with no approval request", len(j["dispatches"]) == 1 and j["dispatches"][0]["attempt"] == 2 and j["approvals"] == [])
                r1b, _ = receipt(run, [outcome(j["dispatches"][0])], rid="rc-" + uuid.uuid4().hex[:8])
                j = r1b.json()
            if timeout_case:
                check(f"{name}: timeout -> failed, effect suppressed", j["status"] == "failed" and j["chosenEffect"] is None and j["suppressed"] == [eff], j)
                fin = j
            else:
                if needs_approval:
                    check(f"{name}: approval request first (no dispatches)", j["status"] == "waiting" and j["dispatches"] == [] and len(j["approvals"]) == 1, j)
                    ap = j["approvals"][0]
                    args = fx["realPlan"]["effect"]["arguments"]
                    check(f"{name}: digest correct", ap["argumentsDigest"] == hashlib.sha256(canon(args).encode()).hexdigest() and ap["toolName"] == eff)
                    rA, _ = receipt(run, None, apps=[{"approvalId": ap["approvalId"], "decision": "approved", "nonce": str(uuid.uuid4())}], rid="rc-" + uuid.uuid4().hex[:8])
                    j = rA.json()
                    e = j["dispatches"]
                    check(f"{name}: effect carries approval id and nonce, reserved action id", len(e) == 1 and e[0]["approvalId"] == ap["approvalId"] and "approvalNonce" in e[0] and e[0]["actionId"] == ap["actionId"], j)
                else:
                    e = j["dispatches"]
                    check(f"{name}: exactly one effect dispatch", len(e) == 1 and e[0]["phase"] == "effect" and e[0]["toolName"] == eff, j)
                check(f"{name}: effect arguments are the planned ones", e[0]["arguments"] == fx["realPlan"]["effect"]["arguments"])
                rE, _ = receipt(run, [outcome(e[0])], rid="rc-" + uuid.uuid4().hex[:8])
                fin = rE.json()
                check(f"{name}: completed with the chosen effect", fin["status"] == "completed" and fin["chosenEffect"] == eff and fin["suppressed"] == [], fin.get("status"))
            check(f"{name}: final fields", {"actionLog", "receiptLog", "otlp", "diagnosis", "chosenEffect", "suppressed"} <= set(fin) and not fin.get("dispatches") and not fin.get("approvals"))
            check(f"{name}: actionLog exactly the issued dispatches", all(x in fin["actionLog"] for x in ds))
            validate_trace(name, fin, body["publicMarker"], run, len(ds) > 1, needs_approval and not timeout_case, incoming=("1a" * 16, "2b" * 8) if n == 0 else None)
            g = httpx.get(BASE + f"/v2/incidents/{run}")
            check(f"{name}: GET equals final", g.status_code == 200 and g.json() == fin)
            rp = post("/v2/incidents", body, hdr)
            check(f"{name}: replay of original request is the first response", rp.status_code == 200 and rp.content == r.content)
            ch = copy.deepcopy(body)
            ch["incident"]["title"] += " changed"
            check(f"{name}: changed content -> 409", post("/v2/incidents", ch, hdr).status_code == 409)
            check(f"{name}: canary absent from every response", canary not in r.text + r1.text + json.dumps(fin) + rp.text + g.text)
    finally:
        srv.terminate()
        srv.wait(timeout=10)
    print("\n%d failure(s)" % len(T.fails) if T.fails else "\nALL REAL-INCIDENT TESTS PASSED")
    return 1 if T.fails else 0


if __name__ == "__main__":
    sys.exit(main())
