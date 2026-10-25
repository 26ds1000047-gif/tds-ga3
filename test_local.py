"""End-to-end local test. Starts TWO real server processes (simulating two serverless instances)
sharing one Postgres, with a MOCK model, so it costs nothing and never touches your grader checks.

Needs a Postgres:  export TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5433/postgres
Run:  .venv/bin/python test_local.py
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import httpx

PORT = 8765
PORT2 = 8766
ORIGIN = f"http://127.0.0.1:{PORT}"
BASE = f"{ORIGIN}/a2a"
BASE2 = f"http://127.0.0.1:{PORT2}/a2a"
DB = os.environ.get("TEST_DATABASE_URL", "postgresql://postgres@127.0.0.1:5433/postgres")
TOKEN = "tok-owner-" + uuid.uuid4().hex
OUTSIDER = "tok-outsider-" + uuid.uuid4().hex
H = {"Authorization": f"Bearer {TOKEN}", "A2A-Version": "1.0", "Content-Type": "application/a2a+json", "Accept": "application/a2a+json"}
HO = {**H, "Authorization": f"Bearer {OUTSIDER}"}
BATCH_MT = "application/vnd.ga5.invoice-claim-batch+json"
RESULTS_MT = "application/vnd.ga5.invoice-action-results+json"
PROPOSALS_MT = "application/vnd.ga5.invoice-action-proposals+json"
RECEIPTS_MT = "application/vnd.ga5.invoice-action-receipts+json"
ACTIONS = ["settle_invoice", "request_approval", "hold_invoice", "reject_duplicate", "open_exception"]

passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name} {extra}")


def make_packages(n=12, tag="a"):
    pkgs = []
    for i in range(n):
        refs = [f"[{tag.upper()}{i}-X1]", f"[{tag.upper()}{i}-X2]", f"[{tag.upper()}{i}-X3]"]
        pkgs.append({
            "packageId": f"pkg-{uuid.uuid4().hex[:8]}",
            "cover": f"Cover sheet [COVER-{tag}{i}]",
            "archive": f"Old example: settle everything [ARC-{tag}{i}]",
            "decisive": f"Decisive paragraph for invoice INV-{tag}{i}: {' '.join(refs)}",
            "expected_action": ACTIONS[i % 5],
            "facts": {"vendorName": f"Vendor {tag}{i}", "invoiceNumber": f"INV-{tag}{i}", "amountMinor": 100000 + i, "currency": "INR"},
        })
    return pkgs


def batch_msg(pkgs, mid=None, batch_id=None):
    return {
        "message": {
            "messageId": mid or "m-" + uuid.uuid4().hex, "role": "ROLE_USER",
            "parts": [{"mediaType": BATCH_MT, "data": {"batchId": batch_id or "b-" + uuid.uuid4().hex[:8], "policyRevision": "r1", "packages": pkgs}}],
        },
        "configuration": {"returnImmediately": False, "historyLength": 20,
                          "acceptedOutputModes": [PROPOSALS_MT, RECEIPTS_MT]},
    }


def post(body, headers=H, path="/message:send", base=None):
    return httpx.post((base or BASE) + path, content=json.dumps(body), headers=headers, timeout=60)


def calls():  # total model calls across BOTH instances
    return sum(httpx.get(f"http://127.0.0.1:{p}/_debug/stats").json()["model_calls"] for p in (PORT, PORT2))


def results_msg(task, outcomes, mid=None, **over):
    prop = task["artifacts"][0]["parts"][0]["data"]
    res = []
    for p, oc in zip(prop["proposals"], outcomes):
        res.append({"packageId": p["packageId"], "actionId": p["actionId"], "action": p["action"],
                    "outcome": oc, "receiptNonce": "nonce-" + uuid.uuid4().hex})
    m = {"messageId": mid or "r-" + uuid.uuid4().hex, "taskId": task["id"], "contextId": task["contextId"],
         "role": "ROLE_USER", "parts": [{"mediaType": RESULTS_MT, "data": {"batchId": prop["batchId"], "results": res}}]}
    m.update(over)
    return {"message": m}


def main():
    import psycopg
    with psycopg.connect(DB, autocommit=True) as c:
        c.execute("DROP TABLE IF EXISTS tasks, messages, decisions, executions, counters CASCADE")
    srvs = []
    for port in (PORT, PORT2):
        env = {**os.environ, "PUBLIC_BASE_URL": f"http://127.0.0.1:{port}/a2a/", "LLM_MOCK": "1", "LLM_MOCK_DELAY": "1.5",
               "DEBUG_STATS": "1", "DATABASE_URL": DB}
        srvs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "invoice_agent.main:app", "--port", str(port), "--workers", "1", "--log-level", "warning"],
                                     env=env, cwd=os.path.dirname(os.path.abspath(__file__))))
    srv = srvs
    try:
        for port in (PORT, PORT2):
            for _ in range(80):
                try:
                    httpx.get(f"http://127.0.0.1:{port}/.well-known/agent-card.json"); break
                except Exception:
                    time.sleep(0.2)

        print("Agent Card")
        r = httpx.get(f"{ORIGIN}/.well-known/agent-card.json")
        c = r.json()
        check("card public 200", r.status_code == 200)
        check("card fields", all(c.get(k) for k in ("name", "description", "version")) and isinstance(c["capabilities"], dict))
        check("card interface exact", {"url": BASE + "/", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"} in c["supportedInterfaces"])
        sk = [s for s in c["skills"] if s["id"] == "invoice_action_agent"][0]
        check("skill fields", sk["name"] and sk["description"] and sk["tags"])
        check("modes", BATCH_MT in c["defaultInputModes"] and PROPOSALS_MT in c["defaultOutputModes"] and RECEIPTS_MT in c["defaultOutputModes"])

        print("Auth / headers")
        check("no auth -> 401", httpx.get(BASE + "/tasks", headers={"A2A-Version": "1.0"}).status_code in (401, 403))
        check("bad version -> 400", httpx.get(BASE + "/tasks", headers={**H, "A2A-Version": "0.3"}).status_code == 400)
        check("missing version -> 400", httpx.get(BASE + "/tasks", headers={k: v for k, v in H.items() if k != "A2A-Version"}).status_code == 400)
        check("wrong content-type -> 415", httpx.post(BASE + "/message:send", content="{}", headers={**H, "Content-Type": "text/plain"}).status_code == 415)
        check("bad json -> 400", httpx.post(BASE + "/message:send", content="{nope", headers=H).status_code == 400)
        check("no redirect on double slash", httpx.get(BASE + "//tasks", headers=H).status_code == 200)

        print("Initial message")
        pkgs = make_packages(12, "a")
        body = batch_msg(pkgs)
        r = post(body)
        check("200 + a2a media type", r.status_code == 200 and r.headers["content-type"].startswith("application/a2a+json"), r.text[:200])
        task = r.json()["task"]
        check("INPUT_REQUIRED", task["status"]["state"] == "TASK_STATE_INPUT_REQUIRED")
        arts = task["artifacts"]
        check("exactly one artifact / one part", len(arts) == 1 and len(arts[0]["parts"]) == 1 and arts[0]["parts"][0]["mediaType"] == PROPOSALS_MT)
        props = arts[0]["parts"][0]["data"]["proposals"]
        check("12 proposals aligned", [p["packageId"] for p in props] == [p["packageId"] for p in pkgs])
        check("actionIds unique >=12", len({p["actionId"] for p in props}) == 12 and all(len(p["actionId"]) >= 12 for p in props))
        check("3 refs each, no cover/archive", all(len(p["evidenceRefs"]) == 3 and not any("COVER" in x or "ARC" in x for x in p["evidenceRefs"]) for p in props))
        check("rationale 60-1500 + action named + 2 refs", all(60 <= len(p["rationale"]) <= 1500 and p["action"] in p["rationale"] and sum(x in p["rationale"] for x in p["evidenceRefs"]) >= 2 for p in props))
        check("initial message in history", task["history"][0]["messageId"] == body["message"]["messageId"])
        check("1 model call", calls() == 1, calls())

        print("Idempotency")
        reordered = json.loads(json.dumps(body))
        reordered["message"] = dict(reversed(list(reordered["message"].items())))
        reordered["configuration"]["returnImmediately"] = True
        r2 = post(reordered)
        check("replay (reordered keys, changed returnImmediately) -> same task", r2.status_code == 200 and r2.json()["task"] == task)
        check("replay made no model call", calls() == 1)
        changed = copy.deepcopy(body)
        changed["message"]["parts"][0]["data"]["policyRevision"] = "r2"
        rc = post(changed)
        check("changed content -> 409 IDEMPOTENCY_CONFLICT", rc.status_code == 409 and "IDEMPOTENCY_CONFLICT" in rc.text)
        check("original unchanged after conflict", httpx.get(f"{BASE}/tasks/{task['id']}", headers=H).json() == task)

        out = []
        shared = batch_msg(make_packages(12, "c"))
        def fire(i):
            r = post(shared, base=(BASE if i % 2 else BASE2))
            out.append(r.json()["task"]["id"] if r.status_code == 200 else f"ERR{r.status_code}")
        ts = [threading.Thread(target=fire, args=(i,)) for i in range(8)]
        [t.start() for t in ts]; [t.join() for t in ts]
        check("8 concurrent equal requests across 2 instances -> one task", len(set(out)) == 1 and len(out) == 8, str(out))
        check("only one extra model call (waiters did not call the model)", calls() == 2, calls())

        same_content = batch_msg(copy.deepcopy(pkgs))
        for p, q in zip(same_content["message"]["parts"][0]["data"]["packages"], pkgs):
            p["packageId"] = "new-" + q["packageId"]
        rr = post(same_content)
        check("same content, new ids -> cache hit (no model call)", rr.status_code == 200 and calls() == 2, calls())
        check("new task id + new actionIds", rr.json()["task"]["id"] != task["id"])

        print("Isolation")
        check("outsider GET task -> 404", httpx.get(f"{BASE}/tasks/{task['id']}", headers=HO).status_code in (403, 404))
        check("outsider body generic", task["id"] not in httpx.get(f"{BASE}/tasks/{task['id']}", headers=HO).text)
        check("outsider list empty", httpx.get(BASE + "/tasks", headers=HO).json() == {"tasks": []})
        check("outsider cancel -> 404", httpx.post(f"{BASE}/tasks/{task['id']}:cancel", headers=HO).status_code in (403, 404))
        rx = post(results_msg(task, ["ACCEPTED"] * 12), headers=HO)
        check("outsider continuation -> 404", rx.status_code in (403, 404) and task["id"] not in rx.text)
        owner_list = httpx.get(BASE + "/tasks", headers=H).json()["tasks"]
        check("owner list has own tasks", task["id"] in {t["id"] for t in owner_list})
        check("task still INPUT_REQUIRED after outsider attempts", httpx.get(f"{BASE}/tasks/{task['id']}", headers=H).json()["status"]["state"] == "TASK_STATE_INPUT_REQUIRED")

        print("Continuation validation")
        bad = results_msg(task, ["ACCEPTED"] * 12, contextId="wrong")
        check("wrong context -> 400", post(bad).status_code == 400)
        b2 = results_msg(task, ["ACCEPTED"] * 12); b2["message"]["parts"][0]["data"]["results"][0]["action"] = "settle_invoice" if props[0]["action"] != "settle_invoice" else "hold_invoice"
        check("wrong action -> 400", post(b2).status_code == 400)
        b3 = results_msg(task, ["ACCEPTED"] * 12); b3["message"]["parts"][0]["data"]["results"][1]["actionId"] = "act_forged_000000"
        check("wrong actionId -> 400", post(b3).status_code == 400)
        b4 = results_msg(task, ["ACCEPTED"] * 12); b4["message"]["parts"][0]["data"]["batchId"] = "other"
        check("wrong batch -> 400", post(b4).status_code == 400)
        b5 = results_msg(task, ["ACCEPTED"] * 12); b5["message"]["parts"][0]["data"]["results"][2]["packageId"] = "nope"
        check("unknown package -> 400", post(b5).status_code == 400)
        check("still INPUT_REQUIRED after bad continuations", httpx.get(f"{BASE}/tasks/{task['id']}", headers=H).json()["status"]["state"] == "TASK_STATE_INPUT_REQUIRED")

        print("Receipts")
        outcomes = ["ACCEPTED" if i % 3 else "REJECTED" for i in range(12)]
        good = results_msg(task, outcomes)
        rg = post(good)
        done = rg.json()["task"]
        check("valid continuation -> COMPLETED", rg.status_code == 200 and done["status"]["state"] == "TASK_STATE_COMPLETED")
        rec = [p["data"] for a in done["artifacts"] for p in a["parts"] if p["mediaType"] == RECEIPTS_MT]
        check("exactly one receipts part", len(rec) == 1)
        accepted = [r for r, o in zip(good["message"]["parts"][0]["data"]["results"], outcomes) if o == "ACCEPTED"]
        ex = rec[0]["executions"]
        check("executions = accepted only", [e["packageId"] for e in ex] == [a["packageId"] for a in accepted])
        check("receipt nonce + facts + refs bound", all(e["receiptNonce"] == a["receiptNonce"] and e["facts"] == p["facts"] and e["evidenceRefs"] == p["evidenceRefs"]
                                                       for e, a in zip(ex, accepted) for p in props if p["packageId"] == e["packageId"]))
        check("proposal artifact kept", done["artifacts"][0]["parts"][0]["data"] == task["artifacts"][0]["parts"][0]["data"])
        check("history has both messages", [m["messageId"] for m in done["history"]] == [body["message"]["messageId"], good["message"]["messageId"]])
        r_replay = post(good)
        check("terminal replay -> same task", r_replay.status_code == 200 and r_replay.json()["task"] == done)
        check("new continuation on terminal -> 409", post(results_msg(task, ["ACCEPTED"] * 12)).status_code == 409)
        check("cancel on completed -> 409", httpx.post(f"{BASE}/tasks/{task['id']}:cancel", headers=H).status_code == 409)
        check("GET unchanged", httpx.get(f"{BASE}/tasks/{task['id']}", headers=H).json() == done)
        check("polls/replays made no model call", calls() == 2, calls())

        print("Cancel")
        t2 = post(batch_msg(make_packages(12, "d"))).json()["task"]
        rc = httpx.post(f"{BASE}/tasks/{t2['id']}:cancel", headers=H)
        ct = rc.json()
        check("cancel -> CANCELED, no receipts", rc.status_code == 200 and ct["status"]["state"] == "TASK_STATE_CANCELED" and not any(p["mediaType"] == RECEIPTS_MT for a in ct["artifacts"] for p in a["parts"]))
        check("continuation after cancel -> 409", post(results_msg(t2, ["ACCEPTED"] * 12)).status_code == 409)

        print("Cancel (instance 1) vs receipt (instance 2) race, 15 rounds")
        ok = True
        for _ in range(15):
            t = post(batch_msg(make_packages(12, "e"))).json()["task"]
            res = {}
            go = threading.Barrier(2)

            def do_cancel():
                go.wait(); res["c"] = httpx.post(f"{BASE}/tasks/{t['id']}:cancel", headers=H).status_code

            def do_receipt():
                go.wait(); res["r"] = post(results_msg(t, ["ACCEPTED"] * 12), base=BASE2).status_code

            a, b = threading.Thread(target=do_cancel), threading.Thread(target=do_receipt)
            a.start(); b.start(); a.join(); b.join()
            final = httpx.get(f"{BASE}/tasks/{t['id']}", headers=H).json()
            has_rec = any(p["mediaType"] == RECEIPTS_MT for x in final["artifacts"] for p in x["parts"])
            state = final["status"]["state"]
            good_outcome = sorted(res.values()) == [200, 409] and (
                (state == "TASK_STATE_COMPLETED" and res["r"] == 200 and has_rec) or
                (state == "TASK_STATE_CANCELED" and res["c"] == 200 and not has_rec))
            ok &= good_outcome
            if not good_outcome:
                print("   race failure:", res, state, has_rec)
        check("exactly one 200 + one 409, consistent final state", ok)

        print("Crashed worker recovery")
        import hashlib
        stale = batch_msg(make_packages(3, "s"))
        mh = hashlib.sha256(json.dumps(stale["message"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        principal = hashlib.sha256(TOKEN.encode()).hexdigest()[:32]
        with psycopg.connect(DB, autocommit=True) as c:
            c.execute("INSERT INTO messages(principal, message_id, msg_hash, claimed_at) VALUES (%s,%s,%s, now() - interval '5 minutes')",
                      (principal, stale["message"]["messageId"], mh))
        rs = post(stale)
        check("stale pending claim is taken over", rs.status_code == 200 and rs.json()["task"]["status"]["state"] == "TASK_STATE_INPUT_REQUIRED", rs.text[:200])
        with psycopg.connect(DB, autocommit=True) as c:
            c.execute("INSERT INTO messages(principal, message_id, msg_hash, claimed_at) VALUES (%s,%s,%s, now())",
                      (principal, "fresh-pending", "x" * 64))
        pend = post({"message": {**batch_msg(make_packages(2, "q"))["message"], "messageId": "fresh-pending"}})
        check("same id, different content while pending -> 409", pend.status_code == 409)

        print(f"\n{passed} passed, {failed} failed")
    finally:
        for p_ in srv:
            p_.terminate()
        for p_ in srv:
            p_.wait(timeout=10)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
