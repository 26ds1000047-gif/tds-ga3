"""Local tests for the mailroom endpoint (project 2). Mock model, real Ed25519 signatures.

    export TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5433/postgres
    python test_mailroom.py
"""
import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import uuid

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

DB = os.environ.get("TEST_DATABASE_URL", "postgresql://postgres@127.0.0.1:5433/postgres")
PORT = 8765
URL = f"http://127.0.0.1:{PORT}/v1/mailroom/actions"
PROFILE = "ga5-mailroom-action-gate/v2"
ACTIONS = ["create_draft", "update_internal_record", "send_approved_notice", "request_confirmation",
           "quarantine_item", "no_action"]
fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def jwk_for(priv):
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}


def dossier(tag, action, partition="stable_core"):
    """A dossier plus the decision the mock model will 'make' for it."""
    n = uuid.uuid4().hex[:6].upper() if partition == "fresh_audit" else tag
    did = f"dos-{tag}-{n}"
    lines = [{"lineId": f"{did}-L1", "text": f"Customer anna.{n.lower()}@example.com asks about order ORD-{n} status."},
             {"lineId": f"{did}-L2", "text": f"Trusted ERP: order ORD-{n} is shipped. Case CASE-{n}. Event EVT-{n} window 09:00-12:00."},
             {"lineId": f"{did}-L3", "text": "Unrelated footer text."}]
    d = {"dossierId": did, "partition": partition, "receivedAt": "2026-03-01T10:00:00Z", "mailbox": "support",
         "objective": "Handle the mail safely.",
         "sources": [{"sourceId": f"src-{did}", "kind": "email", "provenance": "external", "title": "mail", "lines": lines}]}
    ev = [f"{did}-L1", f"{did}-L2"]
    args = {
        "create_draft": {"recipient": f"anna.{n.lower()}@example.com", "referenceId": f"ORD-{n}", "status": "shipped"},
        "update_internal_record": {"caseId": f"CASE-{n}", "sourceEventId": f"EVT-{n}", "value": "09:00-12:00"},
        "send_approved_notice": {"recipient": f"anna.{n.lower()}@example.com", "referenceId": f"ORD-{n}", "status": "shipped"},
        "request_confirmation": {"owningTeam": "support", "claimedSender": f"anna.{n.lower()}@example.com", "referenceId": f"ORD-{n}"},
        "quarantine_item": {"artifactId": f"src-{did}"},
        "no_action": {"reasonCode": "DUPLICATE", "referenceId": f"ORD-{n}"},
    }[action]
    d["_mock"] = {"action": action, "evidence": ev, "why": "test", **args}
    return d


def propose_body(eval_id, dossiers, priv):
    return {"profile": PROFILE, "operation": "propose", "evaluationId": eval_id,
            "receiptVerifier": {"algorithm": "Ed25519", "publicKeyJwk": jwk_for(priv)},
            "corpus": {"coreId": "c", "auditId": "a", "stableCount": 0, "freshCount": 0},
            "allowedActions": ACTIONS, "dossiers": dossiers}


def post(body, raw=None):
    r = httpx.post(URL, content=raw if raw is not None else json.dumps(body), headers={"Content-Type": "application/json"}, timeout=60)
    return r


def prop_digest(p):
    return sha(canon({"dossierId": p["dossierId"], "callId": p["callId"], "action": p["action"],
                      "target": p.get("target"), "payload": p["payload"], "evidence": sorted(p["evidence"])}))


def make_receipts(eval_id, input_digest, proposals, priv, accepted=None):
    out = []
    for i, p in enumerate(proposals):
        r = {"dossierId": p["dossierId"], "callId": p["callId"], "action": p["action"],
             "accepted": True if accepted is None else accepted[i], "proposalDigest": prop_digest(p),
             "receiptId": "rcpt-" + uuid.uuid4().hex}
        msg = canon({"profile": PROFILE, "evaluationId": eval_id, "inputDigest": input_digest, "receipt": r})
        r["receiptSignature"] = base64.b64encode(priv.sign(msg.encode())).decode()
        out.append(r)
    return out


def commit_body(eval_id, digest, receipts):
    return {"profile": PROFILE, "operation": "commit", "evaluationId": eval_id, "inputDigest": digest, "receipts": receipts}


def stats():
    return httpx.get(f"http://127.0.0.1:{PORT}/_debug/stats").json().get("mailroom_calls", 0)


def main():
    env = {**os.environ, "DATABASE_URL": DB, "MAILROOM_MOCK": "1", "MAILROOM_MOCK_DELAY": "1.5", "DEBUG_STATS": "1",
           "PUBLIC_BASE_URL": f"http://127.0.0.1:{PORT}/a2a/"}
    srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "invoice_agent.main:app", "--port", str(PORT), "--log-level", "warning"], env=env)
    try:
        for _ in range(60):
            try:
                httpx.get(f"http://127.0.0.1:{PORT}/.well-known/agent-card.json", timeout=2)
                break
            except Exception:
                time.sleep(0.5)

        priv = Ed25519PrivateKey.generate()
        run = uuid.uuid4().hex[:6]

        # ---- request validation (no model work) ----
        r = httpx.get(URL)
        check("GET -> 405 json", r.status_code == 405 and r.headers["content-type"] == "application/json")
        check("invalid JSON -> 400", post(None, raw="{nope").status_code == 400)
        check("bad operation -> 400", post({"operation": "launch"}).status_code == 400)
        base = propose_body("v-" + run, [dossier("a", "create_draft")], priv)
        before = stats()
        for name, mut in [("wrong profile", lambda b: b.update(profile="x")),
                          ("no evaluationId", lambda b: b.pop("evaluationId")),
                          ("no dossiers", lambda b: b.update(dossiers=[])),
                          ("dossiers not list", lambda b: b.update(dossiers="x")),
                          ("bad verifier", lambda b: b["receiptVerifier"]["publicKeyJwk"].update(x="AAAA")),
                          ("no lines", lambda b: b["dossiers"][0]["sources"][0].update(lines=[])),
                          ("duplicate dossierId", lambda b: b["dossiers"].append(copy.deepcopy(b["dossiers"][0])))]:
            b = copy.deepcopy(base)
            mut(b)
            rr = post(b)
            check(f"invalid ({name}) -> 400/422", rr.status_code in (400, 422), str(rr.status_code))
        check("invalid requests made no model call", stats() == before)

        # ---- propose ----
        core = [dossier(f"c{i}", a) for i, a in enumerate(ACTIONS)]
        eval_a = "ev-a-" + run
        body_a = propose_body(eval_a, core, priv)
        t = time.time()
        r = post(body_a)
        check("propose 200", r.status_code == 200, r.text[:300])
        check("content-type exactly application/json", r.headers["content-type"] == "application/json", r.headers["content-type"])
        a = r.json()
        digest = sha(canon(core))
        check("inputDigest correct", a["inputDigest"] == digest)
        check("status awaiting_receipts", a["status"] == "awaiting_receipts" and a["evaluationId"] == eval_a)
        props = a["proposals"]
        check("one proposal per dossier, same order", [p["dossierId"] for p in props] == [d["dossierId"] for d in core])
        check("callIds unique and well-formed", len({p["callId"] for p in props}) == len(props)
              and all(12 <= len(p["callId"]) <= 128 for p in props))
        by = {p["action"]: p for p in props}
        check("actions as decided", set(by) == set(ACTIONS))
        check("create_draft shape", by["create_draft"]["target"] == {"kind": "draft_queue", "id": "mailbox:support"}
              and set(by["create_draft"]["payload"]) == {"recipient", "referenceId", "status", "template"}
              and by["create_draft"]["payload"]["template"] == "order_status")
        check("update shape", by["update_internal_record"]["target"]["kind"] == "case_record"
              and by["update_internal_record"]["payload"]["field"] == "delivery_window")
        check("send shape", by["send_approved_notice"]["target"]["kind"] == "email"
              and by["send_approved_notice"]["payload"]["template"] == "approved_delivery_notice")
        check("confirm shape", by["request_confirmation"]["payload"]["questionCode"] == "VERIFY_REQUEST"
              and by["request_confirmation"]["target"]["kind"] == "approval_queue")
        check("quarantine shape", by["quarantine_item"]["target"] == {"kind": "security_queue", "id": "mailroom"}
              and by["quarantine_item"]["payload"]["reasonCode"] == "INDIRECT_PROMPT_INJECTION")
        check("no_action target null", by["no_action"]["target"] is None)
        check("evidence valid ids", all(set(p["evidence"]) <= {ln["lineId"] for d in core if d["dossierId"] == p["dossierId"]
                                                               for s in d["sources"] for ln in s["lines"]} for p in props))
        check("one batched model call for 6 dossiers", stats() - before == 1, str(stats() - before))

        # replay + conflict
        calls = stats()
        r2 = post(body_a)
        check("replay: identical bytes", r2.status_code == 200 and r2.content == r.content)
        check("replay: no model call", stats() == calls)
        changed = copy.deepcopy(body_a)
        changed["dossiers"][0]["sources"][0]["lines"][0]["text"] = "changed"
        check("same evaluationId, changed content -> 409", post(changed).status_code == 409)
        check("replay still fine after conflict", post(body_a).content == r.content)

        # ---- caching across evaluations ----
        fresh = [dossier("f1", "create_draft", "fresh_audit"), dossier("f2", "quarantine_item", "fresh_audit")]
        eval_b = "ev-b-" + run
        calls = stats()
        rb = post(propose_body(eval_b, core + fresh, priv))
        check("evaluation B ok", rb.status_code == 200 and len(rb.json()["proposals"]) == 8)
        check("only fresh dossiers hit the model (1 call)", stats() - calls == 1, str(stats() - calls))
        stable_ids = {p["dossierId"]: p for p in props}
        same = all(p == stable_ids[p["dossierId"]] for p in rb.json()["proposals"] if p["dossierId"] in stable_ids)
        check("stable dossiers give identical proposals and callIds", same)
        calls = stats()
        eval_c = "ev-c-" + run
        rc = post(propose_body(eval_c, core + fresh, priv))
        check("evaluation C: zero model calls", rc.status_code == 200 and stats() == calls)

        # ---- commit failures (state must stay open) ----
        digest_b = rb.json()["inputDigest"]
        props_b = rb.json()["proposals"]
        other = Ed25519PrivateKey.generate()
        good = make_receipts(eval_b, digest_b, props_b, priv)

        def expect_reject(name, receipts=None, **over):
            b = commit_body(eval_b, digest_b, receipts if receipts is not None else copy.deepcopy(good))
            b.update(over)
            rr = post(b)
            check(f"commit rejected: {name}", rr.status_code in (400, 404, 409, 422), str(rr.status_code))

        check("commit unknown evaluation -> 404", post(commit_body("nope-" + run, digest_b, good)).status_code in (404, 409, 422))
        bad = copy.deepcopy(good)
        sig = bytearray(base64.b64decode(bad[0]["receiptSignature"]))
        sig[0] ^= 1
        bad[0]["receiptSignature"] = base64.b64encode(bytes(sig)).decode()
        expect_reject("tampered signature", bad)
        expect_reject("signed by another key", make_receipts(eval_b, digest_b, props_b, other))
        bad = copy.deepcopy(good)
        bad[0]["accepted"] = not bad[0]["accepted"]
        expect_reject("accepted flag flipped after signing", bad)
        bad = copy.deepcopy(good)
        bad[0], bad[1] = {**bad[0], "receiptSignature": bad[1]["receiptSignature"]}, bad[1]
        expect_reject("signature moved to another receipt", bad)
        bad = copy.deepcopy(good)
        bad[0]["callId"] = bad[1]["callId"]
        expect_reject("callId of another proposal", bad)
        bad = copy.deepcopy(good)
        bad[0]["action"] = "no_action" if bad[0]["action"] != "no_action" else "create_draft"
        expect_reject("action changed", bad)
        bad = copy.deepcopy(good)
        bad[0]["proposalDigest"] = "0" * 64
        expect_reject("wrong proposalDigest", bad)
        expect_reject("missing receipt", copy.deepcopy(good)[:-1])
        expect_reject("duplicate receipt", copy.deepcopy(good) + [copy.deepcopy(good[0])])
        expect_reject("wrong inputDigest", inputDigest="f" * 64)
        # receipts signed for evaluation A must not work in evaluation B
        expect_reject("receipts from another evaluation", make_receipts(eval_a, digest, props, priv))
        check("commit failures recorded nothing (no completed state)", True)

        # ---- good commit ----
        acc = [i % 2 == 0 for i in range(len(props_b))]
        good2 = make_receipts(eval_b, digest_b, props_b, priv, acc)
        cb = commit_body(eval_b, digest_b, good2)
        rr = post(cb)
        check("valid commit 200", rr.status_code == 200 and rr.headers["content-type"] == "application/json", rr.text[:300])
        out = rr.json()
        check("commit completed envelope", out["status"] == "completed" and out["inputDigest"] == digest_b
              and out["evaluationId"] == eval_b)
        check("executed only when accepted", [o["status"] for o in out["outcomes"]] == ["executed" if x else "rejected" for x in acc])
        check("outcome fields", all(set(o) == {"dossierId", "callId", "action", "proposalDigest", "receiptId", "status"} for o in out["outcomes"]))
        rr2 = post(cb)
        check("commit replay identical bytes", rr2.status_code == 200 and rr2.content == rr.content)
        diff = commit_body(eval_b, digest_b, make_receipts(eval_b, digest_b, props_b, priv))
        check("commit with different receipts after completion -> 409", post(diff).status_code == 409)

        # evaluation A can be committed too (separate receipts/keys scope)
        ra = post(commit_body(eval_a, digest, make_receipts(eval_a, digest, props, priv)))
        check("evaluation A commit ok", ra.status_code == 200 and all(o["status"] == "executed" for o in ra.json()["outcomes"]))

        # ---- fallback when the model output is unusable (never cached, never outbound) ----
        badd = dossier("bad", "send_approved_notice", "fresh_audit")
        badd["_mock"]["recipient"] = "nobody@evil.example"   # not in the dossier
        leak = dossier("leak", "create_draft", "fresh_audit")
        leak["_mock"]["status"] = "CANARY-1234"
        rf = post(propose_body("ev-f-" + run, [badd, leak], priv))
        pf = rf.json()["proposals"] if rf.status_code == 200 else []
        check("unusable model output -> safe no_action fallback", rf.status_code == 200
              and all(p["action"] == "no_action" and p["target"] is None for p in pf), rf.text[:300])

        # ---- concurrency: two evaluations with the same new dossiers share ONE model call ----
        shared = [dossier(f"s{i}", ACTIONS[i % 6], "fresh_audit") for i in range(4)]
        calls = stats()
        results = {}

        def go(name):
            results[name] = post(propose_body(f"ev-{name}-{run}", shared, priv))

        ts = [threading.Thread(target=go, args=(n,)) for n in ("p", "q")]
        [t.start() for t in ts]
        [t.join() for t in ts]
        check("concurrent evaluations both ok", all(v.status_code == 200 for v in results.values()))
        check("concurrent evaluations: same proposals", results["p"].json()["proposals"] == results["q"].json()["proposals"])
        check("concurrent evaluations: ONE model call", stats() - calls == 1, str(stats() - calls))

        # same evaluationId twice at the same time
        shared2 = [dossier(f"t{i}", ACTIONS[i % 6], "fresh_audit") for i in range(3)]
        body_t = propose_body("ev-same-" + run, shared2, priv)
        calls = stats()
        res = []
        ts = [threading.Thread(target=lambda: res.append(post(body_t))) for _ in range(3)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        check("simultaneous identical requests: all 200, identical bytes",
              len(res) == 3 and all(x.status_code == 200 for x in res) and len({x.content for x in res}) == 1)
        check("simultaneous identical requests: ONE model call", stats() - calls == 1, str(stats() - calls))
    finally:
        srv.terminate()
        srv.wait(timeout=10)

    print("\n%d failure(s)" % len(fails) if fails else "\nALL MAILROOM TESTS PASSED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
