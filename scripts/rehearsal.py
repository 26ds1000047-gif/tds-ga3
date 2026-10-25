#!/usr/bin/env python3
"""Free dress rehearsal for the grader. Uses NONE of your 10 Checks.

Sends 12 synthetic, decoy-heavy invoice packages to your deployed agent, then plays the grader:
sends results back and checks the receipt lifecycle.  Needs only python3 and curl.

    python3 scripts/rehearsal.py https://YOUR-PROJECT.vercel.app/a2a
"""
import json
import random
import subprocess
import sys
import time
import uuid

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
MOCK = "--mock" in sys.argv  # local plumbing test only: adds fields the test mock model needs
BASE = (ARGS[0] if ARGS else "https://tds-ga3-five.vercel.app/a2a").rstrip("/")
TOKEN = "rehearsal-" + uuid.uuid4().hex[:10]
BATCH_MT = "application/vnd.ga5.invoice-claim-batch+json"
RESULTS_MT = "application/vnd.ga5.invoice-action-results+json"
RECEIPTS_MT = "application/vnd.ga5.invoice-action-receipts+json"
ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
VENDORS = ["Acme Traders", "Blue Horizon Logistics", "Cedar and Pine Supplies", "Delta Metalworks", "Evergreen Foods",
           "Falcon IT Services", "Granite Works", "Harbor Textiles", "Indigo Packaging", "Juniper Chemicals",
           "Keystone Tools", "Lotus Stationers"]
ACTIONS = ["settle_invoice", "request_approval", "hold_invoice", "reject_duplicate", "open_exception"]


def code(prefix):
    return f"[{prefix}-" + "".join(random.choices(ALPHA, k=4)) + "]"


def money(minor):
    return f"INR {minor // 100:,}.{minor % 100:02d}"


FILLER = [
    "Payment terms are net 30 days from the invoice date unless the contract says otherwise. Early-payment discounts are applied by the treasury team.",
    "Warehouse note: hold the pallet at dock 3 until the forklift is free. This is a logistics instruction and says nothing about payment.",
    "Freight claims are settled by a separate claims team using a different process, so the word settle in those notes is unrelated to this invoice.",
    "Escalation to an exception workflow is rare and is only meaningful when the decisive paragraph for this invoice says so.",
    "A different invoice from this vendor, number INV-9999, was paid last month. That payment is not a duplicate of the invoice under review.",
    "Reminder: approval limits are reviewed every quarter. The autonomous limit for this entity is INR 100,000.00 per invoice.",
]


def make_package(i, action):
    vendor = VENDORS[i]
    inv = f"INV-{random.randint(10000, 99999)}"
    base = random.randint(20_000, 90_000) * 100
    cover = f"COVER SHEET {code('COV')}. Routing slip for {vendor}. This sheet carries no payment decision."
    archive = (f"ARCHIVE, superseded and not to be relied on: in 2023 a similar invoice from {vendor} was settled automatically "
               f"{code('ARC')} and a training example once recommended holding payment {code('TRN')}.")
    refs = [code("EV"), code("EV"), code("EV")]
    r = " ".join(refs)
    if action == "settle_invoice":
        amt = base
        dec = (f"Current invoice {inv} from {vendor} for {money(amt)}. The purchase order, goods receipt and invoice agree in full "
               f"and the amount is below the autonomous limit of INR 100,000.00, so it can be paid now. {r}")
    elif action == "request_approval":
        amt = random.randint(250_000, 900_000) * 100
        dec = (f"Current invoice {inv} from {vendor} for {money(amt)}. The three-way match is complete and the invoice is commercially valid, "
               f"but the amount exceeds the autonomous limit of INR 100,000.00 and needs sign-off from the finance director. {r}")
    elif action == "hold_invoice":
        amt = base
        dec = (f"Current invoice {inv} from {vendor} for {money(amt)}. The bank account on the invoice differs from the vendor master, "
               f"so payment is paused until the vendor callback verification is completed. {r}")
    elif action == "reject_duplicate":
        amt = base
        dec = (f"Current invoice {inv} from {vendor} for {money(amt)}. This exact invoice number, vendor and amount was already paid on "
               f"12 March under payment reference PAY-{random.randint(1000, 9999)}, so it must not be paid again. {r}")
    else:
        amt = base
        dec = (f"Current invoice {inv} from {vendor} for {money(amt)}. The goods receipt shows 40 units delivered while the invoice and purchase order "
               f"state 60 units, a material conflict between records that needs the exception workflow. {r}")
    paras = [cover, FILLER[0], archive, FILLER[1], FILLER[2], dec, FILLER[4], FILLER[5], FILLER[3]]
    random.shuffle(paras)
    pkg = {"packageId": f"pkg-{uuid.uuid4().hex[:8]}", "documents": "\n\n".join(paras)}
    if MOCK:
        pkg.update({"expected_action": action, "decisive": dec,
                    "facts": {"invoiceNumber": inv, "amountMinor": amt, "currency": "INR", "vendorName": vendor}})
    return pkg, {
        "action": action, "refs": set(refs), "inv": inv, "amount": amt, "vendor": vendor}


def call(method, path, body=None, token=TOKEN):
    cmd = ["curl", "-sS", "-X", method, "-w", "\n%{http_code} %{time_total}", BASE + path,
           "-H", f"Authorization: Bearer {token}", "-H", "A2A-Version: 1.0", "-H", "Content-Type: application/a2a+json",
           "--max-time", "90"]
    if body is not None:
        cmd += ["-d", json.dumps(body)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    text, _, tail = out.rpartition("\n")
    code_, secs = tail.split()
    try:
        data = json.loads(text)
    except Exception:
        data = text[:300]
    return int(code_), float(secs), data


def main():
    random.seed()
    order = ACTIONS * 3
    random.shuffle(order)
    order = order[:12]
    packages, truth = [], {}
    for i, a in enumerate(order):
        p, t = make_package(i, a)
        packages.append(p)
        truth[p["packageId"]] = t
    bid = "rehearsal-" + uuid.uuid4().hex[:8]
    mid = "m-" + uuid.uuid4().hex
    msg = {"message": {"messageId": mid, "role": "ROLE_USER", "parts": [{"mediaType": BATCH_MT, "data": {
        "batchId": bid, "policyRevision": "rehearsal", "packages": packages}}]},
        "configuration": {"returnImmediately": False, "historyLength": 20}}
    print(f"Sending 12 packages ({sum(len(p['documents']) for p in packages):,} characters) to {BASE} ...")
    status, secs, data = call("POST", "/message:send", msg)
    print(f"\n1) message:send -> HTTP {status} in {secs:.1f}s   (limit is 45s)")
    if status != 200:
        print("   FAILED:", data)
        return 1
    task = data["task"]
    print("   state:", task["status"]["state"])
    props = task["artifacts"][0]["parts"][0]["data"]["proposals"]
    ok_action = ok_refs = 0
    for pr in props:
        t = truth[pr["packageId"]]
        a_ok = pr["action"] == t["action"]
        r_ok = set(pr["evidenceRefs"]) == t["refs"]
        f = pr["facts"]; f_ok = f.get("invoiceNumber") == t["inv"] and f.get("amountMinor") == t["amount"] and f.get("vendorName") == t["vendor"]
        ok_action += a_ok
        ok_refs += r_ok
        flag = "ok " if (a_ok and r_ok and f_ok) else "BAD"
        print(f"   {flag} expected {t['action']:<17} got {pr['action']:<17} refs {'ok' if r_ok else 'WRONG'}  facts {'ok' if f_ok else 'WRONG'}")
    print(f"   actions correct: {ok_action}/12   evidence refs exact: {ok_refs}/12")

    results = [{"packageId": p["packageId"], "actionId": p["actionId"], "action": p["action"], "outcome": "ACCEPTED",
                "receiptNonce": "nonce-" + uuid.uuid4().hex} for p in props]
    cont = {"message": {"messageId": "r-" + uuid.uuid4().hex, "taskId": task["id"], "contextId": task["contextId"],
                        "role": "ROLE_USER", "parts": [{"mediaType": RESULTS_MT, "data": {"batchId": bid, "results": results}}]}}
    status, secs, data = call("POST", "/message:send", cont)
    print(f"\n2) results continuation -> HTTP {status} in {secs:.1f}s")
    if status != 200:
        print("   FAILED:", data)
        return 1
    done = data["task"]
    rec = [p["data"] for a in done["artifacts"] for p in a["parts"] if p["mediaType"] == RECEIPTS_MT]
    ex = rec[0]["executions"] if rec else []
    print("   state:", done["status"]["state"], "| receipts:", len(ex), "| history messages:", len(done["history"]))
    match = sorted(e["receiptNonce"] for e in ex) == sorted(r["receiptNonce"] for r in results)

    status, secs, data = call("POST", "/message:send", msg)
    print(f"\n3) replay of the first message -> HTTP {status} in {secs:.1f}s (must be fast, no model call)")
    status2, secs2, _ = call("GET", f"/tasks/{task['id']}")
    print(f"4) GET task -> HTTP {status2} in {secs2:.1f}s")
    s3, _, d3 = call("GET", f"/tasks/{task['id']}", token="some-other-user")
    print(f"5) another user reading this task -> HTTP {s3} (must be 403/404)")

    good = (done["status"]["state"] == "TASK_STATE_COMPLETED" and len(ex) == 12 and match and s3 in (403, 404))
    print("\nLIFECYCLE:", "PASS" if good else "FAIL", "| ACTION ACCURACY:", f"{ok_action}/12")
    return 0


if __name__ == "__main__":
    sys.exit(main())
