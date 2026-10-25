"""Incident agent service (project 3): persistent runs, receipt-driven state machine, replay and conflicts.

Layers (kept separate on purpose):
  incident_plan.py   -> the ONLY model call (one per first-seen runId)
  incident.py        -> this file: validation, state machine, storage, response views
  incident_trace.py  -> OTLP trace, built from stored dispatches/receipts only
Replays, GET, receipts and retries never call a model and never rebuild actions.
"""
import hashlib
import json
import logging
import re
import secrets
import time
from typing import Dict, List, Optional, Tuple

from . import config, incident_plan as planner
from .errors import ApiError
from .incident_trace import build_otlp
from .store import store

log = logging.getLogger("incident")

PROFILE = "ga5-incident-agent/v2"
TP_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
EMITTED_KEYS = {"arguments", "approvalId", "approvalNonce", "transcript", "sensitive", "authorization", "result", "prompt"}


# ----------------------------------------------------------------------------
# small helpers
# ----------------------------------------------------------------------------
def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def jdump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _bad(msg: str, code: str = "INVALID_REQUEST", status: int = 422) -> ApiError:
    return ApiError(status, code, msg)


def _is_str(v, n: int = 4096) -> bool:
    return isinstance(v, str) and 0 < len(v) <= n


def _hexid(nbytes: int, used: set) -> str:
    while True:
        v = secrets.token_hex(nbytes)
        if int(v, 16) != 0 and v not in used:
            used.add(v)
            return v


def parse_traceparent(h: Optional[str]) -> Optional[Tuple[str, str]]:
    if not h:
        return None
    m = TP_RE.match(h.strip())
    if not m or int(m.group(1), 16) == 0 or int(m.group(2), 16) == 0:
        return None
    return m.group(1), m.group(2)


def _leaves(obj, acc: List[str]) -> None:
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _leaves(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _leaves(v, acc)


def forbidden_strings(body: dict) -> List[str]:
    acc: List[str] = []
    _leaves(body.get("sensitive"), acc)
    for x in (body.get("policy") or {}).get("doNotExport") or []:
        if isinstance(x, str) and len(x) >= 8 and x not in EMITTED_KEYS:
            acc.append(x)
    out = sorted({a for a in acc if len(a) >= 6}, key=len, reverse=True)
    return out


def scrub(obj, forbidden: List[str]):
    """Last line of defence: no sensitive value may appear in any outgoing value."""
    if not forbidden:
        return obj
    if isinstance(obj, str):
        for f in forbidden:
            if f in obj:
                obj = obj.replace(f, "[REDACTED]")
        return obj
    if isinstance(obj, dict):
        return {k: scrub(v, forbidden) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v, forbidden) for v in obj]
    return obj


def dump(obj, forbidden: List[str]) -> str:
    return jdump(scrub(obj, forbidden))


# ----------------------------------------------------------------------------
# request validation (before any storage or model work)
# ----------------------------------------------------------------------------
def validate_create(body: dict) -> None:
    if body.get("profile") != PROFILE:
        raise _bad("unsupported profile", "UNSUPPORTED_PROFILE", 400)
    if not _is_str(body.get("runId"), 256):
        raise _bad("runId is required")
    for f in ("agentName", "publicMarker"):
        if not _is_str(body.get(f), 256):
            raise _bad(f"{f} is required")
    if "sensitive" in body and not isinstance(body["sensitive"], dict):
        raise _bad("sensitive must be an object")
    inc = body.get("incident")
    if not isinstance(inc, dict):
        raise _bad("incident is required")
    if not isinstance(inc.get("transcript"), str) or not inc["transcript"].strip():
        raise _bad("incident.transcript is required")
    ar = inc.get("allowedRootCauses")
    if not isinstance(ar, list) or not ar or not all(isinstance(x, str) and x for x in ar):
        raise _bad("incident.allowedRootCauses must be a non-empty list of strings")
    for f in ("incidentId", "title", "service", "severity"):
        if f in inc and not isinstance(inc[f], str):
            raise _bad(f"incident.{f} must be a string")
    cat = body.get("toolCatalog")
    if not isinstance(cat, list) or not cat or not all(isinstance(t, dict) and _is_str(t.get("name"), 200) for t in cat):
        raise _bad("toolCatalog must be a non-empty list of tools")
    if len({t["name"] for t in cat}) != len(cat):
        raise _bad("toolCatalog has duplicate tool names")
    pol = body.get("policy")
    if not isinstance(pol, dict):
        raise _bad("policy is required")
    et = pol.get("effectTools")
    if not isinstance(et, list) or not et or not all(isinstance(x, str) for x in et):
        raise _bad("policy.effectTools must be a non-empty list of strings")
    for f in ("approvalRequiredFor", "doNotExport"):
        if f in pol and not (isinstance(pol[f], list) and all(isinstance(x, str) for x in pol[f])):
            raise _bad(f"policy.{f} must be a list of strings")
    md = pol.get("maximumDiagnostics", 3)
    if not isinstance(md, int) or isinstance(md, bool) or md < 1:
        raise _bad("policy.maximumDiagnostics must be a positive integer")


def validate_receipt(body: dict) -> None:
    if not _is_str(body.get("receiptId"), 256):
        raise _bad("receiptId is required")
    outs, apps = body.get("outcomes"), body.get("approvals")
    for name, v in (("outcomes", outs), ("approvals", apps)):
        if v is not None and not isinstance(v, list):
            raise _bad(f"{name} must be a list")
    if not outs and not apps:
        raise _bad("a receipt needs outcomes or approvals")
    if outs:
        if not isinstance(outs, list):
            raise _bad("outcomes must be a list")
        for o in outs:
            if not isinstance(o, dict):
                raise _bad("each outcome must be an object")
            for f in ("actionId", "callId", "nonce"):
                if not _is_str(o.get(f), 512):
                    raise _bad(f"outcome.{f} is required")
            if not isinstance(o.get("attempt"), int) or isinstance(o.get("attempt"), bool) or o["attempt"] < 1:
                raise _bad("outcome.attempt must be a positive integer")
            if not isinstance(o.get("status"), int) or isinstance(o.get("status"), bool):
                raise _bad("outcome.status must be an integer")
            for f in ("resultClass", "errorType"):
                if f in o and o[f] is not None and not isinstance(o[f], str):
                    raise _bad(f"outcome.{f} must be a string")
    if apps:
        for a in apps:
            if not isinstance(a, dict) or not _is_str(a.get("approvalId"), 512) or not _is_str(a.get("nonce"), 512) \
                    or not _is_str(a.get("decision"), 64):
                raise _bad("each approval needs approvalId, decision and nonce")


# ----------------------------------------------------------------------------
# state construction and views
# ----------------------------------------------------------------------------
def _action_ids(run_id: str, kind: str, i: int) -> Tuple[str, str]:
    h = sha(f"{run_id}|{kind}|{i}")
    return f"act_{h[:20]}", f"call_{h[20:40]}"


def _dispatch(st: dict, a: dict, att: dict) -> dict:
    tr = st["trace"]
    d = {"actionId": a["actionId"], "callId": a["callId"], "phase": a["phase"], "toolName": a["toolName"],
         "arguments": a["arguments"], "evidence": a["evidence"], "attempt": att["attempt"],
         "traceparent": f"00-{tr['traceId']}-{att['clientSpanId']}-01"}
    if tr.get("traceState"):
        d["tracestate"] = tr["traceState"]
    if a.get("approvalId"):
        d["approvalId"] = a["approvalId"]
        d["approvalNonce"] = a["approvalNonce"]
    return d


def _new_attempt(st: dict, a: dict, now: int) -> dict:
    att = {"attempt": len(a["attempts"]) + 1, "clientSpanId": _hexid(8, st["_used"]), "dispatchedAt": now, "receipt": None}
    a["attempts"].append(att)
    d = _dispatch(st, a, att)
    st["actionLog"].append(d)
    return d


def _new_action(st: dict, kind: str, idx: int, phase: str, call: dict, now: int, extra: Optional[dict] = None) -> Tuple[dict, dict]:
    aid, cid = _action_ids(st["runId"], kind, idx)
    a = {"actionId": aid, "callId": cid, "phase": phase, "toolName": call["toolName"], "arguments": call["arguments"],
         "evidence": call["evidence"], "execSpanId": _hexid(8, st["_used"]), "status": "pending", "attempts": []}
    if extra:
        a.update(extra)
    st["actions"][aid] = a
    st["order"].append(aid)
    return a, _new_attempt(st, a, now)


def new_state(body: dict, plan_: dict, model: dict, headers: dict, t0: int) -> Tuple[dict, List[dict]]:
    used: set = set()
    inc = parse_traceparent(headers.get("traceparent")) or parse_traceparent(body.get("traceparent") if isinstance(body.get("traceparent"), str) else None)
    tr = {"traceId": inc[0] if inc else _hexid(16, used)}
    ts = headers.get("tracestate") or (body.get("tracestate") if isinstance(body.get("tracestate"), str) else "")
    if inc:
        tr["parentSpanId"] = inc[1]
        if ts:
            tr["traceState"] = ts
    used.add(tr["traceId"])
    for k in ("serverSpanId", "agentSpanId", "chatSpanId", "joinSpanId", "gateSpanId"):
        tr[k] = _hexid(8, used)
    st = {"runId": body["runId"], "agentName": body["agentName"], "publicMarker": body["publicMarker"],
          "trace": tr, "t0": t0, "model": model,
          "diagnosis": {"rootCause": plan_["rootCause"], "evidence": plan_["evidence"]},
          "plan": {"effect": plan_["effect"], "needsApproval": plan_["effect"]["toolName"] in (body["policy"].get("approvalRequiredFor") or [])},
          "actions": {}, "order": [], "actionLog": [], "receiptLog": [], "approval": None,
          "status": "waiting", "chosenEffect": None, "suppressed": [], "finalAt": None,
          "_used": used, "_forbidden": forbidden_strings(body)}
    now = time.time_ns()
    dispatches = []
    for i, c in enumerate(plan_["diagnostics"]):
        _, d = _new_action(st, "diag", i, "diagnostic", c, now)
        dispatches.append(d)
    return st, dispatches


def _pending_dispatches(st: dict) -> List[dict]:
    out = []
    for aid in st["order"]:
        a = st["actions"][aid]
        if a["status"] == "pending" and a["attempts"] and not a["attempts"][-1]["receipt"]:
            n = a["attempts"][-1]["attempt"]
            out += [d for d in st["actionLog"] if d["actionId"] == aid and d["attempt"] == n]
    return out


def _approval_request(st: dict) -> List[dict]:
    ap = st.get("approval")
    if ap and ap["state"] == "pending":
        return [{"approvalId": ap["approvalId"], "actionId": ap["actionId"], "toolName": ap["toolName"],
                 "argumentsDigest": ap["argumentsDigest"]}]
    return []


def view(st: dict, dispatches: List[dict], approvals: List[dict]) -> dict:
    out = {"runId": st["runId"], "status": st["status"], "diagnosis": st["diagnosis"]}
    if st["status"] == "waiting":
        out["dispatches"] = dispatches
        out["approvals"] = approvals
    else:
        out["chosenEffect"] = st["chosenEffect"]
        out["suppressed"] = st["suppressed"]
    if st["status"] != "waiting":
        out["actionLog"] = st["actionLog"]
        out["receiptLog"] = st["receiptLog"]
        out["otlp"] = st["otlp"]
    return out


def _finalize(st: dict, status: str, now: int) -> None:
    eff = st["plan"]["effect"]["toolName"]
    dispatched = any(st["actions"][a]["phase"] == "effect" for a in st["order"])
    st["status"] = status
    st["chosenEffect"] = eff if dispatched else None
    st["suppressed"] = [] if dispatched else [eff]
    st["finalAt"] = now
    st["otlp"] = build_otlp(st)


# ----------------------------------------------------------------------------
# the receipt-driven state machine
# ----------------------------------------------------------------------------
def apply_receipt(st: dict, body: dict, now: int) -> Tuple[List[dict], List[dict]]:
    """Mutates st. Raises ApiError BEFORE any mutation if the receipt is not valid for the current state."""
    if st["status"] != "waiting":
        raise _bad("the run is already finished", "INVALID_STATE")
    outs = body.get("outcomes") or []
    apps = body.get("approvals") or []

    seen = set()
    for o in outs:
        a = st["actions"].get(o["actionId"])
        if a is None or a["status"] != "pending":
            raise _bad("outcome does not match a pending call", "INVALID_STATE")
        att = a["attempts"][-1]
        if att["receipt"] is not None or att["attempt"] != o["attempt"] or a["callId"] != o["callId"]:
            raise _bad("outcome does not match the pending attempt", "INVALID_STATE")
        if o["actionId"] in seen:
            raise _bad("duplicate outcome for one action", "INVALID_STATE")
        seen.add(o["actionId"])
    ap = st.get("approval")
    for x in apps:
        if not ap or ap["state"] != "pending" or ap["approvalId"] != x["approvalId"]:
            raise _bad("approval does not match a pending request", "INVALID_STATE")
    if len(apps) > 1:
        raise _bad("only one approval can be pending", "INVALID_STATE")

    new_dispatches: List[dict] = []
    new_approvals: List[dict] = []

    for o in outs:
        a = st["actions"][o["actionId"]]
        att = a["attempts"][-1]
        status = o["status"]
        att["receipt"] = {"receiptId": body["receiptId"], "status": status, "resultClass": o.get("resultClass"),
                          "errorType": o.get("errorType"), "nonce": o["nonce"], "at": now}
        entry = {"receiptId": body["receiptId"], "actionId": a["actionId"], "callId": a["callId"],
                 "attempt": o["attempt"], "status": status}
        if o.get("resultClass") is not None:
            entry["resultClass"] = o["resultClass"]
        if o.get("errorType") is not None:
            entry["errorType"] = o["errorType"]
        entry["nonce"] = o["nonce"]
        st["receiptLog"].append(entry)
        if 200 <= status < 300:
            a["status"] = "ok"
        elif status == 503 and o["attempt"] == 1:
            new_dispatches.append(_new_attempt(st, a, now))  # exactly one retry, new CLIENT span id
        else:
            a["status"] = "failed"

    if apps:
        x = apps[0]
        ap["receiptId"], ap["nonce"], ap["decision"], ap["decidedAt"] = body["receiptId"], x["nonce"], x["decision"], now
        ap["state"] = "approved" if x["decision"] == "approved" else "denied"
        st["receiptLog"].append({"receiptId": body["receiptId"], "approvalId": ap["approvalId"],
                                 "decision": x["decision"], "nonce": x["nonce"]})
        if ap["state"] == "approved":
            eff = st["plan"]["effect"]
            _, d = _new_action(st, "effect", 0, "effect", eff, now,
                               {"actionId_reserved": ap["actionId"], "approvalId": ap["approvalId"], "approvalNonce": x["nonce"]})
            new_dispatches.append(d)
        else:
            _finalize(st, "failed", now)
            return [], []

    d2, a2 = _advance(st, now)
    return new_dispatches + d2, a2


def _advance(st: dict, now: int) -> Tuple[List[dict], List[dict]]:
    acts = [st["actions"][a] for a in st["order"]]
    if any(a["status"] == "pending" for a in acts):
        return [], []
    if any(a["status"] == "failed" for a in acts):
        _finalize(st, "failed", now)  # a failed diagnostic suppresses the dependent effect
        return [], []
    effect = [a for a in acts if a["phase"] == "effect"]
    if effect:
        _finalize(st, "completed", now)
        return [], []
    eff = st["plan"]["effect"]
    if st["plan"]["needsApproval"]:
        if st.get("approval") is None:
            aid, _ = _action_ids(st["runId"], "effect", 0)  # reserves the id the effect dispatch will use
            st["approval"] = {"approvalId": "appr_" + sha(f"{st['runId']}|approval")[:20], "actionId": aid,
                              "toolName": eff["toolName"], "argumentsDigest": sha(canon(eff["arguments"])),
                              "state": "pending", "requestedAt": now}
            return [], _approval_request(st)
        return [], []
    _, d = _new_action(st, "effect", 0, "effect", eff, now)
    return [d], []


# ----------------------------------------------------------------------------
# storage-facing operations
# ----------------------------------------------------------------------------
def _clean_state_out(st: dict) -> str:
    return jdump({k: v for k, v in st.items() if k != "_used"} | {"_used": sorted(st["_used"])})


def _load_state(text: str) -> dict:
    st = json.loads(text)
    st["_used"] = set(st.get("_used", []))
    return st


def _claim(run_id: str, req_hash: str):
    with store.txn() as c:
        got = c.execute("INSERT INTO inc_runs(run_id, req_hash) VALUES (%s,%s) ON CONFLICT DO NOTHING RETURNING 1 AS ok",
                        (run_id, req_hash)).fetchone()
        if got:
            return "won", None
        row = c.execute("SELECT req_hash, state, create_response, (now() - claimed_at) > make_interval(secs => %s) AS stale "
                        "FROM inc_runs WHERE run_id=%s FOR UPDATE", (config.PENDING_STALE_SECONDS, run_id)).fetchone()
        if row is None:
            return "pending", None
        if row["req_hash"] != req_hash:
            return "conflict", None
        if row["state"]:
            return "done", row
        if row["stale"]:
            c.execute("UPDATE inc_runs SET claimed_at=now() WHERE run_id=%s", (run_id,))
            return "won", None
        return "pending", None


def _release(run_id: str) -> None:
    try:
        with store.txn() as c:
            c.execute("DELETE FROM inc_runs WHERE run_id=%s AND state IS NULL", (run_id,))
    except Exception:
        pass


def _replay_text(row: dict) -> str:
    if config.INCIDENT_REPLAY_MODE == "current":
        st = _load_state(row["state"])
        return dump(view(st, _pending_dispatches(st), _approval_request(st)), st["_forbidden"])
    return row["create_response"]


_sampled = {"n": 0, "r": 0}


def _log_receipt_shape(run_id: str, body: dict) -> None:
    if _sampled["r"] >= 8:
        return
    _sampled["r"] += 1
    try:
        o = (body.get("outcomes") or [{}])[0] if isinstance(body.get("outcomes"), list) and body.get("outcomes") else {}
        a = (body.get("approvals") or [{}])[0] if isinstance(body.get("approvals"), list) and body.get("approvals") else {}
        log.info("RECEIPT_SHAPE run=%s keys=%s outcome_keys=%s approval_keys=%s n_out=%s n_app=%s", run_id, sorted(body.keys()),
                 sorted(o.keys()) if isinstance(o, dict) else o, sorted(a.keys()) if isinstance(a, dict) else a,
                 len(body.get("outcomes") or []), len(body.get("approvals") or []))
    except Exception:
        pass


def _log_sample(body: dict, headers: Optional[dict] = None) -> None:
    if _sampled["n"] >= 6:
        return
    _sampled["n"] += 1
    log.info("INCIDENT_HEADERS traceparent=%s tracestate=%s body_traceparent=%s", (headers or {}).get("traceparent"),
             (headers or {}).get("tracestate"), body.get("traceparent"))
    try:
        inc, pol = body["incident"], body["policy"]
        log.info("INCIDENT_SAMPLE keys=%s incident_keys=%s lines=%d allowed=%s policy=%s tools=%s head=%s",
                 list(body.keys()), list(inc.keys()), inc["transcript"].count("\n") + 1, inc["allowedRootCauses"],
                 json.dumps({k: v for k, v in pol.items() if k != "doNotExport"}),
                 json.dumps([{"name": t.get("name"), "schema": t.get("inputSchema")} for t in body["toolCatalog"]])[:3000],
                 inc["transcript"][:600].replace("\n", " | "))
    except Exception:
        pass


def create(body: dict, headers: dict) -> Tuple[int, str]:
    t0 = time.time_ns()
    started = time.monotonic()
    validate_create(body)
    run_id = body["runId"]
    req_hash = sha(canon(body))
    wait_until = started + 14
    while True:
        state, row = _claim(run_id, req_hash)
        if state == "won":
            break
        if state == "done":
            return 200, _replay_text(row)
        if state == "conflict":
            raise ApiError(409, "RUN_CONFLICT", "This runId was already used with different content.")
        if time.monotonic() > wait_until:
            raise ApiError(503, "BUSY", "The same request is still being processed; retry shortly.")
        time.sleep(0.3)
    try:
        _log_sample(body, headers)
        plan_, model = planner.plan(body, started + config.INCIDENT_BUDGET_SECONDS)
        st, dispatches = new_state(body, plan_, model, headers, t0)
        out = view(st, dispatches, [])
        text = dump(out, st["_forbidden"])
        with store.txn() as c:
            c.execute("UPDATE inc_runs SET state=%s, create_response=%s WHERE run_id=%s", (_clean_state_out(st), text, run_id))
        log.info("incident %s planned: cause=%s diag=%s effect=%s approval=%s model=%s %.1fs", run_id,
                 plan_["rootCause"], [d["toolName"] for d in plan_["diagnostics"]], plan_["effect"]["toolName"],
                 st["plan"]["needsApproval"], model["name"], time.monotonic() - started)
        return 200, text
    except BaseException:
        _release(run_id)
        raise


def receipt(run_id: str, body: dict) -> Tuple[int, str]:
    _log_receipt_shape(run_id, body)
    validate_receipt(body)
    rid = body["receiptId"]
    rhash = sha(canon(body))
    with store.txn() as c:
        row = c.execute("SELECT state FROM inc_runs WHERE run_id=%s FOR UPDATE", (run_id,)).fetchone()
        if row is None or not row["state"]:
            raise ApiError(404, "UNKNOWN_RUN", "No such run.")
        prev = c.execute("SELECT rhash, response FROM inc_receipts WHERE run_id=%s AND receipt_id=%s", (run_id, rid)).fetchone()
        if prev:
            if prev["rhash"] != rhash:
                raise ApiError(409, "RECEIPT_CONFLICT", "This receiptId was already used with different content.")
            return 200, prev["response"]  # identical replay: stored response, no new effect
        st = _load_state(row["state"])
        d, a = apply_receipt(st, body, time.time_ns())  # raises before mutating on an invalid state change
        text = dump(view(st, d, a), st["_forbidden"])
        c.execute("UPDATE inc_runs SET state=%s WHERE run_id=%s", (_clean_state_out(st), run_id))
        c.execute("INSERT INTO inc_receipts(run_id, receipt_id, rhash, response) VALUES (%s,%s,%s,%s)", (run_id, rid, rhash, text))
    log.info("incident %s receipt %s -> %s", run_id, rid, st["status"])
    return 200, text


def get(run_id: str) -> Tuple[int, str]:
    with store.txn() as c:
        row = c.execute("SELECT state FROM inc_runs WHERE run_id=%s", (run_id,)).fetchone()
    if row is None or not row["state"]:
        raise ApiError(404, "UNKNOWN_RUN", "No such run.")
    st = _load_state(row["state"])
    return 200, dump(view(st, _pending_dispatches(st), _approval_request(st)), st["_forbidden"])
