"""Mailroom service (project 2): propose / commit lifecycle on one endpoint.

Layers (same idea as project 1):
  validation   -> 400/422 before any storage or model work
  persistence  -> Postgres; nothing lives in process memory
  decisions    -> mailroom_llm (the only model caller), cached by dossier content
  receipts     -> Ed25519 verification with the key stored for THAT evaluation
"""
import base64
import binascii
import json
import logging
import re
import time
from typing import Dict, List, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import config, mailroom_llm as mlm
from .errors import ApiError
from .store import store

log = logging.getLogger("mailroom")

PROFILE = "ga5-mailroom-action-gate/v2"
KNOWN_ACTIONS = set(mlm.ACTIONS)
_sampled = {"n": 0}


def _jdumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _bad(msg: str, code: str = "INVALID_REQUEST", status: int = 422) -> ApiError:
    return ApiError(status, code, msg)


def _is_str(v, maxlen: int = 4096) -> bool:
    return isinstance(v, str) and 0 < len(v) <= maxlen


# ----------------------------------------------------------------------------
# validation
# ----------------------------------------------------------------------------
def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_verifier(jwk: dict) -> Ed25519PublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not _is_str(jwk.get("x"), 200):
        raise _bad("receiptVerifier.publicKeyJwk must be an Ed25519 OKP key", "INVALID_VERIFIER")
    try:
        raw = _b64url(jwk["x"])
        if len(raw) != 32:
            raise ValueError("length")
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        raise _bad("receiptVerifier.publicKeyJwk.x is not a valid Ed25519 public key", "INVALID_VERIFIER")


def validate_propose(body: dict) -> Tuple[List[dict], dict]:
    if body.get("profile") != PROFILE:
        raise _bad("unsupported profile", "INVALID_PROFILE")
    if not _is_str(body.get("evaluationId"), 256):
        raise _bad("evaluationId is required")
    rv = body.get("receiptVerifier")
    if not isinstance(rv, dict) or rv.get("algorithm") != "Ed25519":
        raise _bad("receiptVerifier.algorithm must be Ed25519", "INVALID_VERIFIER")
    load_verifier(rv.get("publicKeyJwk"))
    aa = body.get("allowedActions")
    if not isinstance(aa, list) or not aa or not all(isinstance(a, str) for a in aa):
        raise _bad("allowedActions must be a non-empty list of strings")
    if "corpus" in body and not isinstance(body["corpus"], dict):
        raise _bad("corpus must be an object")
    ds = body.get("dossiers")
    if not isinstance(ds, list) or not ds:
        raise _bad("dossiers must be a non-empty array")
    if len(ds) > config.MAILROOM_MAX_DOSSIERS:
        raise _bad("too many dossiers", "TOO_MANY_DOSSIERS", 413)
    seen = set()
    for d in ds:
        if not isinstance(d, dict) or not _is_str(d.get("dossierId"), 256):
            raise _bad("each dossier needs a dossierId")
        if d["dossierId"] in seen:
            raise _bad("duplicate dossierId", "DUPLICATE_DOSSIER")
        seen.add(d["dossierId"])
        for f in ("partition", "receivedAt", "mailbox", "objective"):
            if f in d and not isinstance(d[f], str):
                raise _bad(f"dossier.{f} must be a string")
        srcs = d.get("sources")
        if not isinstance(srcs, list) or not srcs:
            raise _bad("each dossier needs sources")
        n_lines = 0
        for s in srcs:
            if not isinstance(s, dict) or not _is_str(s.get("sourceId"), 256):
                raise _bad("each source needs a sourceId")
            for f in ("kind", "provenance", "title"):
                if f in s and not isinstance(s[f], str):
                    raise _bad(f"source.{f} must be a string")
            lines = s.get("lines")
            if not isinstance(lines, list):
                raise _bad("source.lines must be an array")
            for ln in lines:
                if not isinstance(ln, dict) or not _is_str(ln.get("lineId"), 256) or not isinstance(ln.get("text"), str):
                    raise _bad("each line needs lineId and text")
                n_lines += 1
        if n_lines == 0:
            raise _bad("each dossier needs at least one line")
    return ds, rv


def validate_commit_shape(body: dict) -> None:
    if body.get("profile") != PROFILE:
        raise _bad("unsupported profile", "INVALID_PROFILE")
    if not _is_str(body.get("evaluationId"), 256):
        raise _bad("evaluationId is required")
    if not _is_str(body.get("inputDigest"), 128):
        raise _bad("inputDigest is required")
    rs = body.get("receipts")
    if not isinstance(rs, list) or not rs or len(rs) > config.MAILROOM_MAX_DOSSIERS:
        raise _bad("receipts must be a non-empty array")
    for r in rs:
        if not isinstance(r, dict):
            raise _bad("each receipt must be an object")
        for f in ("dossierId", "callId", "action", "proposalDigest", "receiptId", "receiptSignature"):
            if not _is_str(r.get(f), 4096):
                raise _bad(f"receipt.{f} is required")
        if not isinstance(r.get("accepted"), bool):
            raise _bad("receipt.accepted must be a boolean")


# ----------------------------------------------------------------------------
# storage helpers
# ----------------------------------------------------------------------------
def _claim_eval(eval_id: str, req_hash: str, input_digest: str, verifier: dict):
    with store.txn() as c:
        got = c.execute(
            "INSERT INTO mr_evals(evaluation_id, req_hash, input_digest, verifier) VALUES (%s,%s,%s,%s) "
            "ON CONFLICT DO NOTHING RETURNING 1 AS ok",
            (eval_id, req_hash, input_digest, _jdumps(verifier)),
        ).fetchone()
        if got:
            return "won", None
        row = c.execute(
            "SELECT req_hash, propose_response, (now() - claimed_at) > make_interval(secs => %s) AS stale "
            "FROM mr_evals WHERE evaluation_id=%s FOR UPDATE",
            (config.PENDING_STALE_SECONDS, eval_id),
        ).fetchone()
        if row is None:
            return "pending", None
        if row["req_hash"] != req_hash:
            return "conflict", None
        if row["propose_response"]:
            return "done", row["propose_response"]
        if row["stale"]:
            c.execute("UPDATE mr_evals SET claimed_at=now() WHERE evaluation_id=%s", (eval_id,))
            return "won", None
        return "pending", None


def _release_eval(eval_id: str) -> None:
    try:
        with store.txn() as c:
            c.execute("DELETE FROM mr_evals WHERE evaluation_id=%s AND propose_response IS NULL", (eval_id,))
    except Exception:
        pass


def _get_cached(keys: List[str]) -> Dict[str, dict]:
    if not keys:
        return {}
    with store.txn() as c:
        rows = c.execute("SELECT key, doc FROM mr_decisions WHERE key = ANY(%s)", (keys,)).fetchall()
    return {r["key"]: json.loads(r["doc"]) for r in rows}


def _put_cached(items: Dict[str, dict]) -> None:
    if not items:
        return
    with store.txn() as c:
        for k, p in items.items():
            c.execute("INSERT INTO mr_decisions(key, doc) VALUES (%s,%s) ON CONFLICT (key) DO NOTHING",
                      (k, _jdumps(p)))


def _claim_keys(keys: List[str]) -> List[str]:
    """Keys this request now owns (nobody else is computing them, or their claim is stale)."""
    won = []
    with store.txn() as c:
        for k in keys:
            r = c.execute(
                "INSERT INTO mr_inflight(key) VALUES (%s) "
                "ON CONFLICT (key) DO UPDATE SET claimed_at = now() "
                "WHERE mr_inflight.claimed_at < now() - make_interval(secs => %s) RETURNING 1 AS ok",
                (k, config.PENDING_STALE_SECONDS),
            ).fetchone()
            if r:
                won.append(k)
    return won


def _release_keys(keys: List[str]) -> None:
    if not keys:
        return
    try:
        with store.txn() as c:
            c.execute("DELETE FROM mr_inflight WHERE key = ANY(%s)", (keys,))
    except Exception:
        pass


# ----------------------------------------------------------------------------
# propose
# ----------------------------------------------------------------------------
def _resolve(dossiers: List[dict], deadline: float) -> List[dict]:
    keys = [mlm.cache_key(d) for d in dossiers]
    by_key = dict(zip(keys, dossiers))
    got: Dict[str, dict] = {}
    fb: Dict[str, dict] = {}
    while True:
        need = [k for k in keys if k not in got and k not in fb]
        if need:
            got.update(_get_cached(need))
            need = [k for k in need if k not in got]
        if not need or deadline - time.monotonic() < 2:
            break
        won = _claim_keys(need)
        if won:
            got.update(_get_cached(won))  # someone may have just finished them
            won = [k for k in won if k not in got]
        if won:
            try:
                clean, f = mlm.decide([(k, by_key[k]) for k in won], deadline)
                _put_cached(clean)
                got.update(clean)
                fb.update(f)
            finally:
                _release_keys(won)
            continue
        time.sleep(1.0)  # another request is computing these; wait for its cache entries
    out = []
    for k, d in zip(keys, dossiers):
        out.append(got.get(k) or fb.get(k) or mlm.fallback_proposal(d))
    return out


def _log_sample(dossiers: List[dict]) -> None:
    if _sampled["n"] >= 2:
        return
    _sampled["n"] += 1
    try:
        log.info("MAILROOM_SAMPLE n=%d first_dossier=%s", len(dossiers), json.dumps(dossiers[0], ensure_ascii=False)[:5000])
    except Exception:
        pass


def propose(body: dict) -> str:
    t0 = time.monotonic()
    deadline = t0 + config.MAILROOM_BUDGET_SECONDS
    dossiers, verifier = validate_propose(body)
    eval_id = body["evaluationId"]
    req_hash = mlm.sha256_hex(mlm.canonical(body))
    input_digest = mlm.sha256_hex(mlm.canonical(dossiers))

    wait_until = t0 + 50
    while True:
        state, resp = _claim_eval(eval_id, req_hash, input_digest, verifier)
        if state == "won":
            break
        if state == "done":
            return resp
        if state == "conflict":
            raise ApiError(409, "EVALUATION_CONFLICT", "This evaluationId was already used with different content.")
        if time.monotonic() > wait_until:
            raise ApiError(503, "BUSY", "The same request is still being processed; retry shortly.")
        time.sleep(0.3)

    try:
        _log_sample(dossiers)
        proposals = _resolve(dossiers, deadline)
        response = {"profile": PROFILE, "evaluationId": eval_id, "status": "awaiting_receipts",
                    "inputDigest": input_digest, "proposals": proposals}
        text = _jdumps(response)
        if len(text.encode("utf-8")) > config.MAX_RESPONSE_BYTES:
            raise ApiError(500, "RESPONSE_TOO_LARGE", "Response too large.")
        with store.txn() as c:
            c.execute("UPDATE mr_evals SET propose_response=%s, proposals=%s WHERE evaluation_id=%s",
                      (text, _jdumps(proposals), eval_id))
        log.info("mailroom propose %s: %d dossiers in %.1fs, actions=%s", eval_id, len(proposals),
                 time.monotonic() - t0, _count(p["action"] for p in proposals))
        return text
    except BaseException:
        _release_eval(eval_id)
        raise


def _count(it) -> dict:
    out: Dict[str, int] = {}
    for x in it:
        out[x] = out.get(x, 0) + 1
    return out


# ----------------------------------------------------------------------------
# commit
# ----------------------------------------------------------------------------
def _sig_ok(key: Ed25519PublicKey, sig_text: str, message: bytes) -> bool:
    candidates = []
    pad = "=" * (-len(sig_text) % 4)
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            candidates.append(dec(sig_text + pad))
        except (binascii.Error, ValueError):
            pass
    for sig in candidates:
        try:
            key.verify(sig, message)
            return True
        except InvalidSignature:
            continue
    return False


def _verify_all(row: dict, proposals: List[dict], body: dict) -> None:
    props = {p["dossierId"]: p for p in proposals}
    receipts = body["receipts"]
    ids = [r["dossierId"] for r in receipts]
    if len(set(ids)) != len(ids):
        raise _bad("duplicate receipt for a dossier", "DUPLICATE_RECEIPT")
    if set(ids) != set(props):
        raise _bad("there must be exactly one receipt for every proposal", "RECEIPT_SET_MISMATCH")
    rids = [r["receiptId"] for r in receipts]
    if len(set(rids)) != len(rids):
        raise _bad("duplicate receiptId", "DUPLICATE_RECEIPT")
    key = load_verifier(json.loads(row["verifier"])["publicKeyJwk"])
    for r in receipts:
        p = props[r["dossierId"]]
        if r["callId"] != p["callId"] or r["action"] != p["action"]:
            raise _bad("receipt does not match the persisted proposal", "RECEIPT_MISMATCH")
        if r["proposalDigest"] != mlm.proposal_digest(p):
            raise _bad("receipt proposalDigest does not match the persisted proposal", "RECEIPT_MISMATCH")
        inner = {k: v for k, v in r.items() if k != "receiptSignature"}
        message = mlm.canonical({"profile": PROFILE, "evaluationId": body["evaluationId"],
                                 "inputDigest": body["inputDigest"], "receipt": inner}).encode("utf-8")
        if not _sig_ok(key, r["receiptSignature"], message):
            raise _bad("invalid receipt signature", "INVALID_RECEIPT_SIGNATURE")


def commit(body: dict) -> str:
    validate_commit_shape(body)
    eval_id = body["evaluationId"]
    commit_hash = mlm.sha256_hex(mlm.canonical(body))
    with store.txn() as c:
        row = c.execute(
            "SELECT input_digest, verifier, proposals, propose_response, commit_hash, commit_response "
            "FROM mr_evals WHERE evaluation_id=%s FOR UPDATE", (eval_id,)).fetchone()
        if row is None or row["propose_response"] is None:
            raise ApiError(404, "UNKNOWN_EVALUATION", "No proposals exist for this evaluationId.")
        if row["commit_response"]:
            if row["commit_hash"] == commit_hash:
                return row["commit_response"]  # exact replay: same bytes, no new effects
            raise ApiError(409, "EVALUATION_CONFLICT", "This evaluation was already committed with different content.")
        if body["inputDigest"] != row["input_digest"]:
            raise _bad("inputDigest does not match the evaluation", "INPUT_DIGEST_MISMATCH")
        proposals = json.loads(row["proposals"])
        _verify_all(row, proposals, body)  # raises before ANY effect is recorded

        by_id = {r["dossierId"]: r for r in body["receipts"]}
        outcomes = []
        for p in proposals:
            r = by_id[p["dossierId"]]
            status = "executed" if r["accepted"] is True else "rejected"
            outcomes.append({"dossierId": p["dossierId"], "callId": p["callId"], "action": p["action"],
                             "proposalDigest": r["proposalDigest"], "receiptId": r["receiptId"], "status": status})
            c.execute(
                "INSERT INTO mr_executions(evaluation_id, dossier_id, call_id, receipt_id, status) "
                "VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (eval_id, p["dossierId"], p["callId"], r["receiptId"], status))
        response = {"profile": PROFILE, "evaluationId": eval_id, "status": "completed",
                    "inputDigest": row["input_digest"], "outcomes": outcomes}
        text = _jdumps(response)
        c.execute("UPDATE mr_evals SET commit_hash=%s, commit_response=%s WHERE evaluation_id=%s",
                  (commit_hash, text, eval_id))
    log.info("mailroom commit %s: %s", eval_id, _count(o["status"] for o in outcomes))
    return text
