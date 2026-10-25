"""Task lifecycle: new batch -> INPUT_REQUIRED -> (results -> COMPLETED | cancel -> CANCELED).

No HTTP in here. The model is only ever called from `_new_batch`.
"""
import copy
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional

from . import config, llm
from .errors import ApiError
from .store import store, load_task, insert_task, update_task

BATCH_MT = "application/vnd.ga5.invoice-claim-batch+json"
PROPOSALS_MT = "application/vnd.ga5.invoice-action-proposals+json"
RESULTS_MT = "application/vnd.ga5.invoice-action-results+json"
RECEIPTS_MT = "application/vnd.ga5.invoice-action-receipts+json"

S_INPUT = "TASK_STATE_INPUT_REQUIRED"
S_DONE = "TASK_STATE_COMPLETED"
S_CANCELED = "TASK_STATE_CANCELED"
TERMINAL = {S_DONE, S_CANCELED, "TASK_STATE_FAILED", "TASK_STATE_REJECTED"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def message_hash(message: dict) -> str:
    """Hash of the message ONLY (configuration is ignored by design)."""
    return hashlib.sha256(canonical(message).encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------------
def _bad(code="INVALID_MESSAGE") -> ApiError:
    return ApiError(400, code, "The message is not valid.")


def _validate_envelope(message) -> None:
    if not isinstance(message, dict):
        raise _bad()
    mid = message.get("messageId")
    if not isinstance(mid, str) or not mid.strip() or len(mid) > 256:
        raise _bad()
    if message.get("role") != "ROLE_USER":
        raise _bad()
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts or not all(isinstance(p, dict) for p in parts):
        raise _bad()
    for k in ("taskId", "contextId"):
        if k in message and message[k] is not None and not isinstance(message[k], str):
            raise _bad()


def handle_message(principal: str, message: dict) -> dict:
    _validate_envelope(message)
    h = message_hash(message)
    if message.get("taskId"):
        return _continue(principal, message, h)
    return _new_batch(principal, message, h)


# ----------------------------------------------------------------------------
# new batch -> proposals
# ----------------------------------------------------------------------------
def _package_id(pkg) -> Optional[str]:
    if isinstance(pkg, dict):
        for k in ("packageId", "package_id", "id"):
            v = pkg.get(k)
            if isinstance(v, str) and v.strip():
                return v
    return None


def _new_batch(principal: str, message: dict, h: str) -> dict:
    parts = message["parts"]
    if len(parts) != 1 or parts[0].get("mediaType") != BATCH_MT:
        raise ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Unsupported message part.")
    data = parts[0].get("data")
    if not isinstance(data, dict):
        raise _bad()
    batch_id = data.get("batchId")
    packages = data.get("packages")
    if not isinstance(batch_id, str) or not batch_id.strip():
        raise _bad()
    if not isinstance(packages, list) or not packages or len(packages) > config.MAX_PACKAGES:
        raise _bad()
    ids = [_package_id(p) for p in packages]
    if any(i is None for i in ids) or len(set(ids)) != len(ids):
        raise _bad()

    # --- idempotency claim: exactly one request per (principal, messageId) does the work.
    # Equivalent concurrent requests (any instance) wait here and get the same stored Task.
    mid = message["messageId"]
    deadline = time.monotonic() + config.PENDING_WAIT_SECONDS
    while True:
        status, existing = store.claim_message(principal, mid, h)
        if status == "won":
            break
        if status == "done":
            return existing
        if status == "conflict":
            raise ApiError(409, "IDEMPOTENCY_CONFLICT", "This message id was already used with different content.")
        if time.monotonic() > deadline:
            raise ApiError(503, "BUSY", "The request is still being processed. Please retry.")
        time.sleep(0.3)

    try:
        return _build_and_store(principal, message, batch_id, packages, ids, str(data.get("policyRevision", "")))
    except _AlreadyDone:
        status, existing = store.claim_message(principal, mid, h)
        if status == "done":
            return existing
        raise ApiError(503, "BUSY", "Please retry.")
    except BaseException:
        store.release_claim(principal, mid)  # free the id so a retry runs cleanly
        raise


class _AlreadyDone(Exception):
    """Another worker finished this message first (only after a stale-claim takeover)."""


def _build_and_store(principal, message, batch_id, packages, ids, policy) -> dict:
    # --- the only model work in the whole service (cached by package content) ---
    decisions = llm.decide(packages, policy)

    proposals = []
    for pid, d in zip(ids, decisions):
        action_id = "act_" + hashlib.sha256(f"{principal}|{batch_id}|{pid}|{d['action']}".encode()).hexdigest()[:24]
        proposals.append(
            {
                "packageId": pid,
                "actionId": action_id,
                "action": d["action"],
                "facts": d["facts"],
                "evidenceRefs": d["evidenceRefs"],
                "rationale": d["rationale"],
            }
        )

    task_id = str(uuid.uuid4())
    ctx = message.get("contextId") if isinstance(message.get("contextId"), str) and message.get("contextId") else str(uuid.uuid4())
    stored_msg = copy.deepcopy(message)
    stored_msg["taskId"] = task_id
    stored_msg["contextId"] = ctx
    task = {
        "id": task_id,
        "contextId": ctx,
        "status": {"state": S_INPUT, "timestamp": now()},
        "artifacts": [
            {
                "artifactId": f"proposals-{task_id}",
                "name": "invoice-action-proposals",
                "parts": [{"mediaType": PROPOSALS_MT, "data": {"batchId": batch_id, "proposals": proposals}}],
            }
        ],
        "history": [stored_msg],
    }
    with store.txn() as c:  # state is stored BEFORE we respond
        owned = c.execute(
            "UPDATE messages SET task_id=%s WHERE principal=%s AND message_id=%s AND task_id IS NULL RETURNING 1 AS ok",
            (task_id, principal, message["messageId"]),
        ).fetchone()
        if not owned:
            raise _AlreadyDone()  # rolls back; caller returns the winner's task
        insert_task(c, principal, task, batch_id)
    return task


# ----------------------------------------------------------------------------
# results -> receipts
# ----------------------------------------------------------------------------
def _continue(principal: str, message: dict, h: str) -> dict:
    with store.txn() as c:
        # Row lock: receipts and cancel for one task are serialised, so exactly one wins.
        task = load_task(c, principal, message["taskId"], lock=True)
        if task is None:
            raise ApiError(404, "NOT_FOUND", "Resource not found.")
        rec = c.execute(
            "SELECT msg_hash, task_id FROM messages WHERE principal=%s AND message_id=%s",
            (principal, message["messageId"]),
        ).fetchone()
        if rec:  # same message id seen before
            if rec["msg_hash"] != h or rec["task_id"] != task["id"]:
                raise ApiError(409, "IDEMPOTENCY_CONFLICT", "This message id was already used with different content.")
            return task  # exact replay (also after the task became terminal): same Task, no side effects
        if task["status"]["state"] in TERMINAL:
            raise ApiError(409, "TASK_TERMINAL", "The task is no longer accepting changes.")
        if task["status"]["state"] != S_INPUT:
            raise ApiError(409, "TASK_STATE_CONFLICT", "The task is not waiting for input.")
        if message.get("contextId") != task["contextId"]:
            raise _bad("CONTEXT_MISMATCH")

        parts = message["parts"]
        if len(parts) != 1 or parts[0].get("mediaType") != RESULTS_MT:
            raise ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Unsupported message part.")
        data = parts[0].get("data")
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise _bad("INVALID_RESULTS")

        proposal_part = task["artifacts"][0]["parts"][0]["data"]
        if data.get("batchId") != proposal_part["batchId"]:
            raise _bad("BATCH_MISMATCH")
        stored = {p["packageId"]: p for p in proposal_part["proposals"]}

        outcome_by_pkg: Dict[str, dict] = {}
        for r in data["results"]:
            if not isinstance(r, dict):
                raise _bad("INVALID_RESULTS")
            pid = r.get("packageId")
            s = stored.get(pid) if isinstance(pid, str) else None
            if s is None or pid in outcome_by_pkg:
                raise _bad("PACKAGE_MISMATCH")
            if r.get("actionId") != s["actionId"] or r.get("action") != s["action"]:
                raise _bad("ACTION_MISMATCH")
            outcome = r.get("outcome")
            if outcome not in ("ACCEPTED", "REJECTED"):
                raise _bad("INVALID_RESULTS")
            nonce = r.get("receiptNonce")
            if outcome == "ACCEPTED" and (not isinstance(nonce, str) or not nonce.strip() or len(nonce) > 512):
                raise _bad("INVALID_RESULTS")
            outcome_by_pkg[pid] = r

        # --- the action gate: only ACCEPTED proposals are ever "executed" ---
        executions = []
        for p in proposal_part["proposals"]:
            r = outcome_by_pkg.get(p["packageId"])
            if r and r["outcome"] == "ACCEPTED":
                executions.append(
                    {
                        "packageId": p["packageId"],
                        "actionId": p["actionId"],
                        "action": p["action"],
                        "receiptNonce": r["receiptNonce"],
                        "facts": p["facts"],
                        "evidenceRefs": p["evidenceRefs"],
                    }
                )
                c.execute(  # primary key makes a second execution of the same action impossible
                    "INSERT INTO executions(principal, task_id, action_id, receipt_nonce) VALUES (%s,%s,%s,%s)",
                    (principal, task["id"], p["actionId"], r["receiptNonce"]),
                )

        receipts = {"batchId": proposal_part["batchId"], "executions": executions}
        receipt_part = {"mediaType": RECEIPTS_MT, "data": receipts}
        if config.RECEIPTS_IN_SAME_ARTIFACT:
            task["artifacts"][0]["parts"].append(receipt_part)
        else:
            task["artifacts"].append(
                {"artifactId": f"receipts-{task['id']}", "name": "invoice-action-receipts", "parts": [receipt_part]}
            )
        stored_msg = copy.deepcopy(message)
        stored_msg["taskId"] = task["id"]
        stored_msg["contextId"] = task["contextId"]
        task["history"].append(stored_msg)
        task["status"] = {"state": S_DONE, "timestamp": now()}

        update_task(c, principal, task)
        c.execute(
            "INSERT INTO messages(principal, message_id, msg_hash, task_id) VALUES (%s,%s,%s,%s)",
            (principal, message["messageId"], h, task["id"]),
        )
    return task


# ----------------------------------------------------------------------------
# cancel
# ----------------------------------------------------------------------------
def cancel_task(principal: str, task_id: str) -> dict:
    with store.txn() as c:  # same row lock as _continue -> exactly one of them can win
        task = load_task(c, principal, task_id, lock=True)
        if task is None:
            raise ApiError(404, "NOT_FOUND", "Resource not found.")
        if task["status"]["state"] in TERMINAL:
            raise ApiError(409, "TASK_NOT_CANCELABLE", "The task can no longer be canceled.")
        task["status"] = {"state": S_CANCELED, "timestamp": now()}
        update_task(c, principal, task)
    return task


# ----------------------------------------------------------------------------
def get_task(principal: str, task_id: str) -> dict:
    task = store.get_task(principal, task_id)
    if task is None:
        raise ApiError(404, "NOT_FOUND", "Resource not found.")
    return task
