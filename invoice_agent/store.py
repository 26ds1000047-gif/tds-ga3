"""Postgres persistence (Neon or any Postgres).

Serverless means any request may land on a different, short-lived instance, so NOTHING
is kept in process memory. Cross-instance safety comes from the database:
  * messages(principal, message_id) primary key  -> idempotency "claim"
  * SELECT ... FOR UPDATE on the task row         -> exactly one of receipt / cancel wins
  * executions primary key                        -> an action can never run twice
Every task query is filtered by principal.
"""
import contextlib
import json
import threading
from typing import Dict, Iterable, List, Optional, Tuple

import psycopg
from psycopg.rows import dict_row

from . import config
from .errors import ApiError

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    seq        BIGSERIAL PRIMARY KEY,
    task_id    TEXT NOT NULL UNIQUE,
    principal  TEXT NOT NULL,
    context_id TEXT NOT NULL,
    batch_id   TEXT NOT NULL,
    state      TEXT NOT NULL,
    doc        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_principal ON tasks(principal, seq);

-- task_id is NULL while the first request for this message is still working ("pending claim").
CREATE TABLE IF NOT EXISTS messages (
    principal  TEXT NOT NULL,
    message_id TEXT NOT NULL,
    msg_hash   TEXT NOT NULL,
    task_id    TEXT,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (principal, message_id)
);

CREATE TABLE IF NOT EXISTS decisions (
    key TEXT PRIMARY KEY,
    doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS executions (
    principal     TEXT NOT NULL,
    task_id       TEXT NOT NULL,
    action_id     TEXT NOT NULL,
    receipt_nonce TEXT NOT NULL,
    PRIMARY KEY (principal, task_id, action_id)
);

CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    n    BIGINT NOT NULL
);

-- Mailroom (project 2). One row per evaluationId.
CREATE TABLE IF NOT EXISTS mr_evals (
    evaluation_id    TEXT PRIMARY KEY,
    req_hash         TEXT NOT NULL,
    input_digest     TEXT NOT NULL,
    verifier         TEXT NOT NULL,
    claimed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    propose_response TEXT,
    proposals        TEXT,
    commit_hash      TEXT,
    commit_response  TEXT
);
CREATE TABLE IF NOT EXISTS mr_decisions (key TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mr_inflight (key TEXT PRIMARY KEY, claimed_at TIMESTAMPTZ NOT NULL DEFAULT now());
-- Incident agent (project 3)
CREATE TABLE IF NOT EXISTS inc_runs (
    run_id          TEXT PRIMARY KEY,
    req_hash        TEXT NOT NULL,
    claimed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    state           TEXT,
    create_response TEXT
);
CREATE TABLE IF NOT EXISTS inc_receipts (
    run_id     TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    rhash      TEXT NOT NULL,
    response   TEXT NOT NULL,
    PRIMARY KEY (run_id, receipt_id)
);
CREATE TABLE IF NOT EXISTS mr_executions (
    evaluation_id TEXT NOT NULL,
    dossier_id    TEXT NOT NULL,
    call_id       TEXT NOT NULL,
    receipt_id    TEXT NOT NULL,
    status        TEXT NOT NULL,
    PRIMARY KEY (evaluation_id, dossier_id)
);
"""

_SCHEMA_LOCK_ID = 727_001


class Store:
    def __init__(self):
        self._ready = False
        self._init_lock = threading.Lock()

    # ---- connections ----
    def _connect(self):
        if not config.DATABASE_URL:
            raise ApiError(503, "DB_NOT_CONFIGURED", "Storage is not available.")
        # prepare_threshold=None: safe behind PgBouncer-style poolers (Neon pooled URL)
        return psycopg.connect(
            config.DATABASE_URL, row_factory=dict_row, prepare_threshold=None, connect_timeout=10
        )

    def _ensure_schema(self) -> None:
        if self._ready:
            return
        with self._init_lock:
            if self._ready:
                return
            with self._connect() as c:  # commits on success
                c.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK_ID,))
                c.execute(SCHEMA)
            self._ready = True

    @contextlib.contextmanager
    def txn(self):
        """One transaction on a fresh connection. Commit on success, rollback on any exception."""
        self._ensure_schema()
        with self._connect() as c:
            yield c

    # ---- reads ----
    def get_task(self, principal: str, task_id: str) -> Optional[dict]:
        with self.txn() as c:
            return load_task(c, principal, task_id)

    def list_tasks(self, principal: str) -> List[dict]:
        with self.txn() as c:
            rows = c.execute(
                "SELECT doc FROM tasks WHERE principal=%s ORDER BY seq DESC", (principal,)
            ).fetchall()
        return [json.loads(r["doc"]) for r in rows]

    # ---- idempotency claim ----
    def claim_message(self, principal: str, message_id: str, msg_hash: str) -> Tuple[str, Optional[dict]]:
        """Try to become the one request that processes this (principal, messageId).

        Returns one of:
          ("won", None)      -> you own it; do the work, then finish_new_batch() / release_claim()
          ("done", task)     -> already processed with identical content; return this task
          ("conflict", None) -> same id, different content
          ("pending", None)  -> another request is working on it right now; poll again
        """
        with self.txn() as c:
            got = c.execute(
                "INSERT INTO messages(principal, message_id, msg_hash) VALUES (%s,%s,%s) "
                "ON CONFLICT DO NOTHING RETURNING 1 AS ok",
                (principal, message_id, msg_hash),
            ).fetchone()
            if got:
                return "won", None
            row = c.execute(
                "SELECT msg_hash, task_id, (now() - claimed_at) > make_interval(secs => %s) AS stale "
                "FROM messages WHERE principal=%s AND message_id=%s FOR UPDATE",
                (config.PENDING_STALE_SECONDS, principal, message_id),
            ).fetchone()
            if row is None:  # deleted between the two statements: let the caller retry
                return "pending", None
            if row["msg_hash"] != msg_hash:
                return "conflict", None
            if row["task_id"]:
                return "done", load_task(c, principal, row["task_id"])
            if row["stale"]:  # the first worker died (e.g. function timeout): take over
                c.execute(
                    "UPDATE messages SET claimed_at=now() WHERE principal=%s AND message_id=%s",
                    (principal, message_id),
                )
                return "won", None
            return "pending", None

    def release_claim(self, principal: str, message_id: str) -> None:
        """Work failed before a task existed: free the id so a retry can run cleanly."""
        try:
            with self.txn() as c:
                c.execute(
                    "DELETE FROM messages WHERE principal=%s AND message_id=%s AND task_id IS NULL",
                    (principal, message_id),
                )
        except Exception:
            pass  # a stale claim is taken over automatically

    # ---- decision cache ----
    def get_decisions(self, keys: Iterable[str]) -> Dict[str, dict]:
        keys = list(set(keys))
        if not keys:
            return {}
        with self.txn() as c:
            rows = c.execute("SELECT key, doc FROM decisions WHERE key = ANY(%s)", (keys,)).fetchall()
        return {r["key"]: json.loads(r["doc"]) for r in rows}

    def put_decisions(self, items: Dict[str, dict]) -> None:
        if not items:
            return
        with self.txn() as c:
            for k, d in items.items():
                c.execute(
                    "INSERT INTO decisions(key, doc) VALUES (%s,%s) "
                    "ON CONFLICT (key) DO UPDATE SET doc = EXCLUDED.doc",
                    (k, json.dumps(d, ensure_ascii=False)),
                )

    def bump_counter(self, name: str) -> int:
        with self.txn() as c:
            return c.execute(
                "INSERT INTO counters(name, n) VALUES (%s, 1) "
                "ON CONFLICT (name) DO UPDATE SET n = counters.n + 1 RETURNING n",
                (name,),
            ).fetchone()["n"]


# ---- helpers used inside a transaction ----
def load_task(c, principal: str, task_id: str, lock: bool = False) -> Optional[dict]:
    r = c.execute(
        "SELECT doc FROM tasks WHERE principal=%s AND task_id=%s" + (" FOR UPDATE" if lock else ""),
        (principal, task_id),
    ).fetchone()
    return json.loads(r["doc"]) if r else None


def insert_task(c, principal: str, task: dict, batch_id: str) -> None:
    c.execute(
        "INSERT INTO tasks(task_id, principal, context_id, batch_id, state, doc) VALUES (%s,%s,%s,%s,%s,%s)",
        (task["id"], principal, task["contextId"], batch_id, task["status"]["state"],
         json.dumps(task, ensure_ascii=False)),
    )


def update_task(c, principal: str, task: dict) -> None:
    c.execute(
        "UPDATE tasks SET state=%s, doc=%s WHERE principal=%s AND task_id=%s",
        (task["status"]["state"], json.dumps(task, ensure_ascii=False), principal, task["id"]),
    )


store = Store()
