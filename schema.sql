-- Optional: the app creates these tables itself on first request.

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
