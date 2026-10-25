"""HTTP layer: A2A 1.0 HTTP+JSON binding. Auth, headers and envelopes only."""
import hashlib
import hmac
import json
import logging
import re

import psycopg

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from . import config, incident, llm, mailroom, service
from .errors import ApiError

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("a2a")

A2A_MT = "application/a2a+json"
INPUT_MODES = [service.BATCH_MT, service.RESULTS_MT]
OUTPUT_MODES = [service.PROPOSALS_MT, service.RECEIPTS_MT]

class _CollapseSlashes:
    """Treat //a2a//tasks like /a2a/tasks without redirecting."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope["path"] = re.sub(r"/{2,}", "/", scope["path"])
        await self.inner(scope, receive, send)


class _AccessLog:
    """One log line per /v2 request: method, path, status, and the headers that decide how a body is read.
    Silent rejections (unknown route, bad method, unreadable body) otherwise leave no trace in the runtime logs."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/v2/"):
            return await self.inner(scope, receive, send)
        hdr = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        seen = {"status": None, "ct": None}

        async def wrapped(message):
            if message["type"] == "http.response.start":
                seen["status"] = message["status"]
                for k, v in message.get("headers", []):
                    if k.lower() == b"content-type":
                        seen["ct"] = v.decode("latin-1")
            await send(message)

        try:
            await self.inner(scope, receive, wrapped)
        finally:
            log.info("REQ %s %s -> %s resp_ct=%s req_ct=%s len=%s te=%s expect=%s ua=%s", scope.get("method"), scope["path"][:90],
                     seen["status"], seen["ct"], hdr.get("content-type"), hdr.get("content-length"), hdr.get("transfer-encoding"),
                     hdr.get("expect"), (hdr.get("user-agent") or "")[:50])


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.router.redirect_slashes = False  # never redirect grader requests
app.add_middleware(_CollapseSlashes)
app.add_middleware(_AccessLog)


# ----------------------------------------------------------------------------
# responses
# ----------------------------------------------------------------------------
BASE_HEADERS = {"A2A-Version": "1.0", "Cache-Control": "no-store"}


def a2a_json(payload: dict, status: int = 200) -> Response:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return Response(content=body, status_code=status, media_type=A2A_MT, headers=BASE_HEADERS)


def error_response(e: ApiError) -> Response:
    headers = dict(BASE_HEADERS)
    if e.status == 401:
        headers["WWW-Authenticate"] = "Bearer"
    body = {"error": {"code": e.code, "status": e.status, "message": e.message}}
    return Response(
        content=json.dumps(body, separators=(",", ":")).encode(),
        status_code=e.status,
        media_type=A2A_MT,
        headers=headers,
    )


@app.exception_handler(ApiError)
async def _api_error(_: Request, e: ApiError):
    return error_response(e)


@app.exception_handler(psycopg.Error)
async def _db_error(_: Request, e: Exception):
    log.error("database error: %s", type(e).__name__)
    return error_response(ApiError(503, "STORAGE_UNAVAILABLE", "The service is temporarily unavailable."))


@app.exception_handler(Exception)
async def _unhandled(_: Request, e: Exception):
    log.exception("unhandled error")
    return error_response(ApiError(500, "INTERNAL", "Internal error."))


@app.exception_handler(404)
async def _not_found(_: Request, e):
    return error_response(ApiError(404, "NOT_FOUND", "Resource not found."))


@app.exception_handler(405)
async def _method(_: Request, e):
    return error_response(ApiError(405, "METHOD_NOT_ALLOWED", "Method not allowed."))


# ----------------------------------------------------------------------------
# request checks
# ----------------------------------------------------------------------------
def authenticate(request: Request) -> str:
    m = re.fullmatch(r"(?i)bearer\s+(\S+)", request.headers.get("authorization", "").strip())
    if not m:
        raise ApiError(401, "UNAUTHENTICATED", "Authentication required.")
    token = m.group(1)
    if config.AUTH_TOKENS and not any(hmac.compare_digest(token, t) for t in config.AUTH_TOKENS):
        raise ApiError(401, "UNAUTHENTICATED", "Authentication required.")
    return hashlib.sha256(token.encode()).hexdigest()[:32]  # principal id; the token is never stored


def check_headers(request: Request, need_body: bool) -> str:
    principal = authenticate(request)  # 401 first
    if request.headers.get("a2a-version", "").strip() != "1.0":
        raise ApiError(400, "VERSION_NOT_SUPPORTED", "Unsupported protocol version.")
    accept = request.headers.get("accept", "")
    if accept:
        ok = ("application/a2a+json", "application/json", "application/*", "*/*")
        offered = [a.split(";")[0].strip().lower() for a in accept.split(",")]
        if not any(o in ok for o in offered):
            raise ApiError(406, "NOT_ACCEPTABLE", "Not acceptable.")
    if need_body:
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != A2A_MT:
            raise ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Unsupported content type.")
    return principal


async def read_json(request: Request) -> dict:
    raw = await request.body()
    if len(raw) > config.MAX_BODY_BYTES:
        raise ApiError(413, "TOO_LARGE", "Request too large.")
    try:
        data = json.loads(raw)
    except Exception:
        raise ApiError(400, "INVALID_JSON", "The request body is not valid JSON.")
    if not isinstance(data, dict):
        raise ApiError(400, "INVALID_JSON", "The request body is not valid JSON.")
    return data


def _p(path: str) -> str:
    return f"{config.BASE_PATH}{path}"


# ----------------------------------------------------------------------------
# Agent Card (public)
# ----------------------------------------------------------------------------
def agent_card() -> dict:
    return {
        "name": "Invoice Action Agent",
        "description": (
            "Reads invoice packages, proposes exactly one business action per invoice with cited evidence, "
            "and executes only the proposals the grader accepts. Task state is persisted so retries are safe."
        ),
        "version": "1.0.0",
        "supportedInterfaces": [
            {"url": config.PUBLIC_BASE_URL, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}
        ],
        "capabilities": {"streaming": False, "pushNotifications": False},
        "securitySchemes": {"bearerAuth": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}},
        "defaultInputModes": INPUT_MODES,
        "defaultOutputModes": OUTPUT_MODES,
        "skills": [
            {
                "id": "invoice_action_agent",
                "name": "Invoice action agent",
                "description": (
                    "Chooses settle_invoice, request_approval, hold_invoice, reject_duplicate or open_exception "
                    "for each invoice package and cites the decisive evidence."
                ),
                "tags": ["invoice", "accounts-payable", "payments", "approvals", "duplicates"],
                "inputModes": INPUT_MODES,
                "outputModes": OUTPUT_MODES,
            }
        ],
    }


def card_response() -> Response:
    return Response(
        content=json.dumps(agent_card(), separators=(",", ":")).encode(),
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/.well-known/agent-card.json")
async def card():
    return card_response()


if config.BASE_PATH:

    @app.get(_p("/.well-known/agent-card.json"))
    async def card_alias():
        return card_response()


# ----------------------------------------------------------------------------
# helpers for task output
# ----------------------------------------------------------------------------
def _with_history(task: dict, history_length) -> dict:
    if history_length is None:
        return task
    t = dict(task)
    h = task.get("history", [])
    t["history"] = h[-history_length:] if history_length > 0 else []
    return t


def _history_param(request: Request):
    v = request.query_params.get("historyLength")
    if v is None or v == "":
        return None
    try:
        n = int(v)
    except ValueError:
        raise ApiError(400, "INVALID_PARAMETER", "Invalid parameter.")
    if n < 0:
        raise ApiError(400, "INVALID_PARAMETER", "Invalid parameter.")
    return n


def _size(obj) -> int:
    return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


_sampled = {"n": 0}


def _log_sample(raw_message: dict) -> None:
    """Print the first real batches (per instance) to the runtime logs so you can see the true format."""
    if _sampled["n"] >= 3:
        return
    try:
        parts = raw_message.get("parts") or []
        if not parts or parts[0].get("mediaType") != service.BATCH_MT:
            return
        _sampled["n"] += 1
        pk = (parts[0].get("data") or {}).get("packages") or []
        log.info("SAMPLE_BATCH keys=%s n_packages=%d first_package=%s",
                 list((parts[0].get("data") or {}).keys()), len(pk),
                 json.dumps(pk[0], ensure_ascii=False)[:6000] if pk else "")
    except Exception:
        pass


# ----------------------------------------------------------------------------
# A2A routes
# ----------------------------------------------------------------------------
@app.post(_p("/message:send"))
async def message_send(request: Request):
    principal = check_headers(request, need_body=True)
    body = await read_json(request)
    message = body.get("message")
    if not isinstance(message, dict):
        raise ApiError(400, "INVALID_MESSAGE", "The message is not valid.")
    _log_sample(message)
    task = await run_in_threadpool(service.handle_message, principal, message)
    if _size({"task": task}) > config.MAX_RESPONSE_BYTES and task.get("history"):
        task = _with_history(task, 1)  # extreme case only
    return a2a_json({"task": task})


@app.get(_p("/tasks"))
async def list_tasks(request: Request):
    principal = check_headers(request, need_body=False)
    hl = _history_param(request)
    q = request.query_params
    tasks = await run_in_threadpool(service.store.list_tasks, principal)
    if q.get("contextId"):
        tasks = [t for t in tasks if t["contextId"] == q["contextId"]]
    if q.get("status"):
        tasks = [t for t in tasks if t["status"]["state"] == q["status"]]
    try:
        page_size = max(1, min(int(q.get("pageSize", "100")), 100))
        offset = max(0, int(q.get("pageToken") or "0"))
    except ValueError:
        raise ApiError(400, "INVALID_PARAMETER", "Invalid parameter.")
    page = tasks[offset : offset + page_size]
    more = offset + page_size < len(tasks)
    page = [_with_history(t, hl) for t in page]

    # Stay under 512 KiB: shrink history of the oldest tasks first, then page.
    payload = {"tasks": page}
    i = len(page) - 1
    while _size(payload) > config.MAX_RESPONSE_BYTES - 4096 and i >= 0:
        page[i] = _with_history(page[i], 0)
        i -= 1
    while _size(payload) > config.MAX_RESPONSE_BYTES - 4096 and len(page) > 1:
        page.pop()
        more = True
    if more:
        payload["nextPageToken"] = str(offset + len(page))
    return a2a_json(payload)


@app.get(_p("/tasks/{task_id}"))
async def get_task(task_id: str, request: Request):
    principal = check_headers(request, need_body=False)
    hl = _history_param(request)
    task = await run_in_threadpool(service.get_task, principal, task_id)
    return a2a_json(_with_history(task, hl))


@app.post(_p("/tasks/{task_id}:cancel"))
async def cancel(task_id: str, request: Request):
    principal = check_headers(request, need_body=False)
    raw = await request.body()
    if raw.strip():  # optional body; if present it must be JSON with the A2A media type
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != A2A_MT:
            raise ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Unsupported content type.")
        try:
            json.loads(raw)
        except Exception:
            raise ApiError(400, "INVALID_JSON", "The request body is not valid JSON.")
    task = await run_in_threadpool(service.cancel_task, principal, task_id)
    return a2a_json(task)


# ----------------------------------------------------------------------------
# Project 2: mailroom action gate (plain application/json, no auth, one endpoint)
# ----------------------------------------------------------------------------
def _mr_response(text: str, status: int = 200) -> Response:
    return Response(content=text.encode("utf-8"), status_code=status, media_type="application/json",
                    headers={"Cache-Control": "no-store"})


def _mr_error(status: int, code: str, message: str) -> Response:
    return _mr_response(json.dumps({"error": {"code": code, "status": status, "message": message}},
                                   separators=(",", ":")), status)


async def _mailroom_post(request: Request):
    try:
        raw = await request.body()
        if len(raw) > config.MAX_BODY_BYTES:
            return _mr_error(413, "TOO_LARGE", "Request too large.")
        try:
            body = json.loads(raw)
        except Exception:
            return _mr_error(400, "INVALID_JSON", "The request body is not valid JSON.")
        if not isinstance(body, dict):
            return _mr_error(400, "INVALID_JSON", "The request body must be a JSON object.")
        op = body.get("operation")
        if op == "propose":
            return _mr_response(await run_in_threadpool(mailroom.propose, body))
        if op == "commit":
            return _mr_response(await run_in_threadpool(mailroom.commit, body))
        return _mr_error(400, "INVALID_OPERATION", "operation must be 'propose' or 'commit'.")
    except ApiError as e:
        return _mr_error(e.status, e.code, e.message)
    except psycopg.Error as e:
        log.error("mailroom database error: %s %s", type(e).__name__, str(e)[:200])
        return _mr_error(503, "STORAGE_UNAVAILABLE", "The service is temporarily unavailable.")
    except Exception:
        log.exception("mailroom unhandled error")
        return _mr_error(500, "INTERNAL", "Internal error.")


async def _mailroom_other(request: Request):
    return _mr_error(405, "METHOD_NOT_ALLOWED", "Use POST.")


for _path in ("/v1/mailroom/actions", "/v1/mailroom/actions/"):
    app.add_api_route(_path, _mailroom_post, methods=["POST"])
    app.add_api_route(_path, _mailroom_other, methods=["GET", "PUT", "PATCH", "DELETE"])


# ----------------------------------------------------------------------------
# Project 3: incident agent (plain application/json, no auth)
# ----------------------------------------------------------------------------
async def _incident_call(fn, *args):
    try:
        status, text = await run_in_threadpool(fn, *args)
        return _mr_response(text, status)
    except ApiError as e:
        log.info("INCIDENT_REJECTED %s -> %s %s: %s", getattr(fn, "__name__", "?"), e.status, e.code, e.message)
        return _mr_error(e.status, e.code, e.message)
    except psycopg.Error as e:
        log.error("incident database error: %s %s", type(e).__name__, str(e)[:200])
        return _mr_error(503, "STORAGE_UNAVAILABLE", "The service is temporarily unavailable.")
    except Exception:
        log.exception("incident unhandled error")
        return _mr_error(500, "INTERNAL", "Internal error.")


async def _incident_body(request: Request):
    raw = await request.body()
    if len(raw) > config.MAX_BODY_BYTES:
        raise ApiError(413, "TOO_LARGE", "Request too large.")
    try:
        body = json.loads(raw)
    except Exception:
        raise ApiError(400, "INVALID_JSON", "The request body is not valid JSON.")
    if not isinstance(body, dict):
        raise ApiError(400, "INVALID_JSON", "The request body must be a JSON object.")
    return body


async def _incident_create(request: Request):
    try:
        body = await _incident_body(request)
    except ApiError as e:
        log.info("INCIDENT_REJECTED create -> %s %s: %s", e.status, e.code, e.message)
        return _mr_error(e.status, e.code, e.message)
    hdrs = {"traceparent": request.headers.get("traceparent"), "tracestate": request.headers.get("tracestate")}
    return await _incident_call(incident.create, body, hdrs)


async def _incident_receipt(run_id: str, request: Request):
    try:
        body = await _incident_body(request)
    except ApiError as e:
        log.info("INCIDENT_REJECTED receipt body -> %s %s: %s", e.status, e.code, e.message)
        return _mr_error(e.status, e.code, e.message)
    return await _incident_call(incident.receipt, run_id, body)


async def _incident_get(run_id: str, request: Request):
    return await _incident_call(incident.get, run_id)


for _sfx in ("", "/"):
    app.add_api_route("/v2/incidents" + _sfx, _incident_create, methods=["POST"])
    app.add_api_route("/v2/incidents" + _sfx, _mailroom_other, methods=["GET", "PUT", "PATCH", "DELETE"])
    app.add_api_route("/v2/incidents/{run_id}/receipts" + _sfx, _incident_receipt, methods=["POST"])
    app.add_api_route("/v2/incidents/{run_id}" + _sfx, _incident_get, methods=["GET"])


# ----------------------------------------------------------------------------
# tests only
# ----------------------------------------------------------------------------
if config.DEBUG_STATS:

    @app.get("/_debug/stats")
    async def stats():
        return JSONResponse(llm.STATS)

