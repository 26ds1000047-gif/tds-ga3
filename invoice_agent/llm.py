"""AI decision layer.

* One batched model call for every package that is not already cached.
* Decisions are cached by canonical package CONTENT (ids stripped), so re-sent
  packages under new batch/message/task ids cost nothing.
* Every model answer is strictly validated; invalid ones are retried once with feedback.
* Nothing here knows about HTTP, tasks or receipts.
"""
import hashlib
import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import httpx

from . import config
from .errors import ApiError
from .store import store

log = logging.getLogger("llm")

PROMPT_VERSION = "v1"
ACTIONS = (
    "settle_invoice",
    "request_approval",
    "hold_invoice",
    "reject_duplicate",
    "open_exception",
)
ID_KEYS = {"packageId", "package_id", "id", "batchId", "batch_id"}
REF_RE = re.compile(r"\[([^\[\]\n]{1,100})\]")
MAX_VALIDATION_ROUNDS = 3  # rounds where the model answered but some answers were invalid
MAX_PROVIDER_ERRORS = 6    # 503/429/timeouts before giving up (time budget also applies)


class ProviderError(Exception):
    """HTTP error from the model provider (status + short, key-redacted body)."""

    def __init__(self, status: int, body: str):
        body = body.replace(config.LLM_API_KEY, "***") if config.LLM_API_KEY else body
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status

STATS = {"model_calls": 0}
_model_sem = threading.Semaphore(max(1, config.LLM_CONCURRENCY))

SYSTEM_PROMPT = """You are an accounts-payable control analyst. For every invoice package you are given, choose exactly ONE action and cite the decisive evidence.

ACTIONS (use these exact strings):
- settle_invoice: the invoice is valid, fully reconciled (purchase order, receipt and vendor/bank details agree) and the amount is within the autonomous payment authority.
- request_approval: the invoice is commercially valid and reconciled, but the amount or terms are OUTSIDE delegated authority, so a higher approver must sign off before payment.
- hold_invoice: payment must pause until a stated verification completes (for example a vendor bank-detail callback, a missing receipt/goods-received confirmation, a tax or compliance check).
- reject_duplicate: the SAME commercial invoice (same vendor, same invoice number, same amount) was already paid. A payment for a DIFFERENT invoice number is NOT a duplicate, even for the same vendor or a similar amount.
- open_exception: material records conflict (amount, quantity, vendor identity, currency, purchase-order terms) and the case needs an exception workflow.

HOW TO READ A PACKAGE
- Packages mix useful current facts with noise: cover sheets, archived or superseded examples, training material, quotations of old cases, negations ("this is NOT a duplicate", "no hold is required") and action words used in irrelevant contexts. Never decide from keywords. Decide from the current controlling paragraph that describes THIS invoice's situation.
- Exactly one paragraph determines the action. It carries three bracketed evidence references such as [ABC-123]. Return exactly those three references, copied character for character including the square brackets, in the order they appear in that paragraph.
- NEVER return the cover-sheet reference, or any reference from an archive, old example, training, superseded or quoted paragraph.
- Statements that are negated, belong to another invoice, or sit inside an example do not count.

FACTS for the current invoice:
- vendorName and invoiceNumber exactly as written in the documents.
- amountMinor: the invoice total as an INTEGER in minor units (1,234.50 -> 123450; lakh formatting such as 1,23,456.00 -> 12345600; currencies without a minor unit are 1:1).
- currency: 3-letter ISO code.

RATIONALE: 60-1500 characters of plain English. Name the action string and quote at least two of the three evidence references.

OUTPUT: reply with ONE JSON object and nothing else:
{"decisions":[{"index":0,"action":"<one action>","facts":{"vendorName":"...","invoiceNumber":"...","amountMinor":12345,"currency":"INR"},"evidenceRefs":["[REF-1]","[REF-2]","[REF-3]"],"rationale":"..."}]}
Include one entry per package, using the package index shown in its header."""


# ----------------------------------------------------------------------------
# package helpers
# ----------------------------------------------------------------------------
def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def strip_ids(pkg: dict) -> dict:
    return {k: v for k, v in pkg.items() if k not in ID_KEYS}


def package_key(pkg: dict) -> str:
    h = hashlib.sha256()
    h.update(PROMPT_VERSION.encode())
    h.update(b"|" + config.EVIDENCE_REF_STYLE.encode() + b"|")
    h.update(canonical(strip_ids(pkg)).encode())
    return h.hexdigest()


def render(obj, indent: int = 0) -> str:
    """Readable text view of a package (real newlines instead of JSON escapes)."""
    pad = "  " * indent
    lines: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}:")
                lines.append(render(v, indent + 1))
            elif isinstance(v, str) and "\n" in v:
                lines.append(f"{pad}{k}:")
                lines.extend(f"{pad}  {ln}" for ln in v.split("\n"))
            else:
                lines.append(f"{pad}{k}: {v}")
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}-")
                lines.append(render(v, indent + 1))
            elif isinstance(v, str) and "\n" in v:
                lines.append(f"{pad}-")
                lines.extend(f"{pad}  {ln}" for ln in v.split("\n"))
            else:
                lines.append(f"{pad}- {v}")
    else:
        lines.append(f"{pad}{obj}")
    return "\n".join(lines)


def _leaf_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _leaf_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _leaf_strings(v)


def _blocks(pkg: dict) -> List[set]:
    out = []
    for s in _leaf_strings(strip_ids(pkg)):
        for b in re.split(r"\n\s*\n", s):
            refs = set(REF_RE.findall(b))
            if refs:
                out.append(refs)
    return out


# ----------------------------------------------------------------------------
# validation
# ----------------------------------------------------------------------------
def _norm_amount(v) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if v >= 0 else None
    if isinstance(v, float):
        return int(v) if v.is_integer() and v >= 0 else None
    if isinstance(v, str):
        s = v.replace(",", "").strip()
        if re.fullmatch(r"\d+", s):
            return int(s)
    return None


def _fmt_ref(inner: str) -> str:
    return f"[{inner}]" if config.EVIDENCE_REF_STYLE == "bracketed" else inner


def _fix_rationale(text: str, action: str, refs: List[str]) -> str:
    r = re.sub(r"\s+", " ", (text or "")).strip()
    suffix = " Decisive evidence: " + ", ".join(refs) + "."
    if action not in r:
        r = f"Proposed action {action}. " + r
    cited = sum(1 for x in refs if x in r)
    if cited < 2:
        r += suffix
    if len(r) > 1500:
        r = r[: 1500 - len(suffix)].rstrip() + suffix
    if len(r) < 60:
        r += " This follows the decisive paragraph of the invoice package and current policy."
    return r


def validate_decision(raw, pkg: dict) -> Tuple[Optional[dict], List[str], List[str]]:
    """Returns (decision | None, hard_errors, soft_issues)."""
    errors: List[str] = []
    soft: List[str] = []
    if not isinstance(raw, dict):
        return None, ["entry missing or not an object"], []

    action = raw.get("action")
    if action not in ACTIONS:
        errors.append(f"action must be one of {list(ACTIONS)}")

    f = raw.get("facts") if isinstance(raw.get("facts"), dict) else {}
    vendor = str(f.get("vendorName", "")).strip()
    invoice = str(f.get("invoiceNumber", "")).strip()
    amount = _norm_amount(f.get("amountMinor"))
    currency = str(f.get("currency", "")).strip().upper()
    if not vendor:
        errors.append("facts.vendorName missing")
    if not invoice:
        errors.append("facts.invoiceNumber missing")
    if amount is None:
        errors.append("facts.amountMinor must be a non-negative integer in minor units")
    if not re.fullmatch(r"[A-Z]{3}", currency):
        errors.append("facts.currency must be a 3-letter code")

    text = render(strip_ids(pkg))
    found = set(REF_RE.findall(text))
    raw_refs = raw.get("evidenceRefs")
    refs: List[str] = []
    if not isinstance(raw_refs, list):
        errors.append("evidenceRefs must be a list of exactly 3 references")
    else:
        for x in raw_refs:
            inner = str(x).strip()
            if inner.startswith("[") and inner.endswith("]"):
                inner = inner[1:-1].strip()
            if inner in found and inner not in [r.strip("[]") for r in refs]:
                refs.append(_fmt_ref(inner))
            else:
                errors.append(f"evidence reference {str(x)[:60]!r} does not appear verbatim in the package")
        if len(refs) != 3:
            errors.append("evidenceRefs must contain exactly 3 distinct references copied from the package")

    if errors:
        return None, errors, []

    inner_refs = {r.strip("[]") for r in refs}
    if not any(inner_refs <= b for b in _blocks(pkg)):
        soft.append("the three references are not all in the same paragraph; pick the paragraph that determines the action")
    if invoice.lower() not in text.lower():
        soft.append("facts.invoiceNumber does not appear verbatim in the package")

    decision = {
        "action": action,
        "facts": {"vendorName": vendor, "invoiceNumber": invoice, "amountMinor": amount, "currency": currency},
        "evidenceRefs": refs,
        "rationale": _fix_rationale(str(raw.get("rationale", "")), action, refs),
    }
    return decision, [], soft


# ----------------------------------------------------------------------------
# model call
# ----------------------------------------------------------------------------
def _build_messages(items: List[Tuple[int, str]], policy: str, hints: Dict[int, List[str]]):
    parts = [
        f"Policy revision: {policy or 'n/a'}",
        f"Process the {len(items)} invoice packages below. Return one decision per package index.",
    ]
    if hints:
        parts.append(
            "Your previous answer had problems. Fix them:\n"
            + "\n".join(f"- package {i}: {'; '.join(h)}" for i, h in hints.items())
        )
    for i, text in items:
        parts.append(f"===== PACKAGE {i} =====\n{text}\n===== END PACKAGE {i} =====")
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "\n\n".join(parts)},
    ]


def _chat(messages, timeout: float, model: str) -> str:
    if not config.LLM_API_KEY:
        raise RuntimeError("LLM_API_KEY is not set")
    body = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": config.LLM_MAX_TOKENS,
    }
    if config.LLM_JSON_MODE:
        body["response_format"] = {"type": "json_object"}
    body.update(config.LLM_EXTRA_BODY)
    r = httpx.post(
        config.LLM_BASE_URL.rstrip("/") + "/chat/completions",
        json=body,
        headers={"Authorization": f"Bearer {config.LLM_API_KEY}"},
        timeout=timeout,
    )
    if r.status_code >= 400:
        raise ProviderError(r.status_code, r.text)
    return r.json()["choices"][0]["message"]["content"] or ""


def _parse(content: str, expected: int) -> Dict[int, dict]:
    s = content.strip()
    s = re.sub(r"^```(?:json)?\s*|\s*```$", "", s)
    try:
        data = json.loads(s)
    except Exception:
        a, b = s.find("{"), s.rfind("}")
        if a < 0 or b <= a:
            return {}
        try:
            data = json.loads(s[a : b + 1])
        except Exception:
            return {}
    items = data.get("decisions") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return {}
    out: Dict[int, dict] = {}
    for pos, d in enumerate(items):
        if isinstance(d, dict):
            idx = d.get("index", pos if len(items) == expected else None)
            if isinstance(idx, int) and idx not in out:
                out[idx] = d
    return out


def _mock_raw(pos: int, pkg: dict) -> dict:  # tests only (LLM_MOCK=1)
    return {
        "index": pos,
        "action": pkg["expected_action"],
        "facts": pkg["facts"],
        "evidenceRefs": ["[" + r + "]" for r in REF_RE.findall(pkg["decisive"])],
        "rationale": "mock",
    }


def _run_model(pending: Dict[str, dict], policy: str) -> Dict[str, dict]:
    """pending: key -> package. Returns key -> validated decision (clean ones are cached)."""
    keys = list(pending)
    deadline = time.monotonic() + config.LLM_BUDGET_SECONDS
    accepted: Dict[str, dict] = {}
    clean: Dict[str, dict] = {}  # only fully valid answers are cached
    soft_fallback: Dict[str, dict] = {}
    hints: Dict[str, List[str]] = {}
    todo = keys

    models = [config.LLM_MODEL] + config.LLM_FALLBACK_MODELS
    mi = 0          # index into models; advances only when the provider errors
    errors = 0      # provider errors so far
    rounds = 0      # rounds where the model actually answered
    while todo:
        remaining = deadline - time.monotonic()
        if remaining < 5:
            log.error("model budget exhausted")
            break
        model = models[mi % len(models)]
        if not config.LLM_MOCK:
            day = datetime.now(timezone.utc).strftime("calls-%Y-%m-%d")
            if store.bump_counter(day) > config.MAX_LLM_CALLS_PER_DAY:
                log.error("daily model-call cap reached")
                break
        items = [(i, render(strip_ids(pending[k]))) for i, k in enumerate(todo)]
        pos_hints = {i: hints[k] for i, k in enumerate(todo) if k in hints}
        STATS["model_calls"] += 1
        try:
            if config.LLM_MOCK:
                time.sleep(config.LLM_MOCK_DELAY)
                content = json.dumps({"decisions": [_mock_raw(i, pending[k]) for i, k in enumerate(todo)]})
            else:
                with _model_sem:
                    content = _chat(_build_messages(items, policy, pos_hints), timeout=remaining - 1, model=model)
        except Exception as e:  # network, 429, 503, timeout...
            errors += 1
            log.warning("model call failed (error %d, model %s): %s %s", errors, model, type(e).__name__, str(e)[:300])
            mi += 1  # next try uses the next model
            if errors >= MAX_PROVIDER_ERRORS:
                break
            if deadline - time.monotonic() > 10:
                time.sleep(1.0)
            continue

        rounds += 1
        parsed = _parse(content, len(todo))
        if not parsed:
            log.warning("model %s returned no parsable decisions; reply started with: %r", model, content[:200])
        next_todo: List[str] = []
        for i, k in enumerate(todo):
            dec, errs, soft = validate_decision(parsed.get(i), pending[k])
            if dec and not soft:
                accepted[k] = dec
                clean[k] = dec
            elif dec:
                soft_fallback[k] = dec
                hints[k] = soft
                next_todo.append(k)
            else:
                hints[k] = errs
                next_todo.append(k)
        todo = next_todo
        if todo and rounds >= MAX_VALIDATION_ROUNDS:
            break

    for k in todo:
        if k not in soft_fallback:
            log.error("no valid decision for a package; last problems: %s", "; ".join(hints.get(k, ["none"]))[:400])

    try:
        store.put_decisions(clean)  # one DB round trip for the whole batch
    except Exception:
        log.warning("could not cache decisions")
    for k in todo:  # out of attempts: keep soft-valid answers, but do not cache them
        if k in soft_fallback:
            accepted[k] = soft_fallback[k]
    return accepted


def decide(packages: List[dict], policy: str = "") -> List[dict]:
    """One validated decision per package, aligned with `packages`."""
    keys = [package_key(p) for p in packages]
    known = store.get_decisions(keys)
    pending: Dict[str, dict] = {}
    for k, p in zip(keys, packages):
        if k not in known and k not in pending:
            pending[k] = p
    if pending:
        items = list(pending.items())
        size = config.LLM_CHUNK_SIZE if config.LLM_CHUNK_SIZE > 0 else len(items)
        chunks = [dict(items[i : i + size]) for i in range(0, len(items), size)]
        if len(chunks) == 1:
            known.update(_run_model(chunks[0], policy))
        else:  # parallel chunks: wall-clock time is that of the slowest chunk, not the sum
            with ThreadPoolExecutor(max_workers=len(chunks)) as ex:
                for res in ex.map(lambda ch: _run_model(ch, policy), chunks):
                    known.update(res)
    out = []
    for k in keys:
        if k not in known:
            raise ApiError(503, "MODEL_UNAVAILABLE", "The decision service is temporarily unavailable.")
        out.append(json.loads(json.dumps(known[k])))
    return out
