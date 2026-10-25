"""OTLP trace construction for the incident agent (project 3).

Pure function of the STORED run state: no model, no randomness. Span ids and timestamps were fixed when each
dispatch / receipt happened, so rebuilding the trace always gives the same result.
Nothing sensitive is exported: no transcript, prompts, tool arguments/results, or credentials.
"""
from typing import Dict, List

SPAN_INTERNAL, SPAN_SERVER, SPAN_CLIENT = 1, 2, 3
STATUS_OK, STATUS_ERROR = 1, 2


def _s(k: str, v: str) -> dict:
    return {"key": k, "value": {"stringValue": v}}


def _i(k: str, v: int) -> dict:
    return {"key": k, "value": {"intValue": int(v)}}


def _span(st: dict, span_id: str, parent: str, name: str, kind: int, start: int, end: int,
          attrs: List[dict], status: int = STATUS_OK, links: List[dict] = None, trace_state: str = "") -> dict:
    base = [_s("ga5.run.id", st["runId"]), _s("ga5.public.marker", st["publicMarker"])]
    sp = {"traceId": st["trace"]["traceId"], "spanId": span_id, "name": name, "kind": kind,
          "startTimeUnixNano": str(start), "endTimeUnixNano": str(max(end, start + 1)),
          "attributes": base + attrs, "status": {"code": status}}
    if parent:
        sp["parentSpanId"] = parent
    if links:
        sp["links"] = links
    if trace_state:
        sp["traceState"] = trace_state
    return sp


def build_otlp(st: dict) -> dict:
    tr = st["trace"]
    ts = tr.get("traceState", "")
    t0 = st["t0"]
    end_all = st.get("finalAt") or t0 + 1
    agent_name = st["agentName"]
    spans: List[dict] = []

    spans.append(_span(st, tr["serverSpanId"], tr.get("parentSpanId", ""), "POST /v2/incidents", SPAN_SERVER, t0, end_all,
                       [_s("http.request.method", "POST"), _s("http.route", "/v2/incidents"), _i("http.response.status_code", 200)],
                       trace_state=ts))
    spans.append(_span(st, tr["agentSpanId"], tr["serverSpanId"], f"invoke_agent {agent_name}", SPAN_INTERNAL, t0, end_all,
                       [_s("gen_ai.operation.name", "invoke_agent"), _s("gen_ai.agent.name", agent_name)], trace_state=ts))
    m = st["model"]
    spans.append(_span(st, tr["chatSpanId"], tr["agentSpanId"], "chat incident-plan", SPAN_CLIENT, m["startNs"], m["endNs"],
                       [_s("gen_ai.operation.name", "chat"), _s("gen_ai.request.model", m["name"] or "unknown"),
                        _s("gen_ai.system", "openai-compatible")], trace_state=ts))

    exec_spans: Dict[str, dict] = {}
    diag_exec: List[dict] = []
    for aid in st["order"]:
        a = st["actions"][aid]
        atts = a["attempts"]
        start = atts[0]["dispatchedAt"]
        end = max([x["receipt"]["at"] for x in atts if x.get("receipt")] or [start + 1])
        failed = a["status"] == "failed"
        ex = _span(st, a["execSpanId"], tr["agentSpanId"], f"execute_tool {a['toolName']}", SPAN_INTERNAL, start, end,
                   [_s("ga5.action.id", a["actionId"]), _s("gen_ai.tool.name", a["toolName"]),
                    _s("gen_ai.tool.call.id", a["callId"]), _s("gen_ai.operation.name", "execute_tool"),
                    _s("ga5.action.phase", a["phase"])],
                   status=STATUS_ERROR if failed else STATUS_OK, trace_state=ts)
        spans.append(ex)
        exec_spans[aid] = ex
        if a["phase"] == "diagnostic":
            diag_exec.append(ex)
        for x in atts:
            r = x.get("receipt")
            if not r:
                continue
            code = int(r["status"])
            ok = 200 <= code < 300
            attrs = [_s("ga5.action.id", a["actionId"]), _i("ga5.attempt", x["attempt"]),
                     _s("ga5.receipt.id", r["receiptId"]), _s("ga5.receipt.nonce", r["nonce"]),
                     _s("http.request.method", "POST"), _i("http.request.resend_count", x["attempt"] - 1),
                     _s("authorization", "[REDACTED]")]
            if code > 0:
                attrs.append(_i("http.response.status_code", code))
            if not ok:
                attrs.append(_s("error.type", "timeout" if code == 0 else str(code)))
            spans.append(_span(st, x["clientSpanId"], a["execSpanId"], f"POST tool/{a['toolName']}", SPAN_CLIENT,
                               x["dispatchedAt"], r["at"], attrs, status=STATUS_OK if ok else STATUS_ERROR, trace_state=ts))

    if len(diag_exec) > 1:
        js = min(e["startTimeUnixNano"] for e in diag_exec)
        je = max(e["endTimeUnixNano"] for e in diag_exec)
        spans.append(_span(st, tr["joinSpanId"], tr["agentSpanId"], "incident.join", SPAN_INTERNAL, int(js), int(je),
                           [_s("ga5.join.kind", "diagnostics")],
                           links=[{"traceId": tr["traceId"], "spanId": e["spanId"]} for e in diag_exec], trace_state=ts))

    ap = st.get("approval")
    if ap and ap.get("state") != "pending":
        spans.append(_span(st, tr["gateSpanId"], tr["agentSpanId"], "approval_gate", SPAN_INTERNAL, ap["requestedAt"], ap["decidedAt"],
                           [_s("ga5.approval.id", ap["approvalId"]), _s("ga5.approval.receipt.nonce", ap["nonce"]),
                            _s("ga5.approval.nonce", ap["nonce"]), _s("ga5.approval.receipt.id", ap["receiptId"]),
                            _s("ga5.approval.decision", ap["decision"]), _s("ga5.action.id", ap["actionId"])],
                           trace_state=ts))
    return {"resourceSpans": [{"resource": {"attributes": [_s("service.name", agent_name)]},
                               "scopeSpans": [{"scope": {"name": "ga5-incident-agent"}, "spans": spans}]}]}
