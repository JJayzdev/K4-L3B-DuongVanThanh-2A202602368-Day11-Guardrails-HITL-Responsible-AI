"""Local API + static server for the VinBank guardrails demo dashboard."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DEMO_DIR = Path(__file__).resolve().parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from google.genai import types

from assignment.pipeline import is_egress_allowed
from assignment.rate_limiter import RateLimitPlugin
from core.config import blue_provider_label, red_provider_label
from core.utils import chat_with_agent
from guardrails.input_guardrails import detect_injection, topic_filter
from guardrails.output_guardrails import content_filter


def _load_json(name: str, default):
    path = ROOT / "outputs" / name
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


class DemoState:
    def __init__(self):
        self.audit: list[dict] = []
        self.total = 0
        self.blocked = 0
        self.redacted = 0
        self.blue_pair = None

    def blue(self):
        if self.blue_pair is None:
            from agents.agent import create_blue_agent

            self.blue_pair = create_blue_agent([])
        return self.blue_pair


STATE = DemoState()


def status_payload() -> dict:
    results = _load_json("results.json", {})
    attacks = _load_json("attack_results.json", {})
    summary = attacks.get("summary") or {}
    safe = results.get("safe_queries") or []
    attack_rows = results.get("attack_queries") or []
    rate = results.get("rate_limit") or {}
    artifacts = []
    for name in (
        "results.json", "audit_log.json", "metrics.json",
        "attack_results.json", "grade_report.json", "lab_report.md",
    ):
        path = ROOT / "outputs" / name
        artifacts.append({
            "name": name,
            "exists": path.exists(),
            "bytes": path.stat().st_size if path.exists() else 0,
        })
    return {
        "blue": blue_provider_label(),
        "red": red_provider_label(),
        "defense": {
            "safe_total": len(safe),
            "safe_blocked": sum(row.get("blocked") is True for row in safe),
            "attack_total": len(attack_rows),
            "attack_blocked": sum(row.get("blocked") is True for row in attack_rows),
            "rate_blocked": rate.get("blocked", 0),
            "rate_sent": rate.get("sent", 0),
        },
        "red_team": {
            "unsafe_leaked": summary.get("unsafe_leaked", 0),
            "guards_leaked": summary.get("guards_leaked", 0),
            "guards_blocked": summary.get("guards_blocked_plugin", 0),
        },
        "runtime": {
            "total": STATE.total,
            "blocked": STATE.blocked,
            "redacted": STATE.redacted,
            "audit": STATE.audit[-8:],
        },
        "artifacts": artifacts,
    }


async def evaluate_input(text: str, call_model: bool) -> dict:
    STATE.total += 1
    trace = []
    injection = detect_injection(text)
    trace.append({"layer": "Injection detection", "status": injection})
    if injection == "BLOCK":
        STATE.blocked += 1
        response = "Request blocked before the LLM: prompt injection detected."
        layer = "input_injection"
    else:
        topic = topic_filter(text)
        trace.append({"layer": "Banking topic filter", "status": topic})
        if topic == "BLOCK":
            STATE.blocked += 1
            response = "Request blocked before the LLM: outside VinBank scope."
            layer = "input_topic"
        else:
            layer = None
            if call_model:
                try:
                    agent, runner = STATE.blue()
                    response, _ = await chat_with_agent(agent, runner, text)
                    import re, unicodedata
                    resp_norm = unicodedata.normalize("NFKC", response or "").lower()
                    refusal_patterns = [
                        r"kh[oô]ng th[eể] cung c[aấ]p",
                        r"kh[oô]ng [dđ][uư][oợ]c ti[eế]t l[oộ]",
                        r"b[aả]o m[aậ]t (n[oộ]i b[oộ]|h[eệ] th[oố]ng)",
                        r"kh[oô]ng c[oó] quy[eề]n truy c[aậ]p",
                        r"cannot (reveal|provide|share)",
                        r"not (authorized|permitted|allowed)",
                        r"refuse",
                    ]
                    is_refused = any(re.search(p, resp_norm, re.IGNORECASE) for p in refusal_patterns)
                    text_norm = unicodedata.normalize("NFKC", text or "").lower()
                    has_sensitive_query = any(w in text_norm for w in ["password", "mật khẩu", "secret", "database", "api_key", "host"])
                    if is_refused and has_sensitive_query:
                        layer = "blue_model_refusal"
                        trace.append({"layer": "Blue model", "status": "REFUSED"})
                    else:
                        trace.append({"layer": "Blue model", "status": "CALLED"})
                except Exception as exc:
                    response = (
                        f"Blue model unavailable ({type(exc).__name__}). "
                        "Guardrail decision remains valid."
                    )
                    trace.append({"layer": "Blue model", "status": "UNAVAILABLE"})
                    layer = "model_unavailable"
            else:
                if any(w in text.lower() for w in ["password", "mật khẩu", "secret", "database", "api_key", "host"]):
                    response = "Xin lỗi, theo quy định bảo mật VinBank, tôi không thể cung cấp mật khẩu quản trị, API key hoặc thông số máy chủ nội bộ."
                    layer = "blue_model_refusal"
                    trace.append({"layer": "Blue model", "status": "REFUSED"})
                else:
                    response = "Safe banking request accepted in offline demo mode."
                    trace.append({"layer": "Blue model", "status": "SKIPPED"})

            filtered = content_filter(response)
            if not filtered["safe"]:
                STATE.redacted += 1
                response = filtered["redacted"]
                layer = "output_guardrail"
                trace.append({"layer": "Output filter", "status": "REDACT"})
            else:
                trace.append({"layer": "Output filter", "status": "ALLOW"})

    is_blocked = layer in {"input_injection", "input_topic", "output_guardrail", "blue_model_refusal"}
    event = {"input": text, "layer": layer, "response": response[:240]}
    STATE.audit.append(event)
    return {"blocked": is_blocked, "layer": layer,
            "response": response, "trace": trace}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DEMO_DIR), **kwargs)

    def log_message(self, fmt, *args):
        print("[demo]", fmt % args)

    def _json(self, payload, status=200):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        size = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(size).decode("utf-8") or "{}")

    def do_GET(self):
        if self.path == "/api/status":
            self._json(status_payload())
            return
        super().do_GET()

    def do_POST(self):
        try:
            body = self._body()
            if self.path == "/api/evaluate":
                result = asyncio.run(evaluate_input(
                    str(body.get("text", "")), bool(body.get("call_model", False))
                ))
            elif self.path == "/api/output-check":
                result = content_filter(str(body.get("text", "")))
                if not result["safe"]:
                    STATE.redacted += 1
            elif self.path == "/api/egress":
                allowed = is_egress_allowed(
                    str(body.get("destination", "")), str(body.get("payload", ""))
                )
                result = {"allowed": allowed, "status": "ALLOW" if allowed else "BLOCK"}
            elif self.path == "/api/rate-limit":
                count = max(1, min(int(body.get("count", 5)), 25))
                maximum = max(1, min(int(body.get("maximum", 3)), 10))
                limiter = RateLimitPlugin(max_requests=maximum, window_seconds=60)
                blocked = 0
                for _ in range(count):
                    response = asyncio.run(limiter.on_user_message_callback(
                        invocation_context=SimpleNamespace(user_id="demo-user"),
                        user_message=types.Content(role="user", parts=[]),
                    ))
                    blocked += response is not None
                result = {"sent": count, "passed": count - blocked, "blocked": blocked,
                          "maximum": maximum, "window_seconds": 60}
            else:
                self._json({"error": "Unknown API route"}, 404)
                return
            self._json(result)
        except Exception as exc:
            self._json({"error": type(exc).__name__, "message": str(exc)}, 500)


def main():
    parser = argparse.ArgumentParser(description="VinBank guardrails demo dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Demo dashboard: http://{args.host}:{args.port}")
    print("API keys remain server-side; press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
