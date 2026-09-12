"""
Pipeline harness for reproducible end-to-end testing of the documented chain:

    Wazuh alert -> Shuffle workflow -> MISP/Cortex enrichment -> AI engine -> TheHive

What is real vs. mocked (see docs/testing.md):
  - AI engine (analyzer.py, safety.py, schemas.py, thehive_client.py): REAL code.
  - Shuffle workflow JSON (shuffle-workflows/*.json): interpreted faithfully by a
    small runner, because the files are NOT in Shuffle's native import format and
    the embedded Python uses top-level `return` (not executable as-is). See
    shuffle-workflows/README.md.
  - Wazuh/Suricata/Zeek detection: simulated with the repo's own synthetic alert
    fixtures (clearly labelled test data).
  - MISP / Cortex / TheHive: mocked HTTP services with availability toggles.
  - Ollama: real Ollama HTTP API if OLLAMA is reachable, otherwise the
    deterministic offline backend (fallback path) is exercised.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Optional


# --------------------------------------------------------------------------- #
# Tiny threaded JSON HTTP mock service
# --------------------------------------------------------------------------- #
class MockHTTPService:
    """Serves JSON on an ephemeral port; records every request."""

    def __init__(self, handler: Callable[[dict], tuple[int, dict]], name: str = "mock"):
        self.name = name
        self.requests: list[dict] = []
        self._handler = handler

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def do_POST(self):  # noqa: N802
                self._handle()

            def do_GET(self):  # noqa: N802
                self._handle()

            def do_PUT(self):  # noqa: N802
                self._handle()

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    body = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    body = {"_raw": raw.decode(errors="replace")}
                self.server.outer.requests.append(
                    {"method": self.command, "path": self.path, "body": body}
                )
                try:
                    status, resp = self.server.outer._handler(body)
                except Exception as e:  # noqa: BLE001
                    status, resp = 500, {"error": str(e)}
                data = json.dumps(resp).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = HTTPServer(("127.0.0.1", 0), _H)
        self.server.outer = self
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def make_misp(
    enabled: bool = True, found: bool = True, threat_level: str = "high"
) -> MockHTTPService:
    """MISP mock: returns threat-intel context for an IOC search."""

    def h(body):
        if not enabled:
            return 503, {"error": "unavailable"}
        resp = {"found": found}
        if found:
            resp.update({"tags": ["botnet", "tor-exit-node"], "threat_level": threat_level})
        return 200, resp

    return MockHTTPService(h, name="misp")


def make_cortex(enabled: bool = True, malicious: bool = True) -> MockHTTPService:
    """Cortex mock: returns an analyser verdict."""

    def h(body):
        if not enabled:
            return 503, {"error": "unavailable"}
        return 200, {
            "analysers": [
                {"name": "VirusTotal_3_1", "malicious": malicious, "report": "demo report"}
            ]
        }

    return MockHTTPService(h, name="cortex")


def make_thehive(enabled: bool = True) -> MockHTTPService:
    """TheHive mock: records POST /api/v1/case and returns a case id."""

    requests: list = []

    def h(body):
        if not enabled:
            return 503, {"error": "unavailable"}
        return 201, {"_id": f"case-{len(requests)}", "title": body.get("title", "")}

    return MockHTTPService(h, name="thehive")


def make_ollama(response: str, enabled: bool = True) -> MockHTTPService:
    """Ollama mock: returns a canned /api/generate response (or an error)."""

    def h(body):
        if not enabled:
            return 503, {"error": "unavailable"}
        return 200, {"model": body.get("model", "llama3"), "response": response, "done": True}

    return MockHTTPService(h, name="ollama")


# --------------------------------------------------------------------------- #
# Shuffle workflow runner (interprets the repo's simplified workflow JSON)
# --------------------------------------------------------------------------- #
_VAR_RE = re.compile(r"\$([A-Za-z_][\w.]*)")


_FULL_VAR = re.compile(r"^\$([A-Za-z_][\w.]*)$")


def _lookup(key: str, context: dict, env: dict, default: Any) -> Any:
    if key.startswith("ENV."):
        return env.get(key[4:], default)
    parts = key.split(".")
    cur: Any = context
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def _resolve(value: Any, context: dict, env: dict) -> Any:
    if isinstance(value, str):
        # A value that is exactly "$var" is passed through as the object itself
        # (Shuffle semantics for whole-value references), preserving its type.
        whole = _FULL_VAR.match(value)
        if whole:
            return _lookup(whole.group(1), context, env, whole.group(0))

        def repl(m):
            raw = _lookup(m.group(1), context, env, m.group(0))
            return (
                raw
                if isinstance(raw, str)
                else (json.dumps(raw) if isinstance(raw, (dict, list)) else str(raw))
            )

        return _VAR_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _resolve(v, context, env) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, context, env) for v in value]
    return value


def _run_python_step(code: str, execution_argument: Any) -> dict:
    """Execute the workflow's inline Python.

    The repo's snippets use a top-level `return`, which is not valid at module
    scope; we normalise `return X` -> `result = X` (documented in the harness).
    """
    normalized = re.sub(r"^\s*return\s+", "result = ", code, flags=re.MULTILINE)
    ns: dict = {"execution_argument": execution_argument, "json": json}
    exec(compile(normalized, "<workflow>", "exec"), ns)  # noqa: S102 - repo-owned code
    return ns.get("result", {})


class WorkflowRunner:
    """Executes a repo shuffle-workflow JSON against the supplied services."""

    def __init__(self, workflow: dict, ai_engine_url: str, env: Optional[dict] = None):
        self.workflow = workflow
        self.ai_engine_url = ai_engine_url
        self.env = env or {}
        self.context: dict = {}
        self.trace: list[dict] = []

    def run(self, trigger_payload: dict) -> dict:
        self.context = {
            "exec": {
                "timestamp": trigger_payload.get("timestamp", ""),
                "raw": json.dumps(trigger_payload),
            },
        }
        for action in self.workflow.get("actions", []):
            self._run_action(action, trigger_payload)
        return self.context

    def _run_action(self, action: dict, trigger_payload: dict) -> None:
        action_id = action.get("id", "?")
        app = action.get("app", "")
        act = action.get("action", "")
        params = action.get("parameters", {})

        # Honour "requires": only run if the required action produced a truthy
        # filter pass. Filter results are stored as booleans in context.
        requires = action.get("requires")
        if requires and not self.context.get(requires):
            self.trace.append({"id": action_id, "skipped": f"requires {requires}"})
            return

        if app == "Shuffle Tools" and act == "execute_python":
            result = _run_python_step(params.get("code", ""), trigger_payload)
        elif app == "MISP":
            result = self._call_external(params, "misp")
        elif app == "VirusTotal":
            result = self._call_external(params, "vt")
        elif app == "Cortex":
            result = self._call_external(params, "cortex")
        elif app == "HTTP" and act in ("POST", "PUT"):
            result = self._call_external(params, "http", act)
        elif app == "Shuffle Tools" and act == "filter":
            field = _resolve(params.get("field"), self.context, self.env)
            check = params.get("check")
            value = _resolve(params.get("value"), self.context, self.env)
            result = self._filter(field, check, value)
        elif app == "Slack":
            result = {
                "posted": True,
                "message": _resolve(params.get("message"), self.context, self.env),
            }
        else:
            result = {"unsupported": f"{app}/{act}"}

        self.context[action_id] = result
        self.trace.append({"id": action_id, "result": result})

    def _call_external(self, params: dict, kind: str, method: str = "POST") -> dict:
        import httpx

        url = _resolve(params.get("url"), self.context, self.env) or ""
        # Map the docker-network hostname to the engine URL under test.
        if "ai-engine:8888" in url:
            url = url.replace("http://ai-engine:8888", self.ai_engine_url)
        if "wazuh-manager:55000" in url:
            url = url.replace("https://wazuh-manager:55000", self.env.get("WAZUH_URL", ""))
        if kind == "misp":
            url = self.env.get("MISP_URL", "") + "/search"
            body = {
                "value": _resolve(params.get("value"), self.context, self.env),
                "type": params.get("type", "ip-src"),
            }
        elif kind == "cortex":
            url = self.env.get("CORTEX_URL", "") + "/run"
            body = _resolve(params.get("data"), self.context, self.env) or {}
        elif kind == "vt":
            url = self.env.get("VT_URL", "") + "/hash"
            body = {"hash": _resolve(params.get("hash"), self.context, self.env)}
        else:
            body = _resolve(params.get("body"), self.context, self.env)
        headers = _resolve(params.get("headers"), self.context, self.env) or {}
        try:
            r = httpx.request(method, url, json=body, headers=headers, timeout=10.0)
            try:
                return r.json()
            except Exception:  # noqa: BLE001
                return {"status_code": r.status_code, "text": r.text[:500]}
        except httpx.HTTPError as e:
            return {"error": str(e)}

    @staticmethod
    def _filter(field: Any, check: str, value: Any) -> bool:
        if check == "equals":
            return str(field) == str(value)
        if check == "not equal":
            return str(field) != str(value)
        if check == "contains":
            return str(value) in str(field)
        return False


# --------------------------------------------------------------------------- #
# Run the FastAPI engine in-process for HTTP-level tests
# --------------------------------------------------------------------------- #
def start_engine(config, host: str = "127.0.0.1", port: int = 0):
    """Start a uvicorn server (threaded) for the engine and return (server, url)."""
    import time

    import uvicorn

    from app import create_app

    app = create_app(config)
    ucfg = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(ucfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.02)
    if not server.started:
        raise RuntimeError("engine server failed to start")
    bound = server.servers[0].sockets[0].getsockname()
    return server, f"http://{bound[0]}:{bound[1]}"
