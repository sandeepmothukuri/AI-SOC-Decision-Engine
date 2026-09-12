"""AI SOC Engine — FastAPI server (hardened).

The API normalises alerts from Wazuh, Suricata and Zeek, optionally enriches
observables with Cortex, performs deterministic/LLM-assisted triage, and
creates analyst-reviewable TheHive cases.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from analyzer import AlertAnalyzer
from config import Config
from cortex_client import CortexClient
from schemas import AlertPayload, TriageResult
from thehive_client import TheHiveClient


def create_app(config: Optional[Config] = None) -> FastAPI:
    config = config or Config.load()
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logger = logging.getLogger("ai-soc-engine")

    analyzer = AlertAnalyzer(config)
    hive_client = TheHiveClient(
        config.thehive_url, config.thehive_api_key, config.thehive_timeout_seconds
    )
    cortex_client = CortexClient(
        config.cortex_url,
        config.cortex_api_key,
        config.cortex_analyzer_id,
        config.cortex_observable_type,
        config.cortex_tlp,
        config.cortex_timeout_seconds,
        config.cortex_enabled,
    )

    app = FastAPI(
        title="AI SOC Engine",
        description="LLM-powered alert triage and observable enrichment for an open-source SOC",
        version="2.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
    )
    app.state.analyzer = analyzer
    app.state.hive_client = hive_client
    app.state.cortex_client = cortex_client

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex[:12]
        started = time.monotonic()
        response = await call_next(request)
        elapsed = (time.monotonic() - started) * 1000
        response.headers["X-Request-Id"] = request.state.request_id
        if request.url.path.startswith("/analyze"):
            logger.info(
                "request=%s path=%s status=%s %.1fms",
                request.state.request_id,
                request.url.path,
                response.status_code,
                elapsed,
            )
        return response

    class PlaybookRequest(BaseModel):
        alert_type: str
        context: Optional[str] = None

    class QueryRequest(BaseModel):
        question: str

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "model": config.model_name,
            "backend": config.backend,
            "prompt_version": config.prompt_version,
            "human_approval": config.human_approval_enabled,
            "cortex_enrichment": config.cortex_enabled,
        }

    @app.post("/analyze", response_model=TriageResult)
    async def analyze_alert(alert: AlertPayload):
        payload = alert.model_dump()

        cortex_context = await cortex_client.enrich(payload)
        if cortex_context is not None:
            payload["cortex_context"] = cortex_context

        result = await analyzer.analyze(payload)

        # Automation: create a TheHive case only for decisions that do not
        # require human approval and are not benign/duplicate closes.
        if result.verdict == "ESCALATE" and not result.needs_approval:
            await hive_client.create_case(payload, result.model_dump())

        return result

    @app.post("/approve/{decision_id}")
    async def approve(decision_id: str):
        held = analyzer.approve(decision_id)
        if held is None:
            raise HTTPException(status_code=404, detail="unknown or expired decision")
        await hive_client.create_case(held["alert"], held["analysis"].model_dump())
        return {
            "decision_id": decision_id,
            "status": "approved",
            "verdict": held["analysis"].verdict,
        }

    @app.post("/reject/{decision_id}")
    async def reject(decision_id: str):
        held = analyzer.reject(decision_id)
        if held is None:
            raise HTTPException(status_code=404, detail="unknown or expired decision")
        return {"decision_id": decision_id, "status": "rejected"}

    @app.post("/playbook")
    async def generate_playbook(body: PlaybookRequest):
        steps = await analyzer.generate_playbook(body.alert_type, body.context)
        return {"alert_type": body.alert_type, "steps": steps}

    @app.post("/query")
    async def natural_language_query(body: QueryRequest):
        dsl = await analyzer.nl_to_dsl(body.question)
        return {"question": body.question, "elasticsearch_dsl": dsl}

    @app.get("/stats")
    async def stats():
        return analyzer.get_stats()

    @app.get("/config")
    async def get_config():
        return config.as_dict()

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "detail": str(exc),
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8888")))
