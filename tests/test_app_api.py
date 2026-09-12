"""FastAPI layer tests (in-process ASGI transport)."""

from __future__ import annotations

import asyncio
import os

# Configure the app BEFORE importing it.
os.environ["AI_SOC_BACKEND"] = "offline"
os.environ["AI_SOC_HUMAN_APPROVAL"] = "true"
os.environ["THEHIVE_URL"] = "http://127.0.0.1:9"

import httpx  # noqa: E402

from scenarios import TRUE_POSITIVE  # noqa: E402


async def _run(fn):
    from app import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        return await fn(c)


def test_health():
    async def body(c):
        r = await c.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        assert r.json()["prompt_version"] == "v1"

    asyncio.run(_run(body))


def _tp(source_ip: str, alert_id: str) -> dict:
    return dict(TRUE_POSITIVE, source_ip=source_ip, alert_id=alert_id)


def test_analyze_returns_required_schema():
    async def body(c):
        r = await c.post("/analyze", json=_tp("185.220.101.45", "API-1"))
        assert r.status_code == 200
        data = r.json()
        for field in (
            "summary",
            "severity",
            "confidence",
            "rationale",
            "mitre_techniques",
            "recommended_action",
            "evidence",
        ):
            assert field in data, f"missing {field}"
        assert data["verdict"] == "ESCALATE"
        assert data["needs_approval"] is True
        assert data["decision_id"]

    asyncio.run(_run(body))


def test_approve_then_404_on_repeat():
    async def body(c):
        r = await c.post("/analyze", json=_tp("185.220.101.46", "API-2"))
        decision_id = r.json()["decision_id"]
        ok = await c.post(f"/approve/{decision_id}")
        assert ok.status_code == 200
        assert ok.json()["status"] == "approved"
        dup = await c.post(f"/approve/{decision_id}")
        assert dup.status_code == 404

    asyncio.run(_run(body))


def test_reject_unknown_404():
    async def body(c):
        r = await c.post("/reject/does-not-exist")
        assert r.status_code == 404

    asyncio.run(_run(body))


def test_invalid_alert_rejected():
    async def body(c):
        bad = dict(TRUE_POSITIVE, severity=99)
        r = await c.post("/analyze", json=bad)
        assert r.status_code == 422

    asyncio.run(_run(body))


def test_stats_endpoint():
    async def body(c):
        r = await c.get("/stats")
        assert r.status_code == 200
        assert "analyzed" in r.json()

    asyncio.run(_run(body))
