"""
Core alert analysis for the AI SOC Engine (hardened).

Pipeline per alert:
  1. Deduplication check
  2. Deterministic safety pre-assessment (injection detection, IOCs, lists)
  3. LLM analysis (Ollama) with timeout + retries, OR offline rule engine
  4. Strict schema validation — malformed output is rejected
  5. Fallback to the deterministic engine when the LLM is unavailable/malformed
  6. Confidence-threshold enforcement
  7. Human-approval gating for ESCALATE/CLOSE
  8. Structured decision logging + metrics
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from config import Config
from llm_backends import BackendError, OfflineBackend, OllamaBackend
from safety import SafetyEngine
from schemas import AIAnalysis, TriageResult, parse_model_json

logger = logging.getLogger(__name__)

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"
MANIFEST_PATH = PROMPT_DIR / "prompt_manifest.json"


class PromptManager:
    """Loads versioned prompts and verifies their integrity against a manifest."""

    def __init__(self, version: str):
        self.version = version
        self._prompts: dict[str, str] = {}
        self._manifest = {}
        self._load()

    def _load(self) -> None:
        if MANIFEST_PATH.exists():
            try:
                self._manifest = json.loads(MANIFEST_PATH.read_text())
            except json.JSONDecodeError:
                logger.warning("prompt_manifest.json is not valid JSON")
        version_dir = PROMPT_DIR / self.version
        if not version_dir.exists():
            raise FileNotFoundError(f"Prompt version '{self.version}' not found under {PROMPT_DIR}")
        for f in sorted(version_dir.glob("*.txt")):
            content = f.read_text()
            expected = self._manifest.get("versions", {}).get(self.version, {}).get(f.name)
            actual = hashlib.sha256(content.encode()).hexdigest()
            if expected and actual != expected:
                logger.warning(
                    "Prompt %s/%s hash mismatch: manifest %s != file %s",
                    self.version,
                    f.name,
                    expected[:12],
                    actual[:12],
                )
            self._prompts[f.stem] = content
        logger.info("Loaded prompt version %s (%d templates)", self.version, len(self._prompts))

    def get(self, name: str) -> str:
        if name not in self._prompts:
            raise KeyError(f"prompt '{name}' not found in version {self.version}")
        return self._prompts[name]


class AlertAnalyzer:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.load()
        self.model_name = self.config.model_name
        self.prompts = PromptManager(self.config.prompt_version)
        self.safety = SafetyEngine(self.config.blocklist_path, self.config.allowlist_path)
        self.offline = OfflineBackend(self.safety)

        if self.config.backend == "offline":
            self.llm = None
        else:
            self.llm = OllamaBackend(
                host=self.config.ollama_host,
                model=self.model_name,
                temperature=self.config.temperature,
                num_predict=self.config.num_predict,
                timeout=self.config.llm_timeout_seconds,
            )

        # Deduplication cache (OrderedDict as an LRU).
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._dedupe_max = 10_000

        # Pending human-approval decisions.
        self._pending: dict[str, dict] = {}

        # Metrics.
        self._stats: dict[str, Any] = {
            "analyzed": 0,
            "escalated": 0,
            "enriched": 0,
            "closed": 0,
            "pending_approval": 0,
            "needs_approval": 0,
            "malformed_rejected": 0,
            "injection_detected": 0,
            "fallbacks": 0,
            "errors": 0,
            "duplicates": 0,
            "latencies_ms": [],
            "enrichment": {"misp_hits": 0, "misp_misses": 0, "cortex_runs": 0},
        }

    # ------------------------------------------------------------------ #
    # Deduplication
    # ------------------------------------------------------------------ #
    def _dedupe_key(self, alert: dict) -> str:
        parts = [
            str(alert.get(k) or "")
            for k in ("source", "rule_id", "source_ip", "dest_ip", "rule_description")
        ]
        raw = alert.get("raw_log", "")
        m = re.search(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", raw)
        if m:
            parts.append(m.group(1).lower())
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    def is_duplicate(self, alert: dict, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        key = self._dedupe_key(alert)
        self._prune_dedupe(now)
        if key in self._seen:
            return True
        self._seen[key] = now
        if len(self._seen) > self._dedupe_max:
            self._seen.popitem(last=False)
        return False

    def _prune_dedupe(self, now: float) -> None:
        ttl = self.config.dedupe_ttl_seconds
        while self._seen and (now - next(iter(self._seen.values()))) > ttl:
            self._seen.popitem(last=False)

    # ------------------------------------------------------------------ #
    # Main analysis
    # ------------------------------------------------------------------ #
    async def analyze(self, alert: dict) -> TriageResult:
        started = time.monotonic()

        if self.is_duplicate(alert):
            self._stats["duplicates"] += 1
            logger.info("Duplicate event skipped: alert_id=%s", alert.get("alert_id"))
            # A duplicate still returns a valid, structured result so callers
            # can handle it uniformly; automation is suppressed downstream.
            return TriageResult(
                alert_id=alert.get("alert_id", ""),
                verdict="ENRICH",
                severity="LOW",
                confidence=0.0,
                summary="Duplicate event (skipped within dedupe window).",
                rationale="Same event key seen within the dedupe TTL.",
                mitre_techniques=[],
                recommended_action="No action; already processed.",
                evidence=["duplicate detected"],
                model=self.model_name,
                prompt_version=self.prompts.version,
                processing_time_ms=int((time.monotonic() - started) * 1000),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        safety_assessment = self.safety.assess(alert)
        injection = safety_assessment.injection_detected
        if injection:
            self._stats["injection_detected"] += 1

        # Enrichment accounting (MISP context supplied by Shuffle; Cortex optional).
        misp = alert.get("misp_context") or {}
        if misp:
            if misp.get("found"):
                self._stats["enrichment"]["misp_hits"] += 1
            else:
                self._stats["enrichment"]["misp_misses"] += 1
        if alert.get("cortex_context") is not None:
            self._stats["enrichment"]["cortex_runs"] += 1

        # 1. Try the configured backend.
        analysis: Optional[AIAnalysis] = None
        fallback_used = False
        if self.llm is not None and not injection:
            analysis = await self._try_llm(alert)
            if analysis is None:
                fallback_used = True

        # 2. Fallback to deterministic rules (only a "fallback" if an LLM was
        #    expected; for backend=offline this is the intended primary path).
        if analysis is None:
            analysis = await self._offline_analysis(alert)
            if self.llm is not None:
                fallback_used = True
                self._stats["fallbacks"] += 1

        # 3. Deterministic overrides (safety floor).
        analysis = self._apply_safety_overrides(analysis, alert, safety_assessment, injection)

        # 4. Confidence thresholds.
        analysis = self._apply_thresholds(analysis)

        # 5. Human-approval gating.
        needs_approval = False
        decision_id = None
        if (
            self.config.human_approval_enabled
            and analysis.verdict in self.config.human_approval_verdicts
        ):
            needs_approval = True
            decision_id = uuid.uuid4().hex
            self._pending[decision_id] = {"alert": alert, "analysis": analysis}
            self._stats["needs_approval"] += 1
            self._stats["pending_approval"] += 1

        self._stats["analyzed"] += 1
        if analysis.verdict == "ESCALATE":
            self._stats["escalated"] += 1
        elif analysis.verdict == "CLOSE":
            self._stats["closed"] += 1
        else:
            self._stats["enriched"] += 1

        elapsed_ms = int((time.monotonic() - started) * 1000)
        self._stats["latencies_ms"].append(elapsed_ms)
        if len(self._stats["latencies_ms"]) > 5000:
            self._stats["latencies_ms"] = self._stats["latencies_ms"][-5000:]

        result = TriageResult(
            alert_id=alert.get("alert_id", ""),
            verdict=analysis.verdict,
            severity=analysis.severity,
            confidence=analysis.confidence,
            summary=analysis.summary,
            rationale=analysis.rationale,
            mitre_techniques=analysis.mitre_techniques,
            recommended_action=analysis.recommended_action,
            evidence=analysis.evidence,
            is_false_positive=analysis.is_false_positive,
            needs_approval=needs_approval,
            decision_id=decision_id,
            fallback_used=fallback_used,
            injection_detected=injection,
            model=self.model_name if not fallback_used else f"{self.model_name} (offline fallback)",
            prompt_version=self.prompts.version,
            processing_time_ms=elapsed_ms,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self._log_decision(result)
        return result

    # ------------------------------------------------------------------ #
    async def _try_llm(self, alert: dict) -> Optional[AIAnalysis]:
        prompt = self.prompts.get("triage").replace("{alert}", json.dumps(alert, indent=2))
        last_err: Optional[Exception] = None
        for attempt in range(self.config.llm_max_retries + 1):
            try:
                raw = await asyncio.wait_for(
                    self.llm.generate(prompt),
                    timeout=self.config.llm_timeout_seconds + 5,
                )
                parsed = parse_model_json(raw)
                return AIAnalysis.model_validate(parsed)
            except asyncio.TimeoutError as e:
                last_err = e
                logger.error("LLM call timed out (attempt %d)", attempt + 1)
            except (BackendError, ValueError, TypeError) as e:
                last_err = e
                self._stats["malformed_rejected"] += 1
                logger.error("LLM output rejected (attempt %d): %s", attempt + 1, e)
            except Exception as e:  # noqa: BLE001 - surface unexpected failures
                last_err = e
                logger.exception("Unexpected LLM error")
        logger.error(
            "LLM unavailable after %d attempt(s): %s", self.config.llm_max_retries + 1, last_err
        )
        return None

    async def _offline_analysis(self, alert: dict) -> AIAnalysis:
        data = await self.offline.analyze(alert)
        return AIAnalysis.model_validate(data)

    # ------------------------------------------------------------------ #
    def _apply_safety_overrides(
        self,
        analysis: AIAnalysis,
        alert: dict,
        safety,
        injection: bool,
    ) -> AIAnalysis:
        """Deterministic floor rules that the LLM cannot override."""
        data = analysis.model_dump()

        if injection:
            data["verdict"] = "ENRICH"
            data["confidence"] = min(float(data.get("confidence", 0.5)), 0.5)
            data["is_false_positive"] = False
            data["rationale"] = (
                "Prompt-injection pattern detected; LLM output overridden by the "
                "deterministic safety layer. Manual review required."
            )
            data["evidence"] = list(data.get("evidence", [])) + [
                "injection pattern: " + "; ".join(safety.injection_hits[:3])
            ]

        # Blocklist match forces a minimum escalation stance.
        if safety.blocklist_hits and data.get("verdict") == "CLOSE":
            data["verdict"] = "ESCALATE"
            data["is_false_positive"] = False
            data["rationale"] = "Blocklist match overrides CLOSE verdict."

        # Missing-IOC confidence cap.
        if not safety.has_ioc:
            data["confidence"] = min(
                float(data.get("confidence", 0.5)), self.config.missing_ioc_confidence_cap
            )
            if data.get("verdict") == "ESCALATE" and not safety.blocklist_hits:
                data["verdict"] = "ENRICH"

        # Preserve deterministic MITRE mapping if the LLM gave none.
        if not data.get("mitre_techniques") and safety.mitre_techniques:
            data["mitre_techniques"] = safety.mitre_techniques

        return AIAnalysis.model_validate(data)

    def _apply_thresholds(self, analysis: AIAnalysis) -> AIAnalysis:
        data = analysis.model_dump()
        verdict = data["verdict"]
        conf = float(data["confidence"])

        if verdict == "ESCALATE" and conf < self.config.escalate_min_confidence:
            data["verdict"] = "ENRICH"
            data["rationale"] = (
                f"Confidence {conf:.2f} below escalate threshold "
                f"{self.config.escalate_min_confidence}; downgraded to ENRICH."
            )
        elif verdict == "CLOSE" and conf < self.config.close_min_confidence:
            data["verdict"] = "ENRICH"
            data["is_false_positive"] = False
            data["rationale"] = (
                f"Confidence {conf:.2f} below close threshold "
                f"{self.config.close_min_confidence}; downgraded to ENRICH."
            )
        return AIAnalysis.model_validate(data)

    # ------------------------------------------------------------------ #
    # Human approval
    # ------------------------------------------------------------------ #
    def approve(self, decision_id: str) -> Optional[dict]:
        return self._pending.pop(decision_id, None)

    def reject(self, decision_id: str) -> Optional[dict]:
        return self._pending.pop(decision_id, None)

    def pending_count(self) -> int:
        return len(self._pending)

    # ------------------------------------------------------------------ #
    # Playbook + NL->DSL (aux endpoints)
    # ------------------------------------------------------------------ #
    async def generate_playbook(self, alert_type: str, context: str = "") -> list[str]:
        prompt = self.prompts.get("playbook").format(alert_type=alert_type, context=context or "")
        if self.llm is None:
            return [
                "Contain the affected host",
                "Collect and preserve relevant logs",
                "Determine scope of impact",
                "Eradicate the threat",
                "Recover affected systems",
                "Document the incident and IOCs",
            ]
        raw = await self.llm.generate(prompt)
        steps = [s.strip() for s in raw.strip().splitlines() if s.strip()]
        return steps[:10]

    async def nl_to_dsl(self, question: str) -> dict:
        prompt = self.prompts.get("nl_to_dsl").format(question=question)
        if self.llm is None:
            return {"error": "no LLM backend configured"}
        raw = await self.llm.generate(prompt)
        try:
            return parse_model_json(raw)
        except ValueError:
            return {"error": "Could not parse DSL", "raw": raw}

    # ------------------------------------------------------------------ #
    # Observability
    # ------------------------------------------------------------------ #
    def _log_decision(self, result: TriageResult) -> None:
        entry = json.dumps(
            {
                "event": "ai_decision",
                "alert_id": result.alert_id,
                "verdict": result.verdict,
                "severity": result.severity,
                "confidence": result.confidence,
                "needs_approval": result.needs_approval,
                "fallback_used": result.fallback_used,
                "injection_detected": result.injection_detected,
                "model": result.model,
                "prompt_version": result.prompt_version,
                "processing_time_ms": result.processing_time_ms,
            },
            default=str,
        )
        logger.info(entry)
        log_path = self.config.decision_log_path
        if log_path:
            try:
                with open(log_path, "a") as fh:
                    fh.write(entry + "\n")
            except OSError as e:
                logger.error("Could not write decision log: %s", e)

    def get_stats(self) -> dict:
        lat = self._stats["latencies_ms"]
        out = dict(self._stats)
        out["latencies_ms"] = None
        if lat:
            ordered = sorted(lat)
            n = len(ordered)
            out["latency"] = {
                "count": n,
                "avg_ms": round(sum(lat) / n, 1),
                "p50_ms": ordered[n // 2],
                "p95_ms": ordered[int(n * 0.95) - 1 if n > 1 else 0],
                "max_ms": ordered[-1],
            }
        else:
            out["latency"] = {
                "count": 0,
                "avg_ms": None,
                "p50_ms": None,
                "p95_ms": None,
                "max_ms": None,
            }
        out["pending_approvals"] = self.pending_count()
        return out
