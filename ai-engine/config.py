"""
Runtime configuration for the AI SOC Engine.

Loads ai-engine/config.yaml, overrides with environment variables.
All safety/threshold/model settings are centralized here so that behaviour
is explicit, versioned, and auditable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = CONFIG_DIR / "config.yaml"

# Environment variable prefixes and their mapping onto config keys.
# The engine reads MODEL_NAME / OLLAMA_HOST / THEHIVE_URL / THEHIVE_API_KEY /
# LOG_LEVEL for backwards compatibility with the original docker-compose,
# plus AI_SOC_* namespaced variables for the new settings.
ENV_MAP = {
    "MODEL_NAME": "model.name",
    "OLLAMA_HOST": "ollama.host",
    "THEHIVE_URL": "thehive.url",
    "THEHIVE_API_KEY": "thehive.api_key",
    "LOG_LEVEL": "logging.level",
    "AI_SOC_BACKEND": "model.backend",
    "AI_SOC_TEMPERATURE": "model.temperature",
    "AI_SOC_TIMEOUT_SECONDS": "llm.timeout_seconds",
    "AI_SOC_RETRIES": "llm.max_retries",
    "AI_SOC_ESCALATE_MIN_CONFIDENCE": "thresholds.escalate_min_confidence",
    "AI_SOC_CLOSE_MIN_CONFIDENCE": "thresholds.close_min_confidence",
    "AI_SOC_HUMAN_APPROVAL": "human_approval.enabled",
    "AI_SOC_DEDUPE_TTL_SECONDS": "dedupe.ttl_seconds",
    "AI_SOC_PROMPT_VERSION": "prompt.version",
    "AI_SOC_BLOCKLIST": "safety.blocklist_path",
    "AI_SOC_ALLOWLIST": "safety.allowlist_path",
}


def _deep_get(d: dict, dotted: str, default: Any = None) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _deep_set(d: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = d
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


@dataclass
class Config:
    """Resolved configuration with typed accessors."""

    raw: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | str | None = None) -> "Config":
        cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
        raw: dict = {}
        if cfg_path.exists():
            raw = yaml.safe_load(cfg_path.read_text()) or {}

        # Environment overrides (also supports Docker's OLLAMA_HOST etc.)
        for env_var, dotted in ENV_MAP.items():
            value = os.getenv(env_var)
            if value is not None and value != "":
                _deep_set(raw, dotted, _coerce(value))
        return cls(raw=raw)

    # --- model ---
    @property
    def backend(self) -> str:
        return str(_deep_get(self.raw, "model.backend", "ollama"))

    @property
    def model_name(self) -> str:
        return str(_deep_get(self.raw, "model.name", "llama3"))

    @property
    def temperature(self) -> float:
        return float(_deep_get(self.raw, "model.temperature", 0.1))

    @property
    def num_predict(self) -> int:
        return int(_deep_get(self.raw, "model.num_predict", 1024))

    # --- ollama ---
    @property
    def ollama_host(self) -> str:
        return str(_deep_get(self.raw, "ollama.host", "http://localhost:11434"))

    # --- llm call behaviour ---
    @property
    def llm_timeout_seconds(self) -> float:
        return float(_deep_get(self.raw, "llm.timeout_seconds", 30.0))

    @property
    def llm_max_retries(self) -> int:
        return int(_deep_get(self.raw, "llm.max_retries", 1))

    @property
    def request_timeout_seconds(self) -> float:
        return float(_deep_get(self.raw, "llm.request_timeout_seconds", 60.0))

    # --- confidence thresholds ---
    @property
    def escalate_min_confidence(self) -> float:
        return float(_deep_get(self.raw, "thresholds.escalate_min_confidence", 0.75))

    @property
    def close_min_confidence(self) -> float:
        return float(_deep_get(self.raw, "thresholds.close_min_confidence", 0.85))

    @property
    def missing_ioc_confidence_cap(self) -> float:
        return float(_deep_get(self.raw, "thresholds.missing_ioc_confidence_cap", 0.5))

    # --- human approval ---
    @property
    def human_approval_enabled(self) -> bool:
        return bool(_deep_get(self.raw, "human_approval.enabled", True))

    @property
    def human_approval_verdicts(self) -> list[str]:
        return list(_deep_get(self.raw, "human_approval.verdicts", ["ESCALATE", "CLOSE"]))

    # --- dedupe ---
    @property
    def dedupe_ttl_seconds(self) -> int:
        return int(_deep_get(self.raw, "dedupe.ttl_seconds", 300))

    # --- prompts ---
    @property
    def prompt_version(self) -> str:
        return str(_deep_get(self.raw, "prompt.version", "v1"))

    # --- safety lists ---
    @property
    def blocklist_path(self) -> Path:
        p = _deep_get(self.raw, "safety.blocklist_path", "safety/blocklist.txt")
        return (CONFIG_DIR / p).resolve()

    @property
    def allowlist_path(self) -> Path:
        p = _deep_get(self.raw, "safety.allowlist_path", "safety/allowlist.txt")
        return (CONFIG_DIR / p).resolve()

    # --- thehive ---
    @property
    def thehive_url(self) -> str:
        return str(_deep_get(self.raw, "thehive.url", "http://thehive:9000"))

    @property
    def thehive_api_key(self) -> str:
        return str(_deep_get(self.raw, "thehive.api_key", ""))

    @property
    def thehive_timeout_seconds(self) -> float:
        return float(_deep_get(self.raw, "thehive.timeout_seconds", 10.0))

    # --- logging / observability ---
    @property
    def log_level(self) -> str:
        return str(_deep_get(self.raw, "logging.level", "INFO"))

    @property
    def decision_log_path(self) -> str:
        return str(_deep_get(self.raw, "logging.decision_log", ""))

    def as_dict(self) -> dict:
        """Sanitised view of the config (no secrets)."""
        out = dict(self.raw)
        th = out.get("thehive", {})
        if isinstance(th, dict) and th.get("api_key"):
            th["api_key"] = "***redacted***"
        return out


def _coerce(value: str) -> Any:
    v = value.strip()
    lowered = v.lower()
    if lowered in ("true", "yes", "1"):
        return True
    if lowered in ("false", "no", "0"):
        return False
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v
