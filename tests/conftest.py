"""Shared fixtures for the AI SOC Engine test-suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make ai-engine and scripts importable from the tests directory.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "ai-engine"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from config import Config  # noqa: E402


@pytest.fixture
def offline_config(tmp_path):
    """Config with the deterministic offline backend and permissive thresholds."""
    raw = {
        "model": {"backend": "offline", "name": "llama3", "temperature": 0.1, "num_predict": 512},
        "ollama": {"host": "http://127.0.0.1:1"},
        "llm": {"timeout_seconds": 2.0, "max_retries": 0, "request_timeout_seconds": 10.0},
        "thresholds": {
            "escalate_min_confidence": 0.75,
            "close_min_confidence": 0.85,
            "missing_ioc_confidence_cap": 0.5,
        },
        "human_approval": {"enabled": False, "verdicts": ["ESCALATE", "CLOSE"]},
        "dedupe": {"ttl_seconds": 300},
        "prompt": {"version": "v1"},
        "safety": {
            "blocklist_path": str(REPO_ROOT / "ai-engine" / "safety" / "blocklist.txt"),
            "allowlist_path": str(REPO_ROOT / "ai-engine" / "safety" / "allowlist.txt"),
        },
        "thehive": {"url": "http://127.0.0.1:9", "api_key": "", "timeout_seconds": 2.0},
        "logging": {"level": "WARNING", "decision_log": ""},
    }
    return Config(raw=raw)


@pytest.fixture
def approval_config(offline_config):
    """Same as offline but with human-approval mode enabled."""
    offline_config.raw["human_approval"]["enabled"] = True
    return offline_config
