"""Prometheus Metrics Collector and Exposition Engine.

Provides /metrics endpoint tracking SOC triage throughput, latency distribution,
token usage, prompt-injection catches, model fallbacks, and analyst feedback.
"""

from __future__ import annotations

import threading


class MetricsCollector:
    """Thread-safe Prometheus metrics registry for SOC Decision Engine."""

    # Latency histogram buckets in seconds
    LATENCY_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)

    def __init__(self):
        self._lock = threading.Lock()

        # Decision counters by verdict
        self.decisions_total: dict[str, int] = {
            "ESCALATE": 0,
            "CLOSE": 0,
            "ENRICH": 0,
            "PENDING_APPROVAL": 0,
        }

        # Latency tracking
        self.latency_buckets: dict[float, int] = {b: 0 for b in self.LATENCY_BUCKETS}
        self.latency_sum: float = 0.0
        self.latency_count: int = 0

        # Safety & Fallback counters
        self.prompt_injections_total: int = 0
        self.llm_fallbacks_total: int = 0
        self.llm_malformed_rejected_total: int = 0
        self.dedupe_duplicates_total: int = 0

        # Token usage by (provider, model)
        self.token_usage_total: dict[tuple[str, str], int] = {}

        # Feedback counters by (action, reason_code)
        self.feedback_total: dict[tuple[str, str], int] = {}

        # Redaction counters by category (ip, credential, host, user)
        self.redactions_total: dict[str, int] = {
            "ips": 0,
            "credentials": 0,
            "hosts": 0,
            "paths": 0,
        }

    def record_decision(self, verdict: str, duration_seconds: float) -> None:
        """Record a triage decision and its execution latency."""
        with self._lock:
            verdict_norm = verdict.upper()
            self.decisions_total[verdict_norm] = self.decisions_total.get(verdict_norm, 0) + 1

            self.latency_sum += duration_seconds
            self.latency_count += 1
            for b in self.LATENCY_BUCKETS:
                if duration_seconds <= b:
                    self.latency_buckets[b] += 1

    def record_injection(self) -> None:
        with self._lock:
            self.prompt_injections_total += 1

    def record_fallback(self) -> None:
        with self._lock:
            self.llm_fallbacks_total += 1

    def record_malformed(self) -> None:
        with self._lock:
            self.llm_malformed_rejected_total += 1

    def record_duplicate(self) -> None:
        with self._lock:
            self.dedupe_duplicates_total += 1

    def record_tokens(self, provider: str, model: str, tokens: int) -> None:
        with self._lock:
            key = (provider.lower(), model.lower())
            self.token_usage_total[key] = self.token_usage_total.get(key, 0) + tokens

    def record_feedback(self, action: str, reason_code: str) -> None:
        with self._lock:
            key = (action.upper(), reason_code.upper())
            self.feedback_total[key] = self.feedback_total.get(key, 0) + 1

    def record_redactions(self, counts: dict[str, int]) -> None:
        with self._lock:
            for cat, cnt in counts.items():
                if cat in self.redactions_total:
                    self.redactions_total[cat] += cnt

    def render_prometheus_exposition(self) -> str:
        """Format metrics into official Prometheus text-based exposition syntax."""
        with self._lock:
            lines: list[str] = []

            # 1. soc_decisions_total
            lines.append(
                "# HELP soc_decisions_total Total number of alerts triaged by final verdict."
            )
            lines.append("# TYPE soc_decisions_total counter")
            for verdict, count in sorted(self.decisions_total.items()):
                lines.append(f'soc_decisions_total{{verdict="{verdict}"}} {count}')

            # 2. soc_triage_latency_seconds
            lines.append("# HELP soc_triage_latency_seconds Latency of alert triage decisions.")
            lines.append("# TYPE soc_triage_latency_seconds histogram")
            for b in self.LATENCY_BUCKETS:
                lines.append(
                    f'soc_triage_latency_seconds_bucket{{le="{b}"}} {self.latency_buckets[b]}'
                )
            lines.append(f'soc_triage_latency_seconds_bucket{{le="+Inf"}} {self.latency_count}')
            lines.append(f"soc_triage_latency_seconds_sum {self.latency_sum:.6f}")
            lines.append(f"soc_triage_latency_seconds_count {self.latency_count}")

            # 3. soc_prompt_injections_total
            lines.append(
                "# HELP soc_prompt_injections_total Total adversarial prompt injection attacks intercepted."
            )
            lines.append("# TYPE soc_prompt_injections_total counter")
            lines.append(f"soc_prompt_injections_total {self.prompt_injections_total}")

            # 4. soc_llm_fallbacks_total
            lines.append(
                "# HELP soc_llm_fallbacks_total Total fail-soft fallbacks to deterministic rule engine."
            )
            lines.append("# TYPE soc_llm_fallbacks_total counter")
            lines.append(f"soc_llm_fallbacks_total {self.llm_fallbacks_total}")

            # 5. soc_llm_malformed_rejected_total
            lines.append(
                "# HELP soc_llm_malformed_rejected_total Malformed model outputs rejected by schema validator."
            )
            lines.append("# TYPE soc_llm_malformed_rejected_total counter")
            lines.append(f"soc_llm_malformed_rejected_total {self.llm_malformed_rejected_total}")

            # 6. soc_dedupe_duplicates_total
            lines.append(
                "# HELP soc_dedupe_duplicates_total Duplicate alerts suppressed within sliding TTL."
            )
            lines.append("# TYPE soc_dedupe_duplicates_total counter")
            lines.append(f"soc_dedupe_duplicates_total {self.dedupe_duplicates_total}")

            # 7. soc_llm_token_usage_total
            lines.append(
                "# HELP soc_llm_token_usage_total Total estimated tokens consumed by LLM provider."
            )
            lines.append("# TYPE soc_llm_token_usage_total counter")
            if not self.token_usage_total:
                lines.append('soc_llm_token_usage_total{provider="ollama",model="llama3"} 0')
            else:
                for (prov, mdl), tok in sorted(self.token_usage_total.items()):
                    lines.append(
                        f'soc_llm_token_usage_total{{provider="{prov}",model="{mdl}"}} {tok}'
                    )

            # 8. soc_feedback_total
            lines.append(
                "# HELP soc_feedback_total Human analyst approval and rejection actions with reason codes."
            )
            lines.append("# TYPE soc_feedback_total counter")
            if not self.feedback_total:
                lines.append('soc_feedback_total{action="APPROVE",reason_code="CORRECT_TRIAGE"} 0')
            else:
                for (act, rsn), count in sorted(self.feedback_total.items()):
                    lines.append(
                        f'soc_feedback_total{{action="{act}",reason_code="{rsn}"}} {count}'
                    )

            # 9. soc_redactions_total
            lines.append(
                "# HELP soc_redactions_total Total PII and secret elements redacted before external LLM calls."
            )
            lines.append("# TYPE soc_redactions_total counter")
            for cat, count in sorted(self.redactions_total.items()):
                lines.append(f'soc_redactions_total{{category="{cat}"}} {count}')

            lines.append("")  # Trailing newline required by Prometheus specs
            return "\n".join(lines)


# Global singleton instance
metrics_registry = MetricsCollector()
