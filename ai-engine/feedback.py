"""Analyst Feedback Loop & Continuous Evaluation (Active Learning).

Persists human analyst decisions from /approve/{id} and /reject/{id} into SQLite.
Tracks triage accuracy, false-positive reduction, model drift, and generates
curated few-shot examples from validated high-confidence analyst decisions.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "feedback.db"


class FeedbackSubmission(BaseModel):
    """Analyst submission payload on approval or rejection."""

    reason_code: Optional[str] = Field(
        default=None,
        description="Reason code (e.g., CORRECT_TRIAGE, FALSE_POSITIVE, WRONG_SEVERITY, HALLUCINATED_INDICATOR)",
    )
    analyst_id: Optional[str] = Field(default="analyst-01", description="Identifier of the reviewing analyst")
    notes: Optional[str] = Field(default="", description="Optional analyst notes and triage context")
    corrected_verdict: Optional[str] = Field(default=None, description="Corrected verdict if analyst overrode")
    corrected_severity: Optional[str] = Field(default=None, description="Corrected severity if analyst adjusted")


class FeedbackStore:
    """Thread-safe SQLite store for SOC analyst feedback and continuous learning."""

    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    decision_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    analyst_id TEXT NOT NULL,
                    notes TEXT,
                    original_verdict TEXT,
                    original_severity TEXT,
                    original_confidence REAL,
                    corrected_verdict TEXT,
                    corrected_severity TEXT,
                    alert_json TEXT,
                    analysis_json TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fb_alert ON analyst_feedback(alert_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fb_action ON analyst_feedback(action);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fb_reason ON analyst_feedback(reason_code);")
            conn.commit()

    def record_feedback(
        self,
        decision_id: str,
        action: str,
        alert: dict[str, Any],
        analysis: Any,
        submission: Optional[FeedbackSubmission] = None,
    ) -> dict[str, Any]:
        """Record an approval or rejection event with reason codes."""
        submission = submission or FeedbackSubmission()

        # Sensible defaults for reason_code if not supplied
        default_reason = "CORRECT_TRIAGE" if action == "APPROVE" else "FALSE_POSITIVE"
        reason = submission.reason_code or default_reason

        analysis_dict = analysis.model_dump() if hasattr(analysis, "model_dump") else dict(analysis)
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO analyst_feedback (
                    decision_id, alert_id, action, reason_code, analyst_id, notes,
                    original_verdict, original_severity, original_confidence,
                    corrected_verdict, corrected_severity, alert_json, analysis_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    alert.get("alert_id", "UNKNOWN"),
                    action.upper(),
                    reason,
                    submission.analyst_id or "analyst-01",
                    submission.notes or "",
                    analysis_dict.get("verdict"),
                    analysis_dict.get("severity"),
                    float(analysis_dict.get("confidence", 0.0)),
                    submission.corrected_verdict or analysis_dict.get("verdict"),
                    submission.corrected_severity or analysis_dict.get("severity"),
                    json.dumps(alert),
                    json.dumps(analysis_dict),
                    now_iso,
                ),
            )
            conn.commit()
            record_id = cur.lastrowid

        logger.info(
            "Feedback recorded: action=%s reason=%s alert_id=%s decision_id=%s",
            action,
            reason,
            alert.get("alert_id"),
            decision_id,
        )

        return {
            "feedback_id": record_id,
            "decision_id": decision_id,
            "action": action.upper(),
            "reason_code": reason,
            "analyst_id": submission.analyst_id or "analyst-01",
            "recorded_at": now_iso,
        }

    def get_stats(self) -> dict[str, Any]:
        """Calculate continuous evaluation metrics, drift, and reason distribution."""
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM analyst_feedback").fetchone()[0]
            if total == 0:
                return {
                    "total_feedback": 0,
                    "approvals": 0,
                    "rejections": 0,
                    "approval_rate": 0.0,
                    "false_positive_reduction_rate": 0.0,
                    "drift_detected": False,
                    "reasons_breakdown": {},
                }

            approvals = conn.execute(
                "SELECT COUNT(*) FROM analyst_feedback WHERE action = 'APPROVE'"
            ).fetchone()[0]
            rejections = conn.execute(
                "SELECT COUNT(*) FROM analyst_feedback WHERE action = 'REJECT'"
            ).fetchone()[0]

            # Reason codes breakdown
            reasons = {}
            for row in conn.execute(
                "SELECT reason_code, COUNT(*) as cnt FROM analyst_feedback GROUP BY reason_code"
            ):
                reasons[row["reason_code"]] = row["cnt"]

            # False-positive count
            fp_count = conn.execute(
                "SELECT COUNT(*) FROM analyst_feedback WHERE reason_code IN ('FALSE_POSITIVE', 'BENIGN_SCANNER')"
            ).fetchone()[0]

            # Model drift check: rejection rate in the last 20 reviews
            recent_rows = conn.execute(
                "SELECT action FROM analyst_feedback ORDER BY id DESC LIMIT 20"
            ).fetchall()
            recent_rejects = sum(1 for r in recent_rows if r["action"] == "REJECT")
            recent_reject_rate = recent_rejects / len(recent_rows) if recent_rows else 0.0
            drift_detected = recent_reject_rate >= 0.35 and len(recent_rows) >= 5

            approval_rate = round(approvals / total, 3)
            fp_reduction_rate = round(fp_count / total, 3)

            return {
                "total_feedback": total,
                "approvals": approvals,
                "rejections": rejections,
                "approval_rate": approval_rate,
                "false_positive_reduction_rate": fp_reduction_rate,
                "drift_detected": drift_detected,
                "recent_rejection_rate": round(recent_reject_rate, 3),
                "reasons_breakdown": reasons,
            }

    def get_few_shot_examples(self, limit: int = 5) -> list[dict[str, Any]]:
        """Retrieve verified, approved triage decisions for few-shot prompt augmentation."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT alert_json, analysis_json, reason_code, notes, created_at
                FROM analyst_feedback
                WHERE action = 'APPROVE'
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

            examples = []
            for r in rows:
                try:
                    examples.append(
                        {
                            "alert": json.loads(r["alert_json"]),
                            "decision": json.loads(r["analysis_json"]),
                            "reason": r["reason_code"],
                            "notes": r["notes"],
                            "timestamp": r["created_at"],
                        }
                    )
                except Exception:
                    continue
            return examples

    def export_dataset(self, limit: int = 1000) -> list[dict[str, Any]]:
        """Export stored feedback records for dataset compilation or fine-tuning."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, decision_id, alert_id, action, reason_code, analyst_id, notes,
                       original_verdict, original_severity, original_confidence,
                       corrected_verdict, corrected_severity, alert_json, analysis_json, created_at
                FROM analyst_feedback
                ORDER BY id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

            dataset = []
            for r in rows:
                dataset.append(
                    {
                        "id": r["id"],
                        "decision_id": r["decision_id"],
                        "alert_id": r["alert_id"],
                        "action": r["action"],
                        "reason_code": r["reason_code"],
                        "analyst_id": r["analyst_id"],
                        "notes": r["notes"],
                        "original_verdict": r["original_verdict"],
                        "original_severity": r["original_severity"],
                        "original_confidence": r["original_confidence"],
                        "corrected_verdict": r["corrected_verdict"],
                        "corrected_severity": r["corrected_severity"],
                        "alert": json.loads(r["alert_json"]) if r["alert_json"] else {},
                        "analysis": json.loads(r["analysis_json"]) if r["analysis_json"] else {},
                        "created_at": r["created_at"],
                    }
                )
            return dataset
