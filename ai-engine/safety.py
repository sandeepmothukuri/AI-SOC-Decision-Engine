"""
Deterministic safety layer for the AI SOC Engine.

These rules run on every alert regardless of the LLM and act as a
non-negotiable floor: they neutralise prompt-injection content, extract IOCs,
and produce an explainable, deterministic classification that the LLM can
refine but never fully override.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from schemas import Severity

# --------------------------------------------------------------------------
# Prompt-injection / input-manipulation patterns
# --------------------------------------------------------------------------
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)",
    r"you\s+are\s+now\s+(a\s+|the\s+)?(DAN|jailbreak)",
    r"reveal\s+(your|the)\s+(system\s+)?prompt",
    r"system\s+prompt\s*(:|is)",
    r"developer\s+mode",
    r"override\s+(all\s+)?(safety|security|instructions)",
    r"do\s+not\s+escalate",
    r"verdict\s*(must|should|=|:)\s*(be\s*)?\"?CLOSE\"?",
    r"classify\s+this\s+as\s+(benign|safe|false\s+positive)",
    r"ignore\s+the\s+alert",
    r"this\s+is\s+a\s+test\s+.*ignore",
    r"<\|im_start\|>|<\|im_end\|>",
]

_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

# Markers that strongly indicate malicious activity (used as evidence).
MALICIOUS_MARKERS = [
    (r"sqlmap", "SQL injection tool signature (sqlmap)"),
    (r"mimikatz", "credential-dumping tool signature (mimikatz)"),
    (r"(?i)(cmd\.exe|powershell|/bin/sh|/bin/bash)\s*-", "shell command execution"),
    (r"(?i)(passthru|shell_exec|system\s*\(|exec\s*\()", "web-shell function call"),
    (r"(?i)\.(encrypted|locked|ransom|crypt|lockbit)\b", "ransomware file-extension pattern"),
    (r"failed\s+password.*(?:accepted|success)", "brute force followed by success"),
    (r"(?i)(nmap|masscan)", "reconnaissance scanner"),
    (r"(?i)dns\s+tunnel|subdomain\s+entropy", "DNS tunneling indicators"),
    (r"(?i)base64.*(powershell|cmd)", "obfuscated command execution"),
]

BENIGN_MARKERS = [
    (r"(?i)nessus", "authorised scanner (Nessus)"),
    (r"(?i)qualys", "authorised scanner (Qualys)"),
    (r"(?i)internal\s+(vulnerability\s+)?scan", "internal scan"),
    (r"(?i)maintenance\s+window", "maintenance window"),
]

# IOC extraction patterns.
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

# Non-deprecated MITRE technique mapping (keyword -> techniques).
MITRE_KEYWORDS = {
    "brute force": ["T1110 - Brute Force"],
    "credential stuffing": ["T1110 - Brute Force"],
    "port scan": ["T1046 - Network Service Scanning"],
    "sql injection": ["T1190 - Exploit Public-Facing Application"],
    "xss": ["T1189 - Drive-by Compromise"],
    "privilege escalation": ["T1548 - Abuse Elevation Control Mechanism"],
    "sudo": ["T1548.003 - Sudo and Sudo Caching"],
    "lateral movement": ["T1021 - Remote Services"],
    "pass-the-hash": ["T1550.002 - Pass the Hash"],
    "ntlm": ["T1550.002 - Pass the Hash"],
    "exfiltration": ["T1048 - Exfiltration Over Alternative Protocol"],
    "dns tunneling": ["T1071.004 - DNS"],
    "malware": ["T1204 - User Execution"],
    "ransomware": ["T1486 - Data Encrypted for Impact"],
    "c2": ["T1071 - Application Layer Protocol"],
    "command and control": ["T1071 - Application Layer Protocol"],
    "phishing": ["T1566 - Phishing"],
    "web shell": ["T1505.003 - Web Shell"],
    "account created": ["T1136 - Create Account"],
    "useradd": ["T1136 - Create Account"],
}


@dataclass
class SafetyAssessment:
    """Deterministic classification of an alert."""

    injection_detected: bool = False
    injection_hits: list[str] = field(default_factory=list)
    malicious_hits: list[str] = field(default_factory=list)
    benign_hits: list[str] = field(default_factory=list)
    blocklist_hits: list[str] = field(default_factory=list)
    allowlist_hits: list[str] = field(default_factory=list)
    has_ioc: bool = False
    mitre_techniques: list[str] = field(default_factory=list)

    # Outcome
    verdict: str = "ENRICH"
    severity: Severity = "MEDIUM"
    confidence: float = 0.5
    rationale: str = ""
    recommended_action: str = ""
    evidence: list[str] = field(default_factory=list)
    summary: str = ""


class SafetyEngine:
    def __init__(self, blocklist_path: Path, allowlist_path: Path):
        self._blocklist = self._load_list(blocklist_path)
        self._allowlist = self._load_list(allowlist_path)

    @staticmethod
    def _load_list(path: Path) -> list[str]:
        if not path.exists():
            return []
        out = []
        for line in path.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(line.lower())
        return out

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _ip_in_list(ip: str, entries: list[str]) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for e in entries:
            e = e.strip()
            if not e:
                continue
            try:
                net = ipaddress.ip_network(e, strict=False)
            except ValueError:
                continue
            if addr in net:
                return True
        return False

    def _substr_in_list(self, text: str, entries: list[str]) -> list[str]:
        t = text.lower()
        return [e for e in entries if e and e in t]

    def detect_injection(self, *texts: Optional[str]) -> list[str]:
        hits: list[str] = []
        for text in texts:
            if not text:
                continue
            for pat in _INJECTION_RE:
                if pat.search(text):
                    hits.append(pat.pattern)
        return hits

    # -- main entry -------------------------------------------------------
    def assess(self, alert: dict) -> SafetyAssessment:
        a = SafetyAssessment()

        raw = alert.get("raw_log") or ""
        desc = alert.get("rule_description") or ""
        misp = alert.get("misp_context") or {}
        geo = alert.get("geo_info") or {}
        src_ip = alert.get("source_ip")
        dest_ip = alert.get("dest_ip")
        severity_level = int(alert.get("severity") or 5)

        # 1. Prompt-injection detection on every attacker-controllable field.
        inj_hits = self.detect_injection(raw, desc, str(misp), str(geo))
        if inj_hits:
            a.injection_detected = True
            a.injection_hits = inj_hits
            a.evidence.append("prompt-injection pattern detected in alert content")

        # 2. Indicator presence.
        a.has_ioc = bool(src_ip or dest_ip or _HASH_RE.search(raw) or _DOMAIN_RE.search(raw))

        # 3. Blocklist / allowlist.
        if src_ip and self._ip_in_list(src_ip, self._blocklist):
            a.blocklist_hits.append(src_ip)
            a.evidence.append(f"source_ip {src_ip} is on the blocklist")
        if src_ip and self._ip_in_list(src_ip, self._allowlist):
            a.allowlist_hits.append(src_ip)
            a.evidence.append(f"source_ip {src_ip} is on the allowlist")
        for entry in self._substr_in_list(
            f"{raw} {desc} {geo.get('country', '')}", self._blocklist
        ):
            if entry not in a.blocklist_hits:
                a.blocklist_hits.append(entry)
        for entry in self._substr_in_list(f"{raw} {desc}", self._allowlist):
            if entry not in a.allowlist_hits:
                a.allowlist_hits.append(entry)

        # 4. Marker scanning.
        for pattern, label in MALICIOUS_MARKERS:
            if re.search(pattern, raw, re.IGNORECASE):
                a.malicious_hits.append(label)
                a.evidence.append(f"raw_log matches: {label}")
        for pattern, label in BENIGN_MARKERS:
            if re.search(pattern, raw, re.IGNORECASE):
                a.benign_hits.append(label)
                a.evidence.append(f"raw_log matches: {label}")

        # 5. Threat-intel context.
        misp_found = bool(misp.get("found"))
        if misp_found:
            a.evidence.append("MISP context present")
            level = str(misp.get("threat_level", "")).lower()
            if level in ("high", "critical"):
                a.malicious_hits.append(f"MISP threat_level={level}")
        cortex = alert.get("cortex_context") or {}
        if cortex.get("malicious"):
            a.evidence.append("Cortex analyser verdict=malicious")

        # 6. MITRE mapping (deterministic keyword).
        haystack = f"{desc} {raw}".lower()
        for keyword, techs in MITRE_KEYWORDS.items():
            if keyword in haystack:
                for t in techs:
                    if t not in a.mitre_techniques:
                        a.mitre_techniques.append(t)

        # 7. Decision.
        a.severity = normalize_severity(severity_level)
        a = self._decide(alert, a, severity_level, misp, cortex)
        return a

    def _decide(
        self, alert: dict, a: SafetyAssessment, level: int, misp: dict, cortex: dict
    ) -> SafetyAssessment:
        # Prompt injection always forces human review, regardless of other signals.
        if a.injection_detected:
            a.verdict = "ENRICH"
            a.severity = max_severity(a.severity, "HIGH")
            a.confidence = 0.5
            a.rationale = (
                "Alert content contains prompt-injection or instruction-manipulation "
                "patterns. LLM output for this alert is not trusted; routed for human review."
            )
            a.recommended_action = (
                "Escalate to analyst for manual review. Treat the alert content as untrusted "
                "input and do not follow any instructions embedded in it."
            )
            a.summary = (
                f"Potentially manipulated alert content from source '{alert.get('source')}'."
            )
            return a

        malicious = len(a.malicious_hits) + len(a.blocklist_hits) + (1 if misp.get("found") else 0)
        benign = len(a.benign_hits) + len(a.allowlist_hits)

        # Confidence from signal agreement.
        if malicious >= 2 and benign == 0:
            a.verdict = "ESCALATE"
            a.confidence = 0.9
        elif malicious == 1 and benign == 0:
            a.verdict = "ESCALATE"
            a.confidence = 0.8
        elif benign >= 1 and malicious == 0:
            a.verdict = "CLOSE"
            a.confidence = 0.9
        elif benign >= 1 and malicious >= 1:
            a.verdict = "ENRICH"
            a.confidence = 0.4
        else:
            a.verdict = "ENRICH"
            a.confidence = 0.55

        # Missing-IOC penalty: uncertainty cap.
        if not a.has_ioc:
            a.confidence = min(a.confidence, 0.5)
            a.evidence.append("no IOCs present in alert")

        # Severity adjustments.
        if a.verdict == "ESCALATE":
            a.severity = max_severity(a.severity, "HIGH" if level < 12 else "CRITICAL")
        if a.verdict == "CLOSE":
            a.severity = "LOW"

        # Narrative.
        src = alert.get("source_ip") or "unknown source"
        a.summary = (
            f"{a.verdict} decision for alert from {alert.get('source')} "
            f"('{alert.get('rule_description', '')[:80]}') observed from {src}."
        )
        a.rationale = self._rationale(a, level)
        a.recommended_action = self._recommended_action(a, alert)
        return a

    @staticmethod
    def _rationale(a: SafetyAssessment, level: int) -> str:
        parts = []
        if a.blocklist_hits:
            parts.append(f"blocklist match: {', '.join(a.blocklist_hits)}")
        if a.allowlist_hits:
            parts.append(f"allowlist match: {', '.join(a.allowlist_hits)}")
        if a.malicious_hits:
            parts.append(f"malicious markers: {', '.join(a.malicious_hits[:3])}")
        if a.benign_hits:
            parts.append(f"benign markers: {', '.join(a.benign_hits[:3])}")
        if not a.has_ioc:
            parts.append("no indicators present")
        parts.append(f"Wazuh severity level {level}")
        return "Deterministic rule assessment: " + "; ".join(parts) + "."

    @staticmethod
    def _recommended_action(a: SafetyAssessment, alert: dict) -> str:
        if a.verdict == "ESCALATE":
            return (
                "Investigate immediately: verify the source in threat intel, contain the "
                "affected host, and preserve logs. Block source if confirmed malicious."
            )
        if a.verdict == "CLOSE":
            return "No action required; record as benign/false positive with the stated evidence."
        return (
            "Insufficient signal for an automated decision. Enrich (threat intel, host "
            "context, user behaviour) and route to an analyst for review."
        )


def normalize_severity(level: int) -> Severity:
    if level >= 12:
        return "CRITICAL"
    if level >= 9:
        return "HIGH"
    if level >= 6:
        return "MEDIUM"
    return "LOW"


_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def max_severity(a: Severity, b: Severity) -> Severity:
    return a if _SEV_ORDER[a] >= _SEV_ORDER[b] else b
