# MITRE ATT&CK Mapping Reference

This lab covers detection for the following MITRE ATT&CK techniques.

## Detection Coverage

> Note: Suricata and Zeek are **not deployed** in this repository — rows that
> list them describe *aspirational* detection sources only.

| Technique ID | Technique Name | Detection Source | Wazuh Rule |
|-------------|---------------|-----------------|------------|
| T1110 | Brute Force | Wazuh auth logs | 5710-5716, 100001 |
| T1046 | Network Service Scanning | (Suricata/Zeek — not deployed) | — |
| T1190 | Exploit Public-Facing Application | Wazuh web logs | 31100-31199 |
| T1505.003 | Web Shell | Wazuh syscheck | 100003 |
| T1548.003 | Abuse Elevation Control: Sudo | Wazuh sudo logs | 100002 |
| T1136 | Create Account | Wazuh useradd | 100005 |
| T1021 | Remote Services | Wazuh | 5700-5799 |
| T1041 | Exfiltration Over C2 Channel | (Zeek/Suricata — not deployed) | 100004 |
| T1048 | Exfiltration Over Alternative Protocol | (Zeek — not deployed) | — |
| T1071.004 | Application Layer Protocol: DNS | (Zeek — not deployed) | 100008 |
| T1486 | Data Encrypted for Impact | Wazuh FIM | 100006 |
| T1550.002 | Pass the Hash | Wazuh Windows | 100007 |
| T1566 | Phishing | (Wazuh email integration) | — |
| T1204 | User Execution | Wazuh syscheck | 553, 554 |

> `T1068` (Exploitation for Privilege Escalation) is **deprecated** in ATT&CK;
> the engine maps sudo-based privilege escalation to `T1548.003` instead.

## Tactic Coverage

| Tactic | Coverage |
|--------|----------|
| TA0001 Initial Access | Phishing, Web exploits |
| TA0002 Execution | Malware, scripts |
| TA0003 Persistence | Web shells, new accounts |
| TA0004 Privilege Escalation | Sudo abuse, exploits |
| TA0006 Credential Access | Brute force, pass-the-hash |
| TA0007 Discovery | Port scanning |
| TA0008 Lateral Movement | Remote services |
| TA0010 Exfiltration | DNS tunneling, C2 |
| TA0011 Command and Control | C2 channels |
| TA0040 Impact | Ransomware |

## AI MITRE Auto-Mapping

The AI engine maps alerts to MITRE techniques using the deterministic keyword
map in `ai-engine/safety.py` (`MITRE_KEYWORDS`), using non-deprecated technique
IDs. The LLM may propose additional techniques, which are validated by schema
but the deterministic map is always applied as a floor.
