# Shuffle Workflows

> ⚠️ **These JSON files are reference specifications, not importable Shuffle
> workflow exports.**

Shuffle's native workflow format uses `app_name` / `app_version` / `position` /
`parameters` / `branches` nodes (see
[Shuffle workflow docs](https://shuffler.io/docs/workflows)). The files here use
a simplified, human-readable shape (`triggers[].type`, `actions[].app`,
`actions[].requires`) that Shuffle cannot import directly, and the inline Python
uses a top-level `return`, which is not executable as written.

**What they are good for:** describing the intended logic and feeding the
repository's own test harness (`scripts/pipeline_harness.py` →
`WorkflowRunner`), which interprets them faithfully so the end-to-end smoke test
can exercise the documented chain.

**To use them for real:** rebuild the same logic in the Shuffle UI (or export a
native workflow and replace these files):

`ssh-bruteforce.json` logic:

```
Wazuh webhook (rule 5712 / brute_force)
  → parse_alert            (extract id, rule_id, srcip, dstip, hostname, desc, severity)
  → MISP search_ioc        (ip-src lookup)
  → HTTP POST /analyze     (AI engine; misp_context = MISP result)
  → filter verdict != CLOSE
  → Slack notify           (on non-CLOSE)
```

`malware-detection.json` logic:

```
Wazuh malware webhook (virus/malware group or level >= 13)
  → parse_alert            (id, rule_id, hostname, agent_id, sha256, path, desc, severity)
  → VirusTotal get_hash_report
  → MISP search_ioc        (sha256)
  → HTTP POST /analyze     (AI engine)
  → filter severity == CRITICAL
  → Wazuh active-response isolate host
```

The engine is reached at `http://ai-engine:8888/analyze` on the Docker
`ai-engine` service; the test harness rewrites that hostname to its local
instance.
