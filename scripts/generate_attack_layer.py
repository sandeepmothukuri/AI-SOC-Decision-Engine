#!/usr/bin/env python3
"""
CLI script to generate MITRE ATT&CK Navigator Layer JSON.

Usage:
    python scripts/generate_attack_layer.py --out docs/attack-navigator-layer.json
    python scripts/generate_attack_layer.py --api http://localhost:8888 --out layer.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "ai-engine"))

from attack_layer import AttackLayerGenerator  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Export MITRE ATT&CK Navigator Layer JSON.")
    parser.add_argument(
        "--out",
        "-o",
        type=Path,
        default=REPO_ROOT / "docs" / "attack-navigator-layer.json",
        help="Target output path for the layer JSON.",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        help="Minimum threat score to include in layer (0-100).",
    )
    parser.add_argument(
        "--api",
        type=str,
        default="",
        help="Optional URL of running AI SOC engine to fetch live layer from.",
    )
    args = parser.parse_args()

    if args.api:
        import httpx

        url = f"{args.api.rstrip('/')}/export/attack-layer"
        print(f"Fetching ATT&CK layer from {url}...")
        try:
            resp = httpx.get(url, timeout=10.0)
            resp.raise_for_status()
            layer_data = resp.json()
        except Exception as e:
            print(f"Error fetching from API: {e}", file=sys.stderr)
            return 1
    else:
        print("Generating ATT&CK Navigator layer from engine detection taxonomy...")
        generator = AttackLayerGenerator()
        layer_data = generator.generate_layer(min_score=args.min_score)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(layer_data, indent=2), encoding="utf-8")
    print(f"[+] ATT&CK Navigator Layer exported to {args.out}")
    print("[+] Open https://mitre-attack.github.io/attack-navigator/ and select 'Open Existing Layer'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
