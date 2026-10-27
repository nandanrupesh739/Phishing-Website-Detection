#!/usr/bin/env python3
"""
scripts/export_docs_assets.py
-----------------------------
Export trained model evaluation assets and metrics from reports/ and models/
into docs/ and docs/images/ for git tracking and README documentation.

Usage:
    python scripts/export_docs_assets.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT_DIR / "reports"
MODELS_DIR = ROOT_DIR / "models"
DOCS_DIR = ROOT_DIR / "docs"
DOCS_IMAGES_DIR = DOCS_DIR / "images"

IMAGE_ASSETS = [
    ("confusion_matrix.png", "confusion_matrix.png"),
    ("roc_curve.png", "roc_curve.png"),
    ("calibration_curve.png", "calibration_curve.png"),
    ("reliability_curve.png", "reliability_curve.png"),
    ("feature_importance.png", "feature_importance.png"),
]


def export_assets() -> int:
    DOCS_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    copied_count = 0

    print("=" * 60)
    print("PhishGuard AI — Exporting Documentation Assets")
    print("=" * 60)

    # 1. Copy image plots from reports/ to docs/images/
    for src_name, dst_name in IMAGE_ASSETS:
        src_path = REPORTS_DIR / src_name
        dst_path = DOCS_IMAGES_DIR / dst_name

        if src_path.is_file():
            shutil.copy2(src_path, dst_path)
            print(f"[OK] Copied plot: reports/{src_name} -> docs/images/{dst_name}")
            copied_count += 1
        else:
            print(f"[SKIP] Plot not found in reports/: {src_name}")

    # 2. Copy/summarize model_metrics.json to docs/metrics.json
    metrics_src = MODELS_DIR / "model_metrics.json"
    metrics_dst = DOCS_DIR / "metrics.json"

    if metrics_src.is_file():
        try:
            with open(metrics_src, "r", encoding="utf-8") as f:
                data = json.load(f)

            with open(metrics_dst, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            print("[OK] Copied metrics: models/model_metrics.json -> docs/metrics.json")
            copied_count += 1
        except Exception as exc:
            print(f"[ERROR] Failed to process metrics file: {exc}", file=sys.stderr)
            return 1
    elif metrics_dst.is_file():
        print("[NOTE] models/model_metrics.json not present; existing docs/metrics.json preserved.")
    else:
        print("[WARN] No metrics JSON found in models/ or docs/.")

    print(f"\nCompleted: {copied_count} assets exported to docs/.")
    return 0


if __name__ == "__main__":
    sys.exit(export_assets())
