"""
PhishGuard AI — External Benchmark Evaluation Script
====================================================
Evaluates the trained PhishGuard AI model on user-provided external datasets:
  (a) data/external/phishing_urls.txt (fresh phishing URLs from OpenPhish / PhishTank)
  (b) data/external/tranco_top_sites.txt (top legitimate domains from Tranco / Cisco Umbrella)

Rules:
  - NEVER downloads or visits any URL across the internet.
  - Treats all URLs purely as offline string data.
  - If the external files are missing, prints detailed instructions for how
    to manually obtain them and exits cleanly (exit code 0).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.predictor import load_model, predict_url

EXTERNAL_DIR = PROJECT_ROOT / "data" / "external"
PHISHING_LIST_PATH = EXTERNAL_DIR / "phishing_urls.txt"
TRANCO_LIST_PATH = EXTERNAL_DIR / "tranco_top_sites.txt"


def print_instructions_and_exit() -> None:
    print("=" * 70)
    print("PHISHGUARD AI — EXTERNAL EVALUATION DATASET SETUP INSTRUCTIONS")
    print("=" * 70)
    print("External evaluation requires two offline text files in 'data/external/':")
    print(f"  1. Phishing URLs:  {PHISHING_LIST_PATH}")
    print(f"  2. Legitimate URLs: {TRANCO_LIST_PATH}")
    print("\nHow to obtain these files manually (Do NOT fetch URLs during evaluation!):")
    print("  • Phishing URLs: Download the latest verified feed from:")
    print("      - OpenPhish: https://openphish.com/feed.txt")
    print("      - PhishTank: https://data.phishtank.com/data/online-valid.csv")
    print(f"    Save one URL per line to: {PHISHING_LIST_PATH}")
    print("\n  • Legitimate URLs: Download the latest Tranco top sites list from:")
    print("      - Tranco: https://tranco-list.eu/top-1m.csv.zip")
    print("    Extract and save legitimate domain names to:")
    print(f"      {TRANCO_LIST_PATH}")
    print("\nOnce these files are present, re-run:")
    print("  python scripts/build_external_eval.py")
    print("=" * 70)
    sys.exit(0)


def load_lines(path: Path) -> list[str]:
    """Read non-empty lines from file."""
    urls = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def main():
    print("=" * 70)
    print("PHISHGUARD AI — EXTERNAL BENCHMARK EVALUATION")
    print("=" * 70)

    EXTERNAL_DIR.mkdir(parents=True, exist_ok=True)

    has_phish = PHISHING_LIST_PATH.exists()
    has_tranco = TRANCO_LIST_PATH.exists()

    if not has_phish or not has_tranco:
        print(f"Notice: External evaluation files missing in {EXTERNAL_DIR}.\n")
        print_instructions_and_exit()

    phishing_urls = load_lines(PHISHING_LIST_PATH)
    legit_urls = load_lines(TRANCO_LIST_PATH)

    print(f"Loaded {len(phishing_urls):,} external phishing URLs from {PHISHING_LIST_PATH}")
    print(f"Loaded {len(legit_urls):,} external legitimate URLs from {TRANCO_LIST_PATH}")

    # Load model
    print("\nLoading trained model…")
    load_model()

    # Evaluate phishing URLs (positive class = 1 / PHISHING)
    tp, fn = 0, 0
    print("\nEvaluating external phishing URLs…")
    for u in phishing_urls:
        res = predict_url(u)
        if res.get("prediction") == "PHISHING":
            tp += 1
        else:
            fn += 1

    # Evaluate legitimate URLs (negative class = 0 / SAFE)
    tn, fp = 0, 0
    print("Evaluating external legitimate URLs…")
    for u in legit_urls:
        res = predict_url(u)
        if res.get("prediction") == "SAFE":
            tn += 1
        else:
            fp += 1

    total_phish = tp + fn
    total_legit = tn + fp
    total = total_phish + total_legit

    recall = tp / total_phish if total_phish else 0.0
    fpr = fp / total_legit if total_legit else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) else 0.0

    print("\n" + "=" * 70)
    print("EXTERNAL EVALUATION RESULTS (Real-World Out-of-Distribution Benchmark)")
    print("=" * 70)
    print(f"{'Metric':<25} | {'Value':<12}")
    print("-" * 40)
    print(f"{'Total Samples':<25} | {total:<12,}")
    print(f"{'Phishing Samples':<25} | {total_phish:<12,}")
    print(f"{'Legitimate Samples':<25} | {total_legit:<12,}")
    print(f"{'Phishing Recall':<25} | {recall:<12.4%}")
    print(f"{'False Positive Rate':<25} | {fpr:<12.4%}")
    print(f"{'Precision':<25} | {precision:<12.4%}")
    print(f"{'F1 Score':<25} | {f1:<12.4%}")
    print(f"{'Accuracy':<25} | {accuracy:<12.4%}")
    print("-" * 40)
    print(f"Confusion Matrix: TP={tp}, FN={fn}, TN={tn}, FP={fp}")
    print("=" * 70)


if __name__ == "__main__":
    main()
