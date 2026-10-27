"""
PhishGuard AI — External Benchmark Evaluation Script (Phase 3.5)
================================================================
Evaluates the trained PhishGuard AI model on user-provided external datasets:
  (a) data/external/phishing.txt (fresh phishing URLs from OpenPhish / PhishTank)
  (b) data/external/legit.txt    (legitimate domains from Tranco, as https://domain URLs)

Security & Integrity Rules:
  - NEVER downloads or visits any URL across the internet.
  - Treats all URLs strictly as offline plain text strings.
  - If the external files are missing, prints clear instructions for how
    to manually obtain them and exits cleanly with exit code 0.
  - Saves evaluation metrics to reports/external_eval.json.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.predictor import load_model, predict_url

EXTERNAL_DIR = PROJECT_ROOT / "data" / "external"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Primary requested filenames with backward-compatible fallbacks
PHISHING_FILES = [
    EXTERNAL_DIR / "phishing.txt",
    EXTERNAL_DIR / "phishing_urls.txt",
]
LEGIT_FILES = [
    EXTERNAL_DIR / "legit.txt",
    EXTERNAL_DIR / "tranco_top_sites.txt",
]


def find_existing_file(candidates: list[Path]) -> Path | None:
    for p in candidates:
        if p.exists() and p.stat().st_size > 0:
            return p
    return None


def print_instructions_and_exit() -> None:
    print("=" * 75)
    print("PHISHGUARD AI — EXTERNAL BENCHMARK EVALUATION SETUP INSTRUCTIONS")
    print("=" * 75)
    print("External evaluation requires two offline text files in 'data/external/':")
    print(f"  1. Phishing URLs:  {EXTERNAL_DIR / 'phishing.txt'}")
    print(f"  2. Legitimate URLs: {EXTERNAL_DIR / 'legit.txt'}")
    print("\nHow to obtain these files manually (Never fetch URLs during evaluation!):")
    print("  • Phishing URLs: Download the latest verified feed from:")
    print("      - OpenPhish: https://openphish.com/feed.txt")
    print("      - PhishTank: https://data.phishtank.com/data/online-valid.csv")
    print("    Save one URL per line into:")
    print(f"      {EXTERNAL_DIR / 'phishing.txt'}")
    print("\n  • Legitimate URLs: Download the latest Tranco top sites list from:")
    print("      - Tranco: https://tranco-list.eu/top-1m.csv.zip")
    print("    Extract top domain names and format them as 'https://domain.com', one per line into:")
    print(f"      {EXTERNAL_DIR / 'legit.txt'}")
    print("\nOnce these files are placed, re-run:")
    print("  python scripts/external_eval.py")
    print("=" * 75)
    sys.exit(0)


def load_lines(path: Path) -> list[str]:
    """Read non-empty, non-comment lines from file."""
    urls = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def main():
    print("=" * 75)
    print("PHISHGUARD AI — EXTERNAL BENCHMARK EVALUATION (Phase 3.5)")
    print("=" * 75)

    EXTERNAL_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    phish_path = find_existing_file(PHISHING_FILES)
    legit_path = find_existing_file(LEGIT_FILES)

    if phish_path is None or legit_path is None:
        print("Notice: External benchmark dataset files are missing or empty.\n")
        print_instructions_and_exit()

    phishing_urls = load_lines(phish_path)
    legit_urls = load_lines(legit_path)

    print(f"Loaded {len(phishing_urls):,} external phishing URLs from {phish_path}")
    print(f"Loaded {len(legit_urls):,} external legitimate URLs from {legit_path}")

    # Load model
    print("\nLoading trained model…")
    load_model()

    # Evaluate phishing URLs (ground truth = PHISHING)
    tp, fn = 0, 0
    print("\nEvaluating external phishing URLs…")
    for u in phishing_urls:
        res = predict_url(u)
        if res.get("prediction") == "PHISHING":
            tp += 1
        else:
            fn += 1

    # Evaluate legitimate URLs (ground truth = SAFE)
    tn, fp = 0, 0
    print("Evaluating external legitimate URLs…")
    for u in legit_urls:
        res = predict_url(u)
        if res.get("prediction") == "PHISHING":
            fp += 1
        else:
            tn += 1

    # Compute metrics
    total_phish = tp + fn
    total_legit = tn + fp
    total_samples = total_phish + total_legit

    recall = float(tp / total_phish) if total_phish > 0 else 0.0
    fpr = float(fp / total_legit) if total_legit > 0 else 0.0
    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    accuracy = float((tp + tn) / total_samples) if total_samples > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    print("\n" + "=" * 75)
    print("EXTERNAL BENCHMARK EVALUATION RESULTS")
    print("=" * 75)
    print(f"Total Evaluated URLs       : {total_samples:,}")
    print(f"  • External Phishing URLs : {total_phish:,} (TP={tp:,}, FN={fn:,})")
    print(f"  • External Legit URLs    : {total_legit:,} (TN={tn:,}, FP={fp:,})")
    print("-" * 75)
    print(f"Phishing Recall (TPR)      : {recall:.4%} (caught {tp:,} of {total_phish:,})")
    print(f"False Positive Rate (FPR)  : {fpr:.4%} ({fp:,} false alarms on {total_legit:,})")
    print(f"Precision                  : {precision:.4%}")
    print(f"Accuracy                   : {accuracy:.4%}")
    print(f"F1-Score                   : {f1:.4%}")
    print("=" * 75)

    results = {
        "evaluation_date": datetime.now(timezone.utc).isoformat(),
        "datasets": {
            "phishing_file": str(phish_path.name),
            "legit_file": str(legit_path.name),
            "total_phishing_urls": total_phish,
            "total_legit_urls": total_legit,
            "total_samples": total_samples,
        },
        "metrics": {
            "phishing_recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
            "precision": round(precision, 4),
            "accuracy": round(accuracy, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
            },
        },
    }

    out_json = REPORTS_DIR / "external_eval.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nExternal evaluation results saved to: {out_json}")


if __name__ == "__main__":
    main()
