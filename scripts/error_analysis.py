"""
PhishGuard AI — Error Analysis Script
======================================
Identifies the 25 most confident False Positives (legitimate URLs predicted as
phishing with highest probability) and 25 most confident False Negatives
(phishing URLs predicted as safe with highest probability) on the held-out test set.

Saves analysis to `reports/error_analysis.json` and outputs a diagnostic summary.
"""

from __future__ import annotations

import json
import logging
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import scipy.sparse
from sklearn.model_selection import GroupShuffleSplit
import tldextract
from tqdm import tqdm

warnings.filterwarnings("ignore")

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import DATA_PATH, MODEL_PATH, RANDOM_SEED, REPORTS_DIR
from backend.features import (
    FEATURE_NAMES,
    canonical_url_string,
    extract_url_features,
    features_to_vector,
    get_risk_indicators,
)

log = logging.getLogger("error_analysis")
logging.basicConfig(level=logging.INFO, format="%(message)s")


def main():
    print("=" * 75)
    print("PHISHGUARD AI — MODEL ERROR ANALYSIS (HELD-OUT TEST SET)")
    print("=" * 75)

    if not DATA_PATH.exists():
        print(f"Dataset not found at {DATA_PATH}!")
        sys.exit(1)

    print("Loading dataset for test split reproduction…")
    df_raw = pd.read_csv(DATA_PATH, usecols=["URL", "label"], low_memory=False)
    df = df_raw.dropna().copy()
    df["url"] = df["URL"].astype(str).str.strip()
    df = df[df["url"].str.len() > 0]
    df.drop_duplicates(subset=["url"], keep="first", inplace=True)
    df.reset_index(drop=True, inplace=True)

    # Label mapping: Raw 1 (legitimate) -> 0 (SAFE), Raw 0 (phishing) -> 1 (PHISHING)
    df["label"] = df["label"].astype(int).map({1: 0, 0: 1})

    print("Extracting registered domain groups for split reproduction…")
    ext = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
    domain_groups = []
    for u in df["url"]:
        res = ext(u)
        dom = getattr(res, "top_domain_under_public_suffix", None) or res.domain or u
        domain_groups.append(dom.lower())
    df["domain_group"] = domain_groups

    # Reproduce 70/15/15 Domain-Grouped Split
    gss1 = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=RANDOM_SEED)
    _, temp_idx = next(gss1.split(df, df["label"], groups=df["domain_group"]))

    df_temp = df.iloc[temp_idx].reset_index(drop=True)
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=RANDOM_SEED)
    _, test_sub_idx = next(gss2.split(df_temp, df_temp["label"], groups=df_temp["domain_group"]))

    df_test = df_temp.iloc[test_sub_idx].reset_index(drop=True)
    print(f"Isolated held-out test set: {len(df_test):,} URLs")

    print("\nLoading trained model bundle…")
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    scaler = bundle.get("scaler")
    vectorizer = bundle.get("vectorizer")
    threshold = float(bundle.get("threshold", 0.50))
    print(f"Loaded model: {bundle.get('model_name')} (Decision Threshold: {threshold:.4f})")

    print("\nBatch extracting features for test set URLs…")
    tab_rows = []
    feat_dicts = []
    canonical_urls = []
    for u in tqdm(df_test["url"], desc="Extracting features"):
        c_url = canonical_url_string(u)
        canonical_urls.append(c_url)
        fd = extract_url_features(u)
        feat_dicts.append(fd)
        tab_rows.append(features_to_vector(fd))

    X_tab = np.array(tab_rows, dtype=np.float32)
    if scaler is not None:
        X_tab_scaled = scaler.transform(X_tab)
    else:
        X_tab_scaled = X_tab

    if vectorizer is not None:
        X_tfidf = vectorizer.transform(canonical_urls)
        X_test = scipy.sparse.hstack([scipy.sparse.csr_matrix(X_tab_scaled), X_tfidf]).tocsr()
    else:
        X_test = X_tab_scaled

    print("Batch evaluating predictions…")
    probas = model.predict_proba(X_test)
    prob_phish = probas[:, 1]
    prob_safe = probas[:, 0]

    false_positives = []
    false_negatives = []

    for i, row in df_test.iterrows():
        url = row["url"]
        actual_label = int(row["label"])
        actual_str = "PHISHING" if actual_label == 1 else "SAFE"

        p_phish = float(prob_phish[i])
        p_safe = float(prob_safe[i])
        pred_label = 1 if p_phish >= threshold else 0
        pred_str = "PHISHING" if pred_label == 1 else "SAFE"
        confidence = (p_phish if pred_label == 1 else p_safe) * 100.0
        score = p_phish if pred_label == 1 else p_safe
        indicators = get_risk_indicators(feat_dicts[i])

        if actual_str == "SAFE" and pred_str == "PHISHING":
            false_positives.append({
                "url": url,
                "actual": "SAFE",
                "predicted": "PHISHING",
                "confidence": round(confidence, 2),
                "score": round(score, 4),
                "indicators": indicators,
            })
        elif actual_str == "PHISHING" and pred_str == "SAFE":
            false_negatives.append({
                "url": url,
                "actual": "PHISHING",
                "predicted": "SAFE",
                "confidence": round(confidence, 2),
                "score": round(score, 4),
                "indicators": indicators,
            })

    # Sort by highest model confidence
    false_positives.sort(key=lambda x: x["confidence"], reverse=True)
    false_negatives.sort(key=lambda x: x["confidence"], reverse=True)

    top_25_fp = false_positives[:25]
    top_25_fn = false_negatives[:25]

    print(f"\nTotal False Positives on test set: {len(false_positives):,}")
    print(f"Total False Negatives on test set: {len(false_negatives):,}")

    print("\n" + "=" * 75)
    print("TOP 10 MOST CONFIDENT FALSE POSITIVES (Legitimate predicted as Phishing):")
    print("=" * 75)
    for i, item in enumerate(top_25_fp[:10], 1):
        print(f"[{i:02d}] {item['confidence']:.1f}% confidence | Score: {item['score']:.4f}")
        print(f"     URL: {item['url']}")
        if item["indicators"]:
            print(f"     Triggers: {'; '.join(item['indicators'][:3])}")
        print()

    print("=" * 75)
    print("TOP 10 MOST CONFIDENT FALSE NEGATIVES (Phishing predicted as Safe):")
    print("=" * 75)
    for i, item in enumerate(top_25_fn[:10], 1):
        print(f"[{i:02d}] {item['confidence']:.1f}% confidence | Score: {item['score']:.4f}")
        print(f"     URL: {item['url']}")
        if item["indicators"]:
            print(f"     Triggers: {'; '.join(item['indicators'][:3])}")
        print()

    # Save to JSON
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / "error_analysis.json"
    data_out = {
        "summary": {
            "test_set_size": len(df_test),
            "total_false_positives": len(false_positives),
            "total_false_negatives": len(false_negatives),
            "decision_threshold": threshold,
        },
        "top_25_false_positives": top_25_fp,
        "top_25_false_negatives": top_25_fn,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data_out, f, indent=2)

    print(f"Full top-25 error analysis saved to: {out_path}")
    print("=" * 75)


if __name__ == "__main__":
    main()
