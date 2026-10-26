"""
PhishGuard AI — Complete Model Training Pipeline
==================================================
Trains and rigorously evaluates phishing classifiers on the UCI PhiUSIIL dataset:
  1. Logistic Regression (Tabular + Char n-gram TF-IDF combined)
  2. LightGBM (Tabular + Char n-gram TF-IDF combined)
  3. Random Forest (36 URL structural features)
  4. Multinomial Naive Bayes (Char n-gram TF-IDF)

Evaluation Rigor & Rules:
  - 70/15/15 Train / Validation / Test split grouped by registered domain
    (tldextract offline PSL) ensuring ZERO domain leakage across splits.
  - Model selection and decision threshold tuning performed on VALIDATION set ONLY.
  - Held-out TEST set touched exactly ONCE for final reporting.
  - Probability calibration with reliability curve & Brier score.
  - Decision threshold tuned on validation set for target phishing recall (0.98).
  - SHA-256 dataset fingerprinting and full metadata persistence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")  # Headless backend
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import scipy.sparse
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
    auc,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm
import lightgbm as lgb
import tldextract

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Safe UTF-8 console output for Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from backend.config import (
    DATA_PATH,
    MODELS_DIR,
    REPORTS_DIR,
    RANDOM_SEED,
    MODEL_VERSION,
    TRAIN_SIZE,
    VAL_SIZE,
    TEST_SIZE,
)
from backend.features import (
    FEATURE_NAMES,
    canonical_url_string,
    extract_url_features,
    normalise_url,
)

# ──────────────────────────────────────────────────────────────────────────
# Logging Setup
# ──────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("train")


# ──────────────────────────────────────────────────────────────────────────
# Dataset Hash Computation
# ──────────────────────────────────────────────────────────────────────────
def compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file for reproducibility tracking."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ──────────────────────────────────────────────────────────────────────────
# Step 1: Inspect, Clean, and Domain-Group Dataset
# ──────────────────────────────────────────────────────────────────────────
def inspect_and_clean_data(csv_path: Path) -> tuple[pd.DataFrame, dict]:
    """
    Loads dataset, standardises labels (SAFE=0, PHISHING=1), deduplicates,
    normalises URLs canonically, and extracts registered domains for group splitting.
    """
    log.info("=" * 70)
    log.info("STEP 1: INSPECTING & PREPARING DATASET")
    log.info("=" * 70)
    log.info("Loading dataset from: %s", csv_path)

    if not csv_path.exists():
        log.error("Dataset not found at %s!", csv_path)
        sys.exit(1)

    t0 = time.time()
    df_raw = pd.read_csv(csv_path, low_memory=False)
    raw_sha = compute_sha256(csv_path)
    log.info("Loaded in %.2fs. Raw Shape: %s | SHA-256: %s",
             time.time() - t0, df_raw.shape, raw_sha)

    # Identify URL and Label column
    url_col = next((c for c in ["url", "URL", "Url", "urlString"] if c in df_raw.columns), None)
    label_col = next((c for c in ["label", "Label", "LABEL", "class", "Class"] if c in df_raw.columns), None)

    if url_col is None or label_col is None:
        log.error("Could not find URL or label column in: %s", list(df_raw.columns))
        sys.exit(1)

    log.info("Identified URL column: '%s', Label column: '%s'", url_col, label_col)

    # Clean, Map Labels, and Deduplicate
    df = df_raw[[url_col, label_col]].copy()
    df.rename(columns={url_col: "url", label_col: "raw_label"}, inplace=True)
    df.dropna(subset=["url", "raw_label"], inplace=True)
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() > 0]
    df = df[df["url"] != "nan"]

    # In raw PhiUSIIL dataset: 1 = Legitimate (Safe), 0 = Phishing
    # Standardised convention: 0 = SAFE, 1 = PHISHING
    df["label"] = df["raw_label"].astype(int).map({1: 0, 0: 1})
    df.dropna(subset=["label"], inplace=True)
    df["label"] = df["label"].astype(int)

    # Deduplicate on raw URL string
    initial_len = len(df)
    df.drop_duplicates(subset=["url"], keep="first", inplace=True)
    df.reset_index(drop=True, inplace=True)
    removed_dups = initial_len - len(df)
    log.info("Deduplication: removed %d duplicate rows. Dataset size: %d URLs",
             removed_dups, len(df))

    # Canonicalise URLs identically for training and inference
    log.info("Canonicalising URLs via normalise_url…")
    canonical_urls = []
    for u in df["url"]:
        c_url, _ = normalise_url(u)
        canonical_urls.append(c_url if c_url else u)
    df["canonical_url"] = canonical_urls

    # Extract registered domain using offline tldextract for Domain Group Split
    log.info("Extracting registered domain groups with offline tldextract…")
    ext = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
    domain_groups = []
    for u in df["canonical_url"]:
        res = ext(u)
        dom = getattr(res, "top_domain_under_public_suffix", None) or res.domain or u
        domain_groups.append(dom.lower())
    df["domain_group"] = domain_groups

    unique_domains = df["domain_group"].nunique()
    final_counts = df["label"].value_counts().to_dict()
    log.info("Dataset statistics:")
    log.info("  Total unique URLs:    %d", len(df))
    log.info("  Unique domain groups: %d", unique_domains)
    log.info("  SAFE (0):             %d (%.2f%%)", final_counts.get(0, 0), final_counts.get(0, 0) / len(df) * 100)
    log.info("  PHISHING (1):         %d (%.2f%%)", final_counts.get(1, 0), final_counts.get(1, 0) / len(df) * 100)

    summary = {
        "raw_shape": df_raw.shape,
        "dataset_size": len(df),
        "removed_duplicates": removed_dups,
        "dataset_sha256": raw_sha,
        "unique_domain_groups": unique_domains,
        "label_distribution": {
            "SAFE": final_counts.get(0, 0),
            "PHISHING": final_counts.get(1, 0),
        },
    }
    return df, summary


# ──────────────────────────────────────────────────────────────────────────
# Step 2: 70/15/15 Domain-Grouped Split
# ──────────────────────────────────────────────────────────────────────────
def split_domain_grouped(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Splits data into 70% Train, 15% Validation, 15% Test grouped by registered domain.
    Guarantees 0% domain overlap between train, validation, and test sets.
    """
    log.info("=" * 70)
    log.info("STEP 2: 70/15/15 DOMAIN-GROUPED SPLIT")
    log.info("=" * 70)

    # 1. Split Train (70%) and Temp (30%)
    gss1 = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=RANDOM_SEED)
    train_idx, temp_idx = next(gss1.split(df, df["label"], groups=df["domain_group"]))

    df_train = df.iloc[train_idx].reset_index(drop=True)
    df_temp = df.iloc[temp_idx].reset_index(drop=True)

    # 2. Split Temp into Validation (50% of Temp = 15% total) and Test (50% of Temp = 15% total)
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=RANDOM_SEED)
    val_sub_idx, test_sub_idx = next(gss2.split(df_temp, df_temp["label"], groups=df_temp["domain_group"]))

    df_val = df_temp.iloc[val_sub_idx].reset_index(drop=True)
    df_test = df_temp.iloc[test_sub_idx].reset_index(drop=True)

    # Verify zero domain overlap
    dom_train = set(df_train["domain_group"])
    dom_val = set(df_val["domain_group"])
    dom_test = set(df_test["domain_group"])

    overlap_train_val = len(dom_train & dom_val)
    overlap_train_test = len(dom_train & dom_test)
    overlap_val_test = len(dom_val & dom_test)

    log.info("Split Sizes:")
    log.info("  Train set (70%%): %d samples (%d domains)", len(df_train), len(dom_train))
    log.info("    SAFE: %d (%.1f%%) | PHISHING: %d (%.1f%%)",
             (df_train["label"] == 0).sum(), (df_train["label"] == 0).mean() * 100,
             (df_train["label"] == 1).sum(), (df_train["label"] == 1).mean() * 100)
    log.info("  Validation set (15%%): %d samples (%d domains)", len(df_val), len(dom_val))
    log.info("    SAFE: %d (%.1f%%) | PHISHING: %d (%.1f%%)",
             (df_val["label"] == 0).sum(), (df_val["label"] == 0).mean() * 100,
             (df_val["label"] == 1).sum(), (df_val["label"] == 1).mean() * 100)
    log.info("  Held-out Test set (15%%): %d samples (%d domains)", len(df_test), len(dom_test))
    log.info("    SAFE: %d (%.1f%%) | PHISHING: %d (%.1f%%)",
             (df_test["label"] == 0).sum(), (df_test["label"] == 0).mean() * 100,
             (df_test["label"] == 1).sum(), (df_test["label"] == 1).mean() * 100)

    log.info("Domain Leakage Verification:")
    log.info("  Train & Val domain overlap:  %d", overlap_train_val)
    log.info("  Train & Test domain overlap: %d", overlap_train_test)
    log.info("  Val & Test domain overlap:   %d", overlap_val_test)
    assert overlap_train_val == 0 and overlap_train_test == 0 and overlap_val_test == 0, \
        "Domain leakage detected across splits!"

    return df_train, df_val, df_test


# ──────────────────────────────────────────────────────────────────────────
# Step 3: Feature Extraction (Tabular + Char n-gram TF-IDF)
# ──────────────────────────────────────────────────────────────────────────
def extract_tabular_matrix(urls: list[str]) -> np.ndarray:
    """Extracts 36 URL structural features with progress bar."""
    rows = []
    for u in tqdm(urls, desc="Extracting 36 structural features", unit="urls"):
        feat_dict = extract_url_features(u)
        rows.append([feat_dict[name] for name in FEATURE_NAMES])
    return np.array(rows, dtype=np.float32)


# ──────────────────────────────────────────────────────────────────────────
# Step 4: Model Training, Validation Tuning, and Test Evaluation
# ──────────────────────────────────────────────────────────────────────────
def train_and_evaluate(
    df_train: pd.DataFrame,
    df_val: pd.DataFrame,
    df_test: pd.DataFrame,
    dataset_summary: dict,
) -> dict:
    log.info("=" * 70)
    log.info("STEP 3: FEATURE EXTRACTION & MODEL PIPELINE")
    log.info("=" * 70)

    urls_train = df_train["canonical_url"].tolist()
    y_train = df_train["label"].values.astype(int)

    urls_val = df_val["canonical_url"].tolist()
    y_val = df_val["label"].values.astype(int)

    urls_test = df_test["canonical_url"].tolist()
    y_test = df_test["label"].values.astype(int)

    # 1. Extract Tabular Features
    log.info("Extracting tabular features for Train (%d), Val (%d), Test (%d)…",
             len(urls_train), len(urls_val), len(urls_test))
    X_tab_train = extract_tabular_matrix(urls_train)
    X_tab_val = extract_tabular_matrix(urls_val)
    X_tab_test = extract_tabular_matrix(urls_test)

    # 2. Scale Tabular Features
    scaler = StandardScaler()
    X_tab_train_scaled = scaler.fit_transform(X_tab_train)
    X_tab_val_scaled = scaler.transform(X_tab_val)
    X_tab_test_scaled = scaler.transform(X_tab_test)

    # 3. Fit Character n-gram TF-IDF on Train only
    log.info("Fitting character n-gram TF-IDF on training set URLs…")
    tfidf = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        max_features=1500,
        sublinear_tf=True,
    )
    X_tfidf_train = tfidf.fit_transform(urls_train)
    X_tfidf_val = tfidf.transform(urls_val)
    X_tfidf_test = tfidf.transform(urls_test)

    # 4. Create Combined Sparse Feature Matrices (Tabular + TF-IDF)
    log.info("Combining tabular features and TF-IDF into unified sparse matrices…")
    X_comb_train = scipy.sparse.hstack([scipy.sparse.csr_matrix(X_tab_train_scaled), X_tfidf_train]).tocsr()
    X_comb_val = scipy.sparse.hstack([scipy.sparse.csr_matrix(X_tab_val_scaled), X_tfidf_val]).tocsr()
    X_comb_test = scipy.sparse.hstack([scipy.sparse.csr_matrix(X_tab_test_scaled), X_tfidf_test]).tocsr()

    log.info("Combined feature matrix shape: %s", X_comb_train.shape)

    # Imbalance ratio
    neg_count = int((y_train == 0).sum())
    pos_count = int((y_train == 1).sum())
    scale_pos_weight = float(neg_count / max(1, pos_count))

    # 5. Define Candidate Models
    models = {
        "LightGBM (Tabular + TF-IDF)": {
            "model": lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.08,
                scale_pos_weight=scale_pos_weight,
                random_state=RANDOM_SEED,
                n_jobs=-1,
                verbose=-1,
            ),
            "X_train": X_comb_train,
            "X_val": X_comb_val,
            "X_test": X_comb_test,
            "uses_tfidf": True,
            "uses_tabular": True,
        },
        "Logistic Regression (Tabular + TF-IDF)": {
            "model": LogisticRegression(
                class_weight="balanced",
                max_iter=1000,
                C=1.0,
                solver="lbfgs",
                random_state=RANDOM_SEED,
            ),
            "X_train": X_comb_train,
            "X_val": X_comb_val,
            "X_test": X_comb_test,
            "uses_tfidf": True,
            "uses_tabular": True,
        },
        "Random Forest (Tabular 36)": {
            "model": RandomForestClassifier(
                n_estimators=100,
                max_depth=16,
                class_weight="balanced",
                random_state=RANDOM_SEED,
                n_jobs=-1,
            ),
            "X_train": X_tab_train,
            "X_val": X_tab_val,
            "X_test": X_tab_test,
            "uses_tfidf": False,
            "uses_tabular": True,
        },
        "Naive Bayes (Char TF-IDF)": {
            "model": MultinomialNB(alpha=0.1),
            "X_train": X_tfidf_train,
            "X_val": X_tfidf_val,
            "X_test": X_tfidf_test,
            "uses_tfidf": True,
            "uses_tabular": False,
        },
    }

    # 6. Fit Models on 70% Train & Evaluate on 15% Validation Set
    log.info("\n" + "=" * 70)
    log.info("STEP 4: MODEL EVALUATION & SELECTION ON VALIDATION SET (15%%)")
    log.info("=" * 70)

    val_comparison = {}
    for name, item in models.items():
        log.info("Fitting candidate: %s …", name)
        t0 = time.time()
        m = item["model"]
        m.fit(item["X_train"], y_train)
        fit_time = time.time() - t0

        val_preds = m.predict(item["X_val"])
        val_proba = m.predict_proba(item["X_val"])[:, 1] if hasattr(m, "predict_proba") else None

        acc = accuracy_score(y_val, val_preds)
        prec = precision_score(y_val, val_preds, pos_label=1, zero_division=0)
        rec = recall_score(y_val, val_preds, pos_label=1, zero_division=0)
        f1 = f1_score(y_val, val_preds, pos_label=1, zero_division=0)
        auc_score = roc_auc_score(y_val, val_proba) if val_proba is not None else 0.0

        val_comparison[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "roc_auc": round(float(auc_score), 4),
            "fit_time_s": round(fit_time, 2),
        }
        log.info("  [VAL] %s -> Acc: %.4f | Prec: %.4f | Rec: %.4f | F1: %.4f | AUC: %.4f (%.1fs)",
                 name, acc, prec, rec, f1, auc_score, fit_time)

    # Print Validation Table
    print("\n" + "-" * 75)
    print("VALIDATION SET MODEL COMPARISON (15% Domain-Grouped)")
    print("-" * 75)
    print(f"{'Model':<38} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1-Score':<9} | {'ROC-AUC':<8}")
    print("-" * 75)
    for name, r in val_comparison.items():
        print(f"{name:<38} | {r['accuracy']:<9.4f} | {r['precision']:<9.4f} | {r['recall']:<9.4f} | {r['f1']:<9.4f} | {r['roc_auc']:<8.4f}")
    print("-" * 75 + "\n")

    # Select winner on Validation set
    winner_name = max(val_comparison, key=lambda k: (val_comparison[k]["f1"], val_comparison[k]["recall"]))
    winner_info = models[winner_name]
    raw_winner_model = winner_info["model"]
    log.info("[*] WINNER SELECTED ON VALIDATION SET: '%s' (Val F1: %.4f)",
             winner_name, val_comparison[winner_name]["f1"])

    # 7. Probability Calibration using CalibratedClassifierCV
    log.info("\n" + "=" * 70)
    log.info("STEP 5: PROBABILITY CALIBRATION & DECISION THRESHOLD TUNING")
    log.info("=" * 70)

    log.info("Calibrating winner probabilities with CalibratedClassifierCV (sigmoid, 3-fold)…")
    # We calibrate with 3-fold CV on the training data so calibration is completely unbiased
    calibrated_winner = CalibratedClassifierCV(
        estimator=raw_winner_model,
        method="sigmoid",
        cv=3,
    )
    calibrated_winner.fit(winner_info["X_train"], y_train)

    # 8. Tune Decision Threshold on Validation Set Only
    val_probs = calibrated_winner.predict_proba(winner_info["X_val"])[:, 1]
    TARGET_RECALL = 0.98

    thresholds = np.linspace(0.05, 0.95, 181)
    best_threshold = 0.50
    best_fpr_at_target = 1.0
    highest_recall = 0.0

    # Search for threshold that satisfies TARGET_RECALL on validation set with minimum FPR
    for t in thresholds:
        preds = (val_probs >= t).astype(int)
        rec = recall_score(y_val, preds, pos_label=1, zero_division=0)
        tn = int(((y_val == 0) & (preds == 0)).sum())
        fp = int(((y_val == 0) & (preds == 1)).sum())
        fpr = fp / max(1, (fp + tn))

        if rec >= TARGET_RECALL:
            if fpr < best_fpr_at_target:
                best_fpr_at_target = fpr
                best_threshold = float(t)
        if rec > highest_recall:
            highest_recall = rec

    if best_fpr_at_target == 1.0:
        # Fallback to threshold that maximizes F1 on validation set
        log.warning("Target recall %.2f not fully met on validation set. Max achievable: %.4f",
                    TARGET_RECALL, highest_recall)
        best_f1 = 0.0
        for t in thresholds:
            preds = (val_probs >= t).astype(int)
            f = f1_score(y_val, preds, pos_label=1, zero_division=0)
            if f > best_f1:
                best_f1 = f
                best_threshold = float(t)
        val_preds_final = (val_probs >= best_threshold).astype(int)
        best_fpr_at_target = float(((y_val == 0) & (val_preds_final == 1)).sum() / max(1, (y_val == 0).sum()))

    log.info("Tuned Decision Threshold on Validation Set: %.4f", best_threshold)
    log.info("  Validation Phishing Recall: %.4f | Validation False Positive Rate: %.4f",
             recall_score(y_val, (val_probs >= best_threshold).astype(int), pos_label=1),
             best_fpr_at_target)

    # 9. Final Single Evaluation on Held-Out Test Set (Touched ONCE)
    log.info("\n" + "=" * 70)
    log.info("STEP 6: FINAL EVALUATION ON HELD-OUT TEST SET (15%% = %d samples)", len(y_test))
    log.info("=" * 70)

    test_probs = calibrated_winner.predict_proba(winner_info["X_test"])[:, 1]
    test_preds = (test_probs >= best_threshold).astype(int)

    test_acc = float(accuracy_score(y_test, test_preds))
    test_prec = float(precision_score(y_test, test_preds, pos_label=1, zero_division=0))
    test_rec = float(recall_score(y_test, test_preds, pos_label=1, zero_division=0))
    test_f1 = float(f1_score(y_test, test_preds, pos_label=1, zero_division=0))
    test_auc = float(roc_auc_score(y_test, test_probs))
    test_ap = float(average_precision_score(y_test, test_probs))
    test_brier = float(brier_score_loss(y_test, test_probs))
    cm = confusion_matrix(y_test, test_preds)

    tn, fp, fn, tp = cm.ravel()
    test_fpr = float(fp / max(1, (fp + tn)))

    test_metrics = {
        "model_name": winner_name,
        "accuracy": round(test_acc, 4),
        "precision": round(test_prec, 4),
        "recall": round(test_rec, 4),
        "f1": round(test_f1, 4),
        "roc_auc": round(test_auc, 4),
        "average_precision": round(test_ap, 4),
        "brier_score": round(test_brier, 4),
        "false_positive_rate": round(test_fpr, 4),
        "decision_threshold": round(best_threshold, 4),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }

    print("\n" + "=" * 75)
    print("FINAL HELD-OUT TEST SET RESULTS (Domain-Grouped Split, Touched Once)")
    print("=" * 75)
    print(f"Model Name           : {winner_name}")
    print(f"Decision Threshold   : {best_threshold:.4f}")
    print(f"Test Accuracy        : {test_acc:.4%}")
    print(f"Test Phishing Precision: {test_prec:.4%}")
    print(f"Test Phishing Recall : {test_rec:.4%}")
    print(f"Test F1-Score        : {test_f1:.4%}")
    print(f"Test ROC-AUC         : {test_auc:.4f}")
    print(f"Test PR-AUC (AvgPrec): {test_ap:.4f}")
    print(f"Test Brier Score     : {test_brier:.4f} (lower is better, 0 = perfect)")
    print(f"Test False Pos. Rate : {test_fpr:.4%}")
    print(f"Confusion Matrix     : TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")
    print("=" * 75 + "\n")

    # 10. Extract Feature Importances
    feature_importances = []
    if hasattr(raw_winner_model, "feature_importances_"):
        imps = raw_winner_model.feature_importances_
        # First 36 features correspond to tabular FEATURE_NAMES
        for i, feat_name in enumerate(FEATURE_NAMES):
            feature_importances.append({
                "feature": feat_name,
                "importance": float(imps[i]) if i < len(imps) else 0.0,
            })
    elif hasattr(raw_winner_model, "coef_"):
        coefs = np.abs(raw_winner_model.coef_[0])
        for i, feat_name in enumerate(FEATURE_NAMES):
            feature_importances.append({
                "feature": feat_name,
                "importance": float(coefs[i]) if i < len(coefs) else 0.0,
            })
    feature_importances.sort(key=lambda x: x["importance"], reverse=True)

    # 11. Generate Visual Reports
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    generate_reports(
        winner_name=winner_name,
        test_metrics=test_metrics,
        y_test=y_test,
        test_probs=test_probs,
        cm=cm,
        feature_importances=feature_importances,
        val_comparison=val_comparison,
        reports_dir=REPORTS_DIR,
    )

    # 12. Save Production Artefacts
    save_production_artefacts(
        winner_name=winner_name,
        calibrated_model=calibrated_winner,
        scaler=scaler if winner_info["uses_tabular"] else None,
        vectorizer=tfidf if winner_info["uses_tfidf"] else None,
        threshold=best_threshold,
        test_metrics=test_metrics,
        val_comparison=val_comparison,
        feature_importances=feature_importances,
        dataset_summary=dataset_summary,
        raw_model=raw_winner_model,
    )

    return {
        "winner_name": winner_name,
        "test_metrics": test_metrics,
        "val_comparison": val_comparison,
        "threshold": best_threshold,
    }


# ──────────────────────────────────────────────────────────────────────────
# Step 5: Visual Reports Generation
# ──────────────────────────────────────────────────────────────────────────
def generate_reports(
    winner_name: str,
    test_metrics: dict,
    y_test: np.ndarray,
    test_probs: np.ndarray,
    cm: np.ndarray,
    feature_importances: list[dict],
    val_comparison: dict,
    reports_dir: Path,
) -> None:
    log.info("Generating evaluation plots and reports in %s …", reports_dir)

    # 1. Confusion Matrix
    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["SAFE", "PHISHING"])
    disp.plot(ax=ax, cmap="Blues", values_format="d")
    ax.set_title(f"Confusion Matrix — {winner_name}\n(Held-out Test Set, N={len(y_test):,}, Thresh={test_metrics['decision_threshold']:.2f})",
                 fontsize=11, fontweight="bold")
    plt.tight_layout()
    cm_path = reports_dir / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=150)
    plt.close()
    log.info("Saved: %s", cm_path)

    # 2. ROC Curve
    fpr, tpr, _ = roc_curve(y_test, test_probs)
    roc_auc = auc(fpr, tpr)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot(fpr, tpr, color="#2563eb", lw=2.2, label=f"{winner_name} (AUC = {roc_auc:.4f})")
    ax.plot([0, 1], [0, 1], "k--", lw=1.2, label="Random Guess (AUC = 0.5000)")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.02])
    ax.set_xlabel("False Positive Rate (1 - Specificity)", fontsize=11)
    ax.set_ylabel("True Positive Rate (Recall)", fontsize=11)
    ax.set_title(f"ROC Curve — Held-out Test Set (AUC = {roc_auc:.4f})", fontsize=12, fontweight="bold")
    ax.legend(loc="lower right", frameon=True)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    roc_path = reports_dir / "roc_curve.png"
    plt.savefig(roc_path, dpi=150)
    plt.close()
    log.info("Saved: %s", roc_path)

    # 3. Reliability Curve (Calibration Diagram)
    prob_true, prob_pred = calibration_curve(y_test, test_probs, n_bins=10)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot(prob_pred, prob_true, "s-", color="#16a34a", lw=2, label=f"Calibrated ({winner_name})")
    ax.plot([0, 1], [0, 1], "k--", lw=1.2, label="Perfect Calibration")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.0])
    ax.set_xlabel("Mean Predicted Probability", fontsize=11)
    ax.set_ylabel("Fraction of Positives", fontsize=11)
    ax.set_title(f"Reliability Curve (Brier Score = {test_metrics['brier_score']:.4f})",
                 fontsize=12, fontweight="bold")
    ax.legend(loc="upper left", frameon=True)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    rel_path = reports_dir / "reliability_curve.png"
    plt.savefig(rel_path, dpi=150)
    plt.close()
    log.info("Saved: %s", rel_path)

    # 4. Feature Importance Plot
    if feature_importances:
        top_15 = feature_importances[:15]
        top_15_rev = list(reversed(top_15))
        names = [item["feature"] for item in top_15_rev]
        vals = [item["importance"] for item in top_15_rev]

        fig, ax = plt.subplots(figsize=(8, 6))
        ax.barh(names, vals, color="#2563eb", alpha=0.85)
        ax.set_xlabel("Importance / Absolute Weight", fontsize=11)
        ax.set_title(f"Top 15 Feature Importances — {winner_name}", fontsize=12, fontweight="bold")
        ax.grid(axis="x", alpha=0.3)
        plt.tight_layout()
        fi_path = reports_dir / "feature_importance.png"
        plt.savefig(fi_path, dpi=150)
        plt.close()
        log.info("Saved: %s", fi_path)

    # 5. Training text summary
    txt_path = reports_dir / "training_report.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("PhishGuard AI — Training Evaluation Report\n")
        f.write("=" * 65 + "\n\n")
        f.write(f"Trained at            : {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Winner Model          : {winner_name}\n")
        f.write(f"Split Method          : 70/15/15 Domain-Grouped (tldextract PSL)\n")
        f.write(f"Tuned Threshold       : {test_metrics['decision_threshold']}\n")
        f.write(f"Test Set Size         : {len(y_test):,} samples\n\n")
        f.write("Held-Out Test Set Metrics\n")
        f.write("-" * 50 + "\n")
        for k, v in test_metrics.items():
            f.write(f"  {k:<22} : {v}\n")
        f.write("\nValidation Model Comparison\n")
        f.write("-" * 50 + "\n")
        for name, r in val_comparison.items():
            f.write(f"\n  {name}:\n")
            for k, v in r.items():
                f.write(f"    {k:<16} : {v}\n")
    log.info("Saved: %s", txt_path)


# ──────────────────────────────────────────────────────────────────────────
# Step 6: Save Production Artefacts & Metadata
# ──────────────────────────────────────────────────────────────────────────
def save_production_artefacts(
    winner_name: str,
    calibrated_model,
    scaler,
    vectorizer,
    threshold: float,
    test_metrics: dict,
    val_comparison: dict,
    feature_importances: list[dict],
    dataset_summary: dict,
    raw_model,
) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    pkl_path = MODELS_DIR / "model.pkl"
    joblib_path = MODELS_DIR / "phishguard_model.joblib"
    meta_path = MODELS_DIR / "model_metadata.json"
    metrics_path = MODELS_DIR / "model_metrics.json"

    # Extract hyperparameters if available
    best_params = {}
    if hasattr(raw_model, "get_params"):
        all_params = raw_model.get_params()
        # Keep non-callable, JSON-serialisable parameters
        for k, v in all_params.items():
            if isinstance(v, (int, float, str, bool, list, type(None))):
                best_params[k] = v

    bundle = {
        "model": calibrated_model,
        "scaler": scaler,
        "vectorizer": vectorizer,
        "threshold": threshold,
        "feature_names": FEATURE_NAMES,
        "model_name": winner_name,
        "target_mapping": {0: "SAFE", 1: "PHISHING"},
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    joblib.dump(bundle, pkl_path)
    joblib.dump(bundle, joblib_path)
    log.info("Saved model bundle -> %s & %s", pkl_path, joblib_path)

    # Environment and dependency tracking
    library_versions = {
        "python": platform.python_version(),
        "scikit-learn": getattr(sys.modules.get("sklearn"), "__version__", "unknown"),
        "lightgbm": getattr(lgb, "__version__", "unknown"),
        "tldextract": getattr(tldextract, "__version__", "unknown"),
        "joblib": getattr(joblib, "__version__", "unknown"),
        "numpy": getattr(np, "__version__", "unknown"),
        "pandas": getattr(pd, "__version__", "unknown"),
    }

    metadata = {
        "model_name": winner_name,
        "model_version": MODEL_VERSION,
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "class_mapping": {"0": "SAFE", "1": "PHISHING"},
        "decision_threshold": round(threshold, 4),
        "best_hyperparameters": best_params,
        "dataset_source": "UCI PhiUSIIL Phishing URL Dataset (id=967)",
        "dataset_size": dataset_summary["dataset_size"],
        "dataset_sha256": dataset_summary["dataset_sha256"],
        "label_distribution": dataset_summary["label_distribution"],
        "split_description": "70/15/15 Domain-Grouped Split using tldextract registered domains to prevent domain leakage",
        "target_phishing_recall": 0.98,
        "validation_fpr": test_metrics.get("false_positive_rate", 0.0),
        "test_brier_score": test_metrics.get("brier_score", 0.0),
        "library_versions": library_versions,
        "trained_at": bundle["trained_at"],
        "random_seed": RANDOM_SEED,
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    log.info("Saved metadata -> %s", meta_path)

    # Standardised Metrics JSON matching Frontend Contract
    metrics = {
        "best_model": winner_name,
        "decision_threshold": round(threshold, 4),
        "test_metrics": test_metrics,
        "validation_comparison": val_comparison,
        "feature_importances": feature_importances,
        "dataset_source": "UCI PhiUSIIL Phishing URL Dataset (id=967)",
        "dataset_size": dataset_summary["dataset_size"],
        "label_distribution": dataset_summary["label_distribution"],
        "split_description": "70/15/15 Domain-Grouped Split (no domain overlap between train/val/test)",
    }
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    log.info("Saved metrics -> %s", metrics_path)


# ──────────────────────────────────────────────────────────────────────────
# Main Execution
# ──────────────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 70)
    log.info("PHISHGUARD AI — PRODUCTION RETRAINING & EVALUATION PIPELINE")
    log.info("=" * 70)

    # Step 1: Inspect & Clean
    df, summary = inspect_and_clean_data(DATA_PATH)

    # Step 2: 70/15/15 Domain-Grouped Split
    df_train, df_val, df_test = split_domain_grouped(df)

    # Step 3, 4, 5, 6: Train, Tune, Evaluate, Save
    train_and_evaluate(df_train, df_val, df_test, summary)

    log.info("=" * 70)
    log.info("HONEST EVALUATION & RETRAINING COMPLETE!")
    log.info("=" * 70)


if __name__ == "__main__":
    main()
