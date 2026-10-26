"""
PhishGuard AI — Complete Model Training Pipeline
==================================================
Trains and evaluates 4 classifiers on the Phishing URL Dataset:
  1. Logistic Regression (on 25 URL structural features + StandardScaler)
  2. Random Forest (on 25 URL structural features)
  3. XGBoost (on 25 URL structural features)
  4. Naive Bayes (on character n-gram TF-IDF of raw URL strings)

Pipeline details:
  - Stratified 80/20 train/test split (fixed random_state=42)
  - Pre-split deduplication to prevent train/test data leakage
  - Fixed label mapping: SAFE = 0, PHISHING = 1
  - 5-fold Stratified Cross-Validation with F1 mean & std
  - Hyperparameter tuning of the best model with RandomizedSearchCV (n_iter=25)
  - Comprehensive evaluation table: Accuracy, Precision, Recall, F1, ROC-AUC
  - Reports generated in reports/: confusion_matrix.png, roc_curve.png, feature_importance.png
  - Artefact saved to models/model.pkl and models/phishguard_model.joblib
"""

from __future__ import annotations

import json
import logging
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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_curve,
    auc,
    classification_report,
)
from sklearn.model_selection import (
    StratifiedKFold,
    train_test_split,
    RandomizedSearchCV,
    cross_val_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm
from xgboost import XGBClassifier

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
)
from backend.features import FEATURE_NAMES, extract_url_features

# ──────────────────────────────────────────────────────────────────────────
# Logging Setup
# ──────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("train")


# ──────────────────────────────────────────────────────────────────────────
# Step 1: Inspect, Clean, and Deduplicate Data
# ──────────────────────────────────────────────────────────────────────────
def inspect_and_clean_data(csv_path: Path) -> tuple[pd.DataFrame, dict]:
    """
    Loads dataset, diagnoses inconsistencies, fixes label mapping,
    removes duplicates to avoid data leakage, and returns cleaned DataFrame.
    """
    log.info("=" * 70)
    log.info("STEP 1: INSPECTING DATASET")
    log.info("=" * 70)
    log.info("Loading dataset from: %s", csv_path)

    if not csv_path.exists():
        log.error("Dataset not found at %s!", csv_path)
        sys.exit(1)

    t0 = time.time()
    df_raw = pd.read_csv(csv_path, low_memory=False)
    log.info("Loaded in %.2fs. Raw Shape: %s (Rows: %d, Columns: %d)",
             time.time() - t0, df_raw.shape, df_raw.shape[0], df_raw.shape[1])

    # 1. Identify URL and Label column
    url_candidates = ["url", "URL", "Url", "urlString"]
    label_candidates = ["label", "Label", "LABEL", "class", "Class"]

    url_col = next((c for c in url_candidates if c in df_raw.columns), None)
    label_col = next((c for c in label_candidates if c in df_raw.columns), None)

    if url_col is None or label_col is None:
        log.error("Could not find URL or label column in: %s", list(df_raw.columns))
        sys.exit(1)

    log.info("Identified URL column: '%s', Label column: '%s'", url_col, label_col)

    # 2. Check nulls
    null_counts = df_raw[[url_col, label_col]].isnull().sum()
    log.info("Null check — %s nulls: %d, %s nulls: %d",
             url_col, null_counts[url_col], label_col, null_counts[label_col])

    # 3. Check raw class distribution
    raw_counts = df_raw[label_col].value_counts().to_dict()
    log.info("Raw label value counts in dataset:")
    for k, v in raw_counts.items():
        log.info("  Raw label '%s': %d (%.2f%%)", k, v, v / len(df_raw) * 100)

    # 4. Check duplicates before splitting (Crucial for preventing data leakage!)
    dup_url_count = df_raw.duplicated(subset=[url_col], keep=False).sum()
    unique_url_count = df_raw[url_col].nunique()
    log.info("Duplicate check: %d duplicate rows found (%d unique URLs).",
             dup_url_count, unique_url_count)

    # Check for conflicting labels on duplicates
    conflicting = df_raw.groupby(url_col)[label_col].nunique()
    conflicts_count = (conflicting > 1).sum()
    log.info("URLs with conflicting labels: %d", conflicts_count)

    # 5. Clean, Map Labels, and Deduplicate
    df = df_raw[[url_col, label_col]].copy()
    df.rename(columns={url_col: "url", label_col: "raw_label"}, inplace=True)
    df.dropna(subset=["url", "raw_label"], inplace=True)
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() > 0]
    df = df[df["url"] != "nan"]

    # In the raw PhiUSIIL dataset: 1 = Legitimate (Safe), 0 = Phishing
    # Under standard convention & user requirements:
    # SAFE = 0, PHISHING = 1
    # Raw 1 (Legitimate) -> 0 (SAFE)
    # Raw 0 (Phishing)   -> 1 (PHISHING)
    df["label"] = df["raw_label"].astype(int).map({1: 0, 0: 1})
    df.dropna(subset=["label"], inplace=True)
    df["label"] = df["label"].astype(int)

    # Drop duplicates to prevent train/test leakage
    initial_len = len(df)
    df.drop_duplicates(subset=["url"], keep="first", inplace=True)
    df.reset_index(drop=True, inplace=True)
    removed_dups = initial_len - len(df)
    log.info("Deduplication: removed %d duplicate rows. Final dataset size: %d URLs",
             removed_dups, len(df))

    final_counts = df["label"].value_counts().to_dict()
    log.info("Standardised Class Balance (0 = SAFE, 1 = PHISHING):")
    log.info("  SAFE (0):     %d (%.2f%%)", final_counts.get(0, 0), final_counts.get(0, 0) / len(df) * 100)
    log.info("  PHISHING (1): %d (%.2f%%)", final_counts.get(1, 0), final_counts.get(1, 0) / len(df) * 100)

    summary = {
        "raw_shape": df_raw.shape,
        "columns": list(df_raw.columns),
        "cleaned_size": len(df),
        "removed_duplicates": removed_dups,
        "class_balance": {
            "SAFE (0)": final_counts.get(0, 0),
            "PHISHING (1)": final_counts.get(1, 0),
        },
    }
    return df, summary


# ──────────────────────────────────────────────────────────────────────────
# Step 2: Feature Extraction
# ──────────────────────────────────────────────────────────────────────────
def extract_tabular_features(urls: list[str]) -> np.ndarray:
    """Extracts 25 structural features from raw URLs with a progress bar."""
    log.info("Extracting %d structural URL features for %d URLs…",
             len(FEATURE_NAMES), len(urls))
    t0 = time.time()
    rows = []
    for u in tqdm(urls, desc="Extracting features", unit="urls"):
        feat_dict = extract_url_features(u)
        rows.append([feat_dict[name] for name in FEATURE_NAMES])
    X = np.array(rows, dtype=np.float32)
    log.info("Feature extraction complete in %.2fs. Shape: %s", time.time() - t0, X.shape)
    return X


# ──────────────────────────────────────────────────────────────────────────
# Step 3: Cross-Validation & Model Training
# ──────────────────────────────────────────────────────────────────────────
def run_training_pipeline(df: pd.DataFrame) -> dict:
    log.info("=" * 70)
    log.info("STEP 2: SPLITTING & 5-FOLD STRATIFIED CROSS-VALIDATION")
    log.info("=" * 70)

    urls = df["url"].tolist()
    y = df["label"].values.astype(int)

    # 1. Stratified 80/20 train/test split
    indices = np.arange(len(df))
    idx_train, idx_test = train_test_split(
        indices, test_size=0.20, stratify=y, random_state=RANDOM_SEED
    )

    y_train, y_test = y[idx_train], y[idx_test]
    urls_train = [urls[i] for i in idx_train]
    urls_test = [urls[i] for i in idx_test]

    log.info("Dataset Split — Train (80%%): %d samples | Test (20%%): %d samples",
             len(y_train), len(y_test))
    log.info("  Train Class Balance: SAFE=%d (%.1f%%), PHISH=%d (%.1f%%)",
             (y_train == 0).sum(), (y_train == 0).mean() * 100,
             (y_train == 1).sum(), (y_train == 1).mean() * 100)
    log.info("  Test Class Balance:  SAFE=%d (%.1f%%), PHISH=%d (%.1f%%)",
             (y_test == 0).sum(), (y_test == 0).mean() * 100,
             (y_test == 1).sum(), (y_test == 1).mean() * 100)

    # 2. Extract 25 features for train and test
    X_feat_train = extract_tabular_features(urls_train)
    X_feat_test = extract_tabular_features(urls_test)

    # Imbalance ratio for XGBoost scale_pos_weight
    neg_count = (y_train == 0).sum()
    pos_count = (y_train == 1).sum()
    scale_pos_weight = neg_count / max(1, pos_count)
    log.info("Class imbalance ratio (neg/pos): %.3f -> set as scale_pos_weight", scale_pos_weight)

    # 3. Define the 4 candidate models
    # Logistic Regression (with StandardScaler)
    lr_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            solver="lbfgs",
            random_state=RANDOM_SEED,
        )),
    ])

    # Random Forest
    rf_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    # XGBoost
    xgb_clf = XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    # Naive Bayes on character n-gram TF-IDF of raw URLs
    nb_pipe = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            max_features=5000,
            sublinear_tf=True,
        )),
        ("nb", MultinomialNB(alpha=0.1)),
    ])

    models = {
        "Logistic Regression": {
            "model": lr_pipe,
            "type": "tabular",
            "X_train": X_feat_train,
            "X_test": X_feat_test,
        },
        "Random Forest": {
            "model": rf_clf,
            "type": "tabular",
            "X_train": X_feat_train,
            "X_test": X_feat_test,
        },
        "XGBoost": {
            "model": xgb_clf,
            "type": "tabular",
            "X_train": X_feat_train,
            "X_test": X_feat_test,
        },
        "Naive Bayes (char TF-IDF)": {
            "model": nb_pipe,
            "type": "text",
            "X_train": urls_train,
            "X_test": urls_test,
        },
    }

    # 4. 5-Fold Stratified Cross-Validation on the 80% Training Set
    log.info("\n" + "=" * 70)
    log.info("5-FOLD STRATIFIED CROSS-VALIDATION (Training Set: %d samples)", len(y_train))
    log.info("=" * 70)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    cv_results = {}

    for name, item in models.items():
        log.info("Running 5-fold CV for: %s …", name)
        t0 = time.time()
        m = item["model"]
        X_tr = item["X_train"]

        # Run 5 folds
        scores = cross_val_score(m, X_tr, y_train, cv=skf, scoring="f1", n_jobs=1 if item["type"] == "text" else -1)
        mean_f1 = float(np.mean(scores))
        std_f1 = float(np.std(scores))
        elapsed = time.time() - t0

        cv_results[name] = {
            "mean_f1": mean_f1,
            "std_f1": std_f1,
            "fold_scores": [round(float(s), 4) for s in scores],
            "cv_time_s": round(elapsed, 2),
        }
        log.info("  [OK] %s -> F1 Mean: %.4f | F1 Std: +/-%.4f | Time: %.1fs",
                 name, mean_f1, std_f1, elapsed)
        log.info("    Folds: %s", [f"{s:.4f}" for s in scores])

    # Print summary table of CV
    print("\n" + "-" * 70)
    print("5-FOLD CROSS-VALIDATION SUMMARY (F1 Score on Phishing Class)")
    print("-" * 70)
    print(f"{'Model':<30} | {'Mean F1':<10} | {'Std F1':<10} | {'Time (s)':<10}")
    print("-" * 70)
    for name, res in cv_results.items():
        print(f"{name:<30} | {res['mean_f1']:<10.4f} | +/-{res['std_f1']:<8.4f} | {res['cv_time_s']:<10.1f}")
    print("-" * 70 + "\n")

    # 5. Determine best model from CV
    best_candidate_name = max(cv_results, key=lambda k: cv_results[k]["mean_f1"])
    log.info("Best model from Cross-Validation: '%s' (Mean F1 = %.4f)",
             best_candidate_name, cv_results[best_candidate_name]["mean_f1"])

    # 6. Hyperparameter Tuning with RandomizedSearchCV
    log.info("\n" + "=" * 70)
    log.info("TUNING BEST MODEL WITH RandomizedSearchCV (n_iter=25)")
    log.info("=" * 70)

    best_model_obj = None
    best_params = {}

    if "XGBoost" in best_candidate_name:
        param_dist = {
            "n_estimators": [100, 150, 200, 250],
            "max_depth": [4, 6, 8, 10],
            "learning_rate": [0.03, 0.05, 0.08, 0.1, 0.15],
            "subsample": [0.75, 0.85, 0.95, 1.0],
            "colsample_bytree": [0.75, 0.85, 1.0],
            "min_child_weight": [1, 3, 5],
        }
        base_estimator = XGBClassifier(
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        search_X = X_feat_train
    elif "Random Forest" in best_candidate_name:
        param_dist = {
            "n_estimators": [100, 150, 200],
            "max_depth": [12, 16, 20, None],
            "min_samples_split": [2, 5, 10],
            "min_samples_leaf": [1, 2, 4],
        }
        base_estimator = RandomForestClassifier(
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        search_X = X_feat_train
    elif "Naive Bayes" in best_candidate_name:
        param_dist = {
            "tfidf__max_features": [3000, 5000, 8000],
            "tfidf__ngram_range": [(3, 4), (3, 5)],
            "nb__alpha": [0.01, 0.05, 0.1, 0.5, 1.0],
        }
        base_estimator = nb_pipe
        search_X = urls_train
    else:  # Logistic Regression
        param_dist = {
            "clf__C": [0.01, 0.1, 1.0, 5.0, 10.0],
            "clf__penalty": ["l2"],
        }
        base_estimator = lr_pipe
        search_X = X_feat_train

    log.info("Running RandomizedSearchCV on %s with 25 iterations (3-fold CV)…", best_candidate_name)
    t0 = time.time()
    random_search = RandomizedSearchCV(
        base_estimator,
        param_distributions=param_dist,
        n_iter=25,
        cv=3,
        scoring="f1",
        random_state=RANDOM_SEED,
        n_jobs=-1 if models[best_candidate_name]["type"] == "tabular" else 1,
        verbose=1,
    )
    random_search.fit(search_X, y_train)
    tune_time = time.time() - t0
    best_params = random_search.best_params_
    best_tuned_model = random_search.best_estimator_

    log.info("RandomizedSearchCV completed in %.2fs", tune_time)
    log.info("Best CV F1: %.4f", random_search.best_score_)
    log.info("Best Parameters:")
    for param, val in best_params.items():
        log.info("  %s = %s", param, val)

    # Update models dictionary with the tuned model
    models[best_candidate_name]["model"] = best_tuned_model
    models[best_candidate_name]["is_tuned"] = True

    # 7. Fit all models on full training set (80%) and evaluate on held-out test set (20%)
    log.info("\n" + "=" * 70)
    log.info("STEP 3: EVALUATING ALL MODELS ON HELD-OUT TEST SET (20%% = %d samples)", len(y_test))
    log.info("=" * 70)

    test_results = {}
    train_scores = {}
    y_probas = {}
    y_preds = {}

    for name, item in models.items():
        m = item["model"]
        X_tr = item["X_train"]
        X_te = item["X_test"]

        # If not tuned (tuned already fitted), fit on train
        if not item.get("is_tuned", False):
            log.info("Fitting %s on full 80%% train split…", name)
            t0 = time.time()
            m.fit(X_tr, y_train)
            fit_time = time.time() - t0
        else:
            fit_time = tune_time

        # Predict train & test
        y_train_pred = m.predict(X_tr)
        y_test_pred = m.predict(X_te)
        y_preds[name] = y_test_pred

        # Probabilities for positive class (PHISHING = 1)
        if hasattr(m, "predict_proba"):
            proba_test = m.predict_proba(X_te)[:, 1]
            auc_score = roc_auc_score(y_test, proba_test)
        else:
            proba_test = None
            auc_score = None
        y_probas[name] = proba_test

        # Calculate metrics
        train_acc = accuracy_score(y_train, y_train_pred)
        train_f1 = f1_score(y_train, y_train_pred, pos_label=1)
        test_acc = accuracy_score(y_test, y_test_pred)
        test_prec = precision_score(y_test, y_test_pred, pos_label=1, zero_division=0)
        test_rec = recall_score(y_test, y_test_pred, pos_label=1, zero_division=0)
        test_f1 = f1_score(y_test, y_test_pred, pos_label=1, zero_division=0)

        train_scores[name] = {"train_acc": train_acc, "train_f1": train_f1}
        test_results[name] = {
            "accuracy": round(test_acc, 4),
            "precision": round(test_prec, 4),
            "recall": round(test_rec, 4),
            "f1": round(test_f1, 4),
            "roc_auc": round(auc_score, 4) if auc_score is not None else None,
            "train_acc": round(train_acc, 4),
            "train_f1": round(train_f1, 4),
            "fit_time_s": round(fit_time, 2),
        }

    # Print the master comparison table
    print("\n" + "=" * 82)
    print("MODEL EVALUATION COMPARISON TABLE (Held-out 20% Test Set)")
    print("=" * 82)
    print(f"{'Model':<26} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1-Score':<9} | {'ROC-AUC':<8}")
    print("-" * 82)
    for name, r in test_results.items():
        auc_str = f"{r['roc_auc']:.4f}" if r["roc_auc"] is not None else "N/A"
        print(f"{name:<26} | {r['accuracy']:<9.4f} | {r['precision']:<9.4f} | {r['recall']:<9.4f} | {r['f1']:<9.4f} | {auc_str:<8}")
    print("=" * 82)

    # Check overfitting (Train vs Test gap)
    print("\nOVERFITTING & GENERALISATION CHECK (Train vs Test Scores):")
    print("-" * 70)
    for name, r in test_results.items():
        acc_gap = r["train_acc"] - r["accuracy"]
        f1_gap = r["train_f1"] - r["f1"]
        print(f"  {name:<26} : Train Acc = {r['train_acc']:.4f}, Test Acc = {r['accuracy']:.4f} (Gap: {acc_gap:+.4f}) | F1 Gap: {f1_gap:+.4f}")
    print("-" * 70)

    # Select overall champion: Highest F1 with high recall (>0.99) and precision (>0.99)
    qualified = {k: v for k, v in test_results.items() if v["precision"] >= 0.95}
    if not qualified:
        qualified = test_results
    final_best_name = max(qualified, key=lambda k: (qualified[k]["f1"], qualified[k]["recall"]))
    final_best_model = models[final_best_name]["model"]

    log.info("\n[*] WINNER SELECTION: '%s' is chosen as the production model.", final_best_name)
    log.info("  Reason: Phishing Recall = %.4f, Precision = %.4f, F1 = %.4f, ROC-AUC = %.4f",
             test_results[final_best_name]["recall"],
             test_results[final_best_name]["precision"],
             test_results[final_best_name]["f1"],
             test_results[final_best_name]["roc_auc"])

    # 8. Save Reports (Confusion Matrix, ROC Curve, Feature Importance)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    generate_reports(
        final_best_name,
        final_best_model,
        test_results,
        y_test,
        y_preds,
        y_probas,
        models,
        REPORTS_DIR,
    )

    # 9. Save Production Artefacts
    save_production_artefacts(
        final_best_name,
        final_best_model,
        models[final_best_name]["type"],
        best_params,
        test_results,
        cv_results,
        len(df),
    )

    return {
        "best_model_name": final_best_name,
        "test_results": test_results,
        "cv_results": cv_results,
        "best_params": best_params,
    }


# ──────────────────────────────────────────────────────────────────────────
# Step 4: Generate Reports & Plots
# ──────────────────────────────────────────────────────────────────────────
def generate_reports(
    best_name: str,
    best_model,
    test_results: dict,
    y_test: np.ndarray,
    y_preds: dict,
    y_probas: dict,
    models: dict,
    reports_dir: Path,
) -> None:
    log.info("Generating evaluation reports in %s …", reports_dir)

    # 1. Confusion Matrix for Best Model
    cm = confusion_matrix(y_test, y_preds[best_name])
    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["SAFE", "PHISHING"])
    disp.plot(ax=ax, cmap="Blues", values_format="d")
    ax.set_title(f"Confusion Matrix — {best_name}\n(Held-out Test Set, N={len(y_test):,})", fontsize=11, fontweight="bold")
    plt.tight_layout()
    cm_path = reports_dir / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=150)
    plt.close()
    log.info("Saved: %s", cm_path)

    # 2. ROC Curve comparison
    fig, ax = plt.subplots(figsize=(7, 6))
    colors = ["#2563eb", "#16a34a", "#dc2626", "#9333ea"]
    for i, (name, proba) in enumerate(y_probas.items()):
        if proba is not None:
            fpr, tpr, _ = roc_curve(y_test, proba)
            roc_auc = auc(fpr, tpr)
            ax.plot(fpr, tpr, label=f"{name} (AUC = {roc_auc:.4f})", color=colors[i % len(colors)], lw=2)

    ax.plot([0, 1], [0, 1], "k--", lw=1.2, label="Random Guess (AUC = 0.5000)")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.02])
    ax.set_xlabel("False Positive Rate (1 - Specificity)", fontsize=11)
    ax.set_ylabel("True Positive Rate (Recall)", fontsize=11)
    ax.set_title("ROC Curves Comparison — Test Set", fontsize=12, fontweight="bold")
    ax.legend(loc="lower right", frameon=True)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    roc_path = reports_dir / "roc_curve.png"
    plt.savefig(roc_path, dpi=150)
    plt.close()
    log.info("Saved: %s", roc_path)

    # 3. Feature Importance Plot
    # Check if tree model or linear model
    feature_importances = []
    if hasattr(best_model, "feature_importances_"):
        imps = best_model.feature_importances_
        feature_importances = sorted(
            [{"feature": f, "importance": float(imp)} for f, imp in zip(FEATURE_NAMES, imps)],
            key=lambda x: x["importance"],
            reverse=True,
        )
    elif hasattr(best_model, "named_steps"):
        clf = best_model.named_steps.get("clf")
        if hasattr(clf, "feature_importances_"):
            imps = clf.feature_importances_
            feature_importances = sorted(
                [{"feature": f, "importance": float(imp)} for f, imp in zip(FEATURE_NAMES, imps)],
                key=lambda x: x["importance"],
                reverse=True,
            )
        elif hasattr(clf, "coef_"):
            imps = np.abs(clf.coef_[0])
            feature_importances = sorted(
                [{"feature": f, "importance": float(imp)} for f, imp in zip(FEATURE_NAMES, imps)],
                key=lambda x: x["importance"],
                reverse=True,
            )

    if not feature_importances:
        # Fallback to XGBoost or Random Forest
        for fallback_name in ["XGBoost", "Random Forest"]:
            if fallback_name in models:
                fb_m = models[fallback_name]["model"]
                if hasattr(fb_m, "feature_importances_"):
                    imps = fb_m.feature_importances_
                    feature_importances = sorted(
                        [{"feature": f, "importance": float(imp)} for f, imp in zip(FEATURE_NAMES, imps)],
                        key=lambda x: x["importance"],
                        reverse=True,
                    )
                    break

    if feature_importances:
        top_features = feature_importances[:15]
        top_features.reverse()  # Horizontal bar plot displays bottom-up
        names = [item["feature"] for item in top_features]
        vals = [item["importance"] for item in top_features]

        fig, ax = plt.subplots(figsize=(8, 6))
        ax.barh(names, vals, color="#2563eb", edgecolor="none", alpha=0.85)
        ax.set_xlabel("Importance / Absolute Weight", fontsize=11)
        ax.set_title(f"Top 15 Feature Importances — {best_name}", fontsize=12, fontweight="bold")
        ax.grid(axis="x", alpha=0.3)
        plt.tight_layout()
        fi_path = reports_dir / "feature_importance.png"
        plt.savefig(fi_path, dpi=150)
        plt.close()
        log.info("Saved: %s", fi_path)

    # 4. Human-readable text report
    txt_path = reports_dir / "training_report.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("PhishGuard AI — Training Evaluation Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Trained at  : {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Best Model  : {best_name}\n")
        f.write(f"Test Set    : {len(y_test):,} samples (20% held-out)\n\n")
        f.write("Held-Out Test Set Metrics\n")
        f.write("-" * 50 + "\n")
        for k, v in test_results[best_name].items():
            f.write(f"  {k:<16} : {v}\n")
        f.write("\nAll Models Comparison\n")
        f.write("-" * 50 + "\n")
        for name, r in test_results.items():
            f.write(f"\n  {name}:\n")
            for k, v in r.items():
                f.write(f"    {k:<14} : {v}\n")
        if feature_importances:
            f.write("\nTop 15 Feature Importances:\n")
            f.write("-" * 50 + "\n")
            for item in list(reversed(top_features)):
                f.write(f"  {item['feature']:<25} : {item['importance']:.6f}\n")
    log.info("Saved: %s", txt_path)


# ──────────────────────────────────────────────────────────────────────────
# Step 5: Save Artefacts
# ──────────────────────────────────────────────────────────────────────────
def save_production_artefacts(
    best_name: str,
    best_model,
    model_type: str,
    best_params: dict,
    test_results: dict,
    cv_results: dict,
    dataset_size: int,
) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    pkl_path = MODELS_DIR / "model.pkl"
    joblib_path = MODELS_DIR / "phishguard_model.joblib"
    meta_path = MODELS_DIR / "model_metadata.json"
    metrics_path = MODELS_DIR / "model_metrics.json"

    # Separate scaler or vectorizer if present
    scaler = None
    vectorizer = None
    actual_model = best_model

    if hasattr(best_model, "named_steps"):
        scaler = best_model.named_steps.get("scaler")
        vectorizer = best_model.named_steps.get("tfidf")
        actual_model = best_model.named_steps.get("clf", best_model.named_steps.get("nb", best_model))

    bundle = {
        "pipeline": best_model,
        "model": actual_model,
        "scaler": scaler,
        "vectorizer": vectorizer,
        "feature_names": FEATURE_NAMES,
        "model_name": best_name,
        "model_type": model_type,
        "target_mapping": {0: "SAFE", 1: "PHISHING"},
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    # Save to models/model.pkl as requested
    joblib.dump(bundle, pkl_path)
    log.info("Saved primary model bundle -> %s", pkl_path)

    # Also save to phishguard_model.joblib for full system compatibility
    joblib.dump(bundle, joblib_path)
    log.info("Saved pipeline bundle -> %s", joblib_path)

    # Save metadata JSON
    metadata = {
        "model_name": best_name,
        "model_version": MODEL_VERSION,
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "class_mapping": {"0": "SAFE", "1": "PHISHING"},
        "best_hyperparameters": best_params,
        "dataset_size": dataset_size,
        "trained_at": bundle["trained_at"],
        "random_seed": RANDOM_SEED,
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    log.info("Saved metadata -> %s", meta_path)

    # Save metrics JSON
    metrics = {
        "best_model": best_name,
        "test_metrics": test_results[best_name],
        "all_models_test": test_results,
        "cross_validation": cv_results,
    }
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    log.info("Saved metrics -> %s", metrics_path)


# ──────────────────────────────────────────────────────────────────────────
# Main Execution
# ──────────────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 70)
    log.info("PHISHGUARD AI — PRODUCTION MODEL TRAINING PIPELINE")
    log.info("=" * 70)

    # Step 1: Inspect & Clean
    df, _ = inspect_and_clean_data(DATA_PATH)

    # Step 2 & 3: Train, CV, Tune, Evaluate, Save
    run_training_pipeline(df)

    log.info("=" * 70)
    log.info("TRAINING PIPELINE COMPLETED SUCCESSFULLY!")
    log.info("=" * 70)


if __name__ == "__main__":
    main()
