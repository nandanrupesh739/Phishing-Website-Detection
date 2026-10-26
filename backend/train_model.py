"""
PhishGuard AI — Model Training Pipeline
=========================================
Trains multiple classifiers on the PhiUSIIL Phishing URL Dataset,
selects the best model based on validation F1-score (phishing class),
evaluates on the held-out test set, and saves artefacts.

Usage
-----
    python -m backend.train_model

Prerequisites
-------------
  1. Download the dataset from https://archive.ics.uci.edu/dataset/967/
  2. Place the CSV in data/ (or configure DATA_PATH in backend/config.py)
  3. Activate the virtual environment and install requirements.txt
"""

from __future__ import annotations

import json
import logging
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")  # non-interactive backend for headless environments
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import (
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    PrecisionRecallDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score,
)
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Add project root to path so relative imports work when running as __main__
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import (
    DATA_PATH,
    METRICS_PATH,
    METADATA_PATH,
    MODEL_PATH,
    MODEL_VERSION,
    MODELS_DIR,
    RANDOM_SEED,
    REPORTS_DIR,
    TRAIN_SIZE,
    VAL_SIZE,
    TEST_SIZE,
)
from backend.features import FEATURE_NAMES, extract_url_features

# ──────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(
            stream=open(sys.stdout.fileno(), mode='w', encoding='utf-8', closefd=False)
        )
    ],
)
log = logging.getLogger(__name__)

warnings.filterwarnings("ignore", category=UserWarning)

# ──────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────
# Candidate URL column names from the dataset (checked in order)
URL_COLUMN_CANDIDATES = ["url", "URL", "Url", "URLID", "urlString"]
# Candidate label column names
LABEL_COLUMN_CANDIDATES = ["label", "Label", "LABEL", "phish", "class", "Class"]

# Label mapping: in PhiUSIIL dataset 1 = legitimate, 0 = phishing
# We keep this mapping: 0 = phishing (threat), 1 = legitimate (safe)
LABEL_MAP = {0: 0, 1: 1, -1: 0}  # -1 is sometimes used for phishing

CLASS_NAMES = {0: "Phishing", 1: "Legitimate"}


# ──────────────────────────────────────────────────────────────────────────
# Step 1 — Load dataset
# ──────────────────────────────────────────────────────────────────────────

def load_dataset(path: Path) -> pd.DataFrame:
    log.info("Loading dataset from: %s", path)
    if not path.exists():
        log.error(
            "Dataset not found at '%s'.\n"
            "Please download the PhiUSIIL dataset from:\n"
            "  https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset\n"
            "and place the CSV in the data/ directory as 'phishing_dataset.csv'.",
            path,
        )
        sys.exit(1)

    try:
        df = pd.read_csv(path, low_memory=False)
    except Exception as exc:
        log.error("Failed to read CSV: %s", exc)
        sys.exit(1)

    log.info("Raw dataset shape: %s", df.shape)
    log.info("Columns: %s", list(df.columns))
    return df


def identify_columns(df: pd.DataFrame) -> tuple[str, str]:
    """Identify the URL column and label column by checking known candidates."""
    url_col = next(
        (c for c in URL_COLUMN_CANDIDATES if c in df.columns), None
    )
    label_col = next(
        (c for c in LABEL_COLUMN_CANDIDATES if c in df.columns), None
    )

    if url_col is None:
        # Fallback: look for a column containing mostly string values that look like URLs
        for col in df.columns:
            sample = df[col].dropna().astype(str).head(20)
            if sample.str.contains(r"https?://|www\.", regex=True).sum() > 10:
                url_col = col
                log.warning("Inferred URL column as '%s'", url_col)
                break

    if label_col is None:
        # Fallback: look for a binary integer column
        for col in df.columns:
            unique = df[col].dropna().unique()
            if set(unique).issubset({0, 1, -1, "0", "1", "-1"}):
                label_col = col
                log.warning("Inferred label column as '%s'", label_col)
                break

    if url_col is None or label_col is None:
        log.error(
            "Could not identify URL column or label column.\n"
            "URL candidates checked: %s\nLabel candidates checked: %s\n"
            "Actual columns: %s",
            URL_COLUMN_CANDIDATES,
            LABEL_COLUMN_CANDIDATES,
            list(df.columns),
        )
        sys.exit(1)

    log.info("URL column: '%s' | Label column: '%s'", url_col, label_col)
    return url_col, label_col


# ──────────────────────────────────────────────────────────────────────────
# Step 2 — Clean & validate
# ──────────────────────────────────────────────────────────────────────────

def clean_dataset(df: pd.DataFrame, url_col: str, label_col: str) -> pd.DataFrame:
    initial = len(df)

    # Keep only needed columns
    df = df[[url_col, label_col]].copy()
    df = df.rename(columns={url_col: "url", label_col: "label"})

    # Drop rows with missing URL or label
    df = df.dropna(subset=["url", "label"])

    # Ensure URL is a string; drop empties
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() > 0]
    df = df[df["url"] != "nan"]

    # Map labels to {0, 1}
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int).map(LABEL_MAP)
    df = df.dropna(subset=["label"])  # drop unmappable labels
    df["label"] = df["label"].astype(int)

    # Remove duplicates (same URL -> keep first occurrence)
    df = df.drop_duplicates(subset=["url"], keep="first")

    final = len(df)
    log.info(
        "Cleaning: %d rows → %d rows (removed %d)",
        initial, final, initial - final,
    )

    log.info("Label distribution:\n%s", df["label"].value_counts().to_string())
    return df.reset_index(drop=True)


# ──────────────────────────────────────────────────────────────────────────
# Step 3 — Feature extraction
# ──────────────────────────────────────────────────────────────────────────

def extract_features(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    log.info("Extracting features for %d URLs (this may take a few minutes)…", len(df))
    t0 = time.time()

    rows = []
    for url in df["url"]:
        feat_dict = extract_url_features(url)
        rows.append([feat_dict[name] for name in FEATURE_NAMES])

    X = np.array(rows, dtype=np.float64)
    y = df["label"].values.astype(int)

    elapsed = time.time() - t0
    log.info(
        "Feature extraction complete: shape=%s in %.1fs", X.shape, elapsed
    )
    return X, y


# ──────────────────────────────────────────────────────────────────────────
# Step 4 — Train/val/test split
# ──────────────────────────────────────────────────────────────────────────

def split_data(
    X: np.ndarray, y: np.ndarray
) -> tuple[np.ndarray, ...]:
    """
    Stratified 70/15/15 split.
    Returns X_train, X_val, X_test, y_train, y_val, y_test
    """
    # First split: train vs (val + test)
    splitter1 = StratifiedShuffleSplit(
        n_splits=1, test_size=(VAL_SIZE + TEST_SIZE), random_state=RANDOM_SEED
    )
    idx_train, idx_temp = next(splitter1.split(X, y))
    X_train, X_temp = X[idx_train], X[idx_temp]
    y_train, y_temp = y[idx_train], y[idx_temp]

    # Second split: val vs test (equal halves of the temp set)
    val_frac = VAL_SIZE / (VAL_SIZE + TEST_SIZE)
    splitter2 = StratifiedShuffleSplit(
        n_splits=1, test_size=(1 - val_frac), random_state=RANDOM_SEED
    )
    idx_val, idx_test = next(splitter2.split(X_temp, y_temp))
    X_val, X_test = X_temp[idx_val], X_temp[idx_test]
    y_val, y_test = y_temp[idx_val], y_temp[idx_test]

    log.info(
        "Split sizes — Train: %d | Val: %d | Test: %d",
        len(y_train), len(y_val), len(y_test),
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


# ──────────────────────────────────────────────────────────────────────────
# Step 5 — Model definitions
# ──────────────────────────────────────────────────────────────────────────

def build_pipelines() -> dict[str, Pipeline]:
    """Return named sklearn Pipelines for comparison."""
    pipelines = {
        "Logistic Regression": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=1000,
                        class_weight="balanced",
                        random_state=RANDOM_SEED,
                        solver="lbfgs",
                        C=1.0,
                    ),
                ),
            ]
        ),
        "Random Forest": Pipeline(
            [
                (
                    "clf",
                    RandomForestClassifier(
                        n_estimators=200,
                        class_weight="balanced",
                        random_state=RANDOM_SEED,
                        n_jobs=-1,
                        max_depth=None,
                        min_samples_leaf=2,
                    ),
                )
            ]
        ),
        "HistGradientBoosting": Pipeline(
            [
                (
                    "clf",
                    HistGradientBoostingClassifier(
                        max_iter=300,
                        learning_rate=0.05,
                        max_depth=8,
                        random_state=RANDOM_SEED,
                        class_weight="balanced",
                    ),
                )
            ]
        ),
    }
    return pipelines


# ──────────────────────────────────────────────────────────────────────────
# Step 6 — Train and compare on validation set
# ──────────────────────────────────────────────────────────────────────────

def train_and_compare(
    pipelines: dict[str, Pipeline],
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
) -> tuple[str, Pipeline, dict]:
    """
    Fit each pipeline on training data; evaluate on validation set.
    Model selection criterion: phishing-class F1-score (label 0).
    Returns best model name, best pipeline, comparison summary dict.
    """
    comparison: dict[str, dict] = {}

    for name, pipe in pipelines.items():
        log.info("Training: %s …", name)
        t0 = time.time()
        pipe.fit(X_train, y_train)
        elapsed = time.time() - t0

        y_pred = pipe.predict(X_val)
        acc = accuracy_score(y_val, y_pred)
        prec_phish = precision_score(y_val, y_pred, pos_label=0, zero_division=0)
        rec_phish = recall_score(y_val, y_pred, pos_label=0, zero_division=0)
        f1_phish = f1_score(y_val, y_pred, pos_label=0, zero_division=0)
        f1_macro = f1_score(y_val, y_pred, average="macro", zero_division=0)

        # ROC-AUC if probability supported
        try:
            proba = pipe.predict_proba(X_val)[:, 0]  # prob of phishing
            auc = roc_auc_score(y_val, proba, pos_label=0)  # type: ignore[arg-type]
        except Exception:
            auc = None

        comparison[name] = {
            "accuracy": round(acc, 4),
            "phishing_precision": round(prec_phish, 4),
            "phishing_recall": round(rec_phish, 4),
            "phishing_f1": round(f1_phish, 4),
            "macro_f1": round(f1_macro, 4),
            "roc_auc": round(auc, 4) if auc is not None else None,
            "train_time_s": round(elapsed, 1),
        }

        log.info(
            "  %s → Phishing F1=%.4f | Recall=%.4f | Macro F1=%.4f | AUC=%s | Time=%.1fs",
            name, f1_phish, rec_phish, f1_macro,
            f"{auc:.4f}" if auc is not None else "N/A",
            elapsed,
        )

    # Select best by phishing F1
    best_name = max(comparison, key=lambda k: comparison[k]["phishing_f1"])
    log.info("Best model (validation phishing F1): %s", best_name)
    return best_name, pipelines[best_name], comparison


# ──────────────────────────────────────────────────────────────────────────
# Step 7 — Final test evaluation
# ──────────────────────────────────────────────────────────────────────────

def evaluate_on_test(
    pipe: Pipeline,
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_name: str,
) -> dict:
    log.info("Evaluating %s on held-out test set …", model_name)
    y_pred = pipe.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test, y_pred,
        target_names=["Phishing", "Legitimate"],
        output_dict=True,
    )
    cm = confusion_matrix(y_test, y_pred)

    metrics: dict = {
        "model_name": model_name,
        "test_accuracy": round(acc, 4),
        "phishing_precision": round(report["Phishing"]["precision"], 4),
        "phishing_recall": round(report["Phishing"]["recall"], 4),
        "phishing_f1": round(report["Phishing"]["f1-score"], 4),
        "legitimate_precision": round(report["Legitimate"]["precision"], 4),
        "legitimate_recall": round(report["Legitimate"]["recall"], 4),
        "legitimate_f1": round(report["Legitimate"]["f1-score"], 4),
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "weighted_f1": round(report["weighted avg"]["f1-score"], 4),
        "confusion_matrix": cm.tolist(),
    }

    # ROC-AUC
    try:
        proba = pipe.predict_proba(X_test)[:, 1]  # prob of legitimate
        auc = roc_auc_score(y_test, proba)
        avg_prec = average_precision_score(y_test, proba)
        metrics["roc_auc"] = round(float(auc), 4)
        metrics["average_precision"] = round(float(avg_prec), 4)
    except Exception:
        metrics["roc_auc"] = None
        metrics["average_precision"] = None

    log.info(
        "Test results — Accuracy=%.4f | Phishing F1=%.4f | Recall=%.4f | AUC=%s",
        acc,
        report["Phishing"]["f1-score"],
        report["Phishing"]["recall"],
        f"{metrics['roc_auc']:.4f}" if metrics["roc_auc"] else "N/A",
    )
    log.info("\n%s", classification_report(y_test, y_pred, target_names=["Phishing", "Legitimate"]))
    return metrics


# ──────────────────────────────────────────────────────────────────────────
# Step 8 — Feature importance
# ──────────────────────────────────────────────────────────────────────────

def extract_feature_importance(pipe: Pipeline, model_name: str) -> list[dict]:
    """Return sorted feature importances where supported."""
    clf = pipe.named_steps.get("clf")
    importances: list[float] | None = None

    if hasattr(clf, "feature_importances_"):
        importances = list(clf.feature_importances_)
    elif hasattr(clf, "coef_"):
        importances = list(np.abs(clf.coef_[0]))

    if importances is None:
        return []

    result = [
        {"feature": name, "importance": round(float(imp), 6)}
        for name, imp in zip(FEATURE_NAMES, importances)
    ]
    result.sort(key=lambda x: x["importance"], reverse=True)
    return result


# ──────────────────────────────────────────────────────────────────────────
# Step 9 — Plotting
# ──────────────────────────────────────────────────────────────────────────

def plot_confusion_matrix(cm: list[list[int]], report_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(
        confusion_matrix=np.array(cm),
        display_labels=["Phishing", "Legitimate"],
    )
    disp.plot(ax=ax, cmap="Blues", colorbar=False)
    ax.set_title("Confusion Matrix — Test Set", fontsize=13)
    plt.tight_layout()
    out = report_dir / "confusion_matrix.png"
    plt.savefig(out, dpi=150)
    plt.close()
    log.info("Saved confusion matrix → %s", out)


def plot_precision_recall(
    pipe: Pipeline,
    X_test: np.ndarray,
    y_test: np.ndarray,
    report_dir: Path,
) -> None:
    try:
        proba = pipe.predict_proba(X_test)[:, 1]
    except Exception:
        log.warning("Precision-recall plot skipped (predict_proba unavailable).")
        return

    fig, ax = plt.subplots(figsize=(7, 5))
    PrecisionRecallDisplay.from_predictions(
        y_test, proba, ax=ax, name="PhishGuard AI"
    )
    ax.set_title("Precision-Recall Curve — Test Set", fontsize=13)
    plt.tight_layout()
    out = report_dir / "precision_recall_curve.png"
    plt.savefig(out, dpi=150)
    plt.close()
    log.info("Saved precision-recall curve → %s", out)


def plot_feature_importance(importances: list[dict], report_dir: Path) -> None:
    if not importances:
        return
    top_n = importances[:15]
    labels = [d["feature"] for d in top_n]
    values = [d["importance"] for d in top_n]

    fig, ax = plt.subplots(figsize=(8, 6))
    sns.barplot(x=values, y=labels, orient="h", hue=labels, palette="Blues_r", legend=False, ax=ax)
    ax.set_xlabel("Importance")
    ax.set_title("Top 15 Feature Importances", fontsize=13)
    plt.tight_layout()
    out = report_dir / "feature_importance.png"
    plt.savefig(out, dpi=150)
    plt.close()
    log.info("Saved feature importance plot → %s", out)


def plot_model_comparison(comparison: dict[str, dict], report_dir: Path) -> None:
    names = list(comparison.keys())
    metrics_to_plot = ["phishing_f1", "phishing_recall", "accuracy"]
    data = {m: [comparison[n].get(m, 0) or 0 for n in names] for m in metrics_to_plot}

    x = np.arange(len(names))
    width = 0.25
    fig, ax = plt.subplots(figsize=(9, 5))
    for i, (metric, vals) in enumerate(data.items()):
        ax.bar(x + i * width, vals, width, label=metric.replace("_", " ").title())

    ax.set_xticks(x + width)
    ax.set_xticklabels(names, rotation=10)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison — Validation Set", fontsize=13)
    ax.legend()
    plt.tight_layout()
    out = report_dir / "model_comparison.png"
    plt.savefig(out, dpi=150)
    plt.close()
    log.info("Saved model comparison chart → %s", out)


# ──────────────────────────────────────────────────────────────────────────
# Step 10 — Save artefacts
# ──────────────────────────────────────────────────────────────────────────

def save_artefacts(
    pipe: Pipeline,
    metrics: dict,
    comparison: dict,
    importances: list[dict],
    dataset_size: int,
    label_dist: dict,
    model_name: str,
) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Save model
    joblib.dump(pipe, MODEL_PATH)
    log.info("Saved model → %s", MODEL_PATH)

    # Metadata
    metadata = {
        "model_name": model_name,
        "model_version": MODEL_VERSION,
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "class_mapping": {"0": "Phishing", "1": "Legitimate"},
        "dataset_source": "PhiUSIIL Phishing URL Dataset — UCI ML Repository",
        "dataset_size": dataset_size,
        "label_distribution": label_dist,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
    }
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    log.info("Saved metadata → %s", METADATA_PATH)

    # Full metrics (test + comparison)
    full_metrics = {
        "test_metrics": metrics,
        "validation_comparison": comparison,
        "feature_importances": importances,
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(full_metrics, f, indent=2)
    log.info("Saved metrics → %s", METRICS_PATH)

    # Human-readable report
    report_path = REPORTS_DIR / "training_report.txt"
    with open(report_path, "w") as f:
        f.write("PhishGuard AI — Training Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Trained at : {metadata['trained_at']}\n")
        f.write(f"Model      : {model_name}\n")
        f.write(f"Version    : {MODEL_VERSION}\n")
        f.write(f"Dataset    : {dataset_size:,} URLs\n")
        f.write(f"Features   : {len(FEATURE_NAMES)}\n\n")
        f.write("Test Set Metrics\n")
        f.write("-" * 40 + "\n")
        for k, v in metrics.items():
            if k not in ("confusion_matrix", "model_name"):
                f.write(f"  {k}: {v}\n")
        f.write("\nValidation Model Comparison\n")
        f.write("-" * 40 + "\n")
        for name, vals in comparison.items():
            f.write(f"\n  {name}:\n")
            for k, v in vals.items():
                f.write(f"    {k}: {v}\n")
        f.write("\nTop Feature Importances\n")
        f.write("-" * 40 + "\n")
        for item in importances[:15]:
            f.write(f"  {item['feature']}: {item['importance']:.6f}\n")
    log.info("Saved training report → %s", report_path)


# ──────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Forward entrypoint to primary training pipeline in train.py."""
    import train
    train.main()


if __name__ == "__main__":
    main()
