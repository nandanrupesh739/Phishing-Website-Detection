"""
PhishGuard AI — Dataset Downloader
===================================
Fetches the PhiUSIIL Phishing URL Dataset (UCI ML Repository ID: 967)
and saves it to data/phishing_dataset.csv with original labels:
- 1 = Legitimate (Safe)
- 0 = Phishing

Usage:
    python download_data.py
"""

import os

from ucimlrepo import fetch_ucirepo


def download_phiusiil_dataset():
    os.makedirs("data", exist_ok=True)
    target_csv = os.path.join("data", "phishing_dataset.csv")

    print("[*] Fetching PhiUSIIL dataset from UCI ML Repository (ID: 967)...")
    dataset = fetch_ucirepo(id=967)
    df = dataset.data.original

    print(f"[*] Saving {len(df):,} rows to {target_csv}...")
    df.to_csv(target_csv, index=False)

    print(f"[OK] Download complete. Dataset shape: {df.shape}")
    print("[*] Label distribution (Original UCI convention: 1=Legitimate, 0=Phishing):")
    print(df["label"].value_counts().to_string())


if __name__ == "__main__":
    download_phiusiil_dataset()
