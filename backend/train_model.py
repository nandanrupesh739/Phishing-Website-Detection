"""
PhishGuard AI — Legacy Trainer Wrapper
=======================================
Delegates to the canonical production training pipeline in train.py.
Please invoke:
    python train.py
"""
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import train


def main():
    print("[*] backend/train_model.py is delegating to train.py...")
    train.main()


if __name__ == "__main__":
    main()
