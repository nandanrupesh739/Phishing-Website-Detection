"""
PhishGuard AI — System E2E Test Wrapper
=======================================
Delegates to canonical live HTTP smoke test in scripts/e2e_smoke.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.e2e_smoke import main

if __name__ == "__main__":
    main()
