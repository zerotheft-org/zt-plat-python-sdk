from __future__ import annotations

import sys
from pathlib import Path

# Ensure local src layout is importable when running pytest from python/common.
SRC_PATH = Path(__file__).resolve().parents[2] / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))
