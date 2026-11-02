"""Test bootstrap: the offline guard is installed before anything else is imported (see tools/offline_guard.py)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for entry in (str(ROOT), str(ROOT / "src")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from tools import offline_guard as _offline_guard  # noqa: E402

_offline_guard.install()
pytest_plugins = ["tools.offline_guard"]
