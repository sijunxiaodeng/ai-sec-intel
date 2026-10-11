"""Separate runtime data roots for formal deployment and the local demo."""
import os
from pathlib import Path

DATA_ROOT = Path(os.environ.get("MAIN_DATA_DIR") or
                 Path(__file__).resolve().parent.parent / "data").resolve()
