"""Pytest configuration and shared fixtures."""

import sys
from pathlib import Path
import pytest

# Ensure src directory is available on sys.path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
