#!/usr/bin/env python3
"""Convenience entry point to run the mock MCP server."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from tests.mock_server import main

if __name__ == "__main__":
    main()