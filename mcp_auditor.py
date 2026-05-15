#!/usr/bin/env python3
"""Legacy CLI wrapper for backward compatibility."""

import sys
from mcp_security_auditor.cli import main

if __name__ == "__main__":
    sys.exit(main())