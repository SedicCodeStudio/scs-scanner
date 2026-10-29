#!/usr/bin/env python3
"""SCS Scanner – launcher. Without arguments the user interface opens; “python scs.py -h” lists the commands."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scs.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
