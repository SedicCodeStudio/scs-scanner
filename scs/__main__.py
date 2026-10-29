"""Allows “python -m scs” and the single-file version “python scs.pyz”."""
import sys

from scs.cli import main

sys.exit(main())
