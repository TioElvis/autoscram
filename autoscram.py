#!/usr/bin/env python3
"""AUTOSCRAM entrypoint. Usage: python3 autoscram.py ./binary [options]"""
import sys
import warnings

warnings.filterwarnings('ignore', category=BytesWarning)

from autoscram.cli import main

if __name__ == "__main__":
    sys.exit(main())
