#!/usr/bin/python3

"""
HiveEx - Forensic Hive Extraction Tool (CLI only)
"""

import sys
from pathlib import Path

# Add src/main to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src' / 'main'))

# CLI only - direct execution
from main import main as cli_main

if __name__ == '__main__':
    cli_main()
