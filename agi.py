#!/usr/bin/env python
"""
AGI CLI Launcher
Allows running CLI from root directory
"""

import sys
import os

# Add src folder to path so we can import the CLI
src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

# Import and run the CLI
from agi_cli import cli

if __name__ == '__main__':
    cli()
