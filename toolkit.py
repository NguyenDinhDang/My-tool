#!/usr/bin/env python
"""Security Automation Toolkit CLI launcher."""

import sys
import os

src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

from toolkit_cli import cli

if __name__ == '__main__':
    cli()
