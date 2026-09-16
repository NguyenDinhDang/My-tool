#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Forwarding wrapper for network/advanced_techniques.py
Vui lòng sử dụng đường dẫn mới: python network/advanced_techniques.py
"""
import sys
import os

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from network.advanced_techniques import AdvancedSecurityTechniques

if __name__ == "__main__":
    tool = AdvancedSecurityTechniques()
    tool.display_menu()