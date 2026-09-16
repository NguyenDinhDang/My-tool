#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Forwarding wrapper for app_security/source_code_analyzer.py
Vui lòng sử dụng đường dẫn mới: python app_security/source_code_analyzer.py
"""
import sys
import os

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app_security.source_code_analyzer import main

if __name__ == "__main__":
    main()