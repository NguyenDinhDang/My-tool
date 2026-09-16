#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Forwarding wrapper for system/usb_scanner_windows.py
Vui lòng sử dụng đường dẫn mới: python system/usb_scanner_windows.py
"""
import sys
import os

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from system.usb_scanner_windows import main

if __name__ == "__main__":
    main()
