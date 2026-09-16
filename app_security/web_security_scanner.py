#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
LEGAL DISCLAIMER / TUYÊN BỐ MIỄN TRỪ TRÁCH NHIỆM PHÁP LÝ
==============================================================================
Dự án này được tạo ra ĐỘC QUYỀN vì mục đích giáo dục, nghiên cứu an toàn thông
tin và phục vụ học thuật trong môi trường phòng thí nghiệm khép kín (Local Lab).

1. Yêu cầu cấp phép: Tuyệt đối KHÔNG sử dụng công cụ này để quét, bắt gói tin,
   hoặc can thiệp vào bất kỳ hệ thống nào mà không có sự đồng ý bằng văn bản.
2. Không khuyến khích hành vi phi pháp: Nghiêm cấm mọi hành vi lạm dụng mã nguồn.
3. Miễn trừ trách nhiệm: Tác giả (Đặng Đình Nguyên) KHÔNG chịu bất kỳ trách nhiệm
   pháp lý nào đối với các thiệt hại phát sinh từ việc sử dụng công cụ này.
==============================================================================
"""

"""
Web Security Scanner launcher.
Điều hướng trực tiếp tới engine security_scanner.py hợp nhất toàn diện 6 Phase.
Tuân thủ nghiêm ngặt 7 nguyên tắc an toàn, Safe Mode mặc định và Global Request Budget.
Tác giả: Đặng Đình Nguyên
"""

import sys
import os

# Thêm thư mục gốc vào PYTHONPATH
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from security_scanner import main

if __name__ == "__main__":
    sys.exit(main())
