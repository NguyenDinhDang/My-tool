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

import argparse
import os
import subprocess
import sys
import ctypes
from pathlib import Path

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, 'reconfigure'):
        stream.reconfigure(encoding='utf-8', errors='replace')

# ---------- Màu terminal (Windows Terminal / PowerShell mới hỗ trợ ANSI) ----------
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


def log_ok(msg):
    print(f"{C.GREEN}[OK]{C.END} {msg}")


def log_warn(msg):
    print(f"{C.YELLOW}[CẢNH BÁO]{C.END} {msg}")


def log_danger(msg):
    print(f"{C.RED}{C.BOLD}[NGUY HIỂM]{C.END} {msg}")


def log_info(msg):
    print(f"{C.BLUE}[INFO]{C.END} {msg}")


# ---------- 1. Tìm Windows Defender CLI (MpCmdRun.exe) ----------
def find_defender_cli() -> str:
    candidates = [
        r"C:\Program Files\Windows Defender\MpCmdRun.exe",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform",  # cần dò version con bên trong
    ]
    if os.path.exists(candidates[0]):
        return candidates[0]

    # Dò trong thư mục Platform vì Defender có version con dạng 4.18.xxxx.x
    platform_dir = candidates[1]
    if os.path.isdir(platform_dir):
        try:
            versions = sorted(os.listdir(platform_dir), reverse=True)
            for v in versions:
                path = os.path.join(platform_dir, v, "MpCmdRun.exe")
                if os.path.exists(path):
                    return path
        except Exception:
            pass
    return ""


def run_defender_scan(path: str) -> dict:
    exe = find_defender_cli()
    if not exe:
        return {"error": "Không tìm thấy Windows Defender (MpCmdRun.exe). "
                          "Kiểm tra Windows Security > Virus & threat protection có đang bật không."}
    log_info(f"Đang chạy Windows Defender quét: {path} (có thể mất vài phút)...")
    try:
        result = subprocess.run(
            [exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"],
            capture_output=True, text=True, timeout=3600
        )
        # returncode: 0 = sạch, 2 = tìm thấy đe dọa (tùy version)
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"error": "Quét Windows Defender quá thời gian cho phép (timeout)."}
    except Exception as e:
        return {"error": f"Lỗi khi chạy Defender: {e}"}


# ---------- 2. Heuristic: autorun.inf ----------
def check_autorun(usb_path: Path) -> list:
    findings = []
    autorun_file = usb_path / "autorun.inf"
    if autorun_file.exists():
        findings.append(f"Phát hiện file autorun.inf tại: {autorun_file}")
        try:
            content = autorun_file.read_text(errors="ignore")
            findings.append(f"  Nội dung: {content.strip()[:300]}")
        except Exception:
            pass
    return findings


# ---------- 3. Heuristic: file thực thi / giả dạng ----------
SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd",
                          ".com", ".ps1", ".jar", ".lnk", ".hta", ".msi", ".wsf"}
DOUBLE_EXT_PATTERNS = [".jpg.exe", ".png.exe", ".pdf.exe", ".doc.exe", ".docx.exe",
                        ".txt.exe", ".mp4.exe", ".jpg.scr", ".pdf.scr"]


def check_suspicious_files(usb_path: Path) -> list:
    findings = []
    for root, dirs, files in os.walk(usb_path):
        for fname in files:
            lower = fname.lower()
            full = Path(root) / fname

            for pattern in DOUBLE_EXT_PATTERNS:
                if lower.endswith(pattern):
                    findings.append(f"File giả dạng nghi vấn (double extension): {full}")

            ext = Path(fname).suffix.lower()
            if ext in SUSPICIOUS_EXTENSIONS:
                findings.append(f"File thực thi/script: {full}")
    return findings


# ---------- 4. Kiểm tra thuộc tính Hidden/System (Windows API thật) ----------
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4


def get_file_attributes(path: str):
    attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    if attrs == -1:
        return None
    return attrs


def check_hidden_system_files(usb_path: Path) -> list:
    """
    Tìm file vừa Hidden vừa System - tổ hợp thường dùng để giấu mã độc
    (khác với file hệ thống bình thường như System Volume Information do Windows tự tạo).
    """
    findings = []
    ignore_dirs = {"System Volume Information", "$RECYCLE.BIN"}
    for root, dirs, files in os.walk(usb_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for fname in files:
            full = Path(root) / fname
            attrs = get_file_attributes(str(full))
            if attrs is None:
                continue
            is_hidden = bool(attrs & FILE_ATTRIBUTE_HIDDEN)
            is_system = bool(attrs & FILE_ATTRIBUTE_SYSTEM)
            if is_hidden and is_system:
                findings.append(f"File Hidden+System đáng ngờ: {full}")
            elif is_hidden and Path(fname).suffix.lower() in SUSPICIOUS_EXTENSIONS:
                findings.append(f"File ẩn + thực thi: {full}")
    return findings


# ---------- 5. Dung lượng USB ----------
def check_capacity(usb_path: Path) -> list:
    findings = []
    try:
        import shutil
        usage = shutil.disk_usage(usb_path)
        total_gb = usage.total / (1024 ** 3)
        free_gb = usage.free / (1024 ** 3)
        findings.append(f"Dung lượng thực tế: {total_gb:.2f} GB (còn trống {free_gb:.2f} GB) — "
                         f"so sánh với dung lượng ghi trên vỏ USB, nếu lệch nhiều thì nghi ngờ hàng giả.")
    except Exception as e:
        findings.append(f"Không đọc được dung lượng: {e}")
    return findings


# ---------- Main ----------
def scan(usb_path_str: str, full_scan: bool):
    usb_path = Path(usb_path_str).resolve()

    if not usb_path.exists() or not usb_path.is_dir():
        print(f"{C.RED}Đường dẫn không hợp lệ: {usb_path}{C.END}")
        print("Kiểm tra lại tên ổ đĩa trong 'This PC', ví dụ: E:\\ hoặc F:\\")
        sys.exit(1)

    print(f"{C.BOLD}=== QUÉT USB: {usb_path} ==={C.END}\n")
    total_warnings = 0

    # 1. Windows Defender
    if full_scan:
        result = run_defender_scan(str(usb_path))
        if "error" in result:
            log_warn(result["error"])
        else:
            if result["returncode"] == 0:
                log_ok("Windows Defender: không phát hiện mối đe dọa.")
            else:
                log_danger(f"Windows Defender phát hiện mối đe dọa! (mã trả về: {result['returncode']})")
                print(result["stdout"][-1000:])
                total_warnings += 1
    else:
        log_info("Bỏ qua quét Windows Defender đầy đủ (dùng --full để bật). Chỉ chạy heuristic check.")
    print()

    # 2. autorun.inf
    log_info("Kiểm tra autorun.inf...")
    autorun_findings = check_autorun(usb_path)
    if autorun_findings:
        for f in autorun_findings:
            log_danger(f)
        total_warnings += len(autorun_findings)
    else:
        log_ok("Không có autorun.inf.")
    print()

    # 3. File giả dạng / thực thi
    log_info("Kiểm tra file thực thi và file giả dạng...")
    suspicious = check_suspicious_files(usb_path)
    if suspicious:
        for f in suspicious:
            log_warn(f)
        total_warnings += len(suspicious)
    else:
        log_ok("Không tìm thấy file thực thi/script đáng ngờ.")
    print()

    # 4. Hidden + System
    log_info("Kiểm tra file ẩn/hệ thống bất thường...")
    hidden_findings = check_hidden_system_files(usb_path)
    if hidden_findings:
        for f in hidden_findings:
            log_danger(f)
        total_warnings += len(hidden_findings)
    else:
        log_ok("Không có file Hidden+System đáng ngờ.")
    print()

    # 5. Dung lượng
    log_info("Kiểm tra dung lượng USB...")
    for f in check_capacity(usb_path):
        print(f"    {f}")
    print()

    print(f"{C.BOLD}=== KẾT QUẢ TỔNG QUAN ==={C.END}")
    if total_warnings == 0:
        log_ok("Không phát hiện dấu hiệu bất thường rõ ràng. Vẫn nên thận trọng khi mở file lạ.")
    else:
        log_danger(f"Tổng cộng {total_warnings} dấu hiệu đáng ngờ. KHÔNG mở file lạ, "
                    f"nên format USB nếu không rõ nguồn gốc.")


def main():
    parser = argparse.ArgumentParser(description="Quét USB tìm virus/mã độc (Windows)")
    parser.add_argument("path", help="Duong dan o USB, vi du: E:\\ hoac F:\\")
    parser.add_argument("--full", action="store_true",
                         help="Chạy quét Windows Defender đầy đủ (chậm hơn, chính xác hơn)")
    args = parser.parse_args()
    scan(args.path, args.full)


if __name__ == "__main__":
    main()