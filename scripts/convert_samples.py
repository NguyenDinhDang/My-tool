#!/usr/bin/env python
"""
Quick Converter
Simple script to convert any markdown file in samples/ folder
"""

import os
import subprocess
import sys
from pathlib import Path

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, 'reconfigure'):
        stream.reconfigure(encoding='utf-8', errors='replace')

def main():
    """List markdown files in samples/ and convert"""
    root_dir = Path(__file__).resolve().parents[1]
    samples_dir = root_dir / 'samples'
    
    # Find all .md files
    md_files = list(samples_dir.glob('*.md'))
    
    if not md_files:
        print(" Không có file .md nào trong thư mục samples/")
        print(f" Kiểm tra: {samples_dir}")
        return
    
    print(" Các file Markdown trong samples/:\n")
    for i, f in enumerate(md_files, 1):
        print(f"  {i}. {f.name}")
    
    if len(md_files) == 1:
        # Auto-convert single file
        file_name = md_files[0].name
        print(f"\n Chuyển đổi: {file_name}")
        subprocess.run([sys.executable, str(root_dir / "toolkit.py"), "md2word", f"samples/{file_name}"], timeout=90, check=False)
    else:
        # Let user choose
        print(f"\n Nhập số file để chuyển (1-{len(md_files)}): ", end='')
        try:
            choice = int(input()) - 1
            if 0 <= choice < len(md_files):
                file_name = md_files[choice].name
                print(f"\n Chuyển đổi: {file_name}")
                subprocess.run([sys.executable, str(root_dir / "toolkit.py"), "md2word", f"samples/{file_name}"], timeout=90, check=False)
            else:
                print(" Lựa chọn không hợp lệ")
        except ValueError:
            print(" Vui lòng nhập số hợp lệ")

if __name__ == '__main__':
    main()
