#!/usr/bin/env python
"""
Quick Converter
Simple script to convert any markdown file in samples/ folder
"""

import os
import sys
from pathlib import Path

# Add src to path
src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

from agi_cli import cli

def main():
    """List markdown files in samples/ and convert"""
    samples_dir = os.path.join(os.path.dirname(__file__), 'samples')
    output_dir = os.path.join(os.path.dirname(__file__), 'output')
    
    # Find all .md files
    md_files = list(Path(samples_dir).glob('*.md'))
    
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
        os.system(f'python agi.py md2word samples/{file_name}')
    else:
        # Let user choose
        print(f"\n Nhập số file để chuyển (1-{len(md_files)}): ", end='')
        try:
            choice = int(input()) - 1
            if 0 <= choice < len(md_files):
                file_name = md_files[choice].name
                print(f"\n Chuyển đổi: {file_name}")
                os.system(f'python agi.py md2word samples/{file_name}')
            else:
                print(" Lựa chọn không hợp lệ")
        except ValueError:
            print(" Vui lòng nhập số hợp lệ")

if __name__ == '__main__':
    main()
