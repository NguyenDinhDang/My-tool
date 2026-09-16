import click
import sys
import os
from pathlib import Path

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, 'reconfigure'):
        stream.reconfigure(encoding='utf-8', errors='replace')

# Import the existing tools
from autoFill_form import main as autofill_main
from md2word import convert_md_to_docx


@click.group()
@click.version_option(version="1.0.0", prog_name="Security Automation Toolkit")
def cli():
    """
    Security Automation Toolkit
    
    Utilities for authorized security checks, document conversion, and automation.
    """
    pass


@cli.command()
@click.argument('markdown_file')
@click.option(
    '--output', '-o',
    type=click.Path(),
    help='Output Word file path (optional, defaults to output/ folder)'
)
def md2word(markdown_file, output):
    """
    Convert Markdown to Word Document
    
    Converts a Markdown file to a professionally formatted Word (.docx) document
    with support for headings, code blocks, Mermaid diagrams, tables, links, and more.
    
    Example:
        toolkit md2word samples/document.md
        toolkit md2word samples/document.md -o output/result.docx
    """
    try:
        # Get project root directory
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Try to find the file in multiple locations
        file_path = None
        if os.path.exists(markdown_file):
            file_path = markdown_file
        elif os.path.exists(os.path.join(root_dir, markdown_file)):
            file_path = os.path.join(root_dir, markdown_file)
        elif os.path.exists(os.path.join(root_dir, 'samples', markdown_file)):
            file_path = os.path.join(root_dir, 'samples', markdown_file)
        else:
            click.echo(f" Error: File '{markdown_file}' not found", err=True)
            click.echo(f"   Searched in: current dir, project root, samples/ folder", err=True)
            sys.exit(1)
        
        # Determine output path
        if not output:
            output = os.path.join(root_dir, 'output', os.path.splitext(os.path.basename(file_path))[0] + '.docx')
            os.makedirs(os.path.dirname(output), exist_ok=True)
        
        click.echo(" Starting Markdown to Word conversion...")
        convert_md_to_docx(file_path, output)
        
        click.echo(f"Success! File saved: {click.style(output, fg='green', bold=True)}")
        
    except Exception as e:
        click.echo(f" Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    '--url', '-u',
    type=str,
    default=None,
    help='Link Google Form cần điền (vd: https://docs.google.com/forms/d/e/.../viewform)'
)
@click.option(
    '--submissions', '-n',
    type=int,
    default=1,
    help='Số lần gửi form (mặc định: 1)'
)
@click.option(
    '--answer', '-a',
    'answers',
    multiple=True,
    help='Câu trả lời tùy chỉnh (có thể truyền nhiều lần: -a "Trả lời 1" -a "Trả lời 2")'
)
@click.confirmation_option(
    prompt='  Xác nhận bắt đầu tự động điền Google Form?',
    help='Xác nhận trước khi chạy'
)
def autofill(url, submissions, answers):
    """
    Auto-Fill Google Form
    
    Tự động điền Google Form bằng Selenium với đường dẫn tùy chọn.
    
    Ví dụ:
        python toolkit.py autofill -u "https://docs.google.com/forms/d/e/.../viewform"
        python toolkit.py autofill -u "https://docs.google.com/forms/d/e/.../viewform" -n 10
    """
    try:
        from autoFill_form import run_autofill
        click.echo(f"Bắt đầu tự động điền ({submissions} lần gửi)...")
        run_autofill(url=url, count=submissions, answers=list(answers) if answers else None)
        click.echo(f"Hoàn thành {submissions} lần gửi form!")
    except Exception as e:
        click.echo(f" Lỗi: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
def info():
    """
    Display information about available tools
    """
    click.echo("""
                    Security Automation Toolkit - Tools Overview

 Markdown to Word (md2word)
    Converts .md files to professional .docx documents
    Supports: headings, Mermaid diagrams, code blocks, tables, links, formatting
    Usage: python toolkit.py md2word <file.md> [-o output.docx]

 Auto-Fill Form (autofill)
    Automatically fills Google Forms with responses
    Uses standard Selenium Chrome
    Usage: python toolkit.py autofill [-n number_of_submissions]

 Security tools:
    Web security scanner (All-in-One):
      python security_scanner.py <url>
      (hoặc: python app_security/web_security_scanner.py <url>)
    Source code analyzer (SAST):
      python app_security/source_code_analyzer.py <project-path>
    WiFi & Network analyzer:
      python network/advanced_wifi_analyzer.py
    USB Security Scanner:
      python system/usb_scanner_windows.py <drive-letter>

For more help: python toolkit.py --help
For command help: python toolkit.py <command> --help
    """)


if __name__ == '__main__':
    cli()
