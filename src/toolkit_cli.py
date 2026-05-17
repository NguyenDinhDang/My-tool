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
    '--submissions', '-n',
    type=int,
    default=27,
    help='Number of form submissions (default: 27)'
)
@click.confirmation_option(
    prompt='  This will auto-fill a Google Form. Continue?',
    help='Confirm before starting auto-fill'
)
def autofill(submissions):
    """
     Auto-Fill Google Form
    
    Automatically fills out a Google Form with random responses.
    Uses advanced techniques to bypass bot detection.
    
    WARNING: Only use this on forms you have permission to fill!
    
    Example:
        toolkit autofill
        toolkit autofill -n 50
    """
    try:
        # Modify NUM_SUBMISSIONS in autoFill_form.py temporarily
        import autoFill_form
        original_num = autoFill_form.NUM_SUBMISSIONS
        autoFill_form.NUM_SUBMISSIONS = submissions
        
        click.echo(f"Starting auto-fill with {submissions} submissions...")
        autofill_main()
        click.echo(f"All {submissions} submissions completed!")
        
    except Exception as e:
        click.echo(f" Error: {str(e)}", err=True)
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
    Automatically fills Google Forms with random responses
    Uses undetected Chrome + human-like typing
    Bypasses bot detection mechanisms
    Usage: python toolkit.py autofill [-n number_of_submissions]



 Security tools
    Source code analyzer:
      python src/security/source_code_analyzer.py <project-path>
    Web security scanner:
      python src/security/web_security_scanner.py <url>
    WiFi analyzer:
      python src/security/advanced_wifi_analyzer.py

For more help: python toolkit.py --help
For command help: python toolkit.py <command> --help
    """)


if __name__ == '__main__':
    cli()
