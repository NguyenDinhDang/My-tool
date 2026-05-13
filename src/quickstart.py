#!/usr/bin/env python
"""
AGI Quick Start Guide

A simple interactive setup wizard for the AGI CLI tool.
Run this to get started quickly!
"""

import os
import sys
import click


def show_banner():
    """Display AGI banner"""
    banner = """
    
                                                               
                   AGI - Quick Start Setup Guide               
                                                               
               Automation & Conversion CLI Tool v1.0           
                                                               
    
    """
    click.echo(banner)


def check_dependencies():
    """Check if all required packages are installed"""
    click.echo("\n Checking dependencies...\n")
    
    required = {
        "click": "CLI Framework",
        "docx": "Word Document Support (python-docx)",
        "selenium": "Web Automation",
        "undetected_chromedriver": "Anti-Bot Chrome Driver",
    }
    
    missing = []
    for package, description in required.items():
        try:
            __import__(package)
            click.echo(f"   {description:40} Found")
        except ImportError:
            click.echo(f"   {description:40} Missing")
            missing.append(package)
    
    if missing:
        click.echo(f"\n  Missing packages: {', '.join(missing)}")
        if click.confirm("\n Install missing packages now?"):
            os.system(f"pip install {' '.join(missing)}")
            click.echo("\n Installation complete!")
        else:
            click.echo("\n  Some features may not work without these packages.")
    else:
        click.echo("\n All dependencies are installed!")


def show_usage_examples():
    """Display usage examples"""
    examples = """
    
     USAGE EXAMPLES
    
    
    1  Convert Markdown to Word:
        python agi_cli.py md2word document.md
        python agi_cli.py md2word document.md -o output.docx
    
    2  Auto-Fill Google Form:
        python agi_cli.py autofill
        python agi_cli.py autofill -n 50
    
    3  View Available Tools:
        python agi_cli.py info
    
    4  Get Help:
        python agi_cli.py --help
        python agi_cli.py [command] --help
    
    """
    click.echo(examples)


def show_quick_demo():
    """Show a quick demo"""
    click.echo("\n QUICK DEMO")
    click.echo("\n")
    
    if click.confirm("Would you like to test the MD2Word converter with sample.md?"):
        os.system("python agi_cli.py md2word sample.md")
        click.echo("\n Demo complete! Check sample.docx")


def show_next_steps():
    """Show next steps"""
    next_steps = """
    
     NEXT STEPS
    
    
    1. Read the full documentation: cat README.md
    
    2. Customize settings in: config.py
    
    3. Try the first command:
       python agi_cli.py info
    
    4. For detailed help:
       python agi_cli.py --help
    
    5. Create a custom markdown file and convert it:
       python agi_cli.py md2word your_file.md
    
    
    
    Need help? Check README.md or run individual commands with --help
    
    """
    click.echo(next_steps)


@click.command()
def main():
    """AGI Quick Start Wizard"""
    show_banner()
    
    check_dependencies()
    show_usage_examples()
    
    if click.confirm("\n Would you like to see a quick demo?"):
        show_quick_demo()
    
    show_next_steps()
    
    click.echo(" Setup complete! Happy automating! \n")


if __name__ == "__main__":
    main()
