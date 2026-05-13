#!/usr/bin/env python
"""
AGI Configuration File

This file contains customizable settings for the AGI tools.
Modify these values according to your needs.
"""

# ============================================================================
# MARKDOWN TO WORD SETTINGS
# ============================================================================

MD2WORD_SETTINGS = {
    # Default encoding for reading markdown files
    "encoding": "utf-8",
    
    # Code block styling
    "code_font": "Times New Roman",
    "code_font_size": 9,
    "code_bg_color": "F5F5F5",
    "code_text_color": "333333",
    
    # Heading styling
    "heading1_color": "003366",
    "heading1_size": 18,
    "heading2_color": "0066CC",
    "heading2_size": 14,
    
    # Normal text
    "normal_font": "Times New Roman",
    "normal_font_size": 14,
}


# ============================================================================
# AUTO-FILL FORM SETTINGS
# ============================================================================

AUTOFILL_SETTINGS = {
    # Google Form URL - Change this to your target form
    "form_url": "https://forms.gle/ceshtMiF1spZnmfo9",
    
    # Number of default submissions
    "default_submissions": 27,
    
    # Chrome driver settings
    "chrome_headless": False,
    "chrome_start_maximized": True,
    
    # Timing settings (in seconds)
    "min_typing_delay": 0.01,
    "max_typing_delay": 0.08,
    "min_between_fields": 0.3,
    "max_between_fields": 0.8,
    "min_scroll_pause": 0.5,
    "max_scroll_pause": 1.0,
    "min_between_submissions": 2.5,
    "max_between_submissions": 5.5,
    
    # Form filling options
    "gender_choices": ["Nam", "Nữ", "Không muốn nêu cụ thể"],
    "gender_weights": [0.35, 0.35, 0.30],
    "checkbox_selection_rate": 0.3,
}


# ============================================================================
# LOGGING SETTINGS
# ============================================================================

LOGGING_SETTINGS = {
    "verbose": True,
    "save_logs": False,
    "log_file": "agi.log",
}


if __name__ == "__main__":
    print("AGI Configuration Module")
    print("=" * 50)
    print(f"MD2Word Settings: {len(MD2WORD_SETTINGS)} options")
    print(f"AutoFill Settings: {len(AUTOFILL_SETTINGS)} options")
    print(f"Logging Settings: {len(LOGGING_SETTINGS)} options")
