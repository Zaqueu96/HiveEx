#!/usr/bin/python3

"""
HiveEx Launcher - Choose between CLI and GUI interfaces.

Provides a simple way to launch HiveEx in either command-line or graphical mode.
"""

import sys
import argparse
from pathlib import Path

# Add src/main to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src' / 'main'))


def main():
    """Main entry point that decides between CLI and GUI."""
    # Check if no arguments provided - launch GUI automatically
    if len(sys.argv) == 1:
        try:
            from gui import main as gui_main
            gui_main()
        except ImportError:
            print('ERROR: PySimpleGUI is not installed.')
            print('Install it with: pip install PySimpleGUI')
            sys.exit(1)
        return
    
    # Check if --gui flag is present (before full parsing)
    gui_mode = '--gui' in sys.argv or '-g' in sys.argv
    
    if gui_mode:
        # Remove GUI flag from argv before importing GUI
        sys.argv = [arg for arg in sys.argv if arg not in ('--gui', '-g')]
        
        try:
            from gui import main as gui_main
            gui_main()
        except ImportError:
            print('ERROR: PySimpleGUI is not installed.')
            print('Install it with: pip install PySimpleGUI')
            sys.exit(1)
    else:
        # CLI mode - delegate to main.py
        from main import main as cli_main
        cli_main()


if __name__ == '__main__':
    main()
