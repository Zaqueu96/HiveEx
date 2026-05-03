#!/usr/bin/python3

"""
GUI for HiveEx - Compact graphical interface for hive extraction.

Minimalist interface inspired by Windows XP for quick forensic hive extraction.
"""

import sys
import os
import threading

import PySimpleGUI as sg
from main import HiveExCLI, validate_arguments
from utils import loggerUtils

# Classic Windows XP theme
sg.theme('Default1')
sg.set_options(
    font=('MS Shell Dlg 2', 9),
    element_padding=(2, 2),
    margins=(5, 5)
)


class HiveExGUI:
    """Compact GUI for HiveEx extraction tool."""
    
    def __init__(self):
        """Initialize the GUI application."""
        self.logger = loggerUtils.getLogger(__name__)
        self.image_paths = []
        self.extraction_thread = None
        self.is_extracting = False
    
    def create_layout(self):
        """Creates a compact window layout (Windows XP style)."""
        layout = [
            [sg.Text('HiveEx - Hive Extraction', font=('MS Shell Dlg 2', 10, 'bold'))],
            [sg.Text('_' * 55)],
            
            # Images section
            [sg.Text('Forensic Images:')],
            [sg.Listbox(
                values=self.image_paths,
                size=(55, 4),
                key='-IMAGE_LIST-',
                select_mode=sg.LISTBOX_SELECT_MODE_MULTIPLE
            )],
            [
                sg.Button('Add', size=(6, 1), key='-ADD_IMAGE-'),
                sg.Button('Remove', size=(8, 1), key='-REMOVE_IMAGE-'),
                sg.Button('Clear', size=(6, 1), key='-CLEAR_IMAGES-')
            ],
            
            # Extraction options
            [sg.Text('_' * 55)],
            [sg.Text('Extract:')],
            [
                sg.Checkbox('SAM', key='-EXTRACT_SAM-'),
                sg.Checkbox('SYSTEM', key='-EXTRACT_SYSTEM-'),
                sg.Checkbox('SOFTWARE', key='-EXTRACT_SOFTWARE-')
            ],
            [
                sg.Checkbox('SECURITY', key='-EXTRACT_SECURITY-'),
                sg.Checkbox('NTUSER.DAT', key='-EXTRACT_NTUSER-'),
                sg.Checkbox('All', key='-EXTRACT_ALL-')
            ],
            
            # Output path
            [sg.Text('_' * 55)],
            [sg.Text('Output Path:')],
            [
                sg.Input('.', key='-OUTPUT_PATH-', size=(40, 1)),
                sg.FolderBrowse(size=(6, 1))
            ],
            
            # Buttons
            [sg.Text('_' * 55)],
            [
                sg.Button('Extract', size=(10, 1), key='-START_EXTRACTION-'),
                sg.Button('Cancel', size=(10, 1), key='-CANCEL-', disabled=True),
                sg.Button('Exit', size=(10, 1), key='-EXIT-')
            ],
            
            # Status/Log
            [sg.Text('_' * 55)],
            [sg.Multiline(
                size=(57, 8),
                key='-LOG_OUTPUT-',
                disabled=True,
                font=('Courier New', 8)
            )]
        ]
        
        return layout
    
    def _add_log_message(self, window, message):
        """Add a message to the log output."""
        log_widget = window['-LOG_OUTPUT-']
        current_text = log_widget.get()
        log_widget.update(current_text + message + '\n')
    
    def _validate_extraction_options(self, values) -> bool:
        """Check if at least one extraction option is selected."""
        return (values['-EXTRACT_SAM-'] or 
                values['-EXTRACT_SYSTEM-'] or 
                values['-EXTRACT_SOFTWARE-'] or 
                values['-EXTRACT_SECURITY-'] or 
                values['-EXTRACT_NTUSER-'] or 
                values['-EXTRACT_ALL-'])
    
    def _create_args_object(self, values):
        """Create an arguments object from GUI values."""
        class Args:
            def __init__(self, image_paths, output_path, extract_sam, extract_system, 
                         extract_software, extract_security, extract_ntuser, extract_all):
                self.image = image_paths
                self.output = output_path
                self.windows = False
                self.sam = extract_sam
                self.software = extract_software
                self.system = extract_system
                self.security = extract_security
                self.ntuserdat = extract_ntuser
                self.all = extract_all
                self.specific_file = None
                self.config = None
                self.debug = False
                self.verbose = False
                self.list_configs = False
                self.configs_path = None
        
        return Args(
            image_paths=self.image_paths,
            output_path=values['-OUTPUT_PATH-'],
            extract_sam=values['-EXTRACT_SAM-'],
            extract_system=values['-EXTRACT_SYSTEM-'],
            extract_software=values['-EXTRACT_SOFTWARE-'],
            extract_security=values['-EXTRACT_SECURITY-'],
            extract_ntuser=values['-EXTRACT_NTUSER-'],
            extract_all=values['-EXTRACT_ALL-']
        )
    
    def _run_extraction(self, window, args):
        """Run the extraction process."""
        try:
            self._add_log_message(window, "[*] Starting extraction...")
            self._add_log_message(window, f"[*] Processing {len(args.image)} image(s)")
            
            # Redirect logging to GUI
            original_handlers = []
            for handler in self.logger.handlers:
                original_handlers.append(handler)
            
            cli = HiveExCLI(args)
            cli.run()
            
            self._add_log_message(window, "[+] Extraction completed successfully!")
            self.is_extracting = False
            
        except RuntimeError as e:
            self._add_log_message(window, f"[-] Error: {str(e)}")
            self.is_extracting = False
        except Exception as e:
            self._add_log_message(window, f"[-] Unexpected error: {str(e)}")
            import traceback
            self._add_log_message(window, traceback.format_exc())
            self.is_extracting = False
    
    def run(self):
        """Main event loop for the GUI."""
        window = sg.Window(
            'HiveEx',
            self.create_layout(),
            finalize=True,
            size=(480, 550),
            icon=None
        )
        
        while True:
            event, values = window.read(timeout=100)
            
            # Exit events
            if event in (sg.WINDOW_CLOSED, '-EXIT-'):
                break
            
            # Add image
            if event == '-ADD_IMAGE-':
                file_path = sg.popup_get_file(
                    'Select E01 image file',
                    file_types=(('E01 Files', '*.E01'), ('All Files', '*.*'))
                )
                if file_path and file_path not in self.image_paths:
                    self.image_paths.append(file_path)
                    window['-IMAGE_LIST-'].update(self.image_paths)
            
            # Remove image
            if event == '-REMOVE_IMAGE-':
                selected = values['-IMAGE_LIST-']
                if selected:
                    for item in selected:
                        self.image_paths.remove(item)
                    window['-IMAGE_LIST-'].update(self.image_paths)
            
            # Clear all images
            if event == '-CLEAR_IMAGES-':
                self.image_paths = []
                window['-IMAGE_LIST-'].update(self.image_paths)
            
            # Start extraction
            if event == '-START_EXTRACTION-':
                if not self.image_paths:
                    sg.popup_error('Please add at least one image')
                    continue
                
                if not self._validate_extraction_options(values):
                    sg.popup_error('Please select at least one option to extract')
                    continue
                
                args = self._create_args_object(values)
                
                try:
                    validate_arguments(args)
                except RuntimeError as e:
                    sg.popup_error(str(e))
                    continue
                
                window['-START_EXTRACTION-'].update(disabled=True)
                window['-CANCEL-'].update(disabled=False)
                window['-LOG_OUTPUT-'].update('')
                
                self._add_log_message(window, '[*] Extraction started...')
                
                self.is_extracting = True
                self.extraction_thread = threading.Thread(
                    target=self._run_extraction,
                    args=(window, args),
                    daemon=True
                )
                self.extraction_thread.start()
            
            # Cancel extraction
            if event == '-CANCEL-':
                sg.popup('Cannot cancel during extraction')
            
            # Re-enable buttons after extraction
            if not self.is_extracting and self.extraction_thread and not self.extraction_thread.is_alive():
                window['-START_EXTRACTION-'].update(disabled=False)
                window['-CANCEL-'].update(disabled=True)
                self.extraction_thread = None
        
        window.close()


def main():
    """Main entry point for the GUI application."""
    gui = HiveExGUI()
    gui.run()


if __name__ == '__main__':
    main()
