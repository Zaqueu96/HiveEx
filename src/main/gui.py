#!/usr/bin/python3

"""
GUI for HiveEx - Modern, minimalist interface for hive extraction.
"""

import sys
import os
import threading

import PySimpleGUI as sg
from main import HiveExCLI, validate_arguments
from config import ConfigHandler
from utils import loggerUtils

# Modern, friendly theme with light colors
sg.theme('LightBlue2')
sg.set_options(
    font=('Segoe UI', 10),
    element_padding=(3, 3),
    margins=(8, 8),
    button_color=('white', '#0078d4')
)


class HiveExGUI:
    """Modern GUI for HiveEx extraction tool."""
    
    def __init__(self):
        """Initialize the GUI application."""
        self.logger = loggerUtils.getLogger(__name__)
        self.image_paths = []
        self.available_configs = []
        self.extraction_thread = None
        self.is_extracting = False
        self._load_configs()
    
    def _load_configs(self):
        """Load available hive configurations."""
        try:
            self.available_configs = ConfigHandler.get_available_configs()
        except Exception as e:
            self.logger.error(f"Error loading configurations: {e}")
            self.available_configs = []
    
    def create_layout(self):
        """Creates a modern, fluid, and friendly window layout (resizable)."""
        layout = [
            # Sleek Header
            [sg.Text('HiveEx', font=('Segoe UI', 16, 'bold'), text_color='#0078d4')],
            [sg.Text('Forensic Hive Extraction Tool', font=('Segoe UI', 10), text_color='gray')],
            [sg.Text('_' * 80, size=(80, 1))],
            
            # Forensic Images - Simplified
            [sg.Text('Forensic Images', font=('Segoe UI', 11, 'bold'))],
            [sg.Listbox(
                values=self.image_paths,
                size=(80, 6),
                key='-IMAGE_LIST-',
                select_mode=sg.LISTBOX_SELECT_MODE_MULTIPLE,
                background_color='white',
                expand_x=True,
                expand_y=False
            )],
            [sg.Button('+ Add Image', size=(15, 1)), 
             sg.Button('- Remove', size=(15, 1)), 
             sg.Button('Clear All', size=(15, 1)),
             sg.Stretch()],
            
            [sg.Text('_' * 80, size=(80, 1))],
            
            # Two columns layout
            [sg.Column([
                # Extraction Options
                [sg.Text('Extract Options', font=('Segoe UI', 11, 'bold'))],
                [sg.Checkbox('SAM', key='-EXTRACT_SAM-', default=False, enable_events=True),
                 sg.Checkbox('SYSTEM', key='-EXTRACT_SYSTEM-', default=False, enable_events=True)],
                [sg.Checkbox('SOFTWARE', key='-EXTRACT_SOFTWARE-', default=False, enable_events=True),
                 sg.Checkbox('SECURITY', key='-EXTRACT_SECURITY-', default=False, enable_events=True)],
                [sg.Checkbox('NTUSER.DAT', key='-EXTRACT_NTUSER-', default=False, enable_events=True),
                 sg.Checkbox('All Hives', key='-EXTRACT_ALL-', default=False, enable_events=True)],
                [sg.Text('', font=('Segoe UI', 9), key='-SUMMARY-', text_color='#0078d4')],
            ], vertical_alignment='top', expand_x=True),
             
             sg.Column([
                # Configurations
                [sg.Text('Configurations', font=('Segoe UI', 11, 'bold'))],
                [sg.Listbox(
                    values=self.available_configs,
                    size=(35, 5),
                    key='-CONFIG_LIST-',
                    select_mode=sg.LISTBOX_SELECT_MODE_MULTIPLE,
                    background_color='white',
                    enable_events=True,
                    expand_x=True,
                    expand_y=False
                )],
                [sg.Text('Selected: None', font=('Segoe UI', 9), key='-CONFIG_SUMMARY-', text_color='#0078d4')],
            ], vertical_alignment='top', expand_x=True)
            ],
            
            [sg.Text('_' * 80, size=(80, 1))],
            
            # Output Configuration
            [sg.Text('Output Path', font=('Segoe UI', 11, 'bold'))],
            [sg.Input('.', key='-OUTPUT_PATH-', size=(60, 1), expand_x=True), 
             sg.FolderBrowse(size=(10, 1))],
            
            [sg.Text('Options', font=('Segoe UI', 11, 'bold'))],
            [sg.Checkbox('Debug Mode', key='-DEBUG-', default=False),
             sg.Checkbox('Verbose Output', key='-VERBOSE-', default=False)],
            
            [sg.Text('_' * 80, size=(80, 1))],
            
            # Action Buttons
            [sg.Button('Extract', size=(18, 2), button_color=('white', '#0078d4'), font=('Segoe UI', 10, 'bold')), 
             sg.Button('Cancel', size=(18, 2), disabled=True, font=('Segoe UI', 10)),
             sg.Button('Exit', size=(18, 2), font=('Segoe UI', 10)),
             sg.Stretch()],
            
            # Log Output
            [sg.Text('Extraction Log', font=('Segoe UI', 11, 'bold'))],
            [sg.Multiline(
                size=(80, 12),
                key='-LOG_OUTPUT-',
                disabled=True,
                font=('Courier New', 9),
                background_color='white',
                text_color='#333',
                expand_x=True,
                expand_y=True
            )]
        ]
        
        return layout
    
    def _add_log_message(self, window, message):
        """Add a message to the log output."""
        log_widget = window['-LOG_OUTPUT-']
        current_text = log_widget.get()
        log_widget.update(current_text + message + '\n')
    
    def _update_extraction_summary(self, window, values):
        """Update the summary of selected extraction options."""
        selected = []
        if values['-EXTRACT_SAM-']:
            selected.append('SAM')
        if values['-EXTRACT_SYSTEM-']:
            selected.append('SYSTEM')
        if values['-EXTRACT_SOFTWARE-']:
            selected.append('SOFTWARE')
        if values['-EXTRACT_SECURITY-']:
            selected.append('SECURITY')
        if values['-EXTRACT_NTUSER-']:
            selected.append('NTUSER')
        if values['-EXTRACT_ALL-']:
            selected.append('ALL')
        
        if selected:
            summary = f"Selected: {', '.join(selected)}"
        else:
            summary = "Selected: None"
        
        window['-SUMMARY-'].update(summary)
    
    def _update_config_summary(self, window, values):
        """Update the summary of selected configurations."""
        selected_configs = values['-CONFIG_LIST-']
        
        if selected_configs:
            summary = f"Selected: {len(selected_configs)}"
        else:
            summary = "Selected: None"
        
        window['-CONFIG_SUMMARY-'].update(summary)
    
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
                         extract_software, extract_security, extract_ntuser, extract_all,
                         config_list, debug, verbose):
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
                self.config = config_list if config_list else None
                self.debug = debug
                self.verbose = verbose
                self.list_configs = False
                self.configs_path = None
        
        config_list = values['-CONFIG_LIST-'] if values['-CONFIG_LIST-'] else None
        
        return Args(
            image_paths=self.image_paths,
            output_path=values['-OUTPUT_PATH-'],
            extract_sam=values['-EXTRACT_SAM-'],
            extract_system=values['-EXTRACT_SYSTEM-'],
            extract_software=values['-EXTRACT_SOFTWARE-'],
            extract_security=values['-EXTRACT_SECURITY-'],
            extract_ntuser=values['-EXTRACT_NTUSER-'],
            extract_all=values['-EXTRACT_ALL-'],
            config_list=config_list,
            debug=values['-DEBUG-'],
            verbose=values['-VERBOSE-']
        )
    
    def _run_extraction(self, window, args):
        """Run the extraction process with detailed feedback."""
        try:
            self._add_log_message(window, "=" * 60)
            self._add_log_message(window, "[*] HiveEx Extraction Started")
            self._add_log_message(window, "=" * 60)
            
            # Show input configuration
            self._add_log_message(window, "\n[*] Configuration:")
            self._add_log_message(window, f"    └─ Output Path: {args.output}")
            self._add_log_message(window, f"    └─ Images to Process: {len(args.image)}")
            self._add_log_message(window, f"    └─ Debug Mode: {'ON' if args.debug else 'OFF'}")
            self._add_log_message(window, f"    └─ Verbose Mode: {'ON' if args.verbose else 'OFF'}")
            
            # Show extraction options
            self._add_log_message(window, "\n[*] Extraction Options:")
            extraction_opts = []
            if args.sam:
                extraction_opts.append("SAM")
            if args.system:
                extraction_opts.append("SYSTEM")
            if args.software:
                extraction_opts.append("SOFTWARE")
            if args.security:
                extraction_opts.append("SECURITY")
            if args.ntuserdat:
                extraction_opts.append("NTUSER.DAT")
            if args.all:
                extraction_opts.append("All Hives")
            
            for i, opt in enumerate(extraction_opts):
                prefix = "    ├─" if i < len(extraction_opts) - 1 else "    └─"
                self._add_log_message(window, f"{prefix} {opt}")
            
            # Show selected configs
            if args.config:
                self._add_log_message(window, "\n[*] Selected Configurations:")
                configs = args.config if isinstance(args.config, list) else [args.config]
                for i, cfg in enumerate(configs):
                    prefix = "    ├─" if i < len(configs) - 1 else "    └─"
                    self._add_log_message(window, f"{prefix} {cfg}")
            
            self._add_log_message(window, "\n" + "=" * 60)
            self._add_log_message(window, "[*] Starting extraction process...")
            self._add_log_message(window, "=" * 60 + "\n")
            
            # Process each image
            for idx, image_path in enumerate(args.image, 1):
                self._add_log_message(window, f"\n[>] Processing Image {idx}/{len(args.image)}")
                self._add_log_message(window, f"    File: {os.path.basename(image_path)}")
                self._add_log_message(window, f"    Path: {image_path}")
                self._add_log_message(window, "    Status: Initializing...\n")
            
            # Run extraction
            cli = HiveExCLI(args)
            cli.run()
            
            self._add_log_message(window, "\n" + "=" * 60)
            self._add_log_message(window, "[+] Extraction Completed Successfully!")
            self._add_log_message(window, "=" * 60)
            self.is_extracting = False
            
        except RuntimeError as e:
            self._add_log_message(window, f"\n[-] Runtime Error: {str(e)}")
            self.is_extracting = False
        except Exception as e:
            self._add_log_message(window, f"\n[-] Unexpected Error: {str(e)}")
            import traceback
            self._add_log_message(window, traceback.format_exc())
            self.is_extracting = False
    
    def run(self):
        """Main event loop for the GUI."""
        window = sg.Window(
            'HiveEx',
            self.create_layout(),
            finalize=True,
            size=(600, 750),
            resizable=True,
            element_justification='center',
            icon=None
        )
        
        while True:
            event, values = window.read(timeout=100)
            
            # Update summaries when options change
            if event in ['-EXTRACT_SAM-', '-EXTRACT_SYSTEM-', '-EXTRACT_SOFTWARE-', 
                         '-EXTRACT_SECURITY-', '-EXTRACT_NTUSER-', '-EXTRACT_ALL-']:
                self._update_extraction_summary(window, values)
            
            if event == '-CONFIG_LIST-':
                self._update_config_summary(window, values)
            
            # Exit events
            if event in (sg.WINDOW_CLOSED, 'Exit'):
                break
            
            # Add image
            if event == '+ Add Image':
                file_path = sg.popup_get_file(
                    'Select E01 image file',
                    file_types=(('E01 Files', '*.E01'), ('All Files', '*.*'))
                )
                if file_path and file_path not in self.image_paths:
                    self.image_paths.append(file_path)
                    window['-IMAGE_LIST-'].update(self.image_paths)
            
            # Remove image
            if event == '- Remove':
                selected = values['-IMAGE_LIST-']
                if selected:
                    for item in selected:
                        self.image_paths.remove(item)
                    window['-IMAGE_LIST-'].update(self.image_paths)
            
            # Clear all images
            if event == 'Clear All':
                self.image_paths = []
                window['-IMAGE_LIST-'].update(self.image_paths)
            
            # Start extraction
            if event == 'Extract':
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
                
                window['Extract'].update(disabled=True)
                window['Cancel'].update(disabled=False)
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
            if event == 'Cancel':
                sg.popup('Cannot cancel during extraction')
            
            # Re-enable buttons after extraction
            if not self.is_extracting and self.extraction_thread and not self.extraction_thread.is_alive():
                window['Extract'].update(disabled=False)
                window['Cancel'].update(disabled=True)
                self.extraction_thread = None
        
        window.close()


def main():
    """Main entry point for the GUI application."""
    gui = HiveExGUI()
    gui.run()


if __name__ == '__main__':
    main()
