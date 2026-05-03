#!/usr/bin/python3

"""
GUI for HiveEx - Compact graphical interface for hive extraction.

Minimalist interface inspired by Windows XP for quick forensic hive extraction.
"""

import sys
import os
import threading
from pathlib import Path

import PySimpleGUI as sg
from main import HiveExCLI, validate_arguments
from config import ConfigHandler
from utils import loggerUtils

# Classic Windows XP theme
sg.theme('Default1')
sg.set_options(
    font=('MS Shell Dlg 2', 9),
    element_padding=(2, 2),
    margins=(5, 5)
)


class HiveExGUI:
    """Graphical User Interface for HiveEx extraction tool."""
    
    def __init__(self):
        """Initialize the GUI application."""
        self.logger = loggerUtils.getLogger(__name__)
        self.image_paths = []
        self.available_configs = []
        self.extraction_thread = None
        self.is_extracting = False
        self._load_available_configs()
    
    def _load_available_configs(self):
        """Load available hive configurations."""
        try:
            self.available_configs = ConfigHandler.get_available_configs()
            self.logger.info(f"Loaded {len(self.available_configs)} configurations")
        except Exception as e:
            self.logger.error(f"Error loading configurations: {e}")
            self.available_configs = []
    
    def create_layout(self):
        """
        Creates the main window layout with improved design.
        
        Returns:
            list: PySimpleGUI layout definition
        """
        # Header section
        header_section = [
            [sg.Text('HiveEx', font=('Segoe UI', 20, 'bold'), text_color='#00FF00')],
            [sg.Text('Forensic Hive Extraction Tool', font=('Segoe UI', 11), text_color='#CCCCCC')],
            [sg.Text('_' * 90, text_color='#00FF00')]
        ]
        
        # Images section with visual feedback
        images_section = [
            [sg.Text('📁 FORENSIC IMAGES', font=('Segoe UI', 11, 'bold'), text_color='#00FFFF')],
            [sg.Listbox(
                values=self.image_paths,
                size=(85, 5),
                key='-IMAGE_LIST-',
                enable_events=True,
                select_mode=sg.LISTBOX_SELECT_MODE_SINGLE,
                background_color='#1a3a52',
                text_color='#FFFFFF',
                highlight_background_color='#00FFFF',
                highlight_text_color='#000000'
            )],
            [
                sg.Button('📁 Browse', key='-BROWSE_IMAGES-', size=(12, 1), tooltip='Select multiple E01 images'),
                sg.Button('➕ Add', key='-ADD_IMAGE-', size=(12, 1), tooltip='Add single image'),
                sg.Button('❌ Remove', key='-REMOVE_IMAGE-', size=(12, 1), tooltip='Remove selected image'),
                sg.Button('🗑️ Clear', key='-CLEAR_IMAGES-', size=(12, 1), tooltip='Remove all images')
            ],
            [sg.Text(f'Images selected: 0', key='-IMAGE_COUNT-', text_color='#FFFF00')]
        ]
        
        # Extraction options section
        extraction_section = [
            [sg.Text('🎯 EXTRACTION OPTIONS', font=('Segoe UI', 11, 'bold'), text_color='#00FFFF')],
            [
                sg.Checkbox('SAM', key='-EXTRACT_SAM-', default=False, 
                           tooltip='Security Account Manager - password hashes'),
                sg.Checkbox('SYSTEM', key='-EXTRACT_SYSTEM-', default=False,
                           tooltip='System configuration and hardware info'),
                sg.Checkbox('SOFTWARE', key='-EXTRACT_SOFTWARE-', default=False,
                           tooltip='Installed programs and settings')
            ],
            [
                sg.Checkbox('SECURITY', key='-EXTRACT_SECURITY-', default=False,
                           tooltip='Security and audit information'),
                sg.Checkbox('NTUSER.DAT', key='-EXTRACT_NTUSER-', default=False,
                           tooltip='User profiles and settings'),
                sg.Checkbox('All Hives', key='-EXTRACT_ALL-', default=False,
                           tooltip='Extract all Windows hives')
            ],
            [
                sg.Checkbox('Specific File', key='-EXTRACT_SPECIFIC-', default=False,
                           tooltip='Extract a specific file (use [user] as placeholder)'),
                sg.Input(key='-SPECIFIC_FILE_PATH-', size=(40, 1), disabled=True,
                        placeholder_text='/Users/[user]/path/to/file')
            ]
        ]
        
        # Configuration section
        config_section = [
            [sg.Text('⚙️ CONFIGURATION FILES', font=('Segoe UI', 11, 'bold'), text_color='#00FFFF')],
            [sg.Text('Select predefined extraction profiles (YAML):')],
            [
                sg.Listbox(
                    values=self.available_configs,
                    size=(85, 4),
                    key='-CONFIG_LIST-',
                    enable_events=True,
                    select_mode=sg.LISTBOX_SELECT_MODE_MULTIPLE,
                    background_color='#1a3a52',
                    text_color='#FFFFFF',
                    highlight_background_color='#00FFFF',
                    highlight_text_color='#000000'
                )
            ],
            [sg.Button('🔄 Refresh Configs', key='-REFRESH_CONFIGS-', size=(15, 1),
                      tooltip='Reload configuration files from disk')]
        ]
        
        # Extraction summary section
        summary_section = [
            [sg.Text('📋 EXTRACTION SUMMARY', font=('Segoe UI', 11, 'bold'), text_color='#00FFFF')],
            [sg.Multiline(
                default_text='• No options selected yet\n\nSelect images and extraction options above, then click Start to begin.',
                size=(85, 5),
                key='-SUMMARY-',
                disabled=True,
                background_color='#1a3a52',
                text_color='#90EE90',
                autoscroll=False
            )]
        ]
        
        # Output and options section
        options_section = [
            [sg.Text('💾 OUTPUT CONFIGURATION', font=('Segoe UI', 11, 'bold'), text_color='#00FFFF')],
            [
                sg.Text('Output Path:', size=(12, 1)),
                sg.Input(
                    default_text='.',
                    key='-OUTPUT_PATH-',
                    size=(60, 1),
                    tooltip='Directory where extracted files will be saved'
                ),
                sg.FolderBrowse(button_text='📁')
            ],
            [
                sg.Checkbox('🔧 Debug Mode', key='-DEBUG_MODE-', default=False,
                           tooltip='Show detailed error messages'),
                sg.Checkbox('📝 Verbose Logging', key='-VERBOSE-', default=False,
                           tooltip='Show additional logging information')
            ]
        ]
        
        # Progress section
        progress_section = [
            [sg.Text('⏳ PROGRESS', font=('Segoe UI', 11, 'bold'), text_color='#00FFFF')],
            [sg.ProgressBar(
                100,
                orientation='h',
                size=(83, 15),
                key='-PROGRESS_BAR-',
                bar_color=('#00FF00', '#1a3a52')
            )],
            [sg.Text('Ready', key='-STATUS-', text_color='#FFFF00')],
            [sg.Multiline(
                size=(85, 8),
                key='-LOG_OUTPUT-',
                disabled=True,
                background_color='#0a0a0a',
                text_color='#00FF00',
                autoscroll=True,
                font=('Consolas', 9)
            )]
        ]
        
        # Action buttons section
        button_section = [
            [
                sg.Button('▶️ START EXTRACTION', key='-START_EXTRACTION-', size=(20, 2),
                         button_color=('#FFFFFF', '#00AA00'), 
                         tooltip='Begin the extraction process'),
                sg.Button('⏹️ CANCEL', key='-CANCEL-', size=(20, 2), disabled=True,
                         button_color=('#FFFFFF', '#AA0000'),
                         tooltip='Stop the extraction'),
                sg.Button('❌ EXIT', key='-EXIT-', size=(20, 2),
                         button_color=('#FFFFFF', '#555555'),
                         tooltip='Close the application')
            ]
        ]
        
        # Main layout
        layout = [
            [sg.Column(header_section)],
            [sg.Text('')],
            [sg.Column(images_section)],
            [sg.Text('')],
            [sg.Column(extraction_section)],
            [sg.Text('')],
            [sg.Column(config_section)],
            [sg.Text('')],
            [sg.Column(summary_section)],
            [sg.Text('')],
            [sg.Column(options_section)],
            [sg.Text('')],
            [sg.Column(progress_section)],
            [sg.Text('')],
            [sg.Column(button_section, justification='center')]
        ]
        
        return layout
    
    def _update_summary(self, window, values):
        """
        Update the extraction summary based on current selections.
        
        Args:
            window: PySimpleGUI window object
            values (dict): Current window values
        """
        summary_lines = []
        
        # Add images info
        if self.image_paths:
            summary_lines.append(f"📁 Images ({len(self.image_paths)}):")
            for i, img in enumerate(self.image_paths, 1):
                summary_lines.append(f"   {i}. {Path(img).name}")
        else:
            summary_lines.append("⚠️  No images selected")
        
        summary_lines.append('')
        
        # Add extraction options
        extraction_modes = []
        if values['-EXTRACT_SAM-']:
            extraction_modes.append('SAM')
        if values['-EXTRACT_SYSTEM-']:
            extraction_modes.append('SYSTEM')
        if values['-EXTRACT_SOFTWARE-']:
            extraction_modes.append('SOFTWARE')
        if values['-EXTRACT_SECURITY-']:
            extraction_modes.append('SECURITY')
        if values['-EXTRACT_NTUSER-']:
            extraction_modes.append('NTUSER.DAT')
        if values['-EXTRACT_ALL-']:
            extraction_modes = ['All Hives (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT)']
        
        if values['-EXTRACT_SPECIFIC-'] and values['-SPECIFIC_FILE_PATH-']:
            extraction_modes.append(f"Specific File: {values['-SPECIFIC_FILE_PATH-']}")
        
        if values['-CONFIG_LIST-']:
            extraction_modes.extend([f"Config: {cfg}" for cfg in values['-CONFIG_LIST-']])
        
        if extraction_modes:
            summary_lines.append("🎯 Extraction Mode:")
            for mode in extraction_modes:
                summary_lines.append(f"   • {mode}")
        else:
            summary_lines.append("⚠️  No extraction options selected")
        
        summary_lines.append('')
        summary_lines.append(f"💾 Output: {values['-OUTPUT_PATH-']}")
        
        summary_text = '\n'.join(summary_lines)
        window['-SUMMARY-'].update(summary_text)
        
        # Update image count
        window['-IMAGE_COUNT-'].update(f'Images selected: {len(self.image_paths)}')
    
    def _add_log_message(self, window, message):
        """
        Add a message to the log output.
        
        Args:
            window: PySimpleGUI window object
            message (str): Message to add
        """
        log_widget = window['-LOG_OUTPUT-']
        current_text = log_widget.get()
        log_widget.update(current_text + message + '\n')
    
    def _validate_extraction_options(self, values) -> bool:
        """
        Validates that at least one extraction option is selected.
        
        Args:
            values (dict): Window values
            
        Returns:
            bool: True if at least one option is selected
        """
        return (values['-EXTRACT_SAM-'] or 
                values['-EXTRACT_SYSTEM-'] or 
                values['-EXTRACT_SOFTWARE-'] or 
                values['-EXTRACT_SECURITY-'] or 
                values['-EXTRACT_NTUSER-'] or 
                values['-EXTRACT_ALL-'] or 
                values['-EXTRACT_SPECIFIC-'] or 
                len(values['-CONFIG_LIST-']) > 0)
    
    def _create_args_object(self, values):
        """
        Create an arguments object from GUI values.
        
        Args:
            values (dict): Window values
            
        Returns:
            object: Arguments object compatible with HiveExCLI
        """
        class Args:
            def __init__(self):
                self.image = values['-IMAGE_LIST-'] if values['-IMAGE_LIST-'] else []
                self.output = values['-OUTPUT_PATH-']
                self.windows = False
                self.sam = values['-EXTRACT_SAM-']
                self.software = values['-EXTRACT_SOFTWARE-']
                self.system = values['-EXTRACT_SYSTEM-']
                self.security = values['-EXTRACT_SECURITY-']
                self.ntuserdat = values['-EXTRACT_NTUSER-']
                self.all = values['-EXTRACT_ALL-']
                self.specific_file = values['-SPECIFIC_FILE_PATH-'] if values['-EXTRACT_SPECIFIC-'] else None
                self.config = values['-CONFIG_LIST-'] if values['-CONFIG_LIST-'] else None
                self.debug = values['-DEBUG_MODE-']
                self.verbose = values['-VERBOSE-']
                self.list_configs = False
                self.configs_path = None
        
        return Args()
    
    def _run_extraction(self, window, args):
        """
        Run the extraction process.
        
        Args:
            window: PySimpleGUI window object
            args: Arguments object
        """
        try:
            window['-STATUS-'].update('Initializing...', text_color='#FFFF00')
            self._add_log_message(window, "[INFO] Starting hive extraction...")
            self._add_log_message(window, f"[INFO] Processing {len(args.image)} image(s)")
            
            cli = HiveExCLI(args)
            cli.run()
            
            window['-STATUS-'].update('Completed successfully!', text_color='#00FF00')
            self._add_log_message(window, "[SUCCESS] Extraction completed successfully!")
            self.is_extracting = False
            
        except RuntimeError as e:
            window['-STATUS-'].update('Error occurred', text_color='#FF0000')
            self._add_log_message(window, f"[ERROR] {str(e)}")
            self.is_extracting = False
        except Exception as e:
            window['-STATUS-'].update('Error occurred', text_color='#FF0000')
            self._add_log_message(window, f"[ERROR] Unexpected error: {str(e)}")
            self.is_extracting = False
    
    def run(self):
        """Main event loop for the GUI."""
        window = sg.Window(
            'HiveEx - Forensic Hive Extraction Tool',
            self.create_layout(),
            finalize=True,
            size=(950, 1100),
            resizable=True
        )
        
        while True:
            event, values = window.read(timeout=100)
            
            # Exit events
            if event in (sg.WINDOW_CLOSED, '-EXIT-'):
                break
            
            # Update summary on value changes
            if event not in (sg.TIMEOUT_EVENT, '-START_EXTRACTION-', '-CANCEL-'):
                self._update_summary(window, values)
            
            # Image management events
            if event == '-BROWSE_IMAGES-':
                file_path = sg.popup_get_file(
                    'Select E01 image file(s)',
                    file_types=(('E01 Images', '*.E01'), ('All Files', '*.*')),
                    multiple_files=True
                )
                if file_path:
                    files = file_path.split(';') if isinstance(file_path, str) else [file_path]
                    self.image_paths.extend(files)
                    window['-IMAGE_LIST-'].update(self.image_paths)
            
            if event == '-ADD_IMAGE-':
                file_path = sg.popup_get_file(
                    'Select E01 image file',
                    file_types=(('E01 Images', '*.E01'), ('All Files', '*.*'))
                )
                if file_path:
                    if file_path not in self.image_paths:
                        self.image_paths.append(file_path)
                        window['-IMAGE_LIST-'].update(self.image_paths)
            
            if event == '-REMOVE_IMAGE-':
                selected = values['-IMAGE_LIST-']
                if selected:
                    self.image_paths.remove(selected[0])
                    window['-IMAGE_LIST-'].update(self.image_paths)
            
            if event == '-CLEAR_IMAGES-':
                if sg.popup_yes_no('Clear all images?', title='Confirm') == 'Yes':
                    self.image_paths = []
                    window['-IMAGE_LIST-'].update(self.image_paths)
            
            # Specific file checkbox event
            if event == '-EXTRACT_SPECIFIC-':
                window['-SPECIFIC_FILE_PATH-'].update(disabled=not values['-EXTRACT_SPECIFIC-'])
            
            # Refresh configurations
            if event == '-REFRESH_CONFIGS-':
                self._load_available_configs()
                window['-CONFIG_LIST-'].update(self.available_configs)
                self._add_log_message(window, f"[INFO] Loaded {len(self.available_configs)} configuration(s)")
            
            # Start extraction
            if event == '-START_EXTRACTION-':
                # Validate images selected
                if not self.image_paths:
                    sg.popup_error('⚠️ Please select at least one image file', title='Validation Error')
                    continue
                
                # Validate extraction options
                if not self._validate_extraction_options(values):
                    sg.popup_error('⚠️ Please select at least one extraction option', title='Validation Error')
                    continue
                
                # Create args object
                args = self._create_args_object(values)
                
                # Validate arguments
                try:
                    validate_arguments(args)
                except RuntimeError as e:
                    sg.popup_error(str(e), title='Validation Error')
                    continue
                
                # Disable buttons and start extraction
                window['-START_EXTRACTION-'].update(disabled=True)
                window['-CANCEL-'].update(disabled=False)
                window['-LOG_OUTPUT-'].update('')
                window['-STATUS-'].update('Extraction in progress...', text_color='#FFFF00')
                
                self.is_extracting = True
                self.extraction_thread = threading.Thread(
                    target=self._run_extraction,
                    args=(window, args),
                    daemon=True
                )
                self.extraction_thread.start()
            
            # Cancel extraction
            if event == '-CANCEL-':
                if self.is_extracting:
                    sg.popup('Extraction cannot be cancelled at this moment', title='Notice')
            
            # Re-enable buttons after extraction
            if not self.is_extracting and self.extraction_thread and not self.extraction_thread.is_alive():
                window['-START_EXTRACTION-'].update(disabled=False)
                window['-CANCEL-'].update(disabled=True)
                self.extraction_thread = None
        
        window.close()


def main():
    """Main entry point for the GUI application."""
    if os.getenv('HIVEX_CONFIGS_PATH'):
        try:
            ConfigHandler.set_config_path(os.getenv('HIVEX_CONFIGS_PATH'))
        except Exception:
            pass
    
    gui = HiveExGUI()
    gui.run()


if __name__ == '__main__':
    main()


class HiveExGUI:
    """Graphical User Interface for HiveEx extraction tool."""
    
    def __init__(self):
        """Initialize the GUI application."""
        self.logger = loggerUtils.getLogger(__name__)
        self.image_paths = []
        self.available_configs = []
        self.extraction_thread = None
        self.is_extracting = False
        self._load_available_configs()
    
    def _load_available_configs(self):
        """Load available hive configurations."""
        try:
            self.available_configs = ConfigHandler.get_available_configs()
            self.logger.info(f"Loaded {len(self.available_configs)} configurations")
        except Exception as e:
            self.logger.error(f"Error loading configurations: {e}")
            self.available_configs = []
    
    def create_layout(self):
        """
        Creates the main window layout.
        
        Returns:
            list: PySimpleGUI layout definition
        """
        # Image selection section
        image_section = [
            [sg.Text('Forensic Images', font=('Consolas', 12, 'bold'))],
            [sg.Listbox(
                values=self.image_paths,
                size=(60, 6),
                key='-IMAGE_LIST-',
                enable_events=True,
                select_mode=sg.LISTBOX_SELECT_MODE_SINGLE
            )],
            [
                sg.Button('📁 Browse Images', key='-BROWSE_IMAGES-'),
                sg.Button('➕ Add Image', key='-ADD_IMAGE-'),
                sg.Button('❌ Remove Image', key='-REMOVE_IMAGE-'),
                sg.Button('🗑️ Clear All', key='-CLEAR_IMAGES-')
            ]
        ]
        
        # Extraction options section
        extraction_section = [
            [sg.Text('Extraction Options', font=('Consolas', 12, 'bold'))],
            [
                sg.Checkbox('SAM', key='-EXTRACT_SAM-'),
                sg.Checkbox('SYSTEM', key='-EXTRACT_SYSTEM-'),
                sg.Checkbox('SOFTWARE', key='-EXTRACT_SOFTWARE-'),
            ],
            [
                sg.Checkbox('SECURITY', key='-EXTRACT_SECURITY-'),
                sg.Checkbox('NTUSER.DAT', key='-EXTRACT_NTUSER-'),
                sg.Checkbox('All Hives', key='-EXTRACT_ALL-'),
            ],
            [sg.Checkbox('Specific File', key='-EXTRACT_SPECIFIC-'),
             sg.Input(key='-SPECIFIC_FILE_PATH-', size=(35, 1), disabled=True)],
        ]
        
        # Configuration section
        config_section = [
            [sg.Text('Configuration Files', font=('Consolas', 12, 'bold'))],
            [
                sg.Listbox(
                    values=self.available_configs,
                    size=(60, 4),
                    key='-CONFIG_LIST-',
                    enable_events=True,
                    select_mode=sg.LISTBOX_SELECT_MODE_MULTIPLE
                )
            ]
        ]
        
        # Output and options section
        options_section = [
            [sg.Text('Output Configuration', font=('Consolas', 12, 'bold'))],
            [
                sg.Text('Output Path:', size=(12, 1)),
                sg.Input(
                    default_text='.',
                    key='-OUTPUT_PATH-',
                    size=(45, 1)
                ),
                sg.FolderBrowse(button_text='📁')
            ],
            [sg.Checkbox('Show Debug Output', key='-DEBUG_MODE-')],
            [sg.Checkbox('Verbose Logging', key='-VERBOSE-')]
        ]
        
        # Progress section
        progress_section = [
            [sg.Text('Progress', font=('Consolas', 12, 'bold'))],
            [sg.ProgressBar(
                100,
                orientation='h',
                size=(60, 20),
                key='-PROGRESS_BAR-',
                bar_color=('green', 'lightgray')
            )],
            [sg.Multiline(
                size=(70, 10),
                key='-LOG_OUTPUT-',
                disabled=True,
                autoscroll=True
            )]
        ]
        
        # Action buttons
        button_section = [
            [
                sg.Button('▶️ Start Extraction', key='-START_EXTRACTION-', size=(15, 2)),
                sg.Button('⏹️ Cancel', key='-CANCEL-', size=(15, 2), disabled=True),
                sg.Button('🔄 Refresh Configs', key='-REFRESH_CONFIGS-', size=(15, 2)),
                sg.Button('❌ Exit', key='-EXIT-', size=(15, 2))
            ]
        ]
        
        # Main layout
        layout = [
            [sg.Text('HiveEx - Forensic Hive Extraction Tool', font=('Consolas', 14, 'bold'), text_color='#00FF00')],
            [sg.Text('=' * 80)],
            [sg.Column(image_section)],
            [sg.Text('=' * 80)],
            [sg.Column(extraction_section)],
            [sg.Text('=' * 80)],
            [sg.Column(config_section)],
            [sg.Text('=' * 80)],
            [sg.Column(options_section)],
            [sg.Text('=' * 80)],
            [sg.Column(progress_section)],
            [sg.Text('=' * 80)],
            [sg.Column(button_section, justification='center')]
        ]
        
        return layout
    
    def _add_log_message(self, window, message):
        """
        Add a message to the log output.
        
        Args:
            window: PySimpleGUI window object
            message (str): Message to add
        """
        log_widget = window['-LOG_OUTPUT-']
        current_text = log_widget.get()
        log_widget.update(current_text + message + '\n')
    
    def _validate_extraction_options(self, values) -> bool:
        """
        Validates that at least one extraction option is selected.
        
        Args:
            values (dict): Window values
            
        Returns:
            bool: True if at least one option is selected
        """
        return (values['-EXTRACT_SAM-'] or 
                values['-EXTRACT_SYSTEM-'] or 
                values['-EXTRACT_SOFTWARE-'] or 
                values['-EXTRACT_SECURITY-'] or 
                values['-EXTRACT_NTUSER-'] or 
                values['-EXTRACT_ALL-'] or 
                values['-EXTRACT_SPECIFIC-'] or 
                len(values['-CONFIG_LIST-']) > 0)
    
    def _create_args_object(self, values):
        """
        Create an arguments object from GUI values.
        
        Args:
            values (dict): Window values
            
        Returns:
            object: Arguments object compatible with HiveExCLI
        """
        class Args:
            def __init__(self):
                self.image = values['-IMAGE_LIST-'] if values['-IMAGE_LIST-'] else []
                self.output = values['-OUTPUT_PATH-']
                self.windows = False  # Not used in GUI directly
                self.sam = values['-EXTRACT_SAM-']
                self.software = values['-EXTRACT_SOFTWARE-']
                self.system = values['-EXTRACT_SYSTEM-']
                self.security = values['-EXTRACT_SECURITY-']
                self.ntuserdat = values['-EXTRACT_NTUSER-']
                self.all = values['-EXTRACT_ALL-']
                self.specific_file = values['-SPECIFIC_FILE_PATH-'] if values['-EXTRACT_SPECIFIC-'] else None
                self.config = values['-CONFIG_LIST-'] if values['-CONFIG_LIST-'] else None
                self.debug = values['-DEBUG_MODE-']
                self.verbose = values['-VERBOSE-']
                self.list_configs = False
                self.configs_path = None
        
        return Args()
    
    def _run_extraction(self, window, args):
        """
        Run the extraction process.
        
        Args:
            window: PySimpleGUI window object
            args: Arguments object
        """
        try:
            self._add_log_message(window, "[INFO] Starting hive extraction...")
            self._add_log_message(window, f"[INFO] Processing {len(args.image)} image(s)")
            
            cli = HiveExCLI(args)
            cli.run()
            
            self._add_log_message(window, "[SUCCESS] Extraction completed successfully!")
            self.is_extracting = False
            
        except RuntimeError as e:
            self._add_log_message(window, f"[ERROR] {str(e)}")
            self.is_extracting = False
        except Exception as e:
            self._add_log_message(window, f"[ERROR] Unexpected error: {str(e)}")
            self.is_extracting = False
    
    def run(self):
        """Main event loop for the GUI."""
        window = sg.Window('HiveEx - Forensic Hive Extraction Tool', self.create_layout(), finalize=True)
        
        while True:
            event, values = window.read(timeout=100)
            
            # Exit events
            if event in (sg.WINDOW_CLOSED, '-EXIT-'):
                break
            
            # Image management events
            if event == '-BROWSE_IMAGES-':
                file_path = sg.popup_get_file(
                    'Select E01 image file(s)',
                    file_types=(('E01 Images', '*.E01'), ('All Files', '*.*')),
                    multiple_files=True
                )
                if file_path:
                    files = file_path.split(';') if isinstance(file_path, str) else [file_path]
                    self.image_paths.extend(files)
                    window['-IMAGE_LIST-'].update(self.image_paths)
            
            if event == '-ADD_IMAGE-':
                file_path = sg.popup_get_file(
                    'Select E01 image file',
                    file_types=(('E01 Images', '*.E01'), ('All Files', '*.*'))
                )
                if file_path:
                    if file_path not in self.image_paths:
                        self.image_paths.append(file_path)
                        window['-IMAGE_LIST-'].update(self.image_paths)
            
            if event == '-REMOVE_IMAGE-':
                selected = values['-IMAGE_LIST-']
                if selected:
                    self.image_paths.remove(selected[0])
                    window['-IMAGE_LIST-'].update(self.image_paths)
            
            if event == '-CLEAR_IMAGES-':
                if sg.popup_yes_no('Clear all images?', title='Confirm') == 'Yes':
                    self.image_paths = []
                    window['-IMAGE_LIST-'].update(self.image_paths)
            
            # Specific file checkbox event
            if event == '-EXTRACT_SPECIFIC-':
                window['-SPECIFIC_FILE_PATH-'].update(disabled=not values['-EXTRACT_SPECIFIC-'])
            
            # Refresh configurations
            if event == '-REFRESH_CONFIGS-':
                self._load_available_configs()
                window['-CONFIG_LIST-'].update(self.available_configs)
                self._add_log_message(window, f"[INFO] Loaded {len(self.available_configs)} configuration(s)")
            
            # Start extraction
            if event == '-START_EXTRACTION-':
                # Validate images selected
                if not self.image_paths:
                    sg.popup_error('Please select at least one image file')
                    continue
                
                # Validate extraction options
                if not self._validate_extraction_options(values):
                    sg.popup_error('Please select at least one extraction option')
                    continue
                
                # Create args object
                args = self._create_args_object(values)
                
                # Validate arguments
                try:
                    validate_arguments(args)
                except RuntimeError as e:
                    sg.popup_error(str(e))
                    continue
                
                # Disable buttons and start extraction
                window['-START_EXTRACTION-'].update(disabled=True)
                window['-CANCEL-'].update(disabled=False)
                window['-LOG_OUTPUT-'].update('')
                
                self.is_extracting = True
                self.extraction_thread = threading.Thread(
                    target=self._run_extraction,
                    args=(window, args),
                    daemon=True
                )
                self.extraction_thread.start()
            
            # Cancel extraction
            if event == '-CANCEL-':
                if self.is_extracting:
                    sg.popup('Extraction cannot be cancelled at this moment', title='Notice')
                    # In a production version, implement proper thread cancellation
            
            # Re-enable buttons after extraction
            if not self.is_extracting and self.extraction_thread and not self.extraction_thread.is_alive():
                window['-START_EXTRACTION-'].update(disabled=False)
                window['-CANCEL-'].update(disabled=True)
                self.extraction_thread = None
        
        window.close()


def main():
    """Main entry point for the GUI application."""
    # Set custom configs path if environment variable is set
    if os.getenv('HIVEX_CONFIGS_PATH'):
        try:
            ConfigHandler.set_config_path(os.getenv('HIVEX_CONFIGS_PATH'))
        except Exception:
            pass
    
    gui = HiveExGUI()
    gui.run()


if __name__ == '__main__':
    main()
