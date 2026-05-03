"""
Module for managing hive extraction options.
"""

from core import HiveType, HivePath
from utils import terminalPrint
from utils import loggerUtils


class ExtractionOptions:
    """Manages hive extraction options based on command-line arguments."""
    
    def __init__(self):
        """Initializes extraction options."""
        self.logger = loggerUtils.getLogger(__name__)
        self.extract_all_windows = False
        self.extract_system = False
        self.extract_software = False
        self.extract_sam = False
        self.extract_security = False
        self.extract_ntuser_dat = False
        self.extract_specific_file = False
        self.specific_file_path = None
        self.hive_configs = {}  # Stores loaded hive configurations
    
    def configure_from_arguments(self, args):
        """
        Configures extraction options from command-line arguments.
        
        Args:
            args: argparse arguments object
            
        Raises:
            RuntimeError: If no extraction option is specified
        """
        # Process config files if provided
        if hasattr(args, 'config') and args.config and len(args.config) > 0:
            self.logger.info(f"Processing {len(args.config)} configuration(s): {args.config}")
            self._process_configs(args.config)
            # If configs were loaded successfully, we're done
            if self.hive_configs:
                terminalPrint.printSuccess(f"Loaded {len(self.hive_configs)} hive configuration(s)")
                return
            # If configs failed to load, raise error
            else:
                raise RuntimeError('Failed to load any hive configurations')
        
        self.extract_ntuser_dat = args.ntuserdat
        
        if args.all:
            self.extract_all_windows = True
            self.extract_ntuser_dat = True
            self.logger.info("All hives will be extracted")
            terminalPrint.printSuccess("Extraction mode: All hives (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT)")
            return
        
        if args.specific_file:
            self.extract_specific_file = True
            self.specific_file_path = args.specific_file
            self.logger.info(f"Specific file extraction enabled: {args.specific_file}")
            terminalPrint.printSuccess(f"Extraction mode: Specific file ({args.specific_file})")
            return
        
        if args.windows:
            self.extract_all_windows = True
            self.logger.info("All Windows hives will be extracted")
            terminalPrint.printSuccess("Extraction mode: All Windows hives (SAM, SYSTEM, SOFTWARE, SECURITY)")
        else:
            hive_specified = False
            extraction_modes = []
            
            if args.system:
                self.extract_system = True
                hive_specified = True
                extraction_modes.append("SYSTEM")
            
            if args.software:
                self.extract_software = True
                hive_specified = True
                extraction_modes.append("SOFTWARE")
            
            if args.sam:
                self.extract_sam = True
                hive_specified = True
                extraction_modes.append("SAM")
            
            if args.security:
                self.extract_security = True
                hive_specified = True
                extraction_modes.append("SECURITY")
            
            if self.extract_ntuser_dat:
                extraction_modes.append("NTUSER.DAT")
            
            if not hive_specified and not self.extract_ntuser_dat:
                terminalPrint.printError('At least one hive extraction option must be specified')
                terminalPrint.printInfo('Available options:')
                print('  --windows (-ws)        : Extract all Windows hives')
                print('  --sam (-sm)            : Extract SAM hive')
                print('  --system (-sys)        : Extract SYSTEM hive')
                print('  --software (-sfw)      : Extract SOFTWARE hive')
                print('  --security (-sec)      : Extract SECURITY hive')
                print('  --ntuserdat (-n)       : Extract NTUSER.DAT from all users')
                print('  --config (-cfg)        : Extract hive from configuration file')
                print('  --all (-a)             : Extract all hives')
                print('  --specific-file        : Extract a specific file from the image')
                raise RuntimeError('No hive extraction option specified')
            
            if extraction_modes:
                terminalPrint.printSuccess(f"Extraction mode: {', '.join(extraction_modes)}")
                self.logger.info(f"Extraction modes selected: {extraction_modes}")
    
    def _process_configs(self, config_list):
        """
        Process configuration files loaded from --config argument.
        
        Args:
            config_list: List of configuration names or file paths
        """
        from config import ConfigHandler
        
        for config_name in config_list:
            config = ConfigHandler.load_config(config_name)
            if config:
                hive_name = config.get('name', config_name)
                self.hive_configs[hive_name] = config
                self.logger.info(f"Loaded configuration for hive: {hive_name}")
        
        if not self.hive_configs:
            terminalPrint.printError('No valid hive configurations were loaded')
            raise RuntimeError('Failed to load any hive configurations')
    
    def get_windows_hives_to_extract(self):
        """
        Gets dictionary of Windows hives to extract.
        
        Returns:
            dict: Dictionary with hive_name: hive_path
        """
        # If configs are loaded, use them instead
        if self.hive_configs:
            hives = {}
            for hive_name, config in self.hive_configs.items():
                hives[hive_name] = config.get('path', '')
            return hives
        
        hives = {}
        
        if self.extract_all_windows:
            return HivePath.HIVES.copy()
        
        if self.extract_system:
            hives['SYSTEM'] = HivePath.HIVES['SYSTEM']
        
        if self.extract_software:
            hives['SOFTWARE'] = HivePath.HIVES['SOFTWARE']
        
        if self.extract_sam:
            hives['SAM'] = HivePath.HIVES['SAM']
        
        if self.extract_security:
            hives['SECURITY'] = HivePath.HIVES['SECURITY']
        
        return hives
    
    def should_extract_ntuser_dat(self):
        """
        Checks if NTUSER.DAT should be extracted.
        
        Returns:
            bool: True if NTUSER.DAT should be extracted
        """
        return self.extract_ntuser_dat
    
    def should_extract_windows_hives(self):
        """
        Checks if Windows hives should be extracted.
        
        Returns:
            bool: True if any Windows hive should be extracted
        """
        return (self.extract_all_windows or self.extract_system or 
                self.extract_software or self.extract_sam or self.extract_security)
    
    def should_extract_specific_file(self):
        """
        Checks if a specific file should be extracted.
        
        Returns:
            bool: True if specific file extraction is enabled
        """
        return self.extract_specific_file
    
    def has_config_based_extraction(self):
        """
        Checks if extraction is based on configuration files.
        
        Returns:
            bool: True if hive configs are loaded
        """
        return bool(self.hive_configs)
    
    def get_hive_configs(self):
        """
        Gets loaded hive configurations.
        
        Returns:
            dict: Dictionary of loaded hive configurations
        """
        return self.hive_configs
