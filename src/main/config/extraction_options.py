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
    
    def configure_from_arguments(self, args):
        """
        Configures extraction options from command-line arguments.
        
        Args:
            args: argparse arguments object
            
        Raises:
            RuntimeError: If no extraction option is specified
        """
        self.extract_ntuser_dat = args.ntuserdat
        
        if args.all:
            self.extract_all_windows = True
            self.extract_ntuser_dat = True
            self.logger.info("All hives will be extracted")
            return
        
        if args.specific_file:
            self.extract_specific_file = True
            self.specific_file_path = args.specific_file
            self.logger.info(f"Specific file extraction enabled: {args.specific_file}")
            terminalPrint.printWarn("Skipping hive type flags (--windows, --ntuserdat, --sam, --software, --system, --security) because --specific-file is set")
            return
        
        if args.windows:
            self.extract_all_windows = True
            self.logger.info("All Windows hives will be extracted")
        else:
            hive_specified = False
            
            if args.system:
                self.extract_system = True
                hive_specified = True
            
            if args.software:
                self.extract_software = True
                hive_specified = True
            
            if args.sam:
                self.extract_sam = True
                hive_specified = True
            
            if args.security:
                self.extract_security = True
                hive_specified = True
            
            if not hive_specified and not self.extract_ntuser_dat:
                terminalPrint.printError('At least one hive extraction option must be specified (--windows, --ntuserdat, --sam, --software, --system, --security)')
                raise RuntimeError('No hive extraction option specified')
    
    def get_windows_hives_to_extract(self):
        """
        Gets dictionary of Windows hives to extract.
        
        Returns:
            dict: Dictionary with hive_name: hive_path
        """
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
