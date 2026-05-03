"""
Module for managing partition processing and extraction.
"""

import pytsk3
from utils import terminalPrint
import utils.loggerUtils as loggerUtils
from hive_types import HivePath
from hive_extractor import HiveExtractor
from user_hive_extractor import UserHiveExtractor
from specific_file_extractor import SpecificFileExtractor


class PartitionProcessor:
    """Processes a partition and coordinates hive extraction."""
    
    def __init__(self, output_path):
        """
        Initializes the partition processor.
        
        Args:
            output_path (str): Output path for extracted files
        """
        self.output_path = output_path
        self.logger = loggerUtils.getLogger(__name__)
    
    def process_partition(self, filesystem, partition_addr, extraction_options):
        """
        Processes a partition and extracts hives based on options.
        
        Args:
            filesystem: pytsk3 filesystem object
            partition_addr: Partition address
            extraction_options: ExtractionOptions object
        """
        self.logger.debug(f"Partition #{partition_addr}: Starting processing")
        
        if filesystem.info.ftype != pytsk3.TSK_FS_TYPE_NTFS:
            self.logger.info(f"Partition #{partition_addr}: Not NTFS filesystem, skipping")
            return
        
        try:
            self._check_and_extract(filesystem, partition_addr, extraction_options)
        except IOError as e:
            self.logger.error(f"Error reading files on partition {partition_addr}: {e}")
        except Exception as e:
            self.logger.error(f"Error processing partition {partition_addr}: {e}")
        finally:
            self.logger.debug(f"Partition #{partition_addr}: Processing completed")
    
    def _check_and_extract(self, filesystem, partition_addr, extraction_options):
        """
        Checks folders and extracts files based on options.
        
        Args:
            filesystem: pytsk3 filesystem object
            partition_addr: Partition address
            extraction_options: ExtractionOptions object
        """
        self.logger.debug("[_check_and_extract] Starting")
        
        # Extract specific file if requested
        if extraction_options.should_extract_specific_file():
            self._extract_specific_file(filesystem, partition_addr, extraction_options)
        
        # Check for /Users/ and /Windows/ folders
        exists_users, exists_windows = self._check_folders_existence(filesystem)
        
        # Extract NTUSER.DAT from users
        if exists_users and extraction_options.should_extract_ntuser_dat():
            self.logger.info(f"Partition #{partition_addr}: Found /Users/ path")
            user_extractor = UserHiveExtractor(filesystem, partition_addr, self.output_path)
            user_extractor.extract_all_users_hives()
        else:
            self.logger.info(f"Partition #{partition_addr}: /Users/ path not found or extraction not requested")
        
        # Extract Windows hives
        if exists_windows and extraction_options.should_extract_windows_hives():
            self.logger.info(f"Partition #{partition_addr}: Found /Windows/ path")
            hive_extractor = HiveExtractor(filesystem, partition_addr, self.output_path)
            hives = extraction_options.get_windows_hives_to_extract()
            if hives:
                hive_extractor.extract_windows_hives(hives)
        else:
            self.logger.info(f"Partition #{partition_addr}: /Windows/ path not found or no hives selected")
        
        self.logger.debug("[_check_and_extract] Completed")
    
    def _extract_specific_file(self, filesystem, partition_addr, extraction_options):
        """
        Extracts a specific file.
        
        Args:
            filesystem: pytsk3 filesystem object
            partition_addr: Partition address
            extraction_options: ExtractionOptions object
        """
        self.logger.debug("[_extract_specific_file] Starting")
        file_extractor = SpecificFileExtractor(filesystem, partition_addr, self.output_path)
        file_extractor.extract_file(extraction_options.specific_file_path)
        self.logger.debug("[_extract_specific_file] Completed")
    
    def _check_folders_existence(self, filesystem):
        """
        Checks if /Users/ and /Windows/ folders exist.
        
        Args:
            filesystem: pytsk3 filesystem object
            
        Returns:
            tuple: (exists_users, exists_windows)
        """
        try:
            directories = filesystem.open_dir("/")
            folder_names = [entry.info.name.name.decode('utf-8') for entry in directories]
            
            exists_users = "Users" in folder_names
            exists_windows = "Windows" in folder_names
            
            return exists_users, exists_windows
        except Exception as e:
            self.logger.error(f"Error checking folders: {e}")
            return False, False
