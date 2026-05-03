"""
Module for extracting Windows hives.
"""

from utils.fileObjectUtils import FileObjectUtils
from utils import terminalPrint
from utils import loggerUtils
from core import HivePath


class HiveExtractor:
    """Responsible for extracting Windows hives (SYSTEM, SOFTWARE, SAM, SECURITY)."""
    
    def __init__(self, pytsk_filesystem, partition_addr, output_path):
        """
        Initializes the hive extractor.
        
        Args:
            pytsk_filesystem: pytsk3 filesystem object
            partition_addr: Partition address
            output_path: Output path for extracted files
        """
        self.pyTskFileSystem = pytsk_filesystem
        self.partitionAddr = partition_addr
        self.outputPath = output_path
        self.logger = loggerUtils.getLogger(__name__)
    
    def extract_windows_hives(self, hives_dict):
        """
        Extracts multiple Windows hives.
        
        Args:
            hives_dict (dict): Dictionary with name:path of hives to extract
        """
        self.logger.debug("[extract_windows_hives] Starting extraction")
        try:
            for hive_name, hive_path in hives_dict.items():
                self._extract_single_hive(hive_name, hive_path)
        except Exception as e:
            self.logger.info('Unexpected error while trying to extract hives')
            self.logger.error("Error in hive extraction", e)
            raise e
        finally:
            self.logger.debug("[extract_windows_hives] Extraction completed")
    
    def _extract_single_hive(self, hive_name, hive_path):
        """
        Extracts a specific hive.
        
        Args:
            hive_name (str): Hive name
            hive_path (str): Path to the hive in the image
        """
        terminalPrint.printInfo(f"Extracting hive {hive_name}...")
        self.logger.debug(f"Name: {hive_name}, Path: {hive_path}")
        
        try:
            fileObject = self.pyTskFileSystem.open(path=hive_path)
            objectUtils = FileObjectUtils(
                fileObject=fileObject,
                outputPath=self.outputPath,
                prefixName=f"partition_{self.partitionAddr}"
            )
            
            md5_digest, sha1_digest, sha256_digest = objectUtils.fileCalculateHash()
            self.logger.info(f"Hive: {hive_name}")
            self.logger.info(f"MD5: {md5_digest}")
            self.logger.info(f"SHA-1: {sha1_digest}")
            self.logger.info(f"SHA-256: {sha256_digest}")
            
            objectUtils.fileExtract()
            terminalPrint.printSuccess(f"Hive {hive_name} extracted successfully")
        except IOError as e:
            self.logger.error(f"Error extracting hive {hive_name}: {e}")
            terminalPrint.printError(f"Error extracting hive {hive_name}")
            raise
