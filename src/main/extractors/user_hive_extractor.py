"""
Module for extracting user hives (NTUSER.DAT).
"""

import pytsk3
from tenacity import retry, stop_after_attempt, wait_fixed
from utils.fileObjectUtils import FileObjectUtils
from utils import terminalPrint
from utils import loggerUtils
from core import HivePath


class UserHiveExtractor:
    """Responsible for extracting user hives (NTUSER.DAT)."""
    
    def __init__(self, pytsk_filesystem, partition_addr, output_path):
        """
        Initializes the user hive extractor.
        
        Args:
            pytsk_filesystem: pytsk3 filesystem object
            partition_addr: Partition address
            output_path: Output path for extracted files
        """
        self.pyTskFileSystem = pytsk_filesystem
        self.partitionAddr = partition_addr
        self.outputPath = output_path
        self.logger = loggerUtils.getLogger(__name__)
    
    @retry(stop=stop_after_attempt(1), wait=wait_fixed(1))
    def extract_all_users_hives(self):
        """
        Extracts NTUSER.DAT from all users found in /Users/.
        """
        self.logger.debug("[extract_all_users_hives] Starting")
        self.logger.info("Checking folders in /Users/")
        terminalPrint.printInfo("Checking folders in /Users/")
        
        try:
            users = self._get_users_list()
            for user in users:
                self._extract_user_hive(user)
        except Exception as e:
            self.logger.info('Unexpected error while trying to extract NTUSER.dat from users')
            self.logger.error("Error checking folders", e)
            terminalPrint.printError("Unexpected error while trying to extract NTUSER.dat from users")
            raise e
        finally:
            self.logger.debug("[extract_all_users_hives] Completed")
    
    def _get_users_list(self):
        """
        Gets list of users from /Users/ folder.
        
        Returns:
            list: List of user names
        """
        users = []
        directoryListUsers = self.pyTskFileSystem.open_dir(path=HivePath.USERS_PATH)
        
        for entry in directoryListUsers:
            entry_name = entry.info.name.name.decode('utf-8')
            if (entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR and 
                entry_name not in HivePath.NOT_IN_FOLDERS):
                users.append(entry_name)
        
        return users
    
    def _extract_user_hive(self, user_name):
        """
        Extracts NTUSER.DAT from a specific user.
        
        Args:
            user_name (str): User name
        """
        terminalPrint.printInfo(f"Processing user folder: {user_name}")
        self.logger.debug(f"Processing user: {user_name}")
        
        try:
            user_path = f"{HivePath.USERS_PATH}{user_name}"
            directory_by_user = self.pyTskFileSystem.open_dir(path=user_path)
            list_directories = [entry.info.name.name.decode('utf-8') for entry in directory_by_user]
            
            if HivePath.NTUSER_DAT in list_directories:
                terminalPrint.printInfo(f"Found NTUSER.DAT for user: {user_name}")
                self._read_and_extract_ntuser_dat(user_name)
            else:
                terminalPrint.printWarn(f"NTUSER.DAT not found for user: {user_name}")
                self.logger.info(f"NTUSER.DAT not found for user: {user_name}")
        except IOError as e:
            self.logger.error(f"Error accessing user folder {user_name}: {e}")
    
    @retry(stop=stop_after_attempt(2), wait=wait_fixed(1))
    def _read_and_extract_ntuser_dat(self, user_name):
        """
        Reads and extracts NTUSER.DAT file from a user.
        
        Args:
            user_name (str): User name
        """
        terminalPrint.printInfo(f"Reading and extracting NTUSER.DAT for user: {user_name}")
        self.logger.debug(f"Extracting NTUSER.DAT for: {user_name}")
        
        try:
            file_path = f"{HivePath.USERS_PATH}{user_name}/{HivePath.NTUSER_DAT}"
            fileObject = self.pyTskFileSystem.open(file_path)
            objectUtils = FileObjectUtils(
                fileObject,
                self.outputPath,
                f"partition_{self.partitionAddr}_{user_name}"
            )
            
            md5_digest, sha1_digest, sha256_digest = objectUtils.fileCalculateHash()
            self.logger.info(f"User: {user_name}")
            self.logger.info(f"MD5: {md5_digest}")
            self.logger.info(f"SHA-1: {sha1_digest}")
            self.logger.info(f"SHA-256: {sha256_digest}")
            
            objectUtils.fileExtract()
            terminalPrint.printSuccess(f"NTUSER.DAT extracted for user: {user_name}")
        except IOError as e:
            self.logger.error(f"Error extracting NTUSER.DAT for {user_name}: {e}")
            raise
