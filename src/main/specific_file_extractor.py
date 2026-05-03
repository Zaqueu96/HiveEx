"""
Module for extracting specific files from the image.
"""

from utils.fileObjectUtils import FileObjectUtils
from utils import terminalPrint
import utils.loggerUtils as loggerUtils
from hive_types import HivePath
import pytsk3


class SpecificFileExtractor:
    """Responsible for extracting specific files with support for user path placeholders."""
    
    def __init__(self, pytsk_filesystem, partition_addr, output_path):
        """
        Initializes the specific file extractor.
        
        Args:
            pytsk_filesystem: pytsk3 filesystem object
            partition_addr: Partition address
            output_path: Output path for extracted files
        """
        self.pyTskFileSystem = pytsk_filesystem
        self.partitionAddr = partition_addr
        self.outputPath = output_path
        self.logger = loggerUtils.getLogger(__name__)
    
    def extract_file(self, path_template):
        """
        Extracts a specific file, supporting [user] placeholder.
        
        Args:
            path_template (str): Path template for the file (can include [user] placeholder)
        """
        self.logger.debug(f"Partition #{self.partitionAddr}: [extract_file] Starting - searching in {path_template}")
        self.logger.info(f"Partition #{self.partitionAddr}: Searching in {path_template}")
        terminalPrint.printInfo(f"Partition #{self.partitionAddr}: Searching in {path_template}")
        
        try:
            if "[user]" not in path_template:
                self._extract_file_direct(path_template)
            else:
                self._extract_file_for_all_users(path_template)
        except Exception as e:
            if "path not found" in str(e) and "/Users/" in str(e):
                terminalPrint.printWarn(f"Partition #{self.partitionAddr}: /Users/ folder not found")
            else:
                self.logger.info('Unexpected error while searching for the file')
                self.logger.error("Error during file search", e)
                terminalPrint.printError(f"Partition #{self.partitionAddr}: Unexpected error while searching for the file")
        finally:
            self.logger.debug(f"Partition #{self.partitionAddr}: [extract_file] Completed")
    
    def _extract_file_direct(self, file_path):
        """
        Extracts a file directly without user placeholder.
        
        Args:
            file_path (str): Full path to the file
        """
        try:
            fileObject = self.pyTskFileSystem.open(file_path)
            objectUtils = FileObjectUtils(fileObject, self.outputPath)
            terminalPrint.printInfo(f"Partition #{self.partitionAddr}: File found at {file_path}")
            self.logger.info(f"Partition #{self.partitionAddr}: File found at {file_path}")
            objectUtils.fileExtract()
            terminalPrint.printSuccess(f"Partition #{self.partitionAddr}: Extracted {file_path}")
        except IOError:
            terminalPrint.printWarn(f"Partition #{self.partitionAddr}: File not found at {file_path}")
            self.logger.info(f"Partition #{self.partitionAddr}: File not found at {file_path}")
    
    def _extract_file_for_all_users(self, path_template):
        """
        Extracts a file for all users, replacing [user] placeholder.
        
        Args:
            path_template (str): Path template with [user] placeholder
        """
        try:
            users = self._get_users_list()
            for user in users:
                user_specific_path = path_template.replace("[user]", user)
                self._try_extract_user_file(user_specific_path)
        except IOError as e:
            self.logger.error(f"Error accessing /Users/ folder: {e}")
            raise
    
    def _try_extract_user_file(self, file_path):
        """
        Tries to extract a file for a specific user.
        
        Args:
            file_path (str): Full path to the file
        """
        try:
            fileObject = self.pyTskFileSystem.open(file_path)
            objectUtils = FileObjectUtils(fileObject, self.outputPath)
            terminalPrint.printInfo(f"Partition #{self.partitionAddr}: File found at {file_path}")
            self.logger.info(f"Partition #{self.partitionAddr}: File found at {file_path}")
            objectUtils.fileExtract()
            terminalPrint.printSuccess(f"Partition #{self.partitionAddr}: Extracted {file_path}")
        except Exception as e:
            if "path not found" in str(e):
                terminalPrint.printWarn(f"Partition #{self.partitionAddr}: File not found at {file_path}")
                self.logger.info(f"Partition #{self.partitionAddr}: File not found at {file_path}")
            else:
                raise e
    
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
