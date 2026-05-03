"""
Module for handling EWF image and filesystem access.
"""

import pyewf
import pytsk3
from utils import terminalPrint
import utils.loggerUtils as loggerUtils


class ImageHandler:
    """Handles EWF image opening and filesystem access."""
    
    def __init__(self, image_path):
        """
        Initializes the image handler.
        
        Args:
            image_path (str): Path to the EWF image file
        """
        self.image_path = image_path
        self.logger = loggerUtils.getLogger(__name__)
        self.ewf_handle = None
        self.img_info = None
    
    def open_image(self):
        """
        Opens the EWF image file.
        
        Raises:
            IOError: If image cannot be opened
            pyewf.error: If EWF library error occurs
        """
        try:
            self.logger.info(f"Opening image: {self.image_path}")
            filenames = pyewf.glob(self.image_path)
            self.ewf_handle = pyewf.handle()
            self.ewf_handle.open(filenames)
            self.img_info = EWFImgInfo(self.ewf_handle)
            self.logger.info("Image opened successfully")
        except IOError as e:
            self.logger.info("Error opening E01 image")
            self.logger.error(f"Error opening E01 image: {e}")
            raise
        except pyewf.error as e:
            self.logger.error(f"Error with pyewf library: {e}")
            raise
    
    def close_image(self):
        """Closes the EWF image file."""
        if self.ewf_handle:
            self.ewf_handle.close()
            self.logger.info("Image closed")
    
    def get_partition_table(self):
        """
        Gets partition table from the image.
        
        Returns:
            pytsk3.Volume_Info: Partition table object
            
        Raises:
            IOError: If partition table cannot be accessed
        """
        try:
            partition_table = pytsk3.Volume_Info(self.img_info)
            self.logger.info(f"Found {partition_table.info.part_count} partitions")
            return partition_table
        except IOError as e:
            self.logger.error(f"Error accessing partition table: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error accessing partition table: {e}")
            raise
    
    def get_filesystem(self, partition):
        """
        Gets filesystem from a partition.
        
        Args:
            partition: pytsk3 partition object
            
        Returns:
            pytsk3.FS_Info: Filesystem object
            
        Raises:
            IOError: If filesystem cannot be read
        """
        try:
            filesystem = pytsk3.FS_Info(self.img_info, offset=partition.start * 512)
            self.logger.info(f"Filesystem opened for partition {partition.addr}")
            return filesystem
        except IOError as e:
            self.logger.error(f"Error reading filesystem on partition {partition.addr}: {e}")
            raise
    
    def __enter__(self):
        """Context manager entry."""
        self.open_image()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close_image()


class EWFImgInfo(pytsk3.Img_Info):
    """Custom image info class for EWF files."""
    
    def __init__(self, ewf_handle):
        """
        Initializes EWF image info.
        
        Args:
            ewf_handle: pyewf handle object
        """
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    
    def read(self, offset, size):
        """
        Reads data from the image.
        
        Args:
            offset: Byte offset to read from
            size: Number of bytes to read
            
        Returns:
            bytes: Data read from image
        """
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)
    
    def get_size(self):
        """
        Gets the size of the image.
        
        Returns:
            int: Size of the image in bytes
        """
        return self._ewf_handle.get_media_size()
