"""
Module for validating file paths and permissions.
"""

import os
import sys
from utils import terminalPrint
import utils.loggerUtils as loggerUtils


class ConfigValidator:
    """Responsible for validating input and output configurations."""
    
    def __init__(self):
        self.logger = loggerUtils.getLogger(__name__)
    
    def validate_image_path(self, image_path):
        """
        Validates if the image path exists and is a valid file.
        
        Args:
            image_path (str): Path to the E01 image file
            
        Raises:
            RuntimeError: If the path is not valid
        """
        self.logger.debug(f"[validate_image_path] Checking file: {image_path}")
        self.logger.info(f"Checking if is file: {image_path}")
        
        if os.path.isfile(path=image_path):
            self.logger.info(f"File verified: {image_path}")
        else:
            self.logger.info("Verification failed, path is not a file")
            raise RuntimeError("Error: imagePath does not contain a valid file")
    
    def validate_output_path_permission(self, output_path):
        """
        Validates if there is write permission in the output directory.
        
        Args:
            output_path (str): Path to the output directory
            
        Raises:
            SystemExit: If there is no write permission
        """
        try:            
            output_file_verify = os.path.join(output_path, "verify.txt")
            with open(output_file_verify, 'w') as file:
                 file.write("permission check")
            os.remove(output_file_verify)
            self.logger.info(f"Write permission verified in: {output_path}")
        except IOError:
            terminalPrint.printError(f"Permission denied in output path: {output_path}")
            self.logger.error(f"Permission denied in output path: {output_path}")
            sys.exit()
