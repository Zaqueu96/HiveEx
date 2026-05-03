"""
HiveEx - Hive extraction tool from forensic images.

Main submodules:
    - config: Configuration and options management
    - core: Core functionality (types, partition processor)
    - extractors: Hive extraction implementations
    - image: Image file handling
    - utils: Utility functions (logging, terminal output, file operations)
"""

# Core exports
from .core import HiveType, HivePath
from .config import ConfigValidator, ExtractionOptions
from .image import ImageHandler, EWFImgInfo
from .extractors import HiveExtractor, UserHiveExtractor, SpecificFileExtractor

__version__ = "1.0.0"
__author__ = "HiveEx Contributors"

__all__ = [
    'HiveType',
    'HivePath',
    'ConfigValidator',
    'ExtractionOptions',
    'ImageHandler',
    'EWFImgInfo',
    'HiveExtractor',
    'UserHiveExtractor',
    'SpecificFileExtractor',
]

