"""
Config module for HiveEx - Configuration and options management.
"""

import sys
import os

# Add project root to path before importing config_handler
# so it can find hives_configs module
_current_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(_current_dir)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from .config_validator import ConfigValidator
from .extraction_options import ExtractionOptions
from .config_handler import ConfigHandler

__all__ = ['ConfigValidator', 'ExtractionOptions', 'ConfigHandler']
