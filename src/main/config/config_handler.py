"""
Config handler for HiveEx - Manages hive extraction based on configuration files.
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Any

from utils import loggerUtils, terminalPrint
from hives_configs import HivesConfigLoader

logger = loggerUtils.getLogger(__name__)


class ConfigHandler:
    """Handles hive extraction configuration similar to RegRipper with configurable paths."""
    
    @staticmethod
    def set_config_path(config_path: str) -> None:
        """
        Set custom configuration path for hive definitions.
        
        Args:
            config_path: Directory path containing YAML hive configurations
        """
        try:
            HivesConfigLoader.set_config_directory(config_path)
        except ValueError as e:
            logger.error(f'Failed to set config path: {str(e)}')
            terminalPrint.printError(f'Failed to set config path: {str(e)}')
            raise
    
    @staticmethod
    def load_config(config_name_or_path: str) -> Optional[Dict[str, Any]]:
        """
        Load a hive configuration by name or file path.
        
        Args:
            config_name_or_path: Either a hive name (e.g., 'sam') or path to YAML config file.
        
        Returns:
            Configuration dictionary or None if not found or invalid.
        """
        config_path = Path(config_name_or_path)
        
        # If it's a full path, load from that path
        if config_path.is_absolute() and config_path.exists():
            return ConfigHandler._load_from_file(config_path)
        
        # Otherwise, try to load from hives_configs by name
        config = HivesConfigLoader.load_config_by_name(config_name_or_path)
        if config:
            return config
        
        # Try with .yaml or .yml extension if passed as file path
        for ext in ['.yaml', '.yml']:
            yaml_path = Path(config_name_or_path + ext)
            if yaml_path.exists():
                return ConfigHandler._load_from_file(yaml_path)
        
        logger.error(f'Configuration not found: {config_name_or_path}')
        terminalPrint.printError(f'Configuration not found: {config_name_or_path}')
        return None
    
    @staticmethod
    def _load_from_file(file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Load configuration from a specific file path.
        
        Args:
            file_path: Path to the YAML configuration file.
        
        Returns:
            Configuration dictionary or None if invalid.
        """
        try:
            is_valid, msg = HivesConfigLoader.validate_config_file(str(file_path))
            if not is_valid:
                logger.error(f'Configuration validation failed: {msg}')
                terminalPrint.printError(f'Configuration validation failed: {msg}')
                return None
            
            return HivesConfigLoader._load_single_config(file_path)
        except Exception as e:
            logger.error(f'Error loading configuration from {file_path}: {str(e)}')
            terminalPrint.printError(f'Error loading configuration from {file_path}: {str(e)}')
            return None
    
    @staticmethod
    def get_available_configs() -> List[str]:
        """
        Get list of all available hive configurations.
        
        Returns:
            List of available configuration names.
        """
        configs = HivesConfigLoader.load_all_configs()
        return list(configs.keys())
    
    @staticmethod
    def list_available_configs() -> None:
        """Display all available hive configurations."""
        configs = ConfigHandler.get_available_configs()
        
        if not configs:
            terminalPrint.printWarn('No hive configurations found')
            return
        
        terminalPrint.printInfo('Available hive configurations:')
        for config_name in sorted(configs):
            print(f'  - {config_name}')


__all__ = ['ConfigHandler']
