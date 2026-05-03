"""
Hives configuration module for HiveEx - Loads and manages hive configurations from YAML files.
"""

import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional
import sys

# Add main directory to path to allow imports from sibling packages
main_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src', 'main')
sys.path.insert(0, main_dir)

from utils import loggerUtils

logger = loggerUtils.getLogger(__name__)


class HivesConfigLoader:
    """Loads and validates hive configuration files from YAML."""

    REQUIRED_FIELDS = {'name', 'path', 'description', 'author', 'created_at', 'updated_at'}
    CONFIG_DIR = Path(__file__).parent

    @classmethod
    def load_all_configs(cls) -> Dict[str, Dict[str, Any]]:
        """
        Load all hive configuration files from the hives_configs directory.
        
        Returns:
            Dictionary with hive name as key and configuration as value.
            Only includes valid configurations; invalid ones are logged and skipped.
        """
        configs = {}
        
        # Find all YAML files in the configs directory
        yaml_files = list(cls.CONFIG_DIR.glob('*.yaml')) + list(cls.CONFIG_DIR.glob('*.yml'))
        
        if not yaml_files:
            logger.warning('No hive configuration files found in hives_configs directory')
            return configs
        
        for yaml_file in yaml_files:
            try:
                config = cls._load_single_config(yaml_file)
                if config:
                    hive_name = config.get('name', yaml_file.stem)
                    configs[hive_name] = config
                    logger.debug(f'Loaded hive configuration: {hive_name}')
            except Exception as e:
                logger.error(f'Error loading configuration from {yaml_file.name}: {str(e)}')
                continue
        
        return configs

    @classmethod
    def load_config_by_name(cls, hive_name: str) -> Optional[Dict[str, Any]]:
        """
        Load a specific hive configuration by name.
        
        Args:
            hive_name: Name of the hive configuration file (without .yaml/.yml extension).
        
        Returns:
            Configuration dictionary or None if not found or invalid.
        """
        # Try both .yaml and .yml extensions
        config_file = cls.CONFIG_DIR / f'{hive_name}.yaml'
        if not config_file.exists():
            config_file = cls.CONFIG_DIR / f'{hive_name}.yml'
        
        if not config_file.exists():
            logger.warning(f'Configuration file not found: {hive_name}.yaml or {hive_name}.yml')
            return None
        
        try:
            return cls._load_single_config(config_file)
        except Exception as e:
            logger.error(f'Error loading configuration for {hive_name}: {str(e)}')
            return None

    @classmethod
    def _load_single_config(cls, config_file: Path) -> Optional[Dict[str, Any]]:
        """
        Load and validate a single configuration file.
        
        Args:
            config_file: Path to the YAML configuration file.
        
        Returns:
            Validated configuration dictionary or None if invalid.
        
        Raises:
            YAML parsing errors or validation errors.
        """
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        if config is None:
            raise ValueError('Configuration file is empty')
        
        # Validate required fields
        missing_fields = cls.REQUIRED_FIELDS - set(config.keys())
        if missing_fields:
            raise ValueError(f'Missing required fields: {", ".join(missing_fields)}')
        
        # Validate that path is a string
        if not isinstance(config.get('path'), str):
            raise ValueError('Field "path" must be a string')
        
        # Validate that name is a string
        if not isinstance(config.get('name'), str):
            raise ValueError('Field "name" must be a string')
        
        return config

    @classmethod
    def get_all_hive_paths(cls) -> Dict[str, str]:
        """
        Get all hive names and their paths from configuration.
        
        Returns:
            Dictionary with hive name as key and path as value.
        """
        configs = cls.load_all_configs()
        return {name: config.get('path', '') for name, config in configs.items()}

    @classmethod
    def validate_config_file(cls, file_path: str) -> tuple[bool, str]:
        """
        Validate a configuration file without loading it into the system.
        
        Args:
            file_path: Path to the YAML configuration file.
        
        Returns:
            Tuple of (is_valid, message).
        """
        try:
            config_file = Path(file_path)
            if not config_file.exists():
                return False, f'Configuration file not found: {file_path}'
            
            cls._load_single_config(config_file)
            return True, 'Configuration is valid'
        except yaml.YAMLError as e:
            return False, f'Invalid YAML format: {str(e)}'
        except ValueError as e:
            return False, f'Validation error: {str(e)}'
        except Exception as e:
            return False, f'Unexpected error: {str(e)}'


__all__ = ['HivesConfigLoader']
