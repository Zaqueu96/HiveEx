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
    """Loads and validates hive configuration files from YAML with configurable path."""

    REQUIRED_FIELDS = {'name', 'path', 'description', 'author', 'created_at', 'updated_at'}
    
    # Default config directory (project root + hives_configs)
    DEFAULT_CONFIG_DIR = Path(__file__).parent
    
    _config_dir = None  # Can be set globally

    @classmethod
    def set_config_directory(cls, path: str) -> None:
        """
        Set the directory where hive configuration files are located.
        
        Args:
            path: Path to the hives configuration directory
        """
        config_path = Path(path)
        if not config_path.exists():
            raise ValueError(f'Configuration directory does not exist: {path}')
        if not config_path.is_dir():
            raise ValueError(f'Configuration path is not a directory: {path}')
        
        cls._config_dir = config_path
        logger.info(f'Configuration directory set to: {path}')

    @classmethod
    def get_config_directory(cls) -> Path:
        """
        Get the current configuration directory.
        
        Uses priority order:
        1. Explicitly set via set_config_directory()
        2. Environment variable HIVEX_CONFIGS_PATH
        3. Default (project root + hives_configs)
        
        Returns:
            Path to the configuration directory
        """
        # If explicitly set, use that
        if cls._config_dir:
            return cls._config_dir
        
        # Check environment variable
        env_path = os.environ.get('HIVEX_CONFIGS_PATH')
        if env_path:
            config_path = Path(env_path)
            if config_path.exists() and config_path.is_dir():
                logger.debug(f'Using config path from HIVEX_CONFIGS_PATH: {env_path}')
                return config_path
            else:
                logger.warning(f'HIVEX_CONFIGS_PATH points to invalid location: {env_path}')
        
        # Use default
        return cls.DEFAULT_CONFIG_DIR

    @classmethod
    def load_all_configs(cls) -> Dict[str, Dict[str, Any]]:
        """
        Load all hive configuration files from the hives_configs directory.
        
        Returns:
            Dictionary with hive name as key and configuration as value.
            Only includes valid configurations; invalid ones are logged and skipped.
        """
        configs = {}
        config_dir = cls.get_config_directory()
        
        # Find all YAML files in the configs directory
        yaml_files = list(config_dir.glob('*.yaml')) + list(config_dir.glob('*.yml'))
        
        if not yaml_files:
            logger.warning(f'No hive configuration files found in {config_dir}')
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
        config_dir = cls.get_config_directory()
        
        # Try both .yaml and .yml extensions
        config_file = config_dir / f'{hive_name}.yaml'
        if not config_file.exists():
            config_file = config_dir / f'{hive_name}.yml'
        
        if not config_file.exists():
            logger.warning(f'Configuration file not found: {hive_name}.yaml or {hive_name}.yml in {config_dir}')
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
