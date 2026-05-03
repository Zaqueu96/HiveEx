#!/usr/bin/python3

"""
HiveEx - Main entry point for hive extraction from forensic images.

This tool extracts Windows hives from EWF (E01) forensic images without needing
to mount them in an operating system.
"""

import sys
import argparse
from rich.progress import Progress
from utils import terminalPrint
from utils import loggerUtils

from config import ConfigValidator, ExtractionOptions, ConfigHandler
from image import ImageHandler
from core import PartitionProcessor


class DevNull:
    """Utility class to suppress stderr output."""
    def write(self, msg):
        pass


class HiveExCLI:
    """Main CLI class for HiveEx tool."""
    
    def __init__(self, arguments):
        """
        Initializes the HiveEx CLI.
        
        Args:
            arguments: argparse arguments object
        """
        self.logger = loggerUtils.getLogger(__name__)
        self.image_path = arguments.image
        self.output_path = arguments.output
        
        # Suppress stderr if not in debug mode
        if not arguments.debug:
            sys.stderr = DevNull()
        
        # Validate configuration
        validator = ConfigValidator()
        validator.validate_image_path(self.image_path)
        validator.validate_output_path_permission(self.output_path)
        
        # Configure extraction options
        self.extraction_options = ExtractionOptions()
        self.extraction_options.configure_from_arguments(arguments)
        
        self.logger.info("HiveEx initialized successfully")
    
    def run(self):
        """Runs the hive extraction process."""
        try:
            with ImageHandler(self.image_path) as image_handler:
                partition_table = image_handler.get_partition_table()
                terminalPrint.printPartitionsTable(partitionTable=partition_table)
                
                processor = PartitionProcessor(self.output_path)
                
                with Progress() as progress:
                    task = progress.add_task("[cyan]Processing partitions...", total=partition_table.info.part_count)
                    
                    for partition in partition_table:
                        progress.update(task, advance=1, description=f"[cyan]Processing partition #{partition.addr}...")
                        
                        try:
                            filesystem = image_handler.get_filesystem(partition)
                            processor.process_partition(filesystem, partition.addr, self.extraction_options)
                        except IOError as e:
                            self.logger.error(f"Error reading partition {partition.addr}: {e}")
                        except Exception as e:
                            self.logger.error(f"Error processing partition {partition.addr}: {e}")
        
        except IOError as e:
            self.logger.error(f"Error opening image: {e}")
            terminalPrint.printError(f"Error opening image: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            terminalPrint.printError(f"Unexpected error: {e}")


def create_parser():
    """
    Creates and configures the argument parser.
    
    Returns:
        argparse.ArgumentParser: Configured parser
    """
    parser = argparse.ArgumentParser(
        description='HiveEx - Extract Windows hives from forensic images (E01)'
    )
    
    parser.add_argument(
        '--image', '-img',
        required=False,
        type=str,
        help='Path to the E01 image file (required for extraction operations)'
    )
    
    parser.add_argument(
        '--output', '-op',
        type=str,
        default=".",
        help='Output folder for extracted files (default: current directory)'
    )
    
    parser.add_argument(
        '--windows', '-ws',
        action='store_true',
        help='Extract all Windows hives (SAM, SYSTEM, SOFTWARE, SECURITY)'
    )
    
    parser.add_argument(
        '--ntuserdat', '-n',
        action='store_true',
        help='Extract user hives (NTUSER.DAT)'
    )
    
    parser.add_argument(
        '--sam', '-sm',
        action='store_true',
        help='Extract SAM hive'
    )
    
    parser.add_argument(
        '--software', '-sfw',
        action='store_true',
        help='Extract SOFTWARE hive'
    )
    
    parser.add_argument(
        '--system', '-sys',
        action='store_true',
        help='Extract SYSTEM hive'
    )
    
    parser.add_argument(
        '--security', '-sec',
        action='store_true',
        help='Extract SECURITY hive'
    )
    
    parser.add_argument(
        '--all', '-a',
        action='store_true',
        help='Extract all hives (NTUSER.DAT, SAM, SYSTEM, SOFTWARE, SECURITY)'
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Show errors on console'
    )
    
    parser.add_argument(
        '--specific-file',
        type=str,
        help='Extract a specific file from the image. Use [user] as placeholder for usernames. '
             'Examples: /Users/[user]/Downloads/file.pdf or /Windows/System32/config/SAM'
    )
    
    parser.add_argument(
        '--config', '-cfg',
        type=str,
        action='append',
        help='Extract hives based on configuration file. Can be used multiple times. '
             'Specify hive name (e.g., sam, system) or path to YAML config file'
    )
    
    parser.add_argument(
        '--list-configs',
        action='store_true',
        help='List all available hive configurations'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output (use with --list-configs for detailed info)'
    )
    
    parser.add_argument(
        '--configs-path',
        type=str,
        help='Custom path to hive configuration directory (overrides default and HIVEX_CONFIGS_PATH env variable)'
    )
    
    return parser


def is_extraction_operation(args) -> bool:
    """
    Check if the arguments specify an extraction operation.
    
    Args:
        args: argparse arguments object
    
    Returns:
        bool: True if any extraction flag is set
    """
    extraction_flags = [
        args.windows,
        args.sam,
        args.software,
        args.system,
        args.security,
        args.ntuserdat,
        args.all,
        args.specific_file is not None,
        args.config is not None
    ]
    return any(extraction_flags)


def validate_arguments(args) -> None:
    """
    Validate argument combinations.
    
    Args:
        args: argparse arguments object
    
    Raises:
        RuntimeError: If argument combination is invalid
    """
    # Check if extraction operation requires image
    if is_extraction_operation(args):
        if not args.image:
            raise RuntimeError(
                'Image file (--image or -img) is required for extraction operations.\n'
                'Use --image <path> to specify the E01 image file.\n'
                'Example: python main.py --image image.E01 --sam'
            )


def main():
    """Main entry point for the application."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Set custom configs path if provided (before other operations)
    if hasattr(args, 'configs_path') and args.configs_path:
        try:
            ConfigHandler.set_config_path(args.configs_path)
        except Exception as e:
            terminalPrint.printError(f'Invalid configs path: {e}')
            sys.exit(1)
    
    # Handle --list-configs flag (does not require image)
    if args.list_configs:
        verbose = getattr(args, 'verbose', False)
        ConfigHandler.list_available_configs(verbose=verbose)
        sys.exit(0)
    
    # Validate arguments for extraction operations
    try:
        validate_arguments(args)
    except RuntimeError as e:
        terminalPrint.printError(str(e))
        sys.exit(1)
    
    try:
        cli = HiveExCLI(arguments=args)
        cli.run()
    except RuntimeError as e:
        terminalPrint.printError(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        terminalPrint.printWarn("Process interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger = loggerUtils.getLogger(__name__)
        logger.error(f"Fatal error: {e}")
        terminalPrint.printError(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
