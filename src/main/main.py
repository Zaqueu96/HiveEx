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
        self.image_paths = arguments.image  # Now a list of image paths
        self.output_path = arguments.output
        
        # Suppress stderr if not in debug mode
        if not arguments.debug:
            sys.stderr = DevNull()
        
        # Validate configuration
        validator = ConfigValidator()
        
        # Validate all image paths
        for image_path in self.image_paths:
            validator.validate_image_path(image_path)
        
        validator.validate_output_path_permission(self.output_path)
        
        # Configure extraction options
        self.extraction_options = ExtractionOptions()
        self.extraction_options.configure_from_arguments(arguments)
        
        terminalPrint.printInfo(f"Processing {len(self.image_paths)} image(s)")
        self.logger.info(f"HiveEx initialized successfully with {len(self.image_paths)} image(s)")
    
    def run(self):
        """Runs the hive extraction process for all images."""
        for image_index, image_path in enumerate(self.image_paths, 1):
            self._process_image(image_path, image_index)
    
    def _process_image(self, image_path, image_number):
        """
        Processes a single forensic image.
        
        Args:
            image_path (str): Path to the image file
            image_number (int): Sequential number of the image being processed
        """
        try:
            terminalPrint.printInfo(f"\n--- Processing image {image_number}/{len(self.image_paths)}: {image_path} ---")
            self.logger.info(f"Processing image {image_number}/{len(self.image_paths)}: {image_path}")
            
            with ImageHandler(image_path) as image_handler:
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
            self.logger.error(f"Error opening image {image_path}: {e}")
            terminalPrint.printError(f"Error opening image {image_path}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error processing {image_path}: {e}")
            terminalPrint.printError(f"Unexpected error processing {image_path}: {e}")


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
        action='append',
        help='Path to the E01 image file(s). Can be used multiple times to process multiple images (required for extraction operations)'
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
        (hasattr(args, 'config') and args.config is not None)
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
    # Check if extraction operation requires image(s)
    if is_extraction_operation(args):
        if not args.image or len(args.image) == 0:
            raise RuntimeError(
                'Image file(s) (--image or -img) is/are required for extraction operations.\n'
                'Use --image <path> to specify E01 image file(s). Can be used multiple times.\n'
                'Examples:\n'
                '  python main.py --image image1.E01 --sam\n'
                '  python main.py --image image1.E01 --image image2.E01 --sam'
            )


def main():
    """Main entry point for the application."""
    # If no arguments provided, launch GUI
    if len(sys.argv) == 1:
        try:
            from gui import main as gui_main
            gui_main()
        except ImportError:
            parser = create_parser()
            parser.print_help()
        return
    
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
