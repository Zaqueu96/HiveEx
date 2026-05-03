"""
MODULE REFERENCE - Quick Guide to HiveEx Modules

## Core Modules (Extraction)

### hive_extractor.py
- Class: HiveExtractor
- Responsibility: Extract Windows hives (SYSTEM, SOFTWARE, SAM, SECURITY)
- Methods:
  - extract_windows_hives(hives_dict): Main extraction method
  - _extract_single_hive(hive_name, hive_path): Internal helper

### user_hive_extractor.py
- Class: UserHiveExtractor
- Responsibility: Extract NTUSER.DAT from all users
- Methods:
  - extract_all_users_hives(): Main extraction method
  - _get_users_list(): Get list of users from /Users/
  - _extract_user_hive(user_name): Extract for single user
  - _read_and_extract_ntuser_dat(user_name): Read and extract

### specific_file_extractor.py
- Class: SpecificFileExtractor
- Responsibility: Extract specific files with [user] placeholder support
- Methods:
  - extract_file(path_template): Extract file with template
  - _extract_file_direct(file_path): Extract without placeholder
  - _extract_file_for_all_users(path_template): Extract for all users
  - _try_extract_user_file(file_path): Try to extract single file

## Configuration & Management

### extraction_options.py
- Class: ExtractionOptions
- Responsibility: Parse and manage CLI extraction options
- Methods:
  - configure_from_arguments(args): Configure from argparse
  - get_windows_hives_to_extract(): Get hives to extract
  - should_extract_ntuser_dat(): Check if NTUSER.DAT requested
  - should_extract_windows_hives(): Check if Windows hives requested
  - should_extract_specific_file(): Check if specific file requested

### config_validator.py
- Class: ConfigValidator
- Responsibility: Validate image paths and output permissions
- Methods:
  - validate_image_path(image_path): Check if image exists
  - validate_output_path_permission(output_path): Check write permission

### hive_types.py
- Classes: HiveType, HivePath
- Responsibility: Define constants and enums for hives
- Contents:
  - HiveType.WINDOWS, .NTUSERDAT, .SAM, etc.
  - HivePath.HIVES: Dictionary of hive paths
  - HivePath.NTUSER_DAT, USERS_PATH, WINDOWS_PATH, NOT_IN_FOLDERS

## Image & Partition Handling

### image_handler.py
- Classes: ImageHandler, EWFImgInfo
- Responsibility: Handle EWF image file operations
- ImageHandler Methods:
  - open_image(): Open EWF image
  - close_image(): Close image
  - get_partition_table(): Get partition table
  - get_filesystem(partition): Get filesystem from partition
  - Context manager support (__enter__, __exit__)
- EWFImgInfo Methods:
  - read(offset, size): Read from image
  - get_size(): Get image size

### partition_processor.py
- Class: PartitionProcessor
- Responsibility: Coordinate extraction for each partition
- Methods:
  - process_partition(filesystem, partition_addr, options): Process partition
  - _check_and_extract(...): Internal extraction coordinator
  - _extract_specific_file(...): Extract specific files
  - _check_folders_existence(filesystem): Check for /Users/ and /Windows/

## Main Entry Point

### main_refactored.py
- Classes: HiveExCLI
- Functions: create_parser(), main()
- Responsibility: Orchestrate CLI and workflow
- HiveExCLI Methods:
  - __init__(arguments): Initialize and validate
  - run(): Execute extraction workflow
- Functions:
  - create_parser(): Create argument parser
  - main(): Entry point with error handling

## Utilities (Original)

### utils/fileObjectUtils.py
- Class: FileObjectUtils
- Methods:
  - fileCalculateHash(): Calculate MD5, SHA1, SHA256
  - fileExtract(): Extract file to disk
  - _generateFileHashes(): Write hash file
  - _extractOnlyFileName(): Get filename

### utils/loggerUtils.py
- Functions:
  - getLogger(filename): Get logger instance

### utils/terminalPrint.py
- Functions:
  - printError(message), printInfo(), printWarn(), printSuccess()
  - getTablePrint(title), printPartitionsTable()

## Usage Examples

### Example 1: Extract all hives
```python
from main_refactored import HiveExCLI, create_parser

parser = create_parser()
args = parser.parse_args(['--image', 'image.E01', '--all', '--output', '/tmp'])
cli = HiveExCLI(args)
cli.run()
```

### Example 2: Extract only NTUSER.DAT
```python
args = parser.parse_args(['--image', 'image.E01', '--ntuserdat', '--output', '/tmp'])
cli = HiveExCLI(args)
cli.run()
```

### Example 3: Extract specific file with user placeholder
```python
args = parser.parse_args([
    '--image', 'image.E01',
    '--specific-file', '/Users/[user]/Downloads/sensitive.doc',
    '--output', '/tmp'
])
cli = HiveExCLI(args)
cli.run()
```

### Example 4: Use HiveExtractor directly (advanced)
```python
from image_handler import ImageHandler
from hive_extractor import HiveExtractor
from hive_types import HivePath

with ImageHandler('image.E01') as handler:
    partition_table = handler.get_partition_table()
    for partition in partition_table:
        if partition.addr == 2:  # Process specific partition
            filesystem = handler.get_filesystem(partition)
            extractor = HiveExtractor(filesystem, partition.addr, '/tmp')
            extractor.extract_windows_hives(HivePath.HIVES)
```

## Import Structure

```python
# Single responsibility imports
from config_validator import ConfigValidator
from image_handler import ImageHandler
from extraction_options import ExtractionOptions
from hive_extractor import HiveExtractor
from user_hive_extractor import UserHiveExtractor
from specific_file_extractor import SpecificFileExtractor
from partition_processor import PartitionProcessor
from hive_types import HiveType, HivePath

# Main entry point
from main_refactored import HiveExCLI, create_parser, main
```

## Error Handling

All modules use:
- Python logging (via utils.loggerUtils)
- Rich terminal output (via utils.terminalPrint)
- Tenacity retry decorators (@retry) for resilience
- Proper exception propagation for caller handling

## Testing Strategy

Each module can be tested independently:

```python
# Test ConfigValidator
validator = ConfigValidator()
validator.validate_image_path('test.E01')

# Test ExtractionOptions
options = ExtractionOptions()
options.configure_from_arguments(mock_args)

# Test SpecificFileExtractor with mocked filesystem
mock_fs = Mock()
extractor = SpecificFileExtractor(mock_fs, 0, '/tmp')
```

## Performance Considerations

1. FileObjectUtils: Reads files in 1MB chunks for memory efficiency
2. UserHiveExtractor: Processes users sequentially (can be parallelized)
3. PartitionProcessor: Processes partitions sequentially with Progress bar
4. ImageHandler: Lazy opens/closes image for resource efficiency

## Future Enhancements

1. Add hive configuration system (hives_configs/ folder)
2. Parallelize partition processing with ThreadPoolExecutor
3. Add database output format (SQLite)
4. Add JSON report generation
5. Add progress callbacks for GUI integration
6. Add registry parsing integration
"""

pass
