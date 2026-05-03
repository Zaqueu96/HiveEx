"""
Architecture Documentation for HiveEx

## Overview
HiveEx has been refactored into a modular architecture following SOLID principles.
Each class has a single, well-defined responsibility.

## Module Structure

### Core Modules

1. **hive_types.py**
   - HiveType: Defines available hive types
   - HivePath: Defines standard Windows paths for hives and system folders

2. **config_validator.py**
   - ConfigValidator: Validates image paths and output permissions

3. **image_handler.py**
   - ImageHandler: Manages EWF image file operations
   - EWFImgInfo: Custom pytsk3 image info class for EWF support

4. **extraction_options.py**
   - ExtractionOptions: Manages extraction options from CLI arguments

5. **hive_extractor.py**
   - HiveExtractor: Extracts Windows hives (SYSTEM, SOFTWARE, SAM, SECURITY)

6. **user_hive_extractor.py**
   - UserHiveExtractor: Extracts user NTUSER.DAT files

7. **specific_file_extractor.py**
   - SpecificFileExtractor: Extracts specific files with [user] placeholder support

8. **partition_processor.py**
   - PartitionProcessor: Coordinates extraction across partitions

9. **main_refactored.py**
   - HiveExCLI: Main CLI orchestration class
   - create_parser(): Creates argument parser
   - main(): Application entry point

## Class Responsibilities

### Single Responsibility Principle (SRP)
Each class has one clear responsibility:

- ConfigValidator: Only validates paths and permissions
- ImageHandler: Only manages image file operations
- ExtractionOptions: Only manages extraction configuration
- HiveExtractor: Only extracts Windows hives
- UserHiveExtractor: Only extracts user hives
- SpecificFileExtractor: Only extracts specific files
- PartitionProcessor: Only coordinates partition processing
- HiveExCLI: Only orchestrates the main workflow

### Dependency Inversion
- Classes receive dependencies (filesystem, paths) via constructor injection
- No global state or hardcoded paths
- Easy to test and modify

### DRY Principle
- Common file extraction logic is in FileObjectUtils
- Hive paths are centralized in HivePath class
- Error handling is consistent across modules

## Usage

To use the refactored code, replace the old main.py with main_refactored.py:

```bash
python main_refactored.py --image /path/to/image.E01 --all --output /output/path
```

## Benefits of Refactoring

1. **Maintainability**: Each module can be modified independently
2. **Testability**: Classes can be unit tested individually
3. **Reusability**: Classes can be imported and used in other projects
4. **Scalability**: Easy to add new extraction types or features
5. **Clarity**: Clear separation of concerns makes code easier to understand
"""

pass
