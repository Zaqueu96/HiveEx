# Architecture Documentation for HiveEx

## Overview
HiveEx has been refactored into a modular architecture following SOLID principles. Each class has a single, well-defined responsibility, organized into functional modules.

## New Folder Structure

```
src/main/
├── __init__.py                    # Package exports
├── main_refactored.py             # Main entry point
├── main.py                        # Original entry point (deprecated)
│
├── config/                        # Configuration and options management
│   ├── __init__.py
│   ├── config_validator.py        # Path and permission validation
│   └── extraction_options.py      # CLI argument parsing
│
├── core/                          # Core functionality
│   ├── __init__.py
│   ├── hive_types.py              # Constants and types
│   └── partition_processor.py     # Partition processing coordination
│
├── extractors/                    # Hive extraction implementations
│   ├── __init__.py
│   ├── hive_extractor.py          # Windows hives extraction
│   ├── user_hive_extractor.py     # User NTUSER.DAT extraction
│   └── specific_file_extractor.py # Specific file extraction
│
├── image/                         # Image file handling
│   ├── __init__.py
│   └── image_handler.py           # EWF image operations
│
├── utils/                         # Utility functions
│   ├── __init__.py
│   ├── fileObjectUtils.py         # File hashing and extraction
│   ├── loggerUtils.py             # Logging setup
│   └── terminalPrint.py           # Terminal output formatting
│
└── docs/                          # Documentation
    ├── ARCHITECTURE.md            # This file
    ├── MIGRATION_GUIDE.md         # Migration instructions
    └── MODULE_REFERENCE.md        # Module API reference
```

## Module Organization

### config/ - Configuration and Validation
**Responsibility**: Handle CLI arguments, validate paths, and manage extraction options.

- **ConfigValidator**: Validates image paths exist and output paths are writable
- **ExtractionOptions**: Parses command-line arguments and manages extraction configuration

### core/ - Core Functionality
**Responsibility**: Define core types and coordinate partition processing.

- **HiveType**: Enum for available hive types (WINDOWS, SAM, SOFTWARE, SYSTEM, SECURITY, NTUSERDAT)
- **HivePath**: Constants for standard Windows hive paths
- **PartitionProcessor**: Orchestrates extraction for each partition

### extractors/ - Extraction Implementations
**Responsibility**: Extract different types of hives from the filesystem.

- **HiveExtractor**: Extracts Windows system hives (SAM, SYSTEM, SOFTWARE, SECURITY)
- **UserHiveExtractor**: Extracts NTUSER.DAT from user profiles
- **SpecificFileExtractor**: Extracts arbitrary files with [user] placeholder support

### image/ - Image Handling
**Responsibility**: Manage EWF image file operations.

- **ImageHandler**: Opens/closes EWF images, provides partition and filesystem access
- **EWFImgInfo**: Custom pytsk3 adapter for EWF files

### utils/ - Utilities
**Responsibility**: Provide common functionality for other modules.

- **FileObjectUtils**: Calculate file hashes (MD5, SHA1, SHA256) and extract files
- **loggerUtils**: Configure and provide logger instances
- **terminalPrint**: Format and display terminal output with colors

## Class Responsibilities

Each class has a single, well-defined responsibility following SOLID principles:

| Class | Module | Responsibility |
|-------|--------|-----------------|
| ConfigValidator | config/ | Validate image and output paths |
| ExtractionOptions | config/ | Parse CLI arguments, manage options |
| HiveType | core/ | Define hive type constants |
| HivePath | core/ | Define Windows path constants |
| PartitionProcessor | core/ | Coordinate extraction per partition |
| HiveExtractor | extractors/ | Extract Windows system hives |
| UserHiveExtractor | extractors/ | Extract user NTUSER.DAT files |
| SpecificFileExtractor | extractors/ | Extract specific files with placeholders |
| ImageHandler | image/ | Manage EWF image operations |
| EWFImgInfo | image/ | Adapt EWF to pytsk3 interface |

## Dependency Injection

Classes receive dependencies via constructor injection rather than global state:

```python
# Instead of:
hive_extractor = HiveExtractor()  # Would need filesystem global

# We do:
hive_extractor = HiveExtractor(filesystem, partition_addr, output_path)
```

This makes classes:
- **Testable**: Easy to mock dependencies
- **Reusable**: Can be used with different configurations
- **Maintainable**: Clear what each class depends on

## Import Patterns

### Internal Imports (Within Package)
```python
# Relative imports from sibling modules
from ..core import HiveType, HivePath
from ..utils import terminalPrint
from ..utils import loggerUtils
from ..extractors import HiveExtractor
```

### External Imports (From Package)
```python
# Import from top-level __init__.py
from hiveex.config import ConfigValidator, ExtractionOptions
from hiveex.core import HiveType, HivePath
from hiveex.extractors import HiveExtractor
from hiveex.image import ImageHandler
```

## Usage Examples

### Run from Command Line
```bash
python main_refactored.py --image image.E01 --all --output /tmp/hives
```

### Use as Library
```python
from main.config import ExtractionOptions
from main.image import ImageHandler
from main.core import PartitionProcessor

options = ExtractionOptions()
options.configure_from_arguments(args)

with ImageHandler('image.E01') as handler:
    partition_table = handler.get_partition_table()
    processor = PartitionProcessor('/tmp/output')
    for partition in partition_table:
        filesystem = handler.get_filesystem(partition)
        processor.process_partition(filesystem, partition.addr, options)
```

## Benefits of This Structure

1. **Clear Separation of Concerns**: Each module has a specific purpose
2. **Easy Testing**: Classes can be tested independently with mocked dependencies
3. **Scalability**: New extractors can be added to extractors/ without modifying other modules
4. **Maintainability**: Changes to one class don't affect unrelated classes
5. **Reusability**: Modules can be imported and used in other projects
6. **Documentation**: Clear folder structure makes code self-documenting

## Migration from Original

The original monolithic `main.py` (550+ lines) was split as follows:

| Original | New Location | Purpose |
|----------|--------------|---------|
| Path validation | config/config_validator.py | Validate paths |
| Option parsing | config/extraction_options.py | Parse CLI args |
| HiveType enum | core/hive_types.py | Define types |
| Image handling | image/image_handler.py | Manage EWF files |
| Hive extraction | extractors/hive_extractor.py | Extract hives |
| User extraction | extractors/user_hive_extractor.py | Extract NTUSER.DAT |
| File extraction | extractors/specific_file_extractor.py | Extract files |
| Partition loop | core/partition_processor.py | Coordinate extraction |
| Main logic | main_refactored.py | Orchestrate workflow |

