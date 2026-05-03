# Project Structure Guide

## Complete Directory Structure

```
C:\Users\Lucas\github\HiveEx\
├── src/
│   └── main/
│       ├── __init__.py                         # Package init with exports
│       ├── main_refactored.py                  # NEW ENTRY POINT (use this)
│       ├── main.py                             # OLD entry point (deprecated)
│       │
│       ├── config/                             # Configuration module
│       │   ├── __init__.py
│       │   ├── config_validator.py             # Validates paths
│       │   └── extraction_options.py           # Parses CLI arguments
│       │
│       ├── core/                               # Core module
│       │   ├── __init__.py
│       │   ├── hive_types.py                   # Constants (HiveType, HivePath)
│       │   └── partition_processor.py          # Coordinates extraction
│       │
│       ├── extractors/                         # Extraction module
│       │   ├── __init__.py
│       │   ├── hive_extractor.py               # Extracts Windows hives
│       │   ├── user_hive_extractor.py          # Extracts NTUSER.DAT
│       │   └── specific_file_extractor.py      # Extracts specific files
│       │
│       ├── image/                              # Image handling module
│       │   ├── __init__.py
│       │   └── image_handler.py                # EWF image operations
│       │
│       ├── utils/                              # Utilities module (unchanged)
│       │   ├── __init__.py
│       │   ├── fileObjectUtils.py              # File operations
│       │   ├── loggerUtils.py                  # Logging
│       │   └── terminalPrint.py                # Terminal output
│       │
│       └── docs/                               # Documentation
│           ├── ARCHITECTURE.md                 # Architecture overview
│           └── STRUCTURE.md                    # This file
│
├── requirements.txt
├── Readme.md
└── ...other project files...
```

## What Changed

### Files Moved to Folders

| Old Location | New Location | Reason |
|--------------|--------------|--------|
| `config_validator.py` | `config/config_validator.py` | Configuration responsibility |
| `extraction_options.py` | `config/extraction_options.py` | Configuration responsibility |
| `hive_types.py` | `core/hive_types.py` | Core types and constants |
| `partition_processor.py` | `core/partition_processor.py` | Core orchestration |
| `hive_extractor.py` | `extractors/hive_extractor.py` | Hive extraction responsibility |
| `user_hive_extractor.py` | `extractors/user_hive_extractor.py` | Hive extraction responsibility |
| `specific_file_extractor.py` | `extractors/specific_file_extractor.py` | Hive extraction responsibility |
| `image_handler.py` | `image/image_handler.py` | Image handling responsibility |
| `ARCHITECTURE.md` | `docs/ARCHITECTURE.md` | Documentation |
| `MIGRATION_GUIDE.md` | `docs/MIGRATION_GUIDE.md` | Documentation |
| `MODULE_REFERENCE.md` | `docs/MODULE_REFERENCE.md` | Documentation |

### Files That Stayed
- `main_refactored.py` (updated imports) - **USE THIS**
- `main.py` (original) - Deprecated, kept for reference
- `utils/` folder - Unchanged structure
- `__init__.py` - Updated with new exports

## Import Changes

### Old Imports (Deprecated)
```python
from config_validator import ConfigValidator
from extraction_options import ExtractionOptions
from hive_types import HiveType, HivePath
from image_handler import ImageHandler
from hive_extractor import HiveExtractor
from partition_processor import PartitionProcessor
```

### New Imports (Recommended)
```python
from config import ConfigValidator, ExtractionOptions
from core import HiveType, HivePath, PartitionProcessor
from extractors import HiveExtractor, UserHiveExtractor, SpecificFileExtractor
from image import ImageHandler, EWFImgInfo
from utils import terminalPrint, loggerUtils
```

### Or from Top-Level
```python
from . import ConfigValidator, ExtractionOptions, HiveType, HivePath
from . import ImageHandler, HiveExtractor, UserHiveExtractor
```

## Module Dependencies

```
main_refactored.py
├── config/
│   ├── ConfigValidator
│   └── ExtractionOptions
├── image/
│   └── ImageHandler
├── core/
│   └── PartitionProcessor
├── extractors/
│   ├── HiveExtractor
│   ├── UserHiveExtractor
│   └── SpecificFileExtractor
└── utils/
    ├── terminalPrint
    └── loggerUtils
```

## How to Run

### Using New Structure
```bash
cd C:\Users\Lucas\github\HiveEx
python src/main/main_refactored.py --image "path/to/image.E01" --all --output ./extracted_hives
```

### Using with Python Path
```bash
cd C:\Users\Lucas\github\HiveEx
python -m src.main.main_refactored --image "path/to/image.E01" --all --output ./extracted_hives
```

## Best Practices

1. **Use main_refactored.py**: The new entry point with proper module organization
2. **Use new import paths**: Import from modules (config/, core/, etc.) not from root
3. **Keep utils/ utilities**: Don't change the utils module structure
4. **Follow relative imports**: Use `from ..module import Class` within packages

## Configuration System (Future)

The new structure is prepared for the future hive configuration system:
- Config will be organized by responsibility
- Easy to add `hives_configs/` folder with YAML/JSON configuration files
- ConfigValidator can be extended to validate hive configurations

## Testing Structure (Future)

Once tests are added, they should mirror the structure:
```
tests/
├── test_config/
│   ├── test_config_validator.py
│   └── test_extraction_options.py
├── test_core/
│   └── test_partition_processor.py
├── test_extractors/
│   ├── test_hive_extractor.py
│   ├── test_user_hive_extractor.py
│   └── test_specific_file_extractor.py
└── test_image/
    └── test_image_handler.py
```

## Summary

The new structure organizes code by **responsibility** rather than function type:

- **config/** - Everything related to configuration and validation
- **core/** - Core types and orchestration logic
- **extractors/** - All extraction implementations
- **image/** - Image file handling
- **utils/** - General utility functions
- **docs/** - Project documentation

This makes it easier to:
- Find related code
- Understand the project structure
- Add new features
- Test individual components
- Reuse modules in other projects

