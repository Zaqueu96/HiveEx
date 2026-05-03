"""
Migration Guide: From Monolithic to Modular Architecture

## Before: Monolithic Structure (550+ lines in main.py)
- Single MainCli class with multiple responsibilities
- Difficult to test individual components
- Hard to maintain and extend
- Mixed concerns: parsing, validation, extraction, image handling

## After: Modular Architecture (9 focused classes)

### Class Breakdown

#### 1. ConfigValidator
Extracted responsibility: Path and permission validation
Lines moved: ~20-30 lines from MainCli.__init__

#### 2. ImageHandler & EWFImgInfo
Extracted responsibility: EWF image file handling
Lines moved: ~40 lines (EWFImgInfo class from MainCli.run)

#### 3. ExtractionOptions
Extracted responsibility: CLI arguments parsing and extraction options management
Lines moved: ~50 lines from MainCli._defineHiveTypesExtractOptions and MainCli.__init__

#### 4. HiveExtractor
Extracted responsibility: Windows hives extraction
Lines moved: ~30 lines from MainCli._extractHivesFromWindowsFolder and MainCli._extractHiveWindows

#### 5. UserHiveExtractor
Extracted responsibility: User NTUSER.DAT extraction
Lines moved: ~40 lines from MainCli._checkUserFolders and MainCli._readAndExtractNTDUSERDat

#### 6. SpecificFileExtractor
Extracted responsibility: Specific file extraction with placeholder support
Lines moved: ~60 lines from MainCli.extractSpecificFile

#### 7. PartitionProcessor
Extracted responsibility: Partition processing coordination
New class that orchestrates extraction for each partition
Lines: ~50 new lines (previously inline in MainCli.run)

#### 8. HiveExCLI (main_refactored.py)
Refactored MainCli: Now only orchestrates the workflow
Lines: ~70 focused lines instead of 550

#### 9. Supporting Classes
HiveType, HivePath: Constants and enums previously scattered

## How to Migrate

### Option 1: Gradual Migration
Keep main.py as is, import refactored modules:
```python
from config_validator import ConfigValidator
from image_handler import ImageHandler
# Mix old and new code
```

### Option 2: Full Migration
Replace main.py with main_refactored.py:
```bash
mv main.py main_backup.py
mv main_refactored.py main.py
```

### Option 3: Use as Library
Import classes for your own projects:
```python
from hive_extractor import HiveExtractor
from image_handler import ImageHandler
from extraction_options import ExtractionOptions
```

## Code Comparison

### Before (Monolithic)
```python
class MainCli:
    def __init__(self, arguments):
        # Validation logic
        # Config parsing
        # State initialization
        # All mixed together
        
    def run(self):
        # Image handling
        # Partition loop
        # Extraction logic
        # Error handling
        # All in one method
```

### After (Modular)
```python
class HiveExCLI:
    def __init__(self, arguments):
        validator = ConfigValidator()
        validator.validate_image_path(...)  # Clear responsibility
        
    def run(self):
        with ImageHandler(self.image_path) as handler:  # Clear responsibility
            processor = PartitionProcessor(...)  # Clear responsibility
            # Orchestrates workflow
```

## Testing Improvements

### Before
```python
def test_main_cli():
    # Cannot test validation without running image handling
    # Cannot test extraction without setting up filesystem
    # Difficult to mock dependencies
```

### After
```python
def test_config_validator():
    validator = ConfigValidator()
    # Test validation in isolation
    
def test_extraction_options():
    options = ExtractionOptions()
    # Test option parsing in isolation
    
def test_hive_extractor():
    # Mock filesystem, test extraction logic
    extractor = HiveExtractor(mock_filesystem, 0, "/tmp")
```

## Benefits Summary

| Aspect | Before | After |
|--------|--------|-------|
| File Size | 550+ lines | 9 files, avg 50-100 lines |
| Testability | Difficult | Easy (isolated classes) |
| Maintainability | Hard | Easy (clear separation) |
| Reusability | No | Yes (importable classes) |
| Extensibility | Hard | Easy (add new classes) |
| Readability | Low | High (focused code) |
| Dependencies | Mixed | Injected (testable) |

## Next Steps

1. Backup original main.py
2. Test main_refactored.py with your image
3. Gradually replace or refactor remaining utilities
4. Add unit tests for each module
5. Consider adding hive config system (as per requirements)
"""

pass
