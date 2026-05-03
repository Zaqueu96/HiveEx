# HiveEx - Reorganized Project Structure

## ✅ Reorganization Complete!

Your HiveEx project has been successfully reorganized with a clean, responsibility-based folder structure.

### New Structure

```
src/main/
├── config/           # Configuration & validation
│   ├── config_validator.py
│   └── extraction_options.py
├── core/             # Core functionality
│   ├── hive_types.py
│   └── partition_processor.py
├── extractors/       # Hive extraction
│   ├── hive_extractor.py
│   ├── user_hive_extractor.py
│   └── specific_file_extractor.py
├── image/            # Image handling
│   └── image_handler.py
├── utils/            # Utilities (unchanged)
└── docs/             # Documentation
    ├── ARCHITECTURE.md
    └── STRUCTURE.md
```

## 🚀 How to Use

### Run HiveEx
```bash
cd C:\Users\Lucas\github\HiveEx
python src/main/main_refactored.py --image "image.E01" --all --output "./hives"
```

### Import as Library
```python
from src.main.config import ConfigValidator, ExtractionOptions
from src.main.image import ImageHandler
from src.main.core import HiveType, HivePath
from src.main.extractors import HiveExtractor
```

## 📝 Files in Root (src/main/)

These old files are still in the root directory for reference:
- `config_validator.py` ➜ Moved to `config/config_validator.py`
- `extraction_options.py` ➜ Moved to `config/extraction_options.py`
- `hive_types.py` ➜ Moved to `core/hive_types.py`
- `hive_extractor.py` ➜ Moved to `extractors/hive_extractor.py`
- `user_hive_extractor.py` ➜ Moved to `extractors/user_hive_extractor.py`
- `specific_file_extractor.py` ➜ Moved to `extractors/specific_file_extractor.py`
- `partition_processor.py` ➜ Moved to `core/partition_processor.py`
- `image_handler.py` ➜ Moved to `image/image_handler.py`
- `ARCHITECTURE.md` ➜ Moved to `docs/ARCHITECTURE.md`
- `MIGRATION_GUIDE.md` ➜ Still in root (will move to docs/)
- `MODULE_REFERENCE.md` ➜ Still in root (will move to docs/)

**You can safely delete these old files after verifying the new structure works.**

## ✨ Key Improvements

### Organization by Responsibility
- **config/**: All configuration and validation logic
- **core/**: Core types and partition orchestration
- **extractors/**: All extraction implementations
- **image/**: Image file handling
- **utils/**: General utilities
- **docs/**: Project documentation

### Benefits
✅ **Easier Navigation** - Find code by responsibility, not file name
✅ **Better Scalability** - Add new extractors to extractors/ folder
✅ **Clear Dependencies** - Each module has well-defined inputs/outputs
✅ **Improved Testing** - Test each module independently
✅ **Code Reusability** - Import and use modules in other projects

## 📚 Documentation

See the following files for more details:
- **docs/ARCHITECTURE.md** - Detailed architecture and design decisions
- **docs/STRUCTURE.md** - Visual guide to the project structure

## ⚠️ Next Steps (Optional)

1. **Delete Old Files** (when ready):
   ```bash
   # Remove old files from src/main root
   del config_validator.py extraction_options.py hive_types.py
   del hive_extractor.py user_hive_extractor.py specific_file_extractor.py
   del partition_processor.py image_handler.py
   del MIGRATION_GUIDE.md MODULE_REFERENCE.md
   ```

2. **Update Scripts** - Any scripts that import from src.main need import updates:
   ```python
   # Old (will break)
   from config_validator import ConfigValidator
   
   # New (use this)
   from config import ConfigValidator
   from core import HiveType
   from extractors import HiveExtractor
   ```

3. **Move Remaining Docs** (when ready):
   - Move `MIGRATION_GUIDE.md` to `docs/MIGRATION_GUIDE.md`
   - Move `MODULE_REFERENCE.md` to `docs/MODULE_REFERENCE.md`

## 🔍 Verify Structure

All files are in correct locations. You can verify with:
```bash
cd src/main
# List the folder structure
tree /A

# Or check specific folders exist
dir config
dir core
dir extractors
dir image
dir utils
dir docs
```

## 💡 Example Usage

### Extract all hives
```bash
python src/main/main_refactored.py \
  --image "D:\path\to\image.E01" \
  --all \
  --output "./extracted_hives"
```

### Extract specific hive type
```bash
python src/main/main_refactored.py \
  --image "D:\path\to\image.E01" \
  --sam --software \
  --output "./hives"
```

### Extract specific file
```bash
python src/main/main_refactored.py \
  --image "D:\path\to\image.E01" \
  --specific-file "/Users/[user]/Desktop/sensitive.doc" \
  --output "./extracted_files"
```

---

**Your project is now well-organized and ready for expansion!** 🎉
