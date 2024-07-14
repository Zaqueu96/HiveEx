HiveEx is a Python-based tool designed for extracting primary hives from Windows images. The tool supports extraction of various hives such as `SAM`, `SYSTEM`, `SOFTWARE`, `SECURITY`, and `NTUSER.DAT` files from E01 images.

## Requirements

- Python 3.x
- `pyewf` library
- `pytsk3` library
- `tenacity` library
- `rich` library
- `argparse` library
- `blessed` library

Additionally, the tool requires the `libewf` library. Ensure you have this installed on your system.

## Installation

Before using HiveEx, ensure you have the necessary libraries installed:

```bash
pip install pyewf pytsk3 tenacity rich
```
Also, make sure that libewf is installed on your system. You can install it using your system's package manager. For example, on Ubuntu:

```bash
sudo apt-get install libewf-dev
```
## Usage
```bash
python hive_extractor.py --image <path_to_image> --output <output_folder> [options]
```
## Options
-  **--image**, -img (required): Location of the **E01 image**.
-  **--output**, -op: Folder to extract files (default is current directory).
-  **--windows**, -ws: Extract Windows hives (**SAM, SYSTEM, SOFTWARE, SECURITY**).
-  **--ntuserdat**, -n: Extract Windows user hives (**NTUSER.DAT**).
-  **--sam**, -sm: Extract **SAM** hive.
-  **--software**, -sfw: Extract **SOFTWARE** hive.
-  **--system**, -sys: Extract **SYSTEM** hive.
-  **--all**, -a: Extract all hives (**NTUSER.DAT, SAM, SYSTEM, SOFTWARE, SECURITY**).
-  **--debug**, -d: Show errors on the console.
-  **--specific-file**: Extract a specific file. Use [user] as a placeholder for usernames (e.g., **/Users/[user]/Downloads/ff.pdf**).

## Example
Extract all hives from an E01 image:
```bash
python main.py --image D:\\bart.E01 --output ./output --all
```
Extract a specific file for each user:
```bash
python main.py --image D:\\bart.E01 --output ./output --specific-file /Users/[user]/Documents/important.docx
```

## License
This project is licensed under the MIT License.

