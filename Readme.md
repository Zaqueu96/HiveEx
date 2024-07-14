<p align="center">
  <img src="./images/readme_image.png" alt="Readme image center" width="250">
  <h1 style="text-align:center">HiveEx</h1>
</p>

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
pip install pyewf pytsk3 tenacity rich blessed
```
Also, make sure that libewf is installed on your system. You can install it using your system's package manager. For example, on Ubuntu:

```bash
sudo apt-get install libewf-dev
```
## Usage
```bash
python .\\src\\main\\main.py --image <path_to_image> --output <output_folder> [options]
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
python .\\src\\main\\main.py --image D:\\bart.E01 --output ./output --all
```
Extract a specific file for each user:
```bash
python .\\src\\main\\main.py --image D:\\bart.E01 --output ./output --specific-file /Users/[user]/Documents/important.docx
```

### Creating an Executable with PyInstaller

To create a standalone executable from your Python script, you can use PyInstaller. Make sure all necessary dependencies are installed before proceeding.

#### PyInstaller Commands

To create a single executable:

```bash
pyinstaller --onefile --name hiveEx.1.0 --icon ./icon/icon.ico ./src/main/main.py
```

## Download

You can download the latest release of the executable for Windows from the [Releases](https://github.com/Zaqueu96/HiveEx/releases) page.

### Instructions

1. Go to the [Releases](https://github.com/Zaqueu96/HiveEx/releases) page of this repository.
2. Download the executable file for Windows (`hiveEx.1.0`).

## Support and Contributions

If you encounter any issues or have suggestions to improve this project, please [get in touch / open an issue / submit a pull request].

---

**Note:** If you experience compatibility issues or if the executable does not work as expected, ensure all dependencies are correctly installed on your system.

## License
This project is licensed under the MIT License.

