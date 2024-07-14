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
pip install pyewf pytsk3 tenacity rich
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
pyinstaller --onefile src/main/main.py
```

## Generated Executable

The executable was generated using PyInstaller and is located in the `dist` folder. You can find it here:

- **Windows:** [hiveEx.1.0.exe](./dist/hiveEx.1.0.exe)

## How to Run

To run the program:

1. **Windows:**
   - Download the `hiveEx.1.0.exe` file.
   - Double-click to launch or execute via the command line.

## Requirements

Make sure your system meets the following requirements to ensure proper functionality:

- [List any specific requirements or dependencies, such as Python version X.X, etc.]

## Support and Contributions

If you encounter any issues or have suggestions to improve this project, please [get in touch / open an issue / submit a pull request].

---

**Note:** If you experience compatibility issues or if the executable does not work as expected, ensure all dependencies are correctly installed on your system.

## License
This project is licensed under the MIT License.

