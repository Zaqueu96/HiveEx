#!/usr/bin/python3

import pyewf
import pytsk3
from utils.fileObjectUtils import FileObjectUtils
import utils.loggerUtils as loggerUtils
import argparse
from enum import Enum
import os.path
from tenacity import retry, stop_after_attempt, wait_fixed
import utils.terminalPrint as termPrint
from rich.console import Console
from rich.progress import Progress
import sys

console = Console()

class DevNull:
    def write(self, msg):
        pass

class ExtractHiveType:
    WINDOWS = 'windows'
    NTUSERDAT = 'ntuserdat'
    SAM = 'sam'
    SOFTWARE = 'software'
    SYSTEM = 'system'
    SECURITY = 'security'
    ALL = 'all'

# Caminho para a primeira parte da imagem E01
ewf_path = "D:\Forensics Images\Windows Forensics_ForensicVM-Dataset\\bart.E01"

NOT_IN_FOLDERS = [".", ".."]
FILENAME_NTUSER_DAT = "NTUSER.DAT"

class MainCli:
    def __init__(self, arguments):
        self.logger = loggerUtils.getLogger(__name__)
        self.forAllWindowHive = False
        
        if(not arguments.debug):
            sys.stderr = DevNull()


        self._defineHiveTypesExtractOptions(arguments)

        if arguments.image == "":
            termPrint.printError("imagePath is not valid!")
            raise RuntimeError("imagePath is not valid!")

        self.extractNTUSERDatForUsers = arguments.ntuserdat
        if arguments.all:
            self.forAllWindowHive = True
            self.extractNTUSERDatForUsers = True

        self.imagePath = arguments.image
        self.outputPath = arguments.output
        self._checkImagePath()

    def _defineHiveTypesExtractOptions(self, arguments):
        self.hive_types = [
            ExtractHiveType.WINDOWS,
            ExtractHiveType.NTUSERDAT,
            ExtractHiveType.SAM,
            ExtractHiveType.SOFTWARE,
            ExtractHiveType.SYSTEM,
            ExtractHiveType.SECURITY,
            ExtractHiveType.ALL
        ]

        hiveIsDefined = arguments.windows
        self.forAllWindowHive = arguments.windows
        if not arguments.windows and any(hasattr(arguments, hive) for hive in self.hive_types):
            for hive in self.hive_types:
                if getattr(arguments, hive, False):
                    setattr(self, f"extract_{hive}", True)
                    hiveIsDefined = True

        if not hiveIsDefined:
            termPrint.printError('At least one hive extraction option must be specified (--windows, --ntuserdat, --sam, --software, --system, --security)')
            raise RuntimeError("At least one hive extraction option must be specified (--windows, --ntuserdat, --sam, --software, --system, --security)")

    def getOnlyName(self, entry):
        return entry.info.name.name.decode('utf-8')

    def _checkImagePath(self):
        self.logger.debug(f"[isFile] start check file: {self.imagePath}")
        self.logger.info(f"Checking if is file :{self.imagePath}")
        if os.path.isfile(path=self.imagePath):
            self.logger.info(f"Checked file: {self.imagePath}")
        else:
            self.logger.info("Check failed, path is not a file")
            raise RuntimeError("Error imagePath not contains file")

    def _getFoldersExistsCheck(self):
        existsFolderUser = False
        existsFolderWindows = False
        directories = self.pyTskFileSystem.open_dir("/")
        listFolderName = map(self.getOnlyName, directories)
        if "Users" in listFolderName:
            existsFolderUser = True
        if "Windows" in listFolderName:
            existsFolderWindows = True
        return existsFolderUser, existsFolderWindows

    def getHiveFoldersValidated(self):
        if self.forAllWindowHive:
            hives = {
                'SYSTEM': r'/Windows/System32/config/SYSTEM',
                'SOFTWARE': r'/Windows/System32/config/SOFTWARE',
                'SAM': r'/Windows/System32/config/SAM',
                'SECURITY': r'/Windows/System32/config/SECURITY'
            }
            return hives
        else:
            hives = {}
            if hasattr(self, 'extract_system'):
                hives['SYSTEM'] = r'/Windows/System32/config/SYSTEM'
            if hasattr(self, 'extract_software'):
                hives['SOFTWARE'] = r'/Windows/System32/config/SOFTWARE'
            if hasattr(self, 'extract_sam'):
                hives['SAM'] = r'/Windows/System32/config/SAM'
            if hasattr(self, 'extract_security'):
                hives['SECURITY'] = r'/Windows/System32/config/SECURITY'
            return hives

    def _extractHivesFromWindowsFolder(self):
        hivesKeyAndPaths = self.getHiveFoldersValidated()
        self.logger.debug(f"[extractHivesFromWindowsFolder] start ")
        try:
            for nameHive, path in hivesKeyAndPaths.items():
                self._extractHiveWindows(nameHive, path)
        except Exception as e:
            self.logger.info('There was an unexpected error while trying to load the NTUSER.dat file for users')
            self.logger.error("Error on check folders", e)
            raise e
        finally:
            self.logger.debug(f"[extractHivesFromWindowsFolder] end finally")

    def _extractHiveWindows(self, nameHive, path):
        termPrint.printInfo(f"Extracting hive {nameHive}...")
        fileObject = self.pyTskFileSystem.open(path=path)
        objectUtils = FileObjectUtils(fileObject=fileObject, outputPath=self.outputPath, prefixName=f"partition_{self.partitionAddr}")
        self.logger.debug(f"Name: {nameHive}")
        self.logger.info(f"Name: {nameHive} found")
        md5_digest, sha1_digest, sha256_digest = objectUtils.fileCalculateHash()
        self.logger.info(f"MD5: {md5_digest}")
        self.logger.info(f"SHA-1: {sha1_digest}")
        self.logger.info(f"SHA-256: {sha256_digest}")
        objectUtils.fileExtract()
        termPrint.printSuccess(f"Extracted hive {nameHive}")

    @retry(stop=stop_after_attempt(1), wait=wait_fixed(1))  # Retry up to 3 times, waiting 2 seconds between retries
    def _checkUserFolders(self):
        self.logger.debug(f"[checkUserFolders] start ")
        self.logger.info("Checking folders in /Users/")
        termPrint.printInfo("Checking folders in /Users/")
        try:
            # Get user hive NTUSER.DAT
            directoryListUsers = self.pyTskFileSystem.open_dir(path="/Users/")
            for entry in directoryListUsers:
                entryName = entry.info.name.name.decode('utf-8')
                if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR and entryName not in NOT_IN_FOLDERS:
                    termPrint.printInfo(f"Processing user folder: {entryName}")
                    self._listDirectoryUsersAndExtractFile(entry, entryName)
        except Exception as e:
            self.logger.info('There was an unexpected error while trying to load the NTUSER.dat file for users')
            self.logger.error("Error on check folders", e)
            termPrint.printError("There was an unexpected error while trying to load the NTUSER.dat file for users")
            raise e
        finally:
            self.logger.debug(f"[checkUserFolders] end finally")

    def _listDirectoryUsersAndExtractFile(self, entry, entryName):        
        directoryByUser = self.pyTskFileSystem.open_dir(path=f"/Users/{entryName}")
        listDirectories = map(self.getOnlyName, directoryByUser)
        if FILENAME_NTUSER_DAT in listDirectories:
            termPrint.printInfo(f"Found NTUSER.DAT for user: {entryName}")
            self._readAndExtractNTDUSERDat(entry, entryName)
        else:
            termPrint.printWarn(f"NTUSER.DAT not found for user: {entryName}")

    @retry(stop=stop_after_attempt(2), wait=wait_fixed(1))
    def _readAndExtractNTDUSERDat(self, entry, entryName):
        termPrint.printInfo(f"Reading and extracting NTUSER.DAT for user: {entryName}")
        fileObject = self.pyTskFileSystem.open(f"/Users/{entryName}/{FILENAME_NTUSER_DAT}")
        objectUtils = FileObjectUtils(fileObject, self.outputPath, entryName)
        md5_digest, sha1_digest, sha256_digest = objectUtils.fileCalculateHash()
        self.logger.info(f"MD5: {md5_digest}")
        self.logger.info(f"SHA-1: {sha1_digest}")
        self.logger.info(f"SHA-256: {sha256_digest}")
        objectUtils.fileExtract()
        termPrint.printSuccess(f"Extracted NTUSER.DAT for user: {entryName}")

        
    def checkOptionsAndExtractFiles(self):
        self.logger.debug("[checkOptionsAndExtractFiles] - start")
        existsFolderUser, existsFolderWindows = self._getFoldersExistsCheck()
        if(existsFolderUser and self.extractNTUSERDatForUsers):
            self.logger.info("Found path /Users/")
            self.logger.debug("[checkUserFolders] found path /Users/")
            self._checkUserFolders()
        else:            
            self.logger.info("Not found path /Users/")
            self.logger.debug("[checkUserFolders] Not found path /Users/")

        if(existsFolderWindows):
            self.logger.info("Found path /Windows/")
            self.logger.debug("[checkUserFolders] found path /Windows/")
            self._extractHivesFromWindowsFolder()
        else:            
            self.logger.info("Not found path /Windows/")

        self.logger.debug("[checkOptionsAndExtractFiles] - end")

    def run(self):
        try:
            ewf_path = self.imagePath
            # Abrir a imagem E01 (segmentada)
            filenames = pyewf.glob(ewf_path)
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)

            # Criação de um arquivo virtual a partir do handle EWF
            class EWFImgInfo(pytsk3.Img_Info):
                def __init__(self, ewf_handle):
                    self._ewf_handle = ewf_handle
                    super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

                def read(self, offset, size):
                    self._ewf_handle.seek(offset)
                    return self._ewf_handle.read(size)

                def get_size(self):
                    return self._ewf_handle.get_media_size()

            img_info = EWFImgInfo(ewf_handle)

            try:
                partition_table = pytsk3.Volume_Info(img_info)
                
                termPrint.printPartitionsTable(partitionTable=partition_table)
                with Progress() as progress:
                    task = progress.add_task("[cyan]Processing partitions...", total=partition_table.info.part_count)
                    for partition in partition_table:
                        progress.update(task, advance=1, description=f"[cyan]Processing partition #{partition.addr}...")
                        #console.log(f"Process partition #{partition.addr}")
                        #termPrint.printInfo(F"Process partition #{partition.addr}")
                        self.logger.info(f"Partição: {partition.addr}, Offset: {partition.start * 512}, Tamanho: {partition.len * 512}, DEC: {partition.desc}")
                        try:
                           filesystem = pytsk3.FS_Info(img_info, offset=partition.start * 512)
                           if pytsk3.TSK_FS_TYPE_NTFS == filesystem.info.ftype:
                                #termPrint.printInfo(f"NTFS filesystem found")
                                self.partitionAddr = partition.addr
                                self.pyTskFileSystem = filesystem
                                self.checkOptionsAndExtractFiles()

                        except IOError as e:
                            self.logger.error(f"Error on read files on partition {partition.addr}: {e}")
                        except Exception as e:
                            self.logger.error(f"Error on running {partition.addr}: {e}")
            except IOError as e:
               self.logger.error(f"Error on access partitions table {e}")
                #print(f"Erro ao acessar a tabela de partições: {e}")
            except Exception as e:
                self.logger.error(f"Error unexpected. ", e)
                #print(f"Erro inesperado ao acessar a tabela de partições: {e}")

            # Fechar o handle
            ewf_handle.close()

        except IOError as e:
            self.logger.info(f"Error on openImage E01")
            self.logger.error(f"Error on openImage E01: {e}")
        except pyewf.error as e:
            self.logger.error(f"Error on pyewf library: {e}")
        except Exception as e:
            self.logger.error(f"Error unexpected : {e}")
            



parser = argparse.ArgumentParser(description='HiveEx for extraction main hives on windows images')
parser.add_argument('--image', '-img', required=True, type=str, help='Location image E01')
parser.add_argument('--output', '-op', type=str, default=".",help='Folder to extract files')
parser.add_argument('--windows', '-ws', action='store_true', help='Extract windows hives (SAM, SYSTEM, SOFTWARE, SECURITY)')
parser.add_argument('--ntuserdat', '-n', action='store_true', help='Extract windows users hives (NTUSER.DAT)')
parser.add_argument('--sam', '-sm', action='store_true', help='Extract hive SAM')
parser.add_argument('--software', '-sfw', action='store_true', help='Extract hive SOFTWARE')
parser.add_argument('--system', '-sys', action='store_true', help='Extract hive SYSTEM')
parser.add_argument('--all', '-a', action='store_true', help='Extract all hives (NTUSER.DAT, SAM, SYSTEM, SOFTWARE, SECURITY)')
parser.add_argument('--debug', '-d', action='store_true', help='Show errors on console')

args = parser.parse_args()
print(f" Windows: {args.windows}")
mainCli = MainCli(arguments=args)
mainCli.run()