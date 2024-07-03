#/usr/bin/python3

import pyewf
import pytsk3
from utils.fileObjectUtils import FileObjectUtils
import utils.loggerUtils as loggerUtils
import argparse
from enum import Enum
import os.path
from tenacity import retry, stop_after_attempt, wait_fixed



class ExtractHiveType:
    WINDOWS = 'windows'
    NTUSERDAT = 'ntuserdat'
    SAM = 'sam'
    SOFTWARE = 'software'
    SYSTEM = 'system'
    SECURITY = 'security'
    

# Caminho para a primeira parte da imagem E01
ewf_path = "D:\Forensics Images\Windows Forensics_ForensicVM-Dataset\\bart.E01"

NOT_IN_FOLDERS = [".", ".."]
FILENAME_NTUSER_DAT= "NTUSER.DAT"

class MainCli:
    def __init__(self, arguments):
        self.logger = loggerUtils.getLogger(__name__)
        self.forAllWindowHive = False        

        self.defineHiveTypesExtractOptions(arguments)         

              
        if(arguments.image == ""):
            raise RuntimeError(f"imagePath is not valid!")  

        self.extractNTUSERDatForUsers = arguments.ntuserdat        
        self.imagePath = arguments.image
        self.outputPath = arguments.output
        self.checkImagePath()

    def defineHiveTypesExtractOptions(self, arguments):
        self.hive_types = [
            ExtractHiveType.WINDOWS, 
            ExtractHiveType.NTUSERDAT, 
            ExtractHiveType.SAM, 
            ExtractHiveType.SOFTWARE, 
            ExtractHiveType.SYSTEM, 
            ExtractHiveType.SECURITY
        ]
        
        hiveIsDefined = arguments.windows
        self.forAllWindowHive = arguments.windows
        if not arguments.windows and any(hasattr(arguments, hive) for hive in self.hive_types):
                for hive in self.hive_types:
                    if getattr(arguments, hive, False):
                        setattr(self, f"extract_{hive}", True)
                        hiveIsDefined = True
                        
        if(not hiveIsDefined):
            raise RuntimeError("At least one hive extraction option must be specified (--windows, --ntuserdat, --sam, --software, --system, --security)")
    
            
    def getOnlyName(self, entry):
        return entry.info.name.name.decode('utf-8')

    def checkImagePath(self):
        self.logger.debug(f"[isFile] start check file: {self.imagePath}")
        self.logger.info(f"Checking if is file :{self.imagePath}")
        if(os.path.isfile(path=self.imagePath)):
            self.logger.info(f"Checked file: {self.imagePath}")
        else:
            self.logger.info("Check failed, path is not a file")
            raise RuntimeError("Error imagePath not contains file")
    
    def getFoldersExistsCheck(self, filePytskSystem):
        existsFolderUser = False
        existsFolderWindows = False
        directories = filePytskSystem.open_dir("/")
        listFolderName =  map(self.getOnlyName, directories);
        if("Users" in listFolderName):
            existsFolderUser  = True
        if("Windows" in listFolderName):
            existsFolderWindows = True
        return  existsFolderUser, existsFolderWindows
    
    def getHiveFoldersValidated(self):
        if self.forAllWindowHive:
            hives =   {
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
            
            return hives;
        
    def extractHivesFromWindowsFolder(self, fileSystem):
        hivesKeyAndPaths = self.getHiveFoldersValidated()
        self.logger.debug(f"[extractHivesFromWindowsFolder] start ")
        try:
            for nameHive, path in hivesKeyAndPaths.items():
                self.extractHiveWindows(fileSystem, nameHive, path)
        except Exception as e:
            self.logger.info('There was an unexpected error while trying to load the NTUSER.dat file for users')
            self.logger.error("Error on check folders", e)
            raise e
        finally:
            self.logger.debug(f"[extractHivesFromWindowsFolder] end finally")

    def extractHiveWindows(self, fileSystem, nameHive, path):
        self.logger.info(f"Extracting hive {nameHive}...")
        fileObject = fileSystem.open(path=path)
        objectUtils = FileObjectUtils(fileObject, self.outputPath);
        self.logger.debug(f"Name: {nameHive}")
        self.logger.info(f"Name: {nameHive} found")
        md5_digest, sha1_digest, sha256_digest =  objectUtils.fileCalculateHash()
        self.logger.info(f"MD5: {md5_digest}")
        self.logger.info(f"SHA-1: {sha1_digest}")
        self.logger.info(f"SHA-256: {sha256_digest}")
        objectUtils.fileExtract()
            
        
    @retry(stop=stop_after_attempt(1), wait=wait_fixed(1))  # Retry up to 3 times, waiting 2 seconds between retries
    def checkUserFolders(self, filesystem):
        self.logger.debug(f"[checkUserFolders] start ")
        self.logger.info("Checking folders in /Users/")
        try:
            # Get user hive NTUSER.DATmap(self.getOnlyName, directoryByUser);
            directoryListUsers = filesystem.open_dir(path="/Users/")
            for entry in directoryListUsers:
                entryName = entry.info.name.name.decode('utf-8')          
                if( entry.info.meta.type  == pytsk3.TSK_FS_META_TYPE_DIR and entryName not in NOT_IN_FOLDERS):    
                    self.listDirectoryUsersAndExtractFile(filesystem, entry, entryName)
        except Exception as e:
            self.logger.info('There was an unexpected error while trying to load the NTUSER.dat file for users')
            self.logger.error("Error on check folders", e)
            raise e
        finally:
            self.logger.debug(f"[checkUserFolders] end finally")

    def listDirectoryUsersAndExtractFile(self, filesystem, entry, entryName):
        directoryByUser =  filesystem.open_dir(path=f"/Users/{entryName}")  
        listDirectories  = map(self.getOnlyName, directoryByUser);
        if(FILENAME_NTUSER_DAT in listDirectories):
            self.readAndExtractNTDUSERDat(filesystem, entry, entryName)
            
    @retry(stop=stop_after_attempt(2), wait=wait_fixed(1))
    def readAndExtractNTDUSERDat(self, filesystem, entry, entryName):
        fileObject =  filesystem.open(f"/Users/{entryName}/{FILENAME_NTUSER_DAT}")
        objectUtils = FileObjectUtils(fileObject, self.outputPath, entryName);
        self.logger.debug(f"Name: {entryName}, Size: {entry.info.meta.size if entry.info.meta else 'N/A'}")
        self.logger.info(f"Name: {entryName} found")
        md5_digest, sha1_digest, sha256_digest =  objectUtils.fileCalculateHash()
        self.logger.info(f"MD5: {md5_digest}")
        self.logger.info(f"SHA-1: {sha1_digest}")
        self.logger.info(f"SHA-256: {sha256_digest}")
        objectUtils.fileExtract()
        
    def checkOptionsAndExtractFiles(self, pyTskFileSystem):
        self.logger.debug("[checkOptionsAndExtractFiles] - start")
        existsFolderUser, existsFolderWindows = self.getFoldersExistsCheck(filePytskSystem=pyTskFileSystem)
        if(existsFolderUser and self.extractNTUSERDatForUsers):
            self.logger.info("Found path /Users/")
            self.logger.debug("[checkUserFolders] found path /Users/")
            self.checkUserFolders(filesystem=pyTskFileSystem)
        else:            
            self.logger.info("Not found path /Users/")
            self.logger.debug("[checkUserFolders] Not found path /Users/")
            
        if(existsFolderWindows):
            self.logger.info("Found path /Windows/")
            self.logger.debug("[checkUserFolders] found path /Windows/")
            print("Exists folder Windows")
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
                for partition in partition_table:
                    self.logger.error(f"Partição: {partition.addr}, Offset: {partition.start * 512}, Tamanho: {partition.len * 512}, DEC: {partition.desc}")
                    try:
                       filesystem = pytsk3.FS_Info(img_info, offset=partition.start * 512)
                       if pytsk3.TSK_FS_TYPE_NTFS == filesystem.info.ftype:
                            self.checkOptionsAndExtractFiles(pyTskFileSystem=filesystem)
                    except IOError as e:
                        self.logger.error(f"Error on read files on partition {partition.addr}: {e}")
                    except Exception as e:
                        self.logger.error(f"Error on run {partition.addr}: {e}")
            except IOError as e:
                print("")
                #print(f"Erro ao acessar a tabela de partições: {e}")
            except Exception as e:
                print("")
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
parser.add_argument('--image', '-i', required=True, type=str, help='Location image E01')
parser.add_argument('--output', '-o', type=str, help='Folder to extract files')
parser.add_argument('--windows', '-w', action='store_true', help='Extract windows hives (SAM, SYSTEM, SOFTWARE, SECURITY)')
parser.add_argument('--ntuserdat', '-n', action='store_true', help='Extract windows users hives (NTUSER.DAT)')
parser.add_argument('--sam', '-s', action='store_true', help='Extract hive SAM')
parser.add_argument('--software', '-sw', action='store_true', help='Extract hive SOFTWARE')
parser.add_argument('--system', '-sys', action='store_true', help='Extract hive SYSTEM')

args = parser.parse_args()
print(f" Windows: {args.windows}")
mainCli = MainCli(arguments=args)
mainCli.run()