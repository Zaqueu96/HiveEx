#/usr/bin/python3

import pyewf
import pytsk3
from utils.fileObjectUtils import FileObjectUtils

# Caminho para a primeira parte da imagem E01
ewf_path = "D:\Forensics Images\Windows Forensics_ForensicVM-Dataset\\bart.E01"

NOT_IN_FOLDERS = [".", ".."]
FILENAME_NTUSER_DAT= "NTUSER.DAT"

def getOnlyName(entry):
    return entry.info.name.name.decode('utf-8')


def checkFolders(filesystem):
    directoryUsers = filesystem.open_dir(path="/Windows/")
    
    # Get user hive NTUSER.DAT
    directoryListUsers = filesystem.open_dir(path="/Users/")
    for entry in directoryListUsers:
        entryName = entry.info.name.name.decode('utf-8')          
        if( entry.info.meta.type  == pytsk3.TSK_FS_META_TYPE_DIR and entryName not in NOT_IN_FOLDERS):    
            directoryByUser =  filesystem.open_dir(path=f"/Users/{entryName}")  
            listDirectories  = map(getOnlyName, directoryByUser);
            if(FILENAME_NTUSER_DAT in listDirectories):
                fileObject =  filesystem.open(f"/Users/{entryName}/{FILENAME_NTUSER_DAT}")
                objectUtils = FileObjectUtils(fileObject, ".", entryName);
                print(f"Nome: {entryName}, Tamanho: {entry.info.meta.size if entry.info.meta else 'N/A'}")
                md5_digest, sha1_digest, sha256_digest =  objectUtils.fileCalculateHash()
                print(f"MD5: {md5_digest}")
                print(f"SHA-1: {sha1_digest}")
                print(f"SHA-256: {sha256_digest}")
                objectUtils.fileExtract()
            #outfile = open(outFileName, 'w')
            #filedata = fileobject.read_random(0,fileobject.info.meta.size)
            #outfile.write(filedata)
            #outfile.close
    

try:
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
        # Acessar a partição e o sistema de arquivos
        partition_table = pytsk3.Volume_Info(img_info)
        for partition in partition_table:
            print(f"Partição: {partition.addr}, Offset: {partition.start * 512}, Tamanho: {partition.len * 512}, DEC: {partition.desc}")
            try:
               filesystem = pytsk3.FS_Info(img_info, offset=partition.start * 512)
               if pytsk3.TSK_FS_TYPE_NTFS == filesystem.info.ftype:
                   checkFolders(filesystem=filesystem)
            except IOError as e:
                print(f"Erro ao acessar o sistema de arquivos na partição {partition.addr}: {e}")
            except Exception as e:
                print("")
                #print(f"Erro inesperado ao acessar o sistema de arquivos na partição {partition.addr}: {e}")
    except IOError as e:
        print("")
        #print(f"Erro ao acessar a tabela de partições: {e}")
    except Exception as e:
        print("")
        #print(f"Erro inesperado ao acessar a tabela de partições: {e}")

    # Fechar o handle
    ewf_handle.close()

except IOError as e:
    print(f"Erro ao abrir a imagem E01: {e}")
except pyewf.error as e:
    print(f"Erro específico do pyewf: {e}")
except Exception as e:
    print(f"Erro inesperado: {e}")