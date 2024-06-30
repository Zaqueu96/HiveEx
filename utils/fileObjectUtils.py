import hashlib
import logging
import os

class FileObjectUtils:
    def __init__(self, fileObject, outputPath, prefixName=""):
        self.fileObject = fileObject
        self.outputPath = outputPath
        self.prefixName = prefixName.replace(" ","_")
        self.logger = logging.getLogger(__name__)
    
    def fileCalculateHash(self):
        self.logger.info("[fileCalculateHash] start")
        try:
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            
            size = 1024 * 1024 
            offset = 0

            while offset < self.fileObject.info.meta.size:
                available_to_read = min(size, self.fileObject.info.meta.size - offset)
                data = self.fileObject.read_random(offset, available_to_read)
                if not data:
                    break
                md5_hash.update(data)
                sha1_hash.update(data)
                sha256_hash.update(data)
                offset += len(data)

            md5_digest = md5_hash.hexdigest()
            sha1_digest = sha1_hash.hexdigest()
            sha256_digest = sha256_hash.hexdigest()
            self.logger.info("[fileCalculateHash] end")
            return md5_digest, sha1_digest, sha256_digest
        except Exception as e:
            self.logger.error("[fileCalculateHash] error", e)  
            raise RuntimeError(f"Erro inesperado tentar gerar os hashes: {e}")

    def fileExtract(self):
        print("[fileExtract] start")
        self.logger.info(f"[fileExtract] start")
        try:
            fileName  = self.extractOnlyFileName()
            outputFilePath = f"{self.outputPath}{os.sep}{self.prefixName}_{fileName}"
            #countFileExist = self.fileExistsCount(outputFilePath);
            
            #if(countFileExist > 0):
            #    outputFilePath += f"_{countFileExist}"  
                              
            outfile = open(outputFilePath, 'w')
            filedata = self.fileObject.read_random(0,self.fileObject.info.meta.size)
            outfile.write(filedata)
            outfile.close()
            print(f"[fileExtract] end: {self.outputPath}")            
            self.logger.info(f"[fileExtract] end outputPath: {self.outputPath}")
        except Exception as e:  
            #self.logger.error("[fileExtract] error", e)  
            raise RuntimeError(f"Erro inesperado tentar gerar os hashes: {e}")
    
    def extractOnlyFileName(self):
        return self.fileObject.info.name.name.decode('utf-8');
    
    def fileExistsCount(self, filePath):
        self.logger.info("[fileExistsCount] start")  
        try:
            return os.listdir(filePath).count()
        except FileNotFoundError as fileNotFoundExecpt:
            self.logger.info("[fileExistsCount] error file not found")
            return 0
        except Exception as e:
            self.logger.error("[fileExistsCount] error", e)