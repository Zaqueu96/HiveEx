import hashlib
import os
import utils.loggerUtils as loggerUtils
from tenacity import retry, stop_after_attempt, wait_fixed
from utils import terminalPrint
class FileObjectUtils:
    def __init__(self, fileObject, outputPath, prefixName=""):
        self.fileObject = fileObject
        self.outputPath = outputPath
        self.prefixName = prefixName.replace(" ", "_")
        self.logger = loggerUtils.getLogger(__name__)
        
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
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
            self.logger.error("[fileCalculateHash] error", exc_info=True)  
            terminalPrint.printError(f"Error on extract  message: {e.message}")
            raise RuntimeError(f"Unexpected error while trying to generate hashes: {e}")
    
    def _getOutputFormated(self):
        fileName = self._extractOnlyFileName()
        if self.prefixName != None and self.prefixName != "":
            return f"{self.outputPath}{os.sep}{self.prefixName}_{fileName}" 
        else:
            return f"{self.outputPath}{os.sep}{fileName}"
        
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def fileExtract(self):
        self.logger.info("[fileExtract] start")
        try:            
            outputFilePath = self._getOutputFormated()           
            
            with open(outputFilePath, 'wb') as outfile:
                filedata = self.fileObject.read_random(0, self.fileObject.info.meta.size)
                outfile.write(filedata)                
            
            self._generateFileHashes()
                
            self.logger.info(f"[fileExtract] end outputPath: {self.outputPath}")
        except Exception as e:
            term
            self.logger.error("[fileExtract] error", exc_info=True)  
            raise RuntimeError(f"Unexpected error while trying to extract: {e}")
        
    def _generateFileHashes(self):
        self.logger.info("[_generateFileHashes] init")
        try:
            md5_digest, sha1_digest, sha256_digest =  self.fileCalculateHash()
            with open(f"{self._getOutputFormated()}.hash.txt",'w') as outputFile:
                outputFile.write(f"MD5: {md5_digest}\nSHA1: {sha1_digest}\nSHA256: {sha256_digest}")
          
        except Exception as  e:
            self.logger.info("generate file hash error")
            self.logger.error("[_generateFileHashes] error", e)
    
    def _extractOnlyFileName(self):
        return self.fileObject.info.name.name.decode('utf-8')
    
    def fileExistsCount(self, filePath):
        self.logger.info("[fileExistsCount] start")  
        try:
            return os.listdir(filePath).count()
        except FileNotFoundError:
            self.logger.info("[fileExistsCount] error file not found")
            return 0
        except Exception as e:
            self.logger.error("[fileExistsCount] error", exc_info=True)
            return 0
