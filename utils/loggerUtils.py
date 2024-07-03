import logging

loggerFileInfo = "info_hiveex.log"
loggerFileDebug = "debug_hiveex.log"
loggerFileError = "error_hiveex.log"


def getLogger(filename):
    #logging.basicConfig(filename=loggerFileInfo, level=logging.INFO)
    #logging.basicConfig(filename=loggerFileError, level=logging.ERROR)
    #logging.basicConfig(filename=loggerFileDebug, level=logging.DEBUG)
    return logging.getLogger(filename);
    