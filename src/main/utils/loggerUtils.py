import logging

loggerFileInfo = "info_hiveex.log"
loggerFileDebug = "debug_hiveex.log"
loggerFileError = "error_hiveex.log"
loggerFileDefault = "hiveex.log"


def getLogger(filename):
    logging.basicConfig(filename=loggerFileDefault, level=logging.INFO)
    logging.basicConfig(filename=loggerFileDefault, level=logging.ERROR)
    logging.basicConfig(filename=loggerFileDefault, level=logging.DEBUG)
    return logging.getLogger(filename);
    