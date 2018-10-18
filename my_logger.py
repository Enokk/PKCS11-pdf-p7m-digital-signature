from logging import getLogger, INFO, Formatter
from logging.handlers import RotatingFileHandler
from my_config_loader import MyConfigLoader
from os import path, mkdir
from singleton_type import SingletonType


####################################################################
#       CONFIGURATION                                              #
####################################################################
LOGGER_NAME = "cicerone"
LOGGING_FOLDER = MyConfigLoader().get_logger_config()["log_folder"]
LOGGING_FILE = MyConfigLoader().get_logger_config()["log_file_name"]
LOGGING_FILE_PATH = path.join(LOGGING_FOLDER, LOGGING_FILE)
FILE_SIZE = MyConfigLoader().get_logger_config()["file_byte_size"]
LOG_FILE_COUNT = MyConfigLoader().get_logger_config()["log_files_count"]
####################################################################


class MyLogger(object, metaclass=SingletonType):
    _logger = None

    def __init__(self):
        if not path.isdir(LOGGING_FOLDER):
            mkdir(LOGGING_FOLDER)

        self._logger = getLogger(LOGGER_NAME)
        self._logger.setLevel(INFO)

        handler = RotatingFileHandler(
            LOGGING_FILE_PATH, maxBytes=FILE_SIZE, backupCount=LOG_FILE_COUNT)
        formatter = Formatter(
            '%(asctime)s - [%(levelname)s | %(filename)s:%(lineno)s] > %(message)s')
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)

        self._logger.info("  ---  Started logger  ---")

    def my_logger(self):
        return self._logger
