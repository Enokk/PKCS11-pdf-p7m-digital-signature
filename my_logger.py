import logging
from logging.handlers import RotatingFileHandler
import os


class SingletonType(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(
                SingletonType, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class MyLogger(object, metaclass=SingletonType):
    _logger = None

    def __init__(self):
        dirname = "./log"
        if not os.path.isdir(dirname):
            os.mkdir(dirname)

        self._logger = logging.getLogger("cicerone")
        self._logger.setLevel(logging.INFO)

        handler = RotatingFileHandler(
            'log/digiSign.log', maxBytes=51200-51000, backupCount=10)
        formatter = logging.Formatter(
            '%(asctime)s - [%(levelname)s | %(filename)s:%(lineno)s] > %(message)s')
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)


    def my_logger(self):
        return self._logger
