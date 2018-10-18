from json import load
from os import environ, path
from singleton_type import SingletonType

####################################################################
#       CONFIGURATION                                              #
####################################################################
APPDATA = environ["APPDATA"]
BASE_PATH = path.join(APPDATA, "DigiSign")
JSON_CONFIG_FILE = path.join(BASE_PATH, "config.json")
####################################################################

class MyConfigLoader(object, metaclass=SingletonType):
    _config = None

    def __init__(self):
        with open(JSON_CONFIG_FILE) as _file:
            self._config = load(_file)
        # adding BASE_PATH to all folder names
        for group in self._config:
            for item in self._config[group]:
                if item.find("_folder") >= 0:
                    folder_name = self._config[group][item]
                    self._config[group][item] = path.join(BASE_PATH, folder_name)

    def get_logger_config(self):
        return self._config["logger"]

    def get_server_config(self):
        return self._config["server"]