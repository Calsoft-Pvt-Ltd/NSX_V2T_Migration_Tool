# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which handles the logging of the migration of vCloud Director NSXV to NSXT
"""

import os
import datetime
import logging
import logging.config

import yaml

from src import constants


class Logger():
    """
    Description: Class to log the events into a file for vCloud Director migration from NSX-V to NSX-T
    """

    _loggerInstance = None
    def __new__(cls):
        """
        Description : Defining a new method to make the Singleton Logger class
        """
        if not cls._loggerInstance:
            cls._loggerInstance = super(Logger, cls).__new__(cls)
            cls._loggerInstance.instanceCount = 1
        else:
            cls._loggerInstance.instanceCount += 1
        return cls._loggerInstance

    def __init__(self, logConfig="loggingConf.yaml"):
        """
        Description :   Method to initialize the logging set-up
        Parameters  :   logConfig - logging configuration for log handler in yaml. (STRING)
        """
        logConfigFile = os.path.join(constants.parentRootDir, "src", "commonUtils", logConfig)
        if self.instanceCount == 1:
            self.setupLogging(logConfigFile)

    @staticmethod
    def setupLogging(logConfig="loggingConf.yaml", logLevel=logging.INFO):
        """
        Description : Sets up the logging for main log or console log
        Parameters  : logConfig     - logging configuration for log handler in yaml. (STRING)
                      logLevel      - set level of log i.e INFO, DEBUG (STRING)
        """
        logConfigFile = os.path.join(constants.parentRootDir, "src", "commonUtils", logConfig)
        baseLogPath = os.path.join(constants.parentRootDir, "logs")
        if not os.path.exists(baseLogPath):
            os.mkdir(baseLogPath)
        # Importing logging settings from YAML file
        defaultPath = os.path.join(constants.rootDir, logConfigFile)
        path = defaultPath
        if os.path.exists(path):
            with open(path, 'rt') as f:
                config = yaml.safe_load(f.read())
            currentDateTime = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
            mainLogFile = config["handlers"]["main"]["filename"]
            config["handlers"]["main"]["filename"] = '{}-{}.log'.format(mainLogFile.split(".")[0], currentDateTime)
            mainLogPath = config["handlers"]["main"]["filename"]
            config["handlers"]["main"]["filename"] = os.path.join(baseLogPath, mainLogPath)

            componentLogFile = config["handlers"]["tabular"]["filename"]
            config["handlers"]["tabular"]["filename"] = '{}-{}.log'.format(componentLogFile.split(".")[0], currentDateTime)
            componentLogPath = config["handlers"]["tabular"]["filename"]
            config["handlers"]["tabular"]["filename"] = os.path.join(baseLogPath, componentLogPath)
            logging.config.dictConfig(config)

        else:
            logging.basicConfig(level=logLevel)
