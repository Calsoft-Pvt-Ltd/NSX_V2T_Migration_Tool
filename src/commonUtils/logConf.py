# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

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
    def __new__(cls, executionMode):
        """
        Description : Defining a new method to make the Singleton Logger class
        Parameters  : executionMode - mode of execution migrator script to be executed
        """
        if not cls._loggerInstance:
            cls._loggerInstance = super(Logger, cls).__new__(cls)
            cls._loggerInstance.instanceCount = 1
        else:
            cls._loggerInstance.instanceCount += 1
        return cls._loggerInstance

    def __init__(self, executionMode, logConfig="loggingConf.yaml"):
        """
        Description :   Method to initialize the logging set-up
        Parameters  :   executionMode - mode of execution migrator script to be executed
                        logConfig - logging configuration for log handler in yaml. (STRING)
        """
        logConfigFile = os.path.join(constants.parentRootDir, "src", "commonUtils", logConfig)
        if self.instanceCount == 1:
            self.setupLogging(executionMode, logConfigFile)

    @staticmethod
    def setupLogging(executionMode, logConfig="loggingConf.yaml", logLevel=logging.INFO):
        """
        Description : Sets up the logging for main log or console log
        Parameters  : executionMode - mode of execution migrator script to be executed
                      logConfig     - logging configuration for log handler in yaml. (STRING)
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

            if executionMode == 'preCheck':
                # delete handlers and loggers for end state log.
                del config["handlers"]["end-state-log"]
                del config['loggers']['endstateLogger']
                # set handlers for preCheck Details file
                executionMode = executionMode + '-Log'
                componentLogFile = config["handlers"]["pre-assessment"]["filename"]
                config["handlers"]["pre-assessment"]["filename"] = '{}-{}.log'.format(componentLogFile.split(".")[0],
                                                                                      currentDateTime)
                componentLogPath = config["handlers"]["pre-assessment"]["filename"]
                config["handlers"]["pre-assessment"]["filename"] = os.path.join(baseLogPath, componentLogPath)

            if executionMode == 'v2tAssessment':
                # set handlers for preCheck Details file
                del config["handlers"]["pre-assessment"]
                del config['loggers']['precheckLogger']
                # delete handlers and loggers for end state log.
                del config["handlers"]["end-state-log"]
                del config['loggers']['endstateLogger']
                executionMode = executionMode + '-Log'

            # Set handlers for main log file
            mainLogFile = config["handlers"]["main"]["filename"].format(executionMode)
            config["handlers"]["main"]["filename"] = '{}-{}.log'.format(mainLogFile.split(".")[0], currentDateTime)
            mainLogPath = config["handlers"]["main"]["filename"]
            config["handlers"]["main"]["filename"] = os.path.join(baseLogPath, mainLogPath)

            # Set handlers for StateLog file
            if executionMode == 'Main':
                stateLogFile = config["handlers"]["end-state-log"]["filename"].format(executionMode)
                config["handlers"]["end-state-log"]["filename"] = '{}-{}.log'.format(stateLogFile.split(".")[0], currentDateTime)
                stateLogPath = config["handlers"]["end-state-log"]["filename"]
                config["handlers"]["end-state-log"]["filename"] = os.path.join(baseLogPath, stateLogPath)

            if executionMode == 'Main':
                # delete preCheck from handlers and loggers as it is not required in main migrator
                del config["handlers"]["pre-assessment"]
                del config['loggers']['precheckLogger']

            if executionMode == 'cleanup':
                # delete preCheck and inventory from handlers and loggers as it is not required in cleanup mode
                del config["handlers"]["pre-assessment"]
                del config['loggers']['precheckLogger']
                # deletes end state logger as it is not required in cleanup mode.
                del config["handlers"]["end-state-log"]
                del config['loggers']['endstateLogger']

            if executionMode == 'v2tAssessment':
                del config["handlers"]["pre-assessment"]
                del config['loggers']['precheckLogger']
                # deletes end state logger as it is not required in v2tAssessment mode.
                del config["handlers"]["end-state-log"]
                del config['loggers']['endstateLogger']

            logging.config.dictConfig(config)

        else:
            logging.basicConfig(level=logLevel)
