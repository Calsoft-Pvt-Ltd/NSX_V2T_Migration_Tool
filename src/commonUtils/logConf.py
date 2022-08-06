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
    def __new__(cls, executionMode, inputDict=None):
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

    def __init__(self, executionMode, inputDict=None, logConfig="loggingConf.yaml"):
        """
        Description :   Method to initialize the logging set-up
        Parameters  :   executionMode - mode of execution migrator script to be executed
                        logConfig - logging configuration for log handler in yaml. (STRING)
        """
        logConfigFile = os.path.join(constants.parentRootDir, "src", "commonUtils", logConfig)
        if self.instanceCount == 1:
            self.setupLogging(executionMode, inputDict, logConfigFile)

    @staticmethod
    def setupLogging(executionMode, inputDict, logConfig="loggingConf.yaml", logLevel=logging.INFO):
        """
        Description : Sets up the logging for main log or console log
        Parameters  : executionMode - mode of execution migrator script to be executed
                      logConfig     - logging configuration for log handler in yaml. (STRING)
                      logLevel      - set level of log i.e INFO, DEBUG (STRING)
        """
        logConfigFile = os.path.join(constants.parentRootDir, "src", "commonUtils", logConfig)
        baseLogPath = os.path.join(constants.parentRootDir, "logs")
        if executionMode == 'v2tAssessment':
            v2tAssessmentLogPath = os.path.join(baseLogPath, "VCD-" + inputDict["VCloudDirector"]["ipAddress"], "v2tAssessment")
            os.makedirs(v2tAssessmentLogPath, exist_ok=True)
        else:
            orgName = Logger.replace_unsupported_chars(inputDict["VCloudDirector"]["Organization"]["OrgName"])
            migrationLogPath = os.path.join(baseLogPath, "VCD-" + inputDict["VCloudDirector"]["Common"]["ipAddress"], "Migration")
            os.makedirs(migrationLogPath, exist_ok=True)
        # Importing logging settings from YAML file
        defaultPath = os.path.join(constants.rootDir, logConfigFile)
        path = defaultPath
        if os.path.exists(path):
            with open(path, 'rt') as f:
                config = yaml.safe_load(f.read())

            currentDateTime = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")

            if executionMode == 'preCheck':
                # set handlers for precheck Summary log file
                config["handlers"]["pre-assessment"]["filename"] = os.path.join(migrationLogPath, config["handlers"]["pre-assessment"]["filename"].format(
                                                                   orgName=orgName, mode=executionMode, timestamp=currentDateTime))

            if executionMode == 'v2tAssessment':
                # set handler for v2t assessment log file
                config["handlers"]["main"]["filename"] = os.path.join(v2tAssessmentLogPath, config["handlers"]["main"]["filename"].format(
                                                         orgName='', mode=executionMode + '-Log', timestamp=currentDateTime))
            else:
                # set handler for Main log file
                config["handlers"]["main"]["filename"] = os.path.join(migrationLogPath, config["handlers"]["main"]["filename"].format(
                                                         orgName=orgName + '-', mode=executionMode + '-Log' if executionMode == 'preCheck' else executionMode,
                                                         timestamp=currentDateTime))

            if executionMode == 'Main':
                # set handler for end state log file
                config["handlers"]["end-state-log"]["filename"] = os.path.join(migrationLogPath, config["handlers"]["end-state-log"]["filename"].format(
                                                                  orgName=orgName, mode=executionMode, timestamp=currentDateTime))

            if executionMode == 'preCheck':
                # delete handlers and loggers for end state log.
                del config["handlers"]["end-state-log"]
                del config['loggers']['endstateLogger']

            if executionMode == 'v2tAssessment':
                # deletes precheck logger as it is not required in v2tAssessment mode.
                del config["handlers"]["pre-assessment"]
                del config['loggers']['precheckLogger']
                # deletes end state logger as it is not required in v2tAssessment mode.
                del config["handlers"]["end-state-log"]
                del config['loggers']['endstateLogger']

            if executionMode == 'Main':
                # delete preCheck from handlers and loggers as it is not required in main migrator
                del config["handlers"]["pre-assessment"]
                del config['loggers']['precheckLogger']

            if executionMode == 'cleanup':
                # delete preCheck and inventory from handlers and loggers as it is not required in cleanup mode
                del config["handlers"]["pre-assessment"]
                del config['loggers']['precheckLogger']
            try:
                logging.config.dictConfig(config)
            except:
                if 'preCheck' in executionMode:
                    config["handlers"]["pre-assessment"]["filename"] = config["handlers"]["pre-assessment"]["filename"].replace(orgName, "Organization")

                if 'v2tAssessment' not in executionMode:
                    config["handlers"]["main"]["filename"] = config["handlers"]["main"]["filename"].replace(orgName, "Organization")

                # Set handlers for StateLog file
                if 'Main' in executionMode:
                    config["handlers"]["end-state-log"]["filename"] = config["handlers"]["end-state-log"]["filename"].replace(orgName, "Organization")

                logging.config.dictConfig(config)
        else:
            logging.basicConfig(level=logLevel)

    def replace_unsupported_chars(text):
        """
        Description: Removes unsupported characters by replacing with empty string
        """
        for c in ':?><|\*/"':
            text = text.replace(c, '')
        return text
