# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which contains all the utilities required for VMware Cloud Director migration from NSX-V to NSX-T
"""

import json
import logging
import os

import jinja2
import yaml

logger = logging.getLogger('mainLogger')


class Utilities():
    """
    Description :   This class provides commonly used methods for vCloud Director NSXV to NSXT
    """
    @staticmethod
    def readYamlData(yamlFile):
        """
        Description : Read the given yaml file and return a its data as dictionary
        Parameters  : yamlFile - Path of the YAML file to be retrieved (STRING)
        Returns     : yamlData - Dictionary of data from YAML (DICTIONARY)
        """
        if os.path.exists(yamlFile):
            try:
                with open(yamlFile, 'r') as yamlObject:
                    yamlData = yaml.safe_load(yamlObject)
            except Exception:
                invalidYamlMessage = "Invalid YAML file: {}.".format(yamlFile)
                logger.error(invalidYamlMessage)
                raise Exception(invalidYamlMessage)
        else:
            yamlNotPresentMessage = "YAML file '{}' does not exists.".format(yamlFile)
            logger.error(yamlNotPresentMessage)
            raise Exception(yamlNotPresentMessage)
        return yamlData

    @staticmethod
    def readJsonData(jsonFile):
        """
        Description : Read the given json file and return its data
        Parameters  : jsonFile - Path of the Json file to be retrieved (STRING)
        Returns     : jsonData - Dictionary of data from Json file (DICTIONARY)
        """
        if os.path.exists(jsonFile):
            try:
                with open(jsonFile, 'r') as jsonObject:
                    jsonData = json.load(jsonObject)
            except Exception:
                invalidJsonMessage = "Invalid JSON file: {}.".format(jsonFile)
                logger.error(invalidJsonMessage)
                raise Exception(invalidJsonMessage)
        else:
            jsonNotPresentMessage = "JSON file '{}' does not exists.".format(jsonFile)
            logger.error(jsonNotPresentMessage)
            raise Exception(jsonNotPresentMessage)
        return jsonData

    @staticmethod
    def getTemplate(templateData):
        """
        Description : Return data template which can be updated with desired values later.
        Parameters  : templateData - contains the details of data dictionary (DICTIONARY)
        """
        # initialize the jinja2 environment
        env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        # get the template
        template = env.get_template(env.from_string(templateData))
        return template

    def createPayload(self, filePath, payloadDict, fileType='yaml', componentName=None, templateName=None):
        """
        Description : This function creates payload for particular template which can be used in Rest API for vmware component.
        Parameters  : filePath      - Path of the file (STRING)
                      payloadDict   - contains the details of payload values (DICT)
                      fileType      - type of the file (STRING) DEFAULT 'yaml'
                      componentName - Name of component (STRING) DEFAULT None
                      templateName  - Name of template for payload (STRING) DEFAULT None
        Returns     : payloadData   - Returns the updated payload data of particular template
        """
        try:
            if fileType.lower() == 'json':
                # load json file into dict
                templateData = self.readJsonData(filePath)
                templateData = json.dumps(templateData)
            else:
                templateData = self.readYamlData(filePath)
                templateData = json.dumps(templateData)
            # check if the componentName and templateName exists in File, if exists then return it's data
            if componentName and templateName:
                templateData = json.loads(templateData)
                if templateData[componentName][templateName]:
                    templateData = json.dumps(templateData[componentName][templateName])
            # get the template with data which needs to be updated
            template = self.getTemplate(templateData)
            # render the template with the desired payloadDict
            payloadData = template.render(payloadDict)
            # payloadData = json.loads(payloadData)
            logger.debug('Successfully created payload.')
            return payloadData
        except Exception as err:
            logger.error(err)
            raise
