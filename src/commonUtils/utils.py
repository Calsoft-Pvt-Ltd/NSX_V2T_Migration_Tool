# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which contains all the utilities required for VMware Cloud Director migration from NSX-V to NSX-T
"""

import json
import logging
import os
import re
import traceback

import certifi
import jinja2
import yaml
import xmltodict
from xml.sax.saxutils import escape

logger = logging.getLogger('mainLogger')


def listify(_list):
    """
    Description : Converts to list if not a list
    Parameters  : _list - data to be converted to list (ANY)
    """
    # If NoneType or empty value is provided return empty list
    if not _list:
        return []

    return _list if isinstance(_list, list) else [_list]


def urn_id(_id, _type):
    return _id if _id.startswith('urn') else f"urn:vcloud:{_type}:{_id}"


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
                logger.debug(traceback.format_exc())
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
                logger.debug(traceback.format_exc())
                raise Exception(invalidJsonMessage)
        else:
            jsonNotPresentMessage = "JSON file '{}' does not exists.".format(jsonFile)
            logger.error(jsonNotPresentMessage)
            raise Exception(jsonNotPresentMessage)
        return jsonData

    def readFile(self, fileName):
        """
        Description : Read a file with given filename
        Parameters  : fileName   - Name of the file along with the path to be read (STRING)
        """
        try:
            if os.path.exists(fileName):
                with open(fileName, 'r') as f:
                    data = json.load(f)
                    return data
            else:
                logging.debug(f"File Not Found - '{fileName}'")
        except Exception as exception:
            raise exception

    def writeToFile(self, fileName, data):
        """
        Description : Write to a file with given filename
        Parameters  : fileName   - Name of the file along with the path (STRING)
        """
        try:
            with open(fileName, 'w') as f:
                json.dump(data, f, indent=3)
        except Exception as exception:
            raise exception

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

    def fetchJSON(self, templateData, apiVersion):
        """
            Description: Cleanup of metadata after its generation to reduce overall size of metadata
            Parameters: metadata that needs cleanup for size reduction - (DICT)
        """
        if isinstance(templateData, dict):
            for key in list(templateData.keys()):
                # If key present in list of keys to be removed then delete its key value pair from metadata
                if re.match(r'APIVERSION-\d+\.\d+', key) and apiVersion not in key:
                    # Delete key from metadata dictionary
                    del templateData[key]
                elif re.match(r'APIVERSION-\d+\.\d+', key) and apiVersion in key:
                    data = templateData[key]
                    del templateData[key]
                    templateData[list(data.keys())[0]] = data[list(data.keys())[0]]
                else:
                    self.fetchJSON(templateData[key], apiVersion)
        elif isinstance(templateData, list):
            for index in reversed(range(len(templateData))):
                if isinstance(templateData[index], dict):
                    self.fetchJSON(templateData[index], apiVersion)

    def createPayload(self, filePath, payloadDict, fileType='yaml', componentName=None, templateName=None, apiVersion='34.0'):
        """
        Description : This function creates payload for particular template which can be used in Rest API for vmware component.
        Parameters  : filePath      - Path of the file (STRING)
                      payloadDict   - contains the details of payload values (DICT)
                      fileType      - type of the file (STRING) DEFAULT 'yaml'
                      componentName - Name of component (STRING) DEFAULT None
                      templateName  - Name of template for payload (STRING) DEFAULT None
        Returns     : payloadData   - Returns the updated payload data of particular template
        """
        def encodeSpecialCharacters(payload):
            """
            Handling special characters in each string value in payload recursively
            """
            if isinstance(payload, str) and not payload.startswith('<') and not payload.isalnum():
                if fileType == 'yaml':
                    # escape is used for xml payload only to encrypt special characters like <, >, ', ", and &
                    payload = escape(payload, {"'": "&apos;", '"': '&quot;'})

                # json.dumps will encrypt  special characters like \, \r and \n
                # Removing quotes (") at the beginning and end after json.dumps
                payload = json.dumps(payload)[1:-1]
                return payload

            if isinstance(payload, dict):
                return {encodeSpecialCharacters(key): encodeSpecialCharacters(value) for key, value in payload.items()}

            if isinstance(payload, (list, tuple)):
                return [encodeSpecialCharacters(item) for item in payload]

            # Return as it is if datatype is other than evaluated above.
            return payload

        try:
            fileType = fileType.lower()
            if fileType == 'json':
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
                    templateData = templateData[componentName][templateName]
                    if apiVersion and fileType == 'yaml':
                        apiVersionMatches = re.findall(r'<APIVERSION-\d+\.\d+>.*?</APIVERSION-\d+\.\d+>', templateData)
                        for match in apiVersionMatches:
                            if not re.search(f'APIVERSION-{apiVersion}', match):
                                templateData = templateData.replace(match, '')
                        if re.search(r'</?APIVERSION-\d+\.\d+>', templateData):
                            templateData = re.sub(r'</?APIVERSION-\d+\.\d+>', '', templateData)

                    if apiVersion and fileType == 'json':
                        self.fetchJSON(templateData, apiVersion)
                    templateData = json.dumps(templateData)
            # get the template with data which needs to be updated
            template = self.getTemplate(templateData)
            # render the template with the desired payloadDict
            payloadData = template.render(encodeSpecialCharacters(payloadDict))
            logger.debug('Successfully created payload.')
            return payloadData
        except Exception as err:
            logger.debug(f"Error occured while parsing payload {payloadDict}")
            logger.error(err)
            raise

    @staticmethod
    def updateRequestsPemCert(certPath):
        """
        Description : Update the requests module pem cert
        Parameters: certPath - Certificate path from where ca certs are present (PATH
        """
        try:
            cafile = certifi.where()
            # open the certificate Path file which user has provided and read its contents
            with open(certPath, 'r') as infile:
                customCA = infile.read()
            # open the requests module cert path and write certificate path file contents there
            with open(cafile, 'w') as outfile:
                outfile.write(customCA)
        except Exception as err:
            logger.error(err)
            raise

    @staticmethod
    def clearRequestsPemCert():
        """
        Description : Clear the requests module pem cert
        """
        try:
            cafile = certifi.where()
            # open the requests module cert path and empty its contents
            open(cafile, 'w').close()
        except Exception as err:
            logger.error(err)
            raise

    @staticmethod
    def chunksOfList(_list, n):
        """Yield successive n-sized chunks from list."""
        for i in range(0, len(_list), n):
            yield int(i / n), _list[i:i + n]

    @staticmethod
    def renderInputDict(dataStructure):
        """Renders all the values to string apart from required ones"""
        if isinstance(dataStructure, dict):
            for key, value in dataStructure.items():
                if not isinstance(value, (dict, list, bool)) and value != None:
                    dataStructure[key] = str(value)
                Utilities.renderInputDict(value)
        elif isinstance(dataStructure, list):
            for index in reversed(range(len(dataStructure))):
                if isinstance(dataStructure[index], dict):
                    Utilities.renderInputDict(dataStructure[index])

    @staticmethod
    def parseXml(response, **kwargs):
        """Parses XML API Response to dict along with namespace parsing"""
        kwargs.setdefault('process_namespaces', True)
        if kwargs.get('process_namespaces'):
            # Fetching all namespaces present in the response and creating mapping with None as value
            namespaces = {
                ns.split("=")[-1].strip('"'): None
                for ns in re.findall("xmlns.*?\".*?\"", str(response))
            }
            kwargs.setdefault('namespaces', namespaces)

        return xmltodict.parse(response, **kwargs)
