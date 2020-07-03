# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description : Module performs VMware Cloud Director validations related for NSX-V To NSX-T
"""

import inspect
from functools import wraps
from collections import OrderedDict
import json
import logging
import os
import re
import time

import ipaddress
import requests
import xmltodict

import src.core.vcd.vcdConstants as vcdConstants

from src.commonUtils.restClient import RestAPIClient
from src.commonUtils.threadUtils import Thread
from src.commonUtils.utils import Utilities

logger = logging.getLogger('mainLogger')

def getSession(self):
    url = '{}session'.format(vcdConstants.XML_API_URL.format(self.ipAddress))
    response = self.restClientObj.get(url, headers=self.headers)
    if response.status_code != requests.codes.ok:
        logger.debug('Session expired!. Re-login to the vCloud Director')
        self.vcdLogin()


def isSessionExpired(func):
    """
        Description : decorator to check and get vcd Rest API session
    """
    @wraps(func)
    def inner(self, *args, **kwargs):
        getSession(self)
        result = func(self, *args, **kwargs)
        return result
    return inner


def remediate(func):
    """
        Description : decorator to save task status and save metadata in Org VDC after task is performed successfully
    """
    @wraps(func)
    def inner(self, *args, **kwargs):
        if self.rollback.metadata.get(func.__name__) or \
                self.rollback.metadata.get(inspect.stack()[2].function, {}).get(func.__name__):
            return

        # Getting vcd rest api session
        getSession(self)
        if self.rollback.metadata and not hasattr(self.rollback, 'retry') and not self.rollback.retryRollback:
            logger.info('Continuing migration of NSX-V backed Org VDC to NSX-T backed from {}.'.format(self.__desc__))
            self.rollback.retry = True

        if inspect.stack()[2].function != 'run' and inspect.stack()[2].function != '<module>':
            if not self.rollback.executionResult.get(inspect.stack()[2].function):
                self.rollback.executionResult[inspect.stack()[2].function] = {}
        try:
            result = func(self, *args, **kwargs)
            if inspect.stack()[2].function != 'run' and inspect.stack()[2].function != '<module>':
                self.rollback.executionResult[inspect.stack()[2].function][func.__name__] = True
            else:
                self.rollback.executionResult[func.__name__] = True
            self.rollback.key = func.__name__
            # Saving metadata in source Org VDC
            self.saveMetadataInOrgVdc()
            return result
        except Exception as err:
            raise err
    return inner


def description(desc):
    """
        Description : decorator to add description for a task before calling remediation decorator
    """
    def nested(function):
        @wraps(function)
        def wrapped(self, *args, **kwargs):
            setattr(self, '__desc__', desc)
            return function(self, *args, **kwargs)
        return wrapped
    return nested


class VCDMigrationValidation():
    """
    Description : Class performing VMware Cloud Director NSX-V To NSX-T Migration validation
    """
    VCD_SESSION_CREATED = False

    def __init__(self, ipAddress, username, password, verify, rollback, maxThreadCount=None):
        """
        Description :   Initializer method of VMware Cloud Director Operations
        Parameters  :   ipAddress   -   ipAddress of the VMware vCloud Director (STRING)
                        username    -   Username of the VMware vCloud Director (STRING)
                        password    -   Password of the VMware vCloud Director (STRING)
                        verify      -   whether to validate certficate (BOOLEAN)
        """
        self.ipAddress = ipAddress
        self.username = '{}@system'.format(username)
        self.password = password
        self.verify = verify
        self.vcdUtils = Utilities()
        # initializing thread class with specified number of threads
        if maxThreadCount:
            self.thread = Thread(maxNumberOfThreads=maxThreadCount)
        else:
            self.thread = Thread()
        self.rollback = rollback

    def vcdLogin(self):
        """
        Description :   Method which makes the user to login into a VMware Cloud Director for performing further VCD Operations
        Returns     :   Bearer Token    - Bearer token for authorization (TUPLE)
                        Status Code     - Status code for rest api (TUPLE)
        """
        try:
            # getting the RestAPIClient object to call the REST apis
            self.restClientObj = RestAPIClient(self.username, self.password, self.verify)
            # url to create session
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.OPEN_LOGIN_URL)
            # post api call to create sessioned login with basic authentication
            loginResponse = self.restClientObj.post(url, headers={'Accept': vcdConstants.VCD_API_HEADER}, auth=self.restClientObj.auth)
            if loginResponse.status_code == requests.codes.OK:
                logger.debug('Logged in to VMware Cloud Director {}'.format(self.ipAddress))
                # saving the returned bearer token
                self.bearerToken = 'Bearer {}'.format(loginResponse.headers['X-VMWARE-VCLOUD-ACCESS-TOKEN'])
                # creating the default headers required to fire rest api
                self.headers = {'Authorization': self.bearerToken, 'Accept': vcdConstants.VCD_API_HEADER}
                self.VCD_SESSION_CREATED = True
                return self.bearerToken, loginResponse.status_code
            raise Exception("Failed to login to VMware Cloud Director {} with the given credentials".format(self.ipAddress))
        except requests.exceptions.SSLError as e:
            raise e
        except requests.exceptions.ConnectionError as e:
            raise e
        except Exception:
            raise

    @description("Migrating metadata from source Org VDC to target Org VDC")
    @remediate
    def migrateMetadata(self):
        """
            Description :   Migrate metadata from source org vdc to target org vdc
        """
        logger.info("Migrating metadata from source Org VDC to target Org VDC")
        sourceOrgVDCId = self.rollback.apiData['sourceOrgVDC']['@id'].split(':')[-1]
        targetOrgVDCId = self.rollback.apiData['targetOrgVDC']['@id']

        # fetching metadata from source org vdc
        metadata = self.getOrgVDCMetadata(sourceOrgVDCId, wholeData=True)
        # segregating user created metadata
        metadataToMigrate = {key: value for key, value in metadata.items() if not re.search(r'-v2t$', key)}
        if metadataToMigrate:
            # Creating metadata in target org vdc
            self.createMetaDataInOrgVDC(targetOrgVDCId, metadataDict=metadataToMigrate, migration=True)
            logger.debug("Successfully migrated metadata from source Org VDC to target Org VDC")
        else:
            logger.debug("No user metadata present in source Org VDC to migrate to target Org VDC")
        logger.info('Successfully prepared Target VDC.')

    @isSessionExpired
    def getOrgVDCMetadata(self, orgVDCId, wholeData=False, domain='all'):
        """
        Description :   Gets Metadata in the specified Organization VDC
        Parameters  :   orgVDCId    -   Id of the Organization VDC (STRING)
                        wholeData   -   key that decides which metadata is required i.e. whole data or only created by migration tool (BOOLEAN)
                        domain      -   key used to fetch domain specific metadata all/system/general (STRING)
        Returns     :   metadata    -   key value pair of metadata in Organization VDC (DICT)
        """
        try:
            metaData = {}
            # spliting org vdc id as per the requirement of xml api
            orgVDCId = orgVDCId.split(':')[-1]
            # url to fetch metadata from org vdc
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.META_DATA_IN_ORG_VDC_BY_ID.format(orgVDCId))
            # get api to fetch meta data from org vdc
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                if responseDict['Metadata'].get('MetadataEntry'):
                    metaDataList = responseDict['Metadata']['MetadataEntry'] if isinstance(responseDict['Metadata']['MetadataEntry'], list) else [responseDict['Metadata']['MetadataEntry']]
                    for data in metaDataList:
                        if domain == 'general' and data.get('Domain'):
                            continue
                        if domain == 'system' and not data.get('Domain'):
                            continue
                        metadataKey = data['Key']
                        metadataValue = data['TypedValue']['Value']
                        if not wholeData:
                            if not re.search(r'-v2t$', metadataKey):
                                continue
                            # Replacing -system-v2t postfix with empty string
                            if re.search(r'-system-v2t$', metadataKey):
                                metadataKey = metadataKey.replace('-system-v2t', '')
                            else:
                                # Replacing -v2t postfix with empty string
                                metadataKey = metadataKey.replace('-v2t', '')
                            # Checking and restoring api data from metadata
                            if '&amp;' in data['TypedValue']['Value']:
                                metadataValue = metadataValue.replace('&amp;', '&')

                            # Converting python objects back from string
                            try:
                                metadataValue = eval(metadataValue)
                            except (SyntaxError, NameError, ValueError):
                                pass

                        metaData[metadataKey] = metadataValue
                return metaData
            raise Exception("Failed to retrieve metadata")
        except Exception:
            raise

    @isSessionExpired
    def deleteMetadataApiCall(self, key, orgVDCId):
        """
            Description :   API call to delete Metadata from the specified Organization VDC
            Parameters  :   key         -   Metadata key to be deleted (STRING)
                            orgVDCId    -   Id of the Organization VDC (STRING)
        """
        try:
            if re.search(r'-v2t$', key):
                if re.search(r'-system-v2t$', key):
                    # url for system domain metadata delete api call
                    url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                        vcdConstants.META_DATA_IN_ORG_VDC_BY_ID.format(orgVDCId)) + \
                          "/SYSTEM/{}".format(key)
                else:
                    # url to delete metadata from org vdc
                    url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                        vcdConstants.META_DATA_IN_ORG_VDC_BY_ID.format(orgVDCId)) + \
                          "/{}".format(key)
                response = self.restClientObj.delete(url, self.headers)
                if response.status_code == requests.codes.accepted:
                    responseDict = xmltodict.parse(response.content)
                    task = responseDict["Task"]
                    taskUrl = task["@href"]
                    if taskUrl:
                        # checking the status of the creating meta data in org vdc task
                        self._checkTaskStatus(taskUrl, task["@operationName"])
                        logger.debug('Deleted metadata with key: {} successfully'.format(key))
                else:
                    raise Exception('Failed to delete metadata key: {}'.format(key))
        except Exception:
            raise

    @isSessionExpired
    def deleteMetadata(self, orgVDCId):
        """
            Description :   Delete Metadata from the specified Organization VDC
            Parameters  :   orgVDCId    -   Id of the Organization VDC (STRING)
        """
        try:
            # spliting org vdc id as per the requirement of xml api
            orgVDCId = orgVDCId.split(':')[-1]
            metadata = self.getOrgVDCMetadata(orgVDCId, wholeData=True)
            if metadata:
                logger.info("Rollback: Deleting metadata from source org vdc")
                for key in metadata.keys():
                    # spawn thread for deleting metadata key api call
                    self.thread.spawnThread(self.deleteMetadataApiCall, key, orgVDCId)
                # halting main thread till all the threads complete execution
                self.thread.joinThreads()
                # checking if any of the threads raised any exception
                if self.thread.stop():
                    raise Exception("Failed to delete metadata from source Org VDC")
            else:
                logger.debug("No metadata present to delete in source org vdc")
        except Exception:
            raise

    @isSessionExpired
    def createMetaDataInOrgVDC(self, orgVDCId, metadataDict, domain='general', migration=False):
        """
        Description :   Creates/Updates Metadata in the specified Organization VDC
                        If the specified key doesnot already exists in Org VDC then creates new (Key, Value) pair
                        Else updates the specified existing key with the new metadatValue
        Parameters  :   orgVDCId        -   Id of the Organization VDC (STRING)
                        metadataDict    -   Metadata key value pairs (DICT)
                        domain          -   Domain in which metadata is to be created general/system (STRING)
                        migration       -   Key that defines metadata creation is part of migration or not (BOOLEAN)
        """
        try:
            if metadataDict:
                if self.headers.get('Content-Type'):
                    del self.headers['Content-Type']
                # spliting org vdc id as per the requirement of xml api
                orgVDCId = orgVDCId.split(':')[-1]
                # url to create meta data in org vdc
                url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                    vcdConstants.META_DATA_IN_ORG_VDC_BY_ID.format(orgVDCId))

                filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')

                # creating payload for domain in metadata
                domainPayload = '' if domain == 'general' else "<Domain visibility='PRIVATE'>SYSTEM</Domain>"
                xmlPayload = ''
                for key, value in metadataDict.items():
                    if not migration:
                        if domain.lower().strip() == 'system':
                            # appending -system-vdt to metadata key of system domain for identification of migration tool metadata
                            key += '-system-v2t'
                        else:
                            # appending -vdt to metadata key for identification of migration tool metadata
                            key += '-v2t'
                        # replacing & with escape value for XML based API's
                        if '&' in str(value):
                            value = eval(str(value).replace('&', '&amp;'))
                    payloadDict = {'key': key, 'value': value, 'domain': domainPayload}
                    # creating payload data
                    xmlPayload += self.vcdUtils.createPayload(filePath,
                                                              payloadDict,
                                                              fileType='yaml',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.CREATE_ORG_VDC_METADATA_ENTRY_TEMPLATE).strip('"')

                payloadDict = {'MetadataEntry': xmlPayload}
                # creating payload data
                payloadData = self.vcdUtils.createPayload(filePath,
                                                          payloadDict,
                                                          fileType='yaml',
                                                          componentName=vcdConstants.COMPONENT_NAME,
                                                          templateName=vcdConstants.CREATE_ORG_VDC_METADATA_TEMPLATE)

                payloadData = json.loads(payloadData)

                # post api to create meta data in org vdc
                response = self.restClientObj.post(url, self.headers, data=payloadData)
                responseDict = xmltodict.parse(response.content)
                if response.status_code == requests.codes.accepted:
                    task = responseDict["Task"]
                    taskUrl = task["@href"]
                    if taskUrl:
                        # checking the status of the creating meta data in org vdc task
                        self._checkTaskStatus(taskUrl, task["@operationName"])
                    logger.debug("Created Metadata in Org VDC {} successfully".format(orgVDCId))
                    return response
                raise Exception("Failed to create the Metadata in Org VDC: {}".format(responseDict['Error']['@message']))
            else:
                return
        except Exception:
            raise

    def metadataCleanup(self, metadata):
        """
            Description: Cleanup of metadata after its generation to reduce overall size of metadata
            Parameters: metadata that needs cleanup for size reduction - (DICT)
        """
        # Keys to be checked and removed is present cause these lead to unnecessary data
        keysToBeRemoved = ['@rel', 'Link', 'Settings', 'OrgAssociations', 'Networks',
                           'RightReferences', 'RoleReferences', 'VCloudExtension', 'Error', 'Tasks', 'Users',
                           'AvailableNetworks', 'MaxComputePolicy', 'ProviderVdcReference', 'ResourcePoolRefs',
                           '@default', '#text', 'Catalogs', 'ResourceEntities']

        if isinstance(metadata, (dict, OrderedDict)):
            # Removing capabilties if present from source and target org vdc
            if metadata.get('sourceOrgVDC') and metadata.get('sourceOrgVDC').get('Capabilities'):
                del metadata['sourceOrgVDC']['Capabilities']

            if metadata.get('targetOrgVDC') and metadata.get('targetOrgVDC').get('Capabilities'):
                del metadata['targetOrgVDC']['Capabilities']

            for key in list(metadata.keys()):
                # If key present in list of keys to be removed then delete its key value pair from metadata
                if key in keysToBeRemoved:
                    # Delete key from metadata dictionary
                    del metadata[key]
                else:
                    self.metadataCleanup(metadata[key])

    def saveMetadataInOrgVdc(self):
        """
            Description: Saving data necessary for continuation of migration and for rollback in metadata of source Org VDC
        """

        try:
            if self.rollback.executionResult:
                # getting the source org vdc urn
                sourceOrgVDCId = self.rollback.apiData['sourceOrgVDC']['@id']

                metadata = self.rollback.metadata

                # saving execution result in metadata
                for key, value in self.rollback.executionResult.items():
                    if isinstance(value, dict) and metadata.get(key):
                        combinedSubtask = {**metadata.get(key), **value}
                        self.rollback.executionResult[key] = combinedSubtask
                # saving rollback key in metadata
                if self.rollback.key:
                    self.rollback.executionResult.update({'rollbackKey': self.rollback.key})

                self.createMetaDataInOrgVDC(sourceOrgVDCId,
                                                    metadataDict=self.rollback.executionResult, domain='system')

                if self.rollback.apiData:
                    # removing unnecessary data from api data to reduce metadata size
                    self.metadataCleanup(self.rollback.apiData)
                    # saving api data in metadata
                    self.createMetaDataInOrgVDC(sourceOrgVDCId, metadataDict=self.rollback.apiData)

        except Exception as err:
            raise Exception('Failed to save metadata in source Org VDC due to error - {}'.format(err))

    def getOrgUrl(self, orgName):
        """
        Description : Retrieves the Organization URL details
        Parameters  : orgName   - Name of the Organization (STRING)
        Returns     : orgUrl    - Organization URL (STRING)
        """
        logger.debug('Getting Organization {} Url'.format(orgName))
        # admin xml url
        url = vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress)
        try:
            # get api call to retrieve organization details
            response = self.restClientObj.get(url, headers=self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                # retrieving organization references
                responseDict = responseDict['VCloud']['OrganizationReferences']['OrganizationReference']
                if isinstance(responseDict, dict):
                    responseDict = [responseDict]
                for record in responseDict:
                    # retrieving the orgnization details of organization specified in orgName
                    if record['@name'] == orgName:
                        orgUrl = record['@href']
                        logger.debug('Organization {} url {} retrieved successfully'.format(orgName, orgUrl))
                        # returning the organization url
                        return orgUrl
            raise Exception("Failed to retrieve Organization {} url".format(orgName))
        except Exception:
            raise

    def getOrgVDCUrl(self, orgUrl, orgVDCName, saveResponse=True):
        """
        Description : Get Organization VDC Url
        Parameters  : orgUrl        - Organization URL (STRING)
                      orgVDCName    - Name of the Organization VDC (STRING)
        Returns     : orgVDCUrl     - Organization VDC URL (STRING)
        """
        try:
            orgVDCUrl = ''
            data = {}
            logger.debug('Getting Organization VDC Url {}'.format(orgVDCName))
            # get api call to retrieve org vdc details of specified orgVdcName
            response = self.restClientObj.get(orgUrl, headers=self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                data = self.rollback.apiData
                if not data and saveResponse:
                    # creating 'Organization' key to save organization info
                    data['Organization'] = responseDict['AdminOrg']
                if not responseDict['AdminOrg']['Vdcs']:
                    raise Exception('No Org VDC exist in the organization')
                responseDict = responseDict['AdminOrg']['Vdcs']['Vdc']
                if isinstance(responseDict, dict):
                    responseDict = [responseDict]
                for response in responseDict:
                    # checking for orgVDCName in the responseDict, if found then returning the orgVDCUrl
                    if response['@name'] == orgVDCName:
                        orgVDCUrl = response['@href']
                        logger.debug('Organization VDC {} url {} retrieved successfully'.format(orgVDCName, orgVDCUrl))
                if not orgVDCUrl:
                    raise Exception('Org VDC {} does not belong to this organization {}'.format(orgVDCName, orgUrl))
                return orgVDCUrl
            raise Exception("Failed to retrieve Organization VDC {} url".format(orgVDCName))
        except Exception:
            raise

    def getOrgVDCDetails(self, orgUrl, orgVDCName, orgVDCType, saveResponse=True):
        """
        Description :   Gets the details of the Organizational VDC
        Parameters  : orgUrl        - Organization URL (STRING)
                      orgVDCName    - Name of the Organization VDC (STRING)
                      orgVDCType    - type of org vdc whether sourceOrgVDC or targetOrgVDC
        """
        try:
            logger.debug('Getting Organization VDC {} details'.format(orgVDCName))
            # retrieving the org vdc url
            self.orgVDCUrl = self.getOrgVDCUrl(orgUrl, orgVDCName, saveResponse)
            # get api call to retrieve the orgVDCName details
            response = self.restClientObj.get(self.orgVDCUrl, headers=self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                if saveResponse:
                    # loading the existing data from api data dict
                    data = self.rollback.apiData
                    data[orgVDCType] = responseDict['AdminVdc']
                    logger.debug('Retrieved Organization VDC {} details successfully'.format(orgVDCName))
                # returning the orgVDCName details
                return responseDict['AdminVdc']['@id']
            raise Exception("Failed to retrieve details of Organization VDC {} {}".format(orgVDCName,
                                                                                          responseDict['Error']['@message']))
        except Exception:
            raise

    @isSessionExpired
    def validateOrgVDCFastProvisioned(self):
        """
        Description :   Validates whether fast provisioning is enabled on the Org VDC
        """
        try:
            data = self.rollback.apiData
            # checking if the source org vdc uses fast provisioning, if so raising exception
            if data['sourceOrgVDC']['UsesFastProvisioning'] == "true":
                raise Exception("Fast Provisioning enabled on source Org VDC. Will not migrate fast provisioned org vdc")
            logger.debug("Validated Succesfully, Fast Provisioning is not enabled on source Org VDC")
        except Exception:
            raise

    @isSessionExpired
    def getExternalNetwork(self, networkName, isDummyNetwork=False):
        """
        Description :   Gets the details of external networks
        Parameters  :   networkName - Name of the external network (STRING)
                        isDummyNetwork - is the network dummy (BOOL)
        """
        try:
            key = None
            logger.debug("Getting External Network {} details ".format(networkName))
            # url to get all the external networks
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EXTERNAL_NETWORKS)
            # get api call to get all the external networks
            getResponse = self.restClientObj.get(url, self.headers)
            # api output file
            responseDict = getResponse.json()
            if getResponse.status_code == requests.codes.ok:
                # iterating over all the external networks
                for response in responseDict['values']:
                    # checking if networkName is present in the list, if present saving the specified network's details to apiOutput.json
                    if response['name'] == networkName:
                        key = 'targetExternalNetwork' if response['networkBackings']['values'][0]['backingType'] == 'NSXT_TIER0' else 'sourceExternalNetwork'
                        data = self.rollback.apiData
                        if isDummyNetwork:
                            key = 'dummyExternalNetwork'
                        data[key] = response
                        logger.debug("Retrieved External Network {} details Successfully".format(networkName))
                        return response
                if key == None:
                    return Exception('External Network: {} not present'.format(networkName))
            else:
                return Exception('Failed to get External network {}'.format(networkName))
        except Exception:
            raise

    @isSessionExpired
    def getProviderVDCId(self, pvdcName):
        """
        Description :   Gets the id of provider vdc
        Parameters  :   pvdcName - Name of the provider vdc (STRING)
        """
        try:
            logger.debug("Getting Provider VDC {} id".format(pvdcName))
            # url to get details of the all provider vdcs
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.PROVIDER_VDC)
            # get api call to retrieve the all provider vdc details
            response = self.restClientObj.get(url, self.headers)
            responseDict = response.json()
            if response.status_code == requests.codes.ok:
                # iterating over all provider vdcs to find if the specified provider vdc details exists
                for response in responseDict['values']:
                    if response['name'] == pvdcName:
                        logger.debug("Retrieved Provider VDC {} id successfully".format(pvdcName))
                        # returning provider vdc id of specified pvdcName & nsx-t manager
                        return response['id'], bool(response['nsxTManager'])
                else:
                    raise Exception("No provider VDC '{}' found".format(pvdcName))
            raise Exception('Failed to get Provider VDC {} id {}'.format(pvdcName,
                                                                         responseDict['message']))
        except Exception:
            raise

    def getProviderVDCDetails(self, pvdcId, isNSXTbacked=False):
        """
        Description :   Gets the id of provider vdc
        Parameters  :   pvdcId - Id of the provider vdc (STRING)
                        isNSXTbacked - True if NSX-T manager backed else False (BOOL)
        """
        try:
            logger.debug("Getting Provider VDC {} details".format(pvdcId))
            # splitting the provider vdc id as per the requirements of xml api
            providervdcId = pvdcId.split(':')[-1]
            # url to retrieve the specified provider vdc details
            url = "{}{}/{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                   vcdConstants.PROVIDER_VDC_XML,
                                   providervdcId)
            # get api call retrieve the specified provider vdc details
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                key = 'targetProviderVDC' if isNSXTbacked else 'sourceProviderVDC'
                # loading existing data from apiOutput.json
                self.thread.acquireLock()
                data = self.rollback.apiData
                # Save only capabilities of source provider vdc
                if key == 'sourceProviderVDC':
                    data[key] = responseDict['ProviderVdc']['Capabilities']
                data[key] = responseDict['ProviderVdc']
                self.thread.releaseLock()
                logger.debug("Provider VDC {} details retrieved successfully".format(responseDict['ProviderVdc']['@name']))
                if not isNSXTbacked:
                    # warning the user that source pvdc is disabled which may break rollback
                    if responseDict['ProviderVdc']['IsEnabled'] == "false":
                        logger.warning("Source PVDC '{}' is disabled".format(responseDict['ProviderVdc']['@name']))
                return
            raise Exception('Failed to get Provider VDC details')
        except Exception:
            raise

    @isSessionExpired
    def getSourceOrgVDCvAppsList(self, sourceOrgVDCId):
        """
        Description :   Retrieves the list of vApps in the Source Org VDC
        Returns     :   Returns Source vapps list (LIST)
        """
        try:
            logger.debug("Getting Source Org VDC vApps List")

            sourceOrgVDCId = sourceOrgVDCId.split(':')[-1]
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(sourceOrgVDCId))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
            else:
                raise Exception('Error occurred while retrieving Org VDC - {} details'.format(sourceOrgVDCId))
            # getting list instance of resources in the source org
            if responseDict['AdminVdc'].get('ResourceEntities'):
                sourceOrgVDCEntityList = responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'] \
                    if isinstance(responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'], list) else [
                    responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']]
                if sourceOrgVDCEntityList:
                    # getting list of source vapps
                    sourceVappList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if
                                    vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
                    return sourceVappList
            else:
                return []
        except Exception:
            raise

    @isSessionExpired
    def validateVappFencingMode(self, sourceOrgVDCId):
        """
            Description :   Validate if fencing is enable on vApps in source OrgVDC
            Notes       :   It does this by checking status(true/false) of firewallService in the org vdc network of vapp
                            Because fence mode can be enabled on vapp if and only if any org vdc network is present in the vapp
                            Also FirewallService will by default be enabled on the fenced org vdc networks
                            So checking the vappData['NetworkConfigSection']['NetworkConfig']['Configuration']['Features']['FirewallService']['IsEnabled'] is true
        """
        try:
            vAppFencingList = list()
            allVappList = self.getSourceOrgVDCvAppsList(sourceOrgVDCId)

            # iterating over the vapps in the source org vdc
            for eachVapp in allVappList:
                # get api call to get the vapp details
                response = self.restClientObj.get(eachVapp['@href'], self.headers)
                responseDict = xmltodict.parse(response.content)
                vAppData = responseDict['VApp']

                logger.debug('Checking fencing on vApp: {}'.format(eachVapp['@name']))
                # checking for the networks present in the vapp
                if vAppData.get('NetworkConfigSection'):
                    if vAppData['NetworkConfigSection'].get('NetworkConfig'):
                        networksInvApp = vAppData['NetworkConfigSection']['NetworkConfig'] if isinstance(vAppData['NetworkConfigSection']['NetworkConfig'], list) else [vAppData['NetworkConfigSection']['NetworkConfig']]
                        # iterating over the networks present in vapp(example:- vapp networks, org vdc networks, etc)
                        for network in networksInvApp:
                            # checking if the network is org vdc network(i.e if network's name and its parent network name is same means the network is org vdc network)
                            # here our interest networks are only org vdc networks present in vapp
                            if network['Configuration'].get('ParentNetwork') and network['@networkName'] == network['Configuration']['ParentNetwork']['@name']:
                                if network['Configuration'].get('Features') and network['Configuration']['Features'].get('FirewallService'):
                                    # since FirewallService is enabled on org vdc networks if fence mode is enabled, checking if ['FirewallService']['IsEnabled'] attribute is true
                                    if network['Configuration']['Features']['FirewallService']['IsEnabled'] == 'true':
                                        # adding the vapp name in the vAppFencingList to raise the exception
                                        vAppFencingList.append(eachVapp['@name'])
                                        # this will logged number of times equal to org vdc networks present in vapp before enabling the fence mode
                                        logger.debug("Fence mode is enabled on vApp: '{}'".format(eachVapp['@name']))

            if vAppFencingList:
                raise Exception('Fencing mode is enabled on vApp: {}'.format(', '.join(set(vAppFencingList))))
            else:
                logger.debug('vApp fencing is disabled on all vApps')
        except Exception:
            raise

    def validateOrgVDCNSXbacking(self, orgVDCId, providerVDCId, isNSXTbacked):
        """
        Description : Validate whether Org VDC is NSX-V or NSX-T backed
        Parameters : orgVDCId         - Org VDC id (STRING)
                     providerVDCId    - ProviderVDC id (STRING)
                     isNSXTbacked     - True if provider VDC is NSX-T backed else False (BOOL)
        """
        try:
            # splitting the source org vdc id as per the requirements of xml api
            orgVdcId = orgVDCId.split(':')[-1]
            # url to retrieve the specified provider vdc details
            url = '{}{}'.format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(orgVdcId))
            # get api call retrieve the specified provider vdc details
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                responseProviderVDCId = responseDict['AdminVdc']['ProviderVdcReference']['@id']
                # if NSXTbacked is false
                if not isNSXTbacked:
                    # checking if source provider vdc is nsx-v backed, if not then raising exception
                    if responseProviderVDCId == providerVDCId:
                        logger.debug("Validated successfully source Org VDC {} is NSX-V backed.".format(responseDict['AdminVdc']['@name']))
                        return
                    else:
                        raise Exception("Source Org VDC {} is not NSX-V backed.".format(responseDict['AdminVdc']['@name']))
                else:
                    # checking if target provider vdc is nsx-t backed, if not then raising exception
                    if responseProviderVDCId == providerVDCId:
                        logger.debug("Validated successfully target Org VDC {} is NSX-T backed.".format(responseDict['AdminVdc']['@name']))
                        return
                    else:
                        raise Exception("Target Org VDC {} is not NSX-T backed.".format(responseDict['AdminVdc']['@name']))
            else:
                raise Exception('Failed to validate Org VDC NSX backing type.')
        except Exception:
            raise

    @isSessionExpired
    def validateTargetProviderVdc(self):
        """
        Description :   Validates whether the target Provider VDC is Enabled
        """
        try:
            # reading api data from metadata
            data = self.rollback.apiData
            # checking if target provider vdc is enabled, if not raising exception
            if data['targetProviderVDC']['IsEnabled'] != "true":
                raise Exception("Target Provider VDC is not enabled")
            logger.debug("Validated successfully target Provider VDC is enabled")
        except Exception:
            raise

    @isSessionExpired
    def disableOrgVDC(self, orgVDCId):
        """
        Description :   Disable the Organization vdc
        Parameters  :   orgVDCId - Id of the source organization vdc (STRING)
        """
        try:
            # reading api from metadata
            data = self.rollback.apiData
            isEnabled = data['sourceOrgVDC']['IsEnabled']
            orgVDCName = data['sourceOrgVDC']['@name']
            # checking if the org vdc is already disabled, if not then disabling it
            if isEnabled == "false":
                logger.warning('Source Org VDC - {} is already disabled'.format(orgVDCName))
            else:
                vdcId = orgVDCId.split(':')[-1]
                # url to disable the org vdc
                url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                    vcdConstants.ORG_VDC_DISABLE.format(vdcId))
                # post api call to disable org vdc
                response = self.restClientObj.post(url, self.headers)
                if response.status_code == requests.codes['no_content']:
                    logger.debug("Source Org VDC {} disabled successfully".format(orgVDCName))
                else:
                    errorDict = xmltodict.parse(response.content)
                    raise Exception('Failed to disable Source Org VDC - {}'.format(errorDict['Error']['@message']))
        except Exception:
            raise
        else:
            return True

    @description("Disabling target Org VDC if source Org VDC was in disabled state")
    @remediate
    def disableTargetOrgVDC(self):
        """
        Description :   Disable the Organization vdc
        Parameters  :   orgVDCId - Id of the target organization vdc (STRING)
        """
        try:
            # reading api from metadata
            data = self.rollback.apiData
            isEnabled = data['sourceOrgVDC']['IsEnabled']
            # Fetching target VDC Id
            orgVDCId = data['targetOrgVDC']['@id']

            # disabling the target org vdc if and only if the source org vdc was initially in disabled state, else keeping target org vdc enabled
            if isEnabled == "false":
                targetOrgVDCName = data['targetOrgVDC']['@name']
                logger.debug("Disabling the target org vdc since source org vdc was in disabled state")
                vdcId = orgVDCId.split(':')[-1]
                # url to disable the org vdc
                url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                    vcdConstants.ORG_VDC_DISABLE.format(vdcId))
                # post api call to disable org vdc
                response = self.restClientObj.post(url, self.headers)
                if response.status_code == requests.codes['no_content']:
                    logger.debug("Target Org VDC {} disabled successfully".format(targetOrgVDCName))
                else:
                    errorDict = xmltodict.parse(response.content)
                    raise Exception('Failed to disable Target Org VDC - {}'.format(errorDict['Error']['@message']))
        except Exception:
            raise

    @isSessionExpired
    def validateVMPlacementPolicy(self, sourceOrgVDCId):
        """
        Description : Validate whether source Org VDC placement policy exist in target PVDC
        Parameters  : sourceOrgVDCId   - Id of the source org vdc (STRING)
        """
        try:
            targetPVDCComputePolicyList = []
            # reading api data from metadata
            data = self.rollback.apiData
            orgVdcId = sourceOrgVDCId.split(':')[-1]
            # url to retrieve compute policies of source org vdc
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_COMPUTE_POLICY.format(orgVdcId))
            # get api call to retrieve source org vdc compute policies
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                data['sourceOrgVDCComputePolicyList'] = responseDict['VdcComputePolicyReferences']['VdcComputePolicyReference']
            sourceOrgVDCName = data['sourceOrgVDC']['@name']
            targetProviderVDCName = data['targetProviderVDC']['@name']
            targetProviderVDCId = data['targetProviderVDC']['@id']
            sourcePolicyList = data['sourceOrgVDCComputePolicyList']
            sourceComputePolicyList = [sourcePolicyList] if isinstance(sourcePolicyList, dict) else sourcePolicyList
            allOrgVDCComputePolicesList = self.getOrgVDCComputePolicies()
            orgVDCComputePolicesList = [allOrgVDCComputePolicesList] if isinstance(allOrgVDCComputePolicesList, dict) else allOrgVDCComputePolicesList
            targetTemporaryList = []
            # iterating over the org vdc compute policies
            for eachComputePolicy in orgVDCComputePolicesList:
                # checking if the org vdc compute policy's provider vdc is same as target provider vdc
                if eachComputePolicy["pvdcId"] == targetProviderVDCId:
                    # iterating over the source org vdc compute policies
                    for computePolicy in sourceComputePolicyList:
                        if computePolicy['@name'] == eachComputePolicy['name']:
                            # handling the multiple occurrences of same policy, but adding the policy just once in the  list 'targetPVDCComputePolicyList'
                            if eachComputePolicy['name'] not in targetTemporaryList:
                                targetTemporaryList.append(eachComputePolicy['name'])
                                targetPVDCComputePolicyList.append(eachComputePolicy)

            # creating list of source org vdc compute policies excluding system default
            sourceOrgVDCComputePolicyList = [sourceComputePolicy for sourceComputePolicy in sourceComputePolicyList if sourceComputePolicy['@name'] != 'System Default']
            sourceOrgVDCPlacementPolicyList = []
            sourceTemporaryList = []
            # iterating over source org vdc compute policies
            for vdcComputePolicy in sourceOrgVDCComputePolicyList:
                # get api call to retrieve compute policy details
                response = self.restClientObj.get(vdcComputePolicy['@href'], self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    if not responseDict['isSizingOnly']:
                        # handling the multiple occurrences of same policy, but adding the policy just once in the  list 'sourceOrgVDCPlacementPolicyList'
                        if vdcComputePolicy['@name'] not in sourceTemporaryList:
                            sourceTemporaryList.append(vdcComputePolicy['@name'])
                            sourceOrgVDCPlacementPolicyList.append(vdcComputePolicy)
            # deleting both the temporary list, since no longer needed
            del targetTemporaryList
            del sourceTemporaryList
            if len(sourceOrgVDCPlacementPolicyList) != len(targetPVDCComputePolicyList):
                raise Exception('Target PVDC - {} does not have source Org VDC - {} placement policies in it.'.format(targetProviderVDCName,
                                                                                                                     sourceOrgVDCName))
            logger.debug("Validated successfully, source Org VDC placement policy exist in target PVDC")
        except Exception:
            raise

    @isSessionExpired
    def validateStorageProfiles(self):
        """
        Description :   Validate storage profiles of source org vdc with target provider vdc
                        Also validates the source  org vdc storage profiles which are present in target provider vdc are all enabled in target pvdc
        """
        try:
            data = self.rollback.apiData
            errorList = list()
            # retrieving source org vdc storage profiles
            sourceOrgVDCStorageProfile = [data['sourceOrgVDC']['VdcStorageProfiles']['VdcStorageProfile']] if isinstance(data['sourceOrgVDC']['VdcStorageProfiles']['VdcStorageProfile'], dict) else data['sourceOrgVDC']['VdcStorageProfiles']['VdcStorageProfile']
            # retrieving target provider vdc storage profiles
            targetPVDCStorageProfile = [data['targetProviderVDC']['StorageProfiles']['ProviderVdcStorageProfile']] if isinstance(data['targetProviderVDC']['StorageProfiles']['ProviderVdcStorageProfile'], dict) else data['targetProviderVDC']['StorageProfiles']['ProviderVdcStorageProfile']
            # creating list of source org vdc storage profiles found in target provider vdc
            storagePoliciesFound = [sourceDict for sourceDict in sourceOrgVDCStorageProfile for targetDict in
                                    targetPVDCStorageProfile if sourceDict['@name'] == targetDict['@name']]
            logger.debug("Storage Profiles Found in target Provider VDC are {}".format(storagePoliciesFound))
            # checking the length of profiles on source org vdc & storage profiles found on target provider vdc
            if len(sourceOrgVDCStorageProfile) != len(storagePoliciesFound):
                errorList.append("Storage profiles in Target PVDC should be same as those in Source Org VDC")

            # retrieving the storage profiles of the target provider vdc
            targetStorageProfiles = self.rollback.apiData['targetProviderVDC']['StorageProfiles']['ProviderVdcStorageProfile'] if isinstance(self.rollback.apiData['targetProviderVDC']['StorageProfiles']['ProviderVdcStorageProfile'], list) else [self.rollback.apiData['targetProviderVDC']['StorageProfiles']['ProviderVdcStorageProfile']]

            # list to hold the disabled storage profiles in target PVDC which are from source org vdc
            targetPVDCDisabledStorageProfiles = []
            # iterating over the source org vdc storage profiles found in target provider vdc
            for storageProfile in storagePoliciesFound:
                # iterating over the storage profiles of target provider vdc
                for targetStorageProfile in targetStorageProfiles:
                    if storageProfile['@name'] == targetStorageProfile['@name']:
                        # get api call to retrieve the target pvdc storage profile details
                        getResponse = self.restClientObj.get(targetStorageProfile['@href'], self.headers)
                        if getResponse.status_code == requests.codes.ok:
                            getResponseDict = xmltodict.parse(getResponse.content)
                            if getResponseDict['ProviderVdcStorageProfile']['Enabled'] == "false":
                                targetPVDCDisabledStorageProfiles.append(storageProfile['@name'])
                        else:
                            raise Exception("Failed to retrieve target provider vdc storage profile '{}' information".format(targetStorageProfile['@name']))
                        break

            # if targetPVDCDisabledStorageProfiles is not empty then appending the error message in errorList
            if targetPVDCDisabledStorageProfiles:
                errorList.append("Storage profiles '{}' disabled on target Provider VDC".format(', '.join(targetPVDCDisabledStorageProfiles)))

            # if errorList is not empty then raising all the exception present in the list
            if errorList:
                raise Exception('\n'.join(errorList))
            else:
                logger.debug("Validated successfully, storage Profiles in target PVDC are same as those of source Org VDC")
                logger.debug("Validated successfully, source org vdc storage profiles are all enabled in target provider vdc")

        except Exception:
            raise

    @isSessionExpired
    def validateExternalNetworkSubnets(self):
        """
        Description :  Validate the external networks subnet configuration
        """
        try:
            # reading the data from metadata
            data = self.rollback.apiData
            # comparing the source and target external network subnet configuration
            if 'sourceExternalNetwork' in data.keys() and 'targetExternalNetwork' in data.keys():
                sourceExternalGateway = data['sourceExternalNetwork']['subnets']['values'][0]['gateway']
                sourceExternalPrefixLength = data['sourceExternalNetwork']['subnets']['values'][0]['prefixLength']
                targetExternalGateway = data['targetExternalNetwork']['subnets']['values'][0]['gateway']
                targetExternalPrefixLength = data['targetExternalNetwork']['subnets']['values'][0]['prefixLength']
                sourceNetworkAddress = ipaddress.ip_network('{}/{}'.format(sourceExternalGateway, sourceExternalPrefixLength), strict=False)
                targetNetworkAddress = ipaddress.ip_network('{}/{}'.format(targetExternalGateway, targetExternalPrefixLength), strict=False)
                if sourceNetworkAddress != targetNetworkAddress:
                    raise Exception('Source and target External Networks have different subnets.')
                logger.debug('Validated successfully, source and target External Networks have same subnets.')
            else:
                raise Exception ('sourceExternalNetwork or targetExternalNetwork not present')
        except Exception:
            raise

    @isSessionExpired
    def getOrgVDCAffinityRules(self, orgVDCId):
        """
        Description : Get Org VDC affinity rules
        Parameters :  orgVDCId - org VDC id (STRING)
        """
        try:
            logger.debug("Getting Source Org VDC affinity rules")
            vdcId = orgVDCId.split(':')[-1]
            # url to retrieve org vdc affinity rules
            url = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_AFFINITY_RULES.format(vdcId))
            # get api call to retrieve org vdc affinity rules
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                data = self.rollback.apiData
                data['sourceVMAffinityRules'] = responseDict['VmAffinityRules']['VmAffinityRule'] if responseDict['VmAffinityRules'].get('VmAffinityRule', None) else {}
                logger.debug("Retrieved Source Org VDC affinity rules Successfully")
            else:
                raise Exception("Failed to retrieve VM Affinity rules of source Org VDC")
        except Exception:
            raise

    @isSessionExpired
    def getOrgVDCEdgeGateway(self, orgVDCId):
        """
        Description : Gets the list of all Edge Gateways for the specified Organization VDC
        Parameters  : orgVDCId - source Org VDC Id (STRING)
        Returns     : Org VDC edge gateway dict (DICTIONARY)
        """
        try:
            logger.debug("Getting Org VDC Edge Gateway details")
            url = "{}{}?filter=(orgVdc.id=={})".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                       vcdConstants.ALL_EDGE_GATEWAYS, orgVDCId)
            # get api call to retrieve all edge gateways of the specified org vdc
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                logger.debug('Org VDC Edge gateway details retrieved successfully.')
                # returning the responseDict
                return responseDict
            logger.debug('Failed to retrieve Org VDC Edge gateway details.')
        except Exception:
            raise

    @isSessionExpired
    def validateSingleEdgeGatewayExistForOrgVDC(self, orgVDCId):
        """
        Description :   Validates whether the specified Org VDC has a single Edge Gateway
        Parameters  :   orgVDCId    -   id of the source org vdc (STRING)
        """
        try:
            responseDict = self.getOrgVDCEdgeGateway(orgVDCId)
            # if the edge gateway result total is greater than 1 raise exception
            if responseDict['resultTotal'] > 1:
                raise Exception('More than One Edge gateway exist for source Org VDC')
            logger.info('Getting the source Edge gateway details')
            data = self.rollback.apiData
            if not responseDict['values']:
                raise Exception('Source Edge gateway does not exist for that org VDC.')
            data['sourceEdgeGateway'] = responseDict['values'][0]
            # self.vcdUtils.writeToFile(fileName, data)
            # self.thread.releaseLock()
            logger.debug("Validated Successfully, Single Edge Gateway exist in Source Org VDC")
            return responseDict['values'][0]['id']
        except Exception:
            raise

    def retrieveNetworkListFromMetadata(self, orgVdcId, orgVDCType='source'):
        """
            Description :   Gets the details of all the Org VDC Networks as per the status saved in metadata
            Parameters  :   orgVDCId     - source Org VDC Id (STRING)
                            orgVDCType   - type of Org VDC i.e. source/target (STRING)
            Returns     :   Org VDC Networks object (LIST)
        """
        networkType = 'sourceOrgVDCNetworks' if orgVDCType == 'source' else 'targetOrgVDCNetworks'
        orgVdcNetworkList = self.getOrgVDCNetworks(orgVdcId, networkType, saveResponse=False)
        sourceNetworkStatus = self.rollback.apiData[networkType]

        for network in orgVdcNetworkList:
            network['subnets']['values'][0]['enabled'] = sourceNetworkStatus[network['name']]['enabled']
            network['networkType'] = sourceNetworkStatus[network['name']]['networkType']
            network['connection'] = sourceNetworkStatus[network['name']]['connection']
        return orgVdcNetworkList

    @isSessionExpired
    def getOrgVDCNetworks(self, orgVDCId, orgVDCNetworkType, saveResponse=True):
        """
        Description :   Gets the details of all the Organizational VDC Networks for specific org VDC
        Parameters  :   orgVDCId            - source Org VDC Id (STRING)
                        orgVDCNetworkType   - type of Org VDC Network (STRING)
        Returns     :   Org VDC Networks object (LIST)
        """
        try:
            orgVDCNetworkList = list()
            logger.debug("Getting Org VDC network details")
            # url to retrieve all the org vdc networks of the specified org vdc
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_ORG_VDC_NETWORKS)
            # get api call to retrieve all the org vdc networks of the specified org vdc
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                # iterating over the org vdc networks
                for response in responseDict['values']:
                    if response['orgVdc']['id'] == orgVDCId:
                        orgVDCNetworkList.append(response)
                logger.debug('Org VDC network details retrieved successfully')
                if saveResponse:
                    networkDataToSave = {}
                    for network in orgVDCNetworkList:
                        networkDataToSave[network['name']] = {
                            'enabled': network['subnets']['values'][0]['enabled'],
                            'networkType': network['networkType'],
                            'connection': network['connection']
                        }
                    self.rollback.apiData[orgVDCNetworkType] = networkDataToSave
                return orgVDCNetworkList
            else:
                responseDict = response.json()
                raise Exception('Failed to get Org VDC network details due to: {}'.format(responseDict['message']))
        except Exception:
            raise

    @isSessionExpired
    def validateDHCPEnabledonIsolatedVdcNetworks(self, orgVdcNetworkList):
        """
        Description : Validate that DHCP is not enabled on isolated Org VDC Network
        Parameters  : orgVdcNetworkList - Org VDC's network list for a specific Org VDC (LIST)
        """
        try:
            DHCPEnabledList = list()
            # iterating over the org vdc network list
            for orgVdcNetwork in orgVdcNetworkList:
                # checking only for isolated Org VDC Network
                if orgVdcNetwork['networkType'] == 'ISOLATED':
                    url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                           vcdConstants.ALL_ORG_VDC_NETWORKS,
                                           vcdConstants.DHCP_ENABLED_FOR_ORG_VDC_NETWORK_BY_ID.format(orgVdcNetwork['id']))
                    # get api call to retrieve org vdc networks on which dhcp is enabled
                    response = self.restClientObj.get(url, self.headers)
                    if response.status_code == requests.codes.ok:
                        responseDict = response.json()
                        # checking for enabled parameter in response
                        if responseDict['enabled']:
                            DHCPEnabledList.append(orgVdcNetwork['name'])
                        else:
                            logger.debug("Validated Successfully, DHCP is not enabled on source Isolated Org VDC Network.")
                    else:
                        responseDict = response.json()
                        raise Exception('Failed to fetch DHCP details from Isolated network due to {}'.format
                                        (responseDict['message']))
            if DHCPEnabledList:
                raise Exception(
                    "DHCP is enabled on source Isolated Org VDC Network - {}".format(','.join(DHCPEnabledList)))
        except Exception:
            raise

    @isSessionExpired
    def validateOrgVDCNetworkShared(self, orgVdcNetworkList):
        """
        Description :   Validates if Org VDC Networks are not Shared
        Parameters  :   orgVdcNetworkList   -   list of org vdc network list (LIST)
        """
        try:
            # iterating over the org vdc networks
            orgVdcNetworkSharedList = list()
            for orgVdcNetwork in orgVdcNetworkList:
                # checking only for isolated Org VDC Network
                if bool(orgVdcNetwork['shared']):
                    orgVdcNetworkSharedList.append(orgVdcNetwork['name'])
            if orgVdcNetworkSharedList:
                raise Exception("Org VDC Network {} is a shared network. No shared networks should exist.".format(','.join(orgVdcNetworkSharedList)))
            else:
                logger.debug("Validated Successfully, No Source Org VDC Networks are shared")
        except Exception:
            raise

    @isSessionExpired
    def validateOrgVDCNetworkDirect(self, orgVdcNetworkList):
        """
        Description :   Validates if Source Org VDC Networks are not direct networks
        Parameters  :   orgVdcNetworkList   -   list of org vdc network list (LIST)
        """
        try:
            orgVdcNetworkDirectList = list()
            for orgVdcNetwork in orgVdcNetworkList:
                if orgVdcNetwork['networkType'] == 'DIRECT':
                    orgVdcNetworkDirectList.append(orgVdcNetwork['name'])
            if orgVdcNetworkDirectList:
                raise Exception("Direct network {} exist in source Org VDC. Direct networks cant be migrated to target Org VDC".format(','.join(orgVdcNetworkDirectList)))
            else:
                logger.debug("Validated Successfully, No direct networks exist in Source Org VDC")
        except Exception:
            raise

    @isSessionExpired
    def validateEdgeGatewayUplinks(self, edgeGatewayId):
        """
            Description :   Validate Edge Gateway uplinks
            Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            # url to connect uplink the source edge gateway
            logger.debug("Validating if all edge gateways interfaces are in use")
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.UPDATE_EDGE_GATEWAY_BY_ID.format(edgeGatewayId))
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
            # retrieving the details of the edge gateway
            response = self.restClientObj.get(url, headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                gatewayInterfaces = responseDict['configuration']['gatewayInterfaces']['gatewayInterface']
                if len(gatewayInterfaces) >= 9:
                    return ['No more uplinks present on source Edge Gateway to connect dummy External Uplink.']
                return []
            else:
                return ['Failed to get Edge Gateway Uplink details']
        except Exception:
            raise

    @isSessionExpired
    def getEdgeGatewayServices(self, edgeGatewayId):
        """
        Description :   Gets the Edge gateway services Configuration details
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            gatewayId = edgeGatewayId.split(':')[-1]
            # getting the dhcp config details of specified edge gateway
            self.thread.spawnThread(self.getEdgeGatewayDhcpConfig, gatewayId)
            time.sleep(2)
            # getting the firewall config details of specified edge gateway
            self.thread.spawnThread(self.getEdgeGatewayFirewallConfig, gatewayId)
            time.sleep(2)
            # getting the nat config details of specified edge gateway
            self.thread.spawnThread(self.getEdgeGatewayNatConfig, gatewayId)
            time.sleep(2)
            # getting the ipsec config details of specified edge gateway
            self.thread.spawnThread(self.getEdgeGatewayIpsecConfig, gatewayId)
            time.sleep(2)
            # getting the bgp config details of specified edge gateway
            self.thread.spawnThread(self.getEdgegatewayBGPconfig, gatewayId)
            time.sleep(2)
            # getting the routing config details of specified edge gateway
            self.thread.spawnThread(self.getEdgeGatewayRoutingConfig, gatewayId)
            time.sleep(2)
            # getting the load balancer config details of specified edge gateway
            self.thread.spawnThread(self.getEdgeGatewayLoadBalancerConfig, gatewayId)
            time.sleep(2)
            # getting the l2vpn config details of specified edge gateway
            self.thread.spawnThread(self.getEdgeGatewayL2VPNConfig, gatewayId)
            time.sleep(2)
            # getting the sslvpn config details of specified edge gateway
            self.thread.spawnThread(self.getEdgeGatewaySSLVPNConfig, gatewayId)
            time.sleep(2)
            # getting the dns config of specified edge gateway
            self.thread.spawnThread(self.getEdgeGatewayDnsConfig, gatewayId)
            time.sleep(2)

            # Halting the main thread till all the threads have completed their execution
            self.thread.joinThreads()

            # Fetching saved values from thread class of all the threads
            dhcpErrorList, dhcpConfigOut = self.thread.returnValues['getEdgeGatewayDhcpConfig']
            firewallErrorList = self.thread.returnValues['getEdgeGatewayFirewallConfig']
            natErrorList = self.thread.returnValues['getEdgeGatewayNatConfig']
            ipsecErrorList, ipsecConfigOut = self.thread.returnValues['getEdgeGatewayIpsecConfig']
            bgpErrorList = self.thread.returnValues['getEdgegatewayBGPconfig']
            routingErrorList = self.thread.returnValues['getEdgeGatewayRoutingConfig']
            loadBalancingErrorList = self.thread.returnValues['getEdgeGatewayLoadBalancerConfig']
            L2VpnErrorList = self.thread.returnValues['getEdgeGatewayL2VPNConfig']
            SslVpnErrorList = self.thread.returnValues['getEdgeGatewaySSLVPNConfig']
            dnsErrorList = self.thread.returnValues['getEdgeGatewayDnsConfig']
            allErrorList = dhcpErrorList + firewallErrorList + natErrorList + ipsecErrorList \
                           + bgpErrorList + routingErrorList + loadBalancingErrorList + L2VpnErrorList \
                           + SslVpnErrorList + dnsErrorList
            if allErrorList:
                raise Exception(' '.join(allErrorList))
            self.rollback.apiData['sourceEdgeGatewayDHCP'] = dhcpConfigOut
            # self.rollback.apiData['sourceEdgeGatewayFirewall'] = firewallConfigOut
            # self.rollback.apiData['sourceEdgeGatewayNAT'] = natConfigOut
            # self.rollback.apiData['sourceEdgeGatewayRouting'] = routingConfigOut
            # if dnsConfigOut:
            #     self.rollback.apiData['sourceEdgeGatewayDNS'] = dnsConfigOut
            logger.debug("Source Edge Gateway services configuration retrieved successfully")
            return ipsecConfigOut
        except Exception:
            raise

    @isSessionExpired
    def validateIndependentDisksDoesNotExistsInOrgVDC(self, orgVDCId):
        """
        Description :   Validates if the Independent disks does not exists in the specified Org VDC(probably source Org VDC)
                        If exists, then raising an exception
        Parameters  :   orgVDCId    -   Id of the Org VDC (STRING)
        Returns     :   True        -   If Independent disks doesnot exist in Org VDC (BOOL)
        """
        try:
            independentDisksList = list()
            orgVDCId = orgVDCId.split(':')[-1]
            # url to get specified org vdc details
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(orgVDCId))
            # get api call to get specified org vdc details
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if responseDict['AdminVdc'].get('ResourceEntities'):
                if isinstance(responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'], list):
                    # iterating over the resource entities of org vdc & checking if independent disks exist, if so raising exception
                    for eachResourceEntity in responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']:
                        if eachResourceEntity['@type'] == vcdConstants.INDEPENDENT_DISKS_EXIST_IN_ORG_VDC_TYPE:
                            independentDisksList.append(eachResourceEntity['@name'])
                    logger.debug("Validated Successfully, Independent Disks do not exist in Source Org VDC")
                else:
                    # if single resource entity, checking if independent disks exist, if so raising exception
                    if responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']['@type'] == vcdConstants.INDEPENDENT_DISKS_EXIST_IN_ORG_VDC_TYPE:
                        independentDisksList.append(responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']['@name'])
                        #raise Exception("Independent Disks Exist In Source Org VDC.")
                    logger.debug("Validated Successfully, Independent Disks do not exist in Source Org VDC")
            else:
                logger.debug("No resource entity is available in source Org VDC.")
            if independentDisksList:
                raise Exception("Independent Disks: {} Exist In Source Org VDC.".format(','.join(independentDisksList)))
        except Exception:
            raise

    @isSessionExpired
    def getEdgeGatewayDhcpConfig(self, edgeGatewayId):
        """
        Description :   Gets the DHCP Configuration details of the specified Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            logger.debug("Getting DHCP Services Configuration Details of Source Edge Gateway")
            # url to get dhcp config details of specified edge gateway
            errorList = list()
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_DHCP_CONFIG_BY_ID.format(edgeGatewayId))
            # relay url to get dhcp config details of specified edge gateway
            relayurl = "{}{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                         vcdConstants.NETWORK_EDGES,
                                         vcdConstants.EDGE_GATEWAY_DHCP_CONFIG_BY_ID.format(edgeGatewayId),
                                         vcdConstants.EDGE_GATEWAY_DHCP_RELAY_CONFIG_BY_ID)
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
            # call to get api to get dhcp config details of specified edge gateway
            response = self.restClientObj.get(url, headers)
            # call to get api to get dhcp relay config details of specified edge gateway
            relayresponse = self.restClientObj.get(relayurl, self.headers)
            if relayresponse.status_code == requests.codes.ok:
                relayresponsedict = xmltodict.parse(relayresponse.content)
                # checking if relay is configured in dhcp, if so raising exception
                if relayresponsedict['relay'] is not None:
                    errorList.append('DHCP Relay is configured in source edge gateway\n')
            else:
                errorList.append('Failed to retrieve DHCP Relay configuration of Source Edge Gateway with error code {} \n'.format(relayresponse.status_code))
                return errorList, None
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                # checking if static binding is configured in dhcp, if so raising exception
                if responseDict['staticBindings']:
                    errorList.append("Static binding is in DHCP configuration of Source Edge Gateway\n")
                logger.debug("DHCP configuration of Source Edge Gateway retrieved successfully")
                # returning the dhcp details
                return errorList, responseDict
            else:
                errorList.append('Failed to retrieve DHCP configuration of Source Edge Gateway with error code {} \n'.format(response.status_code))
                return errorList, None
        except Exception:
            raise

    @isSessionExpired
    def getEdgeGatewayFirewallConfig(self, edgeGatewayId, validation=True):
        """
        Description :   Gets the Firewall Configuration details of the specified Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            logger.debug("Getting Firewall Services Configuration Details of Source Edge Gateway")
            errorList = list()
            # url to retrieve the firewall config details of edge gateway
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_FIREWALL_CONFIG_BY_ID.format(edgeGatewayId))
            # get api call to retrieve the firewall config details of edge gateway
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                # checking if firewall is enabled on edge gateway, if so returning the user defined firewall details, else raising exception
                if responseDict['firewall']['enabled'] != 'false':
                    logger.debug("Firewall configuration of Source Edge Gateway retrieved successfully")
                    userDefinedFirewall = [firewall for firewall in
                                           responseDict['firewall']['firewallRules']['firewallRule'] if
                                           firewall['ruleType'] == 'user']
                    # getting the default policy rules which the user has marked as 'DENY'
                    defaultFirewallRule = [defaultRule for defaultRule in responseDict['firewall']['firewallRules']['firewallRule'] if
                                           defaultRule['ruleType'] == 'default_policy' and defaultRule['action'] != 'accept']
                    userDefinedFirewall.extend(defaultFirewallRule)
                    if not validation:
                        return userDefinedFirewall
                    groupingobjects = []
                    for firewall in userDefinedFirewall:
                        if firewall.get('application'):
                            if firewall['application'].get('service'):
                                services = firewall['application']['service'] if isinstance(firewall['application']['service'], list) else [firewall['application']['service']]
                                for service in services:
                                    if service['protocol'] == "tcp" or service['protocol'] == "udp":
                                        if service['port'] == "any":
                                            errorList.append("Any as a TCP/UDP port present in the firewall rule '{}'\n".format(firewall['name']))
                        if firewall.get('source'):
                            if firewall['source'].get('vnicGroupId'):
                                errorList.append("vNicGroupId '{}' is present in the source of firewall rule '{}'\n".format(firewall['source']['vnicGroupId'], firewall['name']))
                            if firewall['source'].get('groupingObjectId'):
                                groupingobjects = firewall['source']['groupingObjectId'] if isinstance(firewall['source']['groupingObjectId'], list) else [firewall['source']['groupingObjectId']]
                                for groupingobject in groupingobjects:
                                    if "ipset" not in groupingobject and "network" not in groupingobject:
                                        errorList.append("The grouping object type '{}' in the source of firewall rule '{}' is not supported\n".format(groupingobject, firewall['name']))
                        if firewall.get('destination'):
                            if firewall['destination'].get('vnicGroupId'):
                                errorList.append("vNicGroupId '{}' is present in the destination of firewall rule '{}'\n".format(firewall['destination']['vnicGroupId'], firewall['name']))
                            if firewall['destination'].get('groupingObjectId'):
                                groupingobjects = firewall['destination']['groupingObjectId'] if isinstance(firewall['destination']['groupingObjectId'], list) else [firewall['destination']['groupingObjectId']]
                                for groupingobject in groupingobjects:
                                    if "ipset" not in groupingobject and "network" not in groupingobject:
                                        errorList.append("The grouping object type '{}' in the destination of firewall rule '{}' is not supported\n".format(groupingobject, firewall['name']))
                    return errorList
                else:
                    errorList.append('Firewall is disabled in source\n')
                    return errorList
            return [
                "Failed to retrieve the Firewall Configurations of Source Edge Gateway with error code {} \n".format(
                    response.status_code)]
        except Exception:
            raise

    @isSessionExpired
    def getEdgeGatewayNatConfig(self, edgeGatewayId, validation=True):
        """
        Description :   Gets the NAT Configuration details of the specified Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            errorList = list()
            logger.debug("Getting NAT Services Configuration Details of Source Edge Gateway")
            # url to retrieve the nat config details of the specified edge gateway
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_NAT_CONFIG_BY_ID.format(edgeGatewayId))
            # get api call to retrieve the nat config details of the specified edge gateway
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                if not validation:
                    return responseDict['nat']
                logger.debug("NAT configuration of Source Edge Gateway retrieved successfully")
                # checking if nat64 rules are present, if not raising exception
                if responseDict['nat']['nat64Rules']:
                    errorList.append('Nat64 rule is configured in source but not supported in Target\n')
                # checking if nat rules are present
                if responseDict['nat']['natRules']:
                    natrules = responseDict['nat']['natRules']['natRule']
                    natrules = natrules if isinstance(natrules, list) else [natrules]
                    # iterating over the nat rules
                    for natrule in natrules:
                        if natrule['action'] == "dnat" and "-" in natrule['translatedAddress'] or "/" in natrule['translatedAddress']:
                            errorList.append(
                                'Range of IPs or network found in this DNAT rule {} and range cannot be used in target edge gateway\n'.format(
                                    natrule['ruleId']))
                    return errorList
                else:
                    return errorList
            else:
                errorList.append(
                    'Failed to retrieve the NAT Configurations of Source Edge Gateway with error code {} \n'.format(
                        response.status_code))
                return errorList
        except Exception:
            raise

    @isSessionExpired
    def getEdgeGatewaySSLVPNConfig(self, edgeGatewayId):
        """
        Description :   Gets the SSLVPN Configuration details on the Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            logger.debug("Getting SSLVPN Services Configuration Details of Source Edge Gateway")
            # url to retrieve sslvpn config info
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_SSLVPN_CONFIG.format(edgeGatewayId))
            # get api call to retrieve sslvpn config info
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                logger.debug("SSLVPN configuration of Source Edge Gateway retrieved successfully")
                # checking if sslvpn is enabled, if so raising exception
                if responseDict['sslvpnConfig']['enabled'] == "true":
                    return ['SSLVPN service is configured in the Source but not supported in the Target\n']
                else:
                    return []
            else:
                return ['Unable to get SSLVPN Services Configuration Details with error code {}\n'.format(response.status_code)]
        except Exception:
            raise

    @isSessionExpired
    def getEdgeGatewayL2VPNConfig(self, edgeGatewayId):
        """
        Description :   Gets the L2VPN Configuration details on the Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            logger.debug("Getting L2VPN Services Configuration Details of Source Edge Gateway")
            # url to retrieve the l2vpn config info
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_L2VPN_CONFIG.format(edgeGatewayId))
            # get api call to retrieve the l2vpn config info
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                logger.debug("L2VPN configuration of Source Edge Gateway retrieved Successfully")
                # checking if l2vpn is enabled, if so raising exception
                if responseDict['l2Vpn']['enabled'] == "true":
                    return ["L2VPN service is configured in the Source but not supported in the Target\n"]
                else:
                    return []
            else:
                return ['Unable to get L2VPN Services Configuration Details of Source Edge Gateway with error code {} \n'.format(response.status_code)]
        except Exception:
            raise

    @isSessionExpired
    def getEdgeGatewayLoadBalancerConfig(self, edgeGatewayId):
        """
        Description :   Gets the Load Balancer Configuration details on the Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            logger.debug("Getting Load Balancer Services Configuration Details of Source Edge Gateway")
            # url to retrieve the load balancer config info
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_LOADBALANCER_CONFIG.format(edgeGatewayId))
            # get api call to retrieve the load balancer config info
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                logger.debug("Load Balancer configuration of Source Edge Gateway retrieved Successfully")
                # checking if load balancer is enabled, if so raising exception
                if responseDict['loadBalancer']['enabled'] == "true":
                    return ["Load Balancer service is configured in the Source but not supported in the Target\n"]
                else:
                    return []
            else:
                return ['Unable to get load balancer service configuration with error code {} \n'.format(response.status_code)]
        except Exception:
            raise

    @isSessionExpired
    def getEdgeGatewayRoutingConfig(self, edgeGatewayId, validation=True):
        """
        Description :   Gets the Routing Configuration details on the Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            logger.debug("Getting Routing Configuration Details of Source Edge Gateway")
            # url to retrieve the routing config info
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_ROUTING_CONFIG.format(edgeGatewayId))
            # get api call to retrieve the routing config info
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                if not validation:
                    return responseDict['routing']
                # checking if routing is enabled, if so raising exception
                if responseDict['routing']['ospf']['enabled'] == "true":
                    return ["OSPF routing protocol is configured in the Source but not supported in the Target\n"]
                else:
                    logger.debug("Routing configuration of Source Edge Gateway retrieved Successfully")
                    return []
            else:
                return ['Failed to get Routing service details with error code {} \n'.format(response.status_code)]
        except Exception:
            raise

    @isSessionExpired
    def getEdgeGatewayIpsecConfig(self, edgeGatewayId):
        """
        Description :   Gets the IPSEC Configuration details on the Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            errorList = list()
            logger.debug("Getting IPSEC Services Configuration Details of Source Edge Gateway")
            # url to retrieve the ipsec config info
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_IPSEC_CONFIG.format(edgeGatewayId))
            headers = {'Authorization': self.headers['Authorization'], 'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE}
            # get api call to retrieve the ipsec config info
            response = self.restClientObj.get(url, headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                if responseDict['sites']:
                    sites = responseDict['sites']['sites']
                    sourceIPsecSite = sites if isinstance(sites, list) else [sites]
                    # iterating over source ipsec sites
                    for eachsourceIPsecSite in sourceIPsecSite:
                        # raising exception if ipsecSessionType is not equal to policybasedsession
                        if eachsourceIPsecSite['ipsecSessionType'] != "policybasedsession":
                            errorList.append(
                                'Source IPSEC rule is having routebased session type which is not supported\n')
                        # raising exception if the ipsec encryption algorithm in the source ipsec rule  is not present in the target
                        if eachsourceIPsecSite['encryptionAlgorithm'] != "aes256":
                            errorList.append(
                                'Source IPSEC rule is configured with unsupported encryption algorithm {}\n'.format(
                                    eachsourceIPsecSite['encryptionAlgorithm']))
                        # raising exception if the authentication mode is not psk
                        if eachsourceIPsecSite['authenticationMode'] != "psk":
                            errorList.append(
                                'Authentication mode as Certificate is not supported in target edge gateway\n')
                        # raising exception if the digest algorithm is not supported in target
                        if eachsourceIPsecSite['digestAlgorithm'] != "sha1":
                            errorList.append(
                                'The specified digest algorithm {} is not supported in target edge gateway\n'.format(
                                    eachsourceIPsecSite['digestAlgorithm']))
                    logger.debug("IPSEC configuration of Source Edge Gateway retrieved successfully")
                    return errorList, responseDict
                else:
                    return errorList, responseDict
            else:
                errorList.append("Failed to retrieve the IPSEC Configurations of Source Edge Gateway with error code {} \n".format(response.status_code))
                return errorList, None
        except Exception:
            raise

    @isSessionExpired
    def getEdgegatewayBGPconfig(self, edgeGatewayId, validation=True):
        """
        Description :   Gets the BGP Configuration details on the Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            errorList = list()
            logger.debug("Getting BGP Services Configuration Details of Source Edge Gateway")
            # url to retrieve the bgp config into
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_BGP_CONFIG.format(edgeGatewayId))
            # get api call to retrieve the bgp config info
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                if response.content:
                    responseDict = xmltodict.parse(response.content)
                    if not validation:
                        return responseDict['bgp']
                    logger.debug("BGP configuration of Source Edge Gateway retrieved successfully")
                    # returning bdp config details dict
                    return errorList
                else:
                    return []
            else:
                return ["Failed to retrieve the BGP Configurations of Source Edge Gateway with error code {} \n".format(response.status_code)]
        except Exception:
            raise

    @isSessionExpired
    def _checkTaskStatus(self, taskUrl, taskName, returnOutput=False, timeoutForTask=vcdConstants.VCD_CREATION_TIMEOUT):
        """
        Description : Checks status of a task in VDC
        Parameters  : taskUrl   - Url of the task monitored (STRING)
                      taskName  - Name of the task monitored (STRING)
                      timeOutForTask - Timeout value to check the task status (INT)
        """
        if self.headers.get("Content-Type", None):
            del self.headers['Content-Type']
        timeout = 0.0
        # Get the task details
        output = ''
        try:
            while timeout < timeoutForTask:
                logger.debug("Checking status for task : {}".format(taskName))
                response = self.restClientObj.get(url=taskUrl, headers=self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = xmltodict.parse(response.content)
                    responseDict = responseDict["Task"]
                    if returnOutput:
                        output = responseDict['@operation']
                        # rfind will search from right to left, here Id always comes in the last
                        output = output[output.rfind("(") + 1:output.rfind(")")]
                    if taskName in responseDict["@operationName"]:
                        if responseDict["@status"] == "success":
                            logger.debug("Successfully completed task : {}".format(taskName))
                            if not returnOutput:
                                return
                            return output
                        if responseDict["@status"] == "error":
                            logger.debug("Task {} is in Error state {}".format(taskName, responseDict['Details']))
                            raise Exception(responseDict['Details'])
                        msg = "Task {} is in running state".format(taskName)
                        logger.debug(msg)
                time.sleep(vcdConstants.VCD_CREATION_INTERVAL)
                timeout += vcdConstants.VCD_CREATION_INTERVAL
            raise Exception('Task {} could not complete in the allocate'
                            'd time.'.format(taskName))
        except:
            raise

    def getOrgVDCComputePolicies(self):
        """
        Description :   Gets VDC Compute Policies
        """
        try:
            logger.debug("Getting Org VDC Compute Policies Details")
            # url to retrieve org vdc compute policies
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.VDC_COMPUTE_POLICIES)
            # get api call to retrieve org vdc compute policies
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                logger.debug("Retrieved Org VDC Compute Policies details successfully")
                # returning the list of org vdc compute policies
                responseDict = response.json()
                # return responseDict['values']
                resultTotal = responseDict['resultTotal']
            pageNo = 1
            pageSizeCount = 0
            resultList = []
            logger.debug('Getting Org VDC Compute Policies')
            while resultTotal > 0 and pageSizeCount < resultTotal:
                url = "{}{}?page={}&pageSize={}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                        vcdConstants.VDC_COMPUTE_POLICIES, pageNo,
                                                        vcdConstants.ORG_VDC_COMPUTE_POLICY_PAGE_SIZE)
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    resultList.extend(responseDict['values'])
                    pageSizeCount += len(responseDict['values'])
                    logger.debug('Org VDC Compute Policies result pageSize = {}'.format(pageSizeCount))
                    pageNo += 1
            logger.debug('Total Org VDC Compute Policies result count = {}'.format(len(resultList)))
            logger.debug('All Org VDC Compute Policies successfully retrieved')
            return resultList
        except Exception:
            raise

    def enableSourceOrgVdc(self, sourceOrgVdcId):
        """
        Description :   Re-Enables the Source Org VDC
        Parameters  :   sourceOrgVdcId  -   id of the source org vdc (STRING)
        """
        try:
            # reading data from metadata
            data = self.rollback.apiData
            # enabling the source org vdc only if it was previously enabled, else not
            if data['sourceOrgVDC']['IsEnabled'] == "true":
                logging.info("RollBack: Enabling Source Org-Vdc")
                sourceOrgVdcId = sourceOrgVdcId.split(':')[-1]
                # url to enable source org vdc
                url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                    vcdConstants.ENABLE_ORG_VDC.format(sourceOrgVdcId))
                # post api call to enable source org vdc
                response = self.restClientObj.post(url, self.headers)
                if response.status_code == requests.codes.no_content:
                    logger.debug("Source Org VDC Enabled successfully")
                else:
                    responseDict = xmltodict.parse(response.content)
                    raise Exception("Failed to Enable Source Org VDC: {}".format(responseDict['Error']['@message']))
            else:
                logger.debug("Not Enabling Source Org VDC since it was already disabled")
        except Exception:
            raise

    @isSessionExpired
    def _checkSuspendedVMsInVapp(self, vApp):
        """
        Description :   Send get request for vApp and check for suspended VM in response
        Parameters  :   vApp - data related to a vApp (DICT)
        """
        vAppResponse = self.restClientObj.get(vApp['@href'], self.headers)
        responseDict = xmltodict.parse(vAppResponse.content)
        # checking if the vapp has vms present in it
        if not responseDict['VApp'].get('Children'):
            logger.debug('Source vApp {} has no VM present in it.'.format(vApp['@name']))
            return
        # retrieving vms of the vapp
        vmList = responseDict['VApp']['Children']['Vm'] if isinstance(responseDict['VApp']['Children']['Vm'],
                                                                      list) else [
            responseDict['VApp']['Children']['Vm']]
        # iterating over the vms in the vapp
        for vm in vmList:
            if vm["@status"] == "3":
                self.suspendedVMList.append(vm['@name'])

    def validateSourceSuspendedVMsInVapp(self, sourceOrgVDCId):
        """
        Description :   Validates that there exists no VMs in suspended state in Source Org VDC
                        If found atleast single VM in suspended state then raises exception
        """
        try:
            self.suspendedVMList = list()
            sourceVappsList = self.getSourceOrgVDCvAppsList(sourceOrgVDCId)
            if not sourceVappsList:
                return

            # iterating over the source vapps
            for vApp in sourceVappsList:
                self.thread.spawnThread(self._checkSuspendedVMsInVapp, vApp)
            self.thread.joinThreads()
            if self.suspendedVMList:
                raise Exception("VM: {} is in suspended state, Unable to migrate".format(','.join(self.suspendedVMList)))
            logger.debug("Validated Successfully, No Suspended VMs in Source Vapps")
        except Exception:
            raise

    @isSessionExpired
    def _checkVappWithOwnNetwork(self, vApp):
        """
        Description :   Send get request for vApp and check if vApp has its own vapp routed network in response
        Parameters  :   vApp - data related to a vApp (DICT)
        """
        # get api call to retrieve the vapp details
        response = self.restClientObj.get(vApp['@href'], self.headers)
        responseDict = xmltodict.parse(response.content)
        vAppData = responseDict['VApp']
        # checking if the networkConfig is present in vapp's NetworkConfigSection
        if vAppData['NetworkConfigSection'].get('NetworkConfig'):
            vAppNetworkList = vAppData['NetworkConfigSection']['NetworkConfig'] if isinstance(
                vAppData['NetworkConfigSection']['NetworkConfig'], list) else [
                vAppData['NetworkConfigSection']['NetworkConfig']]
            if vAppNetworkList:
                networkList = []
                DHCPEnabledNetworkList = []
                # iterating over the source vapp network list
                for vAppNetwork in vAppNetworkList:
                    if vAppNetwork['Configuration'].get('ParentNetwork'):
                        # if parent network is present, then name of parent network and name of the network itself should be same - means it is an org vdc network present in vapp, else raising exception since it's a vapp network
                        # Fence mode is always "bridged" for org vdc networks and "natRouted" for vApp routed network which is not supported and vapp network - when network name is not same as that of its parent network name.
                        if vAppNetwork['Configuration']['FenceMode'] == "natRouted" and vAppNetwork['@networkName'] != vAppNetwork['Configuration']['ParentNetwork']['@name']:
                            networkList.append(vAppNetwork['@networkName'])
                        else:
                            logger.debug("validation successful the vApp networks {} in vApp {} is isolated".format(vAppNetwork['@networkName'], vApp['@name']))
                    else:
                        # if parent network is absent then raising exception only if the  network gateway is not dhcp
                        if vAppNetwork['Configuration']['IpScopes']['IpScope']['Gateway'] != '196.254.254.254':
                            # the fence mode for isolated vApp network is isolated which is supported and for routed it is natRouted
                            if vAppNetwork['Configuration']['FenceMode'] != "isolated":
                                networkList.append(vAppNetwork['@networkName'])
                            else:
                                logger.debug("validation successful the vApp networks {} in vApp {} is isolated".format(vAppNetwork['@networkName'], vApp['@name']))
                            if vAppNetwork['Configuration'].get('Features', {}).get('DhcpService', {}).get('IsEnabled') == 'true':
                                logger.debug("validation failed the vApp networks {} in vApp {} is isolated with DHCP enabled".format(
                                    vAppNetwork['@networkName'], vApp['@name']))
                                DHCPEnabledNetworkList.append(vAppNetwork['@networkName'])

                        else:
                            logger.debug("Validated successfully {} network within vApp {} is not a Vapp Network".format(vAppNetwork['@networkName'], vApp['@name']))
                if networkList:
                    self.vAppNetworkDict[vApp['@name']] = networkList
                if DHCPEnabledNetworkList:
                    self.DHCPEnabled[vApp['@name']] = DHCPEnabledNetworkList

    def validateNoVappNetworksExist(self, sourceOrgVDCId):
        """
        Description :   Validates there exists no vapp routed network in source vapps
        """
        try:
            vAppNetworkList = list()
            self.vAppNetworkDict = dict()
            self.DHCPEnabled = dict()

            vAppList = self.getSourceOrgVDCvAppsList(sourceOrgVDCId)
            if not vAppList:
                return

                # iterating over the source vapps
            for vApp in vAppList:
                # spawn thread for check vapp with own network task
                self.thread.spawnThread(self._checkVappWithOwnNetwork, vApp)
                # halt the main thread till all the threads complete execution
            self.thread.joinThreads()
            if self.vAppNetworkDict:
                for key, value in self.vAppNetworkDict.items():
                    vAppNetworkList.append('vAppName: ' + key + ' : NetworkName: ' + ', '.join(value))
                raise Exception("vApp Routed Network: '{}' exist in Source Org VDC".format(', '.join(vAppNetworkList)))
            if self.DHCPEnabled:
                for key, value in self.DHCPEnabled.items():
                    vAppNetworkList.append('vAppName: ' + key + ' : NetworkName: ' + ', '.join(value))
                raise Exception("DHCP is configured on vApp Isolated Network: '{}'".format(', '.join(vAppNetworkList)))
        except Exception:
            raise

    @isSessionExpired
    def _checkVappWithIsolatedNetwork(self, vApp):
        """
        Description :   Send get request for vApp and check if vApp has its own vapp routed network in response
        Parameters  :   vApp - data related to a vApp (DICT)
        """
        # get api call to retrieve the vapp details
        response = self.restClientObj.get(vApp['@href'], self.headers)
        responseDict = xmltodict.parse(response.content)
        vAppData = responseDict['VApp']
        # checking if the networkConfig is present in vapp's NetworkConfigSection
        if vAppData['NetworkConfigSection'].get('NetworkConfig'):
            vAppNetworkList = vAppData['NetworkConfigSection']['NetworkConfig'] if isinstance(
                vAppData['NetworkConfigSection']['NetworkConfig'], list) else [
                vAppData['NetworkConfigSection']['NetworkConfig']]
            if vAppNetworkList:
                networkList = []
                DHCPEnabledNetworkList = []
                # iterating over the source vapp network list
                for vAppNetwork in vAppNetworkList:
                    if not vAppNetwork['Configuration'].get('ParentNetwork'):
                        # if parent network is absent then raising exception only if the  network gateway is not dhcp
                        if vAppNetwork['Configuration']['IpScopes']['IpScope']['Gateway'] != '196.254.254.254':
                            # Checking for dhcp configuration on vapp isolated networks
                            if vAppNetwork['Configuration'].get('Features', {}).get('DhcpService', {}).get(
                                    'IsEnabled') == 'true':
                                logger.debug(
                                    "validation failed the vApp networks {} in vApp {} is isolated with DHCP enabled".format(
                                        vAppNetwork['@networkName'], vApp['@name']))
                                DHCPEnabledNetworkList.append(vAppNetwork['@networkName'])

                        else:
                            logger.debug(
                                "Validated successfully {} network within vApp {} is not a Vapp Network".format(
                                    vAppNetwork['@networkName'], vApp['@name']))
                if DHCPEnabledNetworkList:
                    self.DHCPEnabled[vApp['@name']] = DHCPEnabledNetworkList

    def validateDHCPOnIsolatedvAppNetworks(self, sourceOrgVDCId):
        """
        Description :   Validates there exists no vapp routed network in source vapps
        """
        try:
            vAppNetworkList = list()
            self.DHCPEnabled = dict()

            vAppList = self.getSourceOrgVDCvAppsList(sourceOrgVDCId)
            if not vAppList:
                return

            # iterating over the source vapps
            for vApp in vAppList:
                # spawn thread for check vapp with own network task
                self.thread.spawnThread(self._checkVappWithIsolatedNetwork, vApp)
                # halt the main thread till all the threads complete execution
            self.thread.joinThreads()
            if self.DHCPEnabled:
                for key, value in self.DHCPEnabled.items():
                    vAppNetworkList.append('vAppName: ' + key + ' : NetworkName: ' + ', '.join(value))
                raise Exception("DHCP is enabled on vApp Isolated Network: '{}'".format(', '.join(vAppNetworkList)))
        except Exception:
            raise

    @isSessionExpired
    def _checkMediaAttachedToVM(self, vApp):
        """
            Description :   Send get request for vApp and check if VMs in vApp have media attached
            Parameters  :   vApp - data related to a vApp (DICT)
        """
        try:
            hrefVapp = vApp['@href']
            vmWithMediaList = list()
            # get api call to retrieve vapp details
            response = self.restClientObj.get(hrefVapp, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                # checking if vapp has vms in it
                if responseDict['VApp'].get('Children'):
                    vmList = responseDict['VApp']['Children']['Vm'] if isinstance(responseDict['VApp']['Children']['Vm'],
                                                                                  list) else [
                        responseDict['VApp']['Children']['Vm']]
                    # iterating over vms in the vapp
                    for vm in vmList:
                        mediaSettings = vm['VmSpecSection']['MediaSection']['MediaSettings']
                        # iterating over the list of media settings of vm
                        for mediaSetting in mediaSettings:
                            # checking for the ISO media type that should be disconnected, else raising exception
                            if mediaSetting['MediaType'] == "ISO":
                                if mediaSetting['MediaState'] != "DISCONNECTED":
                                    vmWithMediaList.append(vApp['@name'] + ':' + vm['@name'])
                    if vmWithMediaList:
                        return vmWithMediaList
                    else:
                        logger.debug("Validated successfully that media of source vm {} is not connected".format(vm['@name']))
                else:
                    logger.debug("Source vApp {} has no VMs in it".format(vApp['@name']))
            else:
                raise Exception ('Unable to get vApp details from vApp: {}'.format(vApp['@name']))
        except Exception:
            raise

    @isSessionExpired
    def validateVappVMsMediaNotConnected(self, OrgVDCID, raiseError=False):
        """
        Description :   Validates none VM's media is connected from any of the Source vApps
        """
        try:
            orgvdcId = OrgVDCID.split(':')[-1]
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(orgvdcId))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
            else:
                raise Exception('Error occurred while retrieving Org VDC - {} details'.format(OrgVDCID))
            if not responseDict['AdminVdc']['ResourceEntities']:
                return
            sourceOrgVDCEntityList = responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'] if isinstance(
                responseDict["AdminVdc"]['ResourceEntities']['ResourceEntity'], list) else [
                responseDict["AdminVdc"]['ResourceEntities']['ResourceEntity']]
            # creating source vapp list
            sourceVappList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if
                              vAppEntity['@type'] == vcdConstants.TYPE_VAPP]

            for sourceVapp in sourceVappList:
                # spawn thread for check media connected to vm in vapp
                self.thread.spawnThread(self._checkMediaAttachedToVM, sourceVapp, saveOutputKey=sourceVapp['@name'])
                # halt the main thread till all the threads complete execution
            self.thread.joinThreads()
            if self.thread.stop():
                raise Exception("Validation failed vApp/s exist VM/s with media connected")
            allVmWithMediaList = list()
            for each_vApp, eachVmValues in self.thread.returnValues.items():
                if eachVmValues is not None:
                    allVmWithMediaList.append(','.join(eachVmValues))
            if raiseError and allVmWithMediaList:
                raise Exception('The following VMs have media attached to it: {}'.format(', '.join(allVmWithMediaList)))
            elif raiseError == False and allVmWithMediaList:
                logger.warning('The following VMs have media attached to it: {}'.format(', '.join(allVmWithMediaList)))
            else:
                logger.debug("Validated successfully no vApp/s has VM/s with media connected")
        except Exception:
            raise

    def validateSourceNetworkPools(self):
        """
        Description :   Validates the source network pool is VXLAN backed
        """
        try:
            # reading data from metadata
            data = self.rollback.apiData
            # checking for the network pool associated with source org vdc
            if data['sourceOrgVDC'].get('NetworkPoolReference'):
                # source org vdc network pool reference dict
                networkPool = data['sourceOrgVDC']['NetworkPoolReference']
                # get api call to retrieve the info of source org vdc network pool
                networkPoolResponse = self.restClientObj.get(networkPool['@href'], self.headers)
                networkPoolDict = xmltodict.parse(networkPoolResponse.content)
                # checking if the source network pool is VXLAN backed
                if networkPoolDict['vmext:VMWNetworkPool']['@xsi:type'] == vcdConstants.VXLAN_NETWORK_POOL_TYPE or \
                        networkPoolDict['vmext:VMWNetworkPool']['@xsi:type'] == vcdConstants.VLAN_NETWORK_POOL_TYPE:
                    # success - source network pool is VXLAN backed
                    logger.debug("Validated successfully, source org VDC network pool {} is VXLAN backed".format(networkPoolDict['vmext:VMWNetworkPool']['@name']))
                else:
                    # fail - source network pool is not VXLAN backed
                    raise Exception("Source org VDC network pool {} is not VXLAN backed".format(networkPoolDict['vmext:VMWNetworkPool']['@name']))
            else:
                raise Exception("No Network pool is associated with Source Org VDC")
        except Exception:
            raise

    def validateNoTargetOrgVDCExists(self, sourceOrgVDCName):
        """
        Description :   Validates the target Org VDC does not exist with same name as that of source Org VDC
                        with '-t' appended
                        Eg: source org vdc name :-  v-CokeOVDC
                            target org vdc name :-  v-CokeOVDC-t
        Parameters : sourceOrgVDCName - Name of the source Org VDC (STRING)
        """
        try:
            data = self.rollback.apiData
            # retrieving list instance of org vdcs under the specified organization in user input file
            orgVDCsList = data['Organization']['Vdcs']['Vdc'] if isinstance(data['Organization']['Vdcs']['Vdc'], list) else [data['Organization']['Vdcs']['Vdc']]
            # iterating over the list of org vdcs under the specified organization
            for orgVDC in orgVDCsList:
                # checking if target org vdc's name already exist in the given organization; if so raising exception
                if orgVDC['@name'] == "{}-t".format(sourceOrgVDCName):
                    raise Exception("Target Org VDC '{}-t' already exists".format(sourceOrgVDCName))
            logger.debug("Validated successfully, no target org VDC named '{}-t' exists".format(sourceOrgVDCName))
        except Exception:
            raise

    @description("performing pre-migration validations")
    @remediate
    def preMigrationValidation(self, vcdDict, sourceOrgVDCId, nsxtObj):
        """
        Description : Pre migration validation tasks
        Parameters  : vcdDict   -   dictionary of the vcd details (DICTIONARY)
        """
        try:
            logger.info('Starting with PreMigration validation tasks')
            disableOrgVDC = False

            logger.info('Validating NSX-T Bridge Uplink Profile does not exist')
            nsxtObj.validateBridgeUplinkProfile()

            logger.info('Validating Edge Cluster Exists in NSX-T and Edge Transport Nodes are not in use')
            nsxtObj.validateEdgeNodesNotInUse(vcdDict.EdgeClusterName)

            logger.info("Validating Transport Zone Exists in NSX-T")
            nsxtObj.validateTransportZoneExistsInNSXT(vcdDict.TransportZoneName)

            orgVdcNetworkList = self.getOrgVDCNetworks(sourceOrgVDCId, 'sourceOrgVDCNetworks',
                                                              saveResponse=False)
            nsxtObj.validateOrgVdcNetworksAndEdgeTransportNodes(vcdDict.EdgeClusterName, orgVdcNetworkList)

            # validating whether target org vdc with same name as that of source org vdc exists
            logger.info("Validating whether target Org VDC already exists")
            self.validateNoTargetOrgVDCExists(vcdDict.OrgVDCName)

            # validating whether there are empty vapps in source org vdc
            logger.info("Validating no empty vapps exist in source org VDC")
            self.validateNoEmptyVappsExistInSourceOrgVDC(sourceOrgVDCId)

            # validating the source org vdc does not have any suspended state vms in any of the vapps
            logger.info('Validating suspended state VMs does not exist in any of the Source vApps')
            self.validateSourceSuspendedVMsInVapp(sourceOrgVDCId)

            # Validating if fencing is enabled on vApps in source OrgVDC
            logger.info('Validating if fencing is enabled on vApps in source OrgVDC')
            self.validateVappFencingMode(sourceOrgVDCId)

            # validating that No vApps have its own vApp Networks
            logger.info('Validate vApps have no routed vApp Networks')
            self.validateNoVappNetworksExist(sourceOrgVDCId)

            # validating that No vApps have isolated networks with dhcp configured
            logger.info('Validate vApps have not isolated vApp networks with DHCP enabled')
            self.validateDHCPOnIsolatedvAppNetworks(sourceOrgVDCId)

            # validating org vdc fast provisioned
            logger.info('Validating whether source Org VDC is fast provisioned')
            self.validateOrgVDCFastProvisioned()

            # getting the source External Network details
            logger.info('Getting the source External Network - {} details.'.format(vcdDict.NSXVProviderVDCExternalNetwork))
            sourceExternalNetwork = self.getExternalNetwork(vcdDict.NSXVProviderVDCExternalNetwork)
            if isinstance(sourceExternalNetwork, Exception):
                raise sourceExternalNetwork

            # getting the target External Network details
            logger.info('Getting the target External Network - {} details.'.format(vcdDict.NSXTProviderVDCExternalNetwork))
            targetExternalNetwork = self.getExternalNetwork(vcdDict.NSXTProviderVDCExternalNetwork)
            if isinstance(targetExternalNetwork, Exception):
                raise targetExternalNetwork

            # getting the source dummy External Network details
            logger.info('Getting the source dummy External Network - {} details.'.format(vcdDict.NSXVProviderVDCDummyExternalNetwork))
            dummyExternalNetwork = self.getExternalNetwork(vcdDict.NSXVProviderVDCDummyExternalNetwork, isDummyNetwork=True)
            if isinstance(dummyExternalNetwork, Exception):
                raise dummyExternalNetwork

            # validating whether edge gateway have dedicated external network
            logger.info('Validating whether other Edge gateways are using dedicated external network')
            self.validateDedicatedExternalNetwork()

            # getting the source provider VDC details and checking if its NSX-V backed
            logger.info('Getting the source Provider VDC - {} details.'.format(vcdDict.NSXVProviderVDCName))
            sourceProviderVDCId, isNSXTbacked = self.getProviderVDCId(vcdDict.NSXVProviderVDCName)
            self.getProviderVDCDetails(sourceProviderVDCId, isNSXTbacked)

            # validating the source network pool is VXLAN or VLAN backed
            logger.info("Validating Source Network Pool is VXLAN or VLAN backed")
            self.validateSourceNetworkPools()

            # validating whether source org vdc is NSX-V backed
            logger.info('Validating whether source Org VDC is NSX-V backed')
            self.validateOrgVDCNSXbacking(sourceOrgVDCId, sourceProviderVDCId, isNSXTbacked)

            #  getting the target provider VDC details and checking if its NSX-T backed
            logger.info('Getting the target Provider VDC - {} details.'.format(vcdDict.NSXTProviderVDCName))
            targetProviderVDCId, isNSXTbacked = self.getProviderVDCId(vcdDict.NSXTProviderVDCName)
            self.getProviderVDCDetails(targetProviderVDCId, isNSXTbacked)

            # validating hardware version of source and target Provider VDC
            logging.info('Validating Hardware version of Source Provider VDC: {} and Target Provider VDC: {}'.format(vcdDict.NSXVProviderVDCName, vcdDict.NSXTProviderVDCName))
            self.validateHardwareVersion()

            # validating if the target provider vdc is enabled or not
            logger.info('Validating Target Provider VDC {} is enabled'.format(vcdDict.NSXTProviderVDCName))
            self.validateTargetProviderVdc()

            # disable the source Org VDC so that operations cant be performed on it
            logger.info('Disabling the source Org VDC - {}'.format(vcdDict.OrgVDCName))
            disableOrgVDC = self.disableOrgVDC(sourceOrgVDCId)

            # validating the source org vdc placement policies exist in target PVDC also
            logger.info('Validating whether source org vdc - {} placement policies are present in target PVDC'.format(vcdDict.OrgVDCName))
            self.validateVMPlacementPolicy(sourceOrgVDCId)

            # validating whether source and target P-VDC have same vm storage profiles
            logger.info('Validating whether source Org VDC and target Provider VDC have same storage profiles')
            logger.info('Validating source org vdc storage profiles present in target provider vdc are all enabled in target provider vdc')
            self.validateStorageProfiles()

            # validating whether same subnet exist in source and target External networks
            logger.info('Validating source and target External networks have same subnets')
            self.validateExternalNetworkSubnets()

            # get the affinity rules of source Org VDC
            logger.info('Getting the VM affinity rules of source Org VDC {}'.format(vcdDict.OrgVDCName))
            self.getOrgVDCAffinityRules(sourceOrgVDCId)

            # disabling Affinity rules
            logger.info('Disabling source Org VDC affinity rules if its enabled.')
            self.disableSourceAffinityRules()

            # validating single Edge gateway exist in source Org VDC
            logger.info('Validating whether single Edge gateway exist in source Org VDC {}.'.format(vcdDict.OrgVDCName))
            sourceEdgeGatewayId = self.validateSingleEdgeGatewayExistForOrgVDC(sourceOrgVDCId)
            self.rollback.apiData['sourceEdgeGatewayId'] = sourceEdgeGatewayId

            # getting the source Org VDC networks
            logger.info('Getting the Org VDC networks of source Org VDC {}'.format(vcdDict.OrgVDCName))
            orgVdcNetworkList = self.getOrgVDCNetworks(sourceOrgVDCId, 'sourceOrgVDCNetworks')

            # validating whether DHCP is enabled on source Isolated Org VDC network
            logger.info('Validating whether DHCP is enabled on source Isolated Org VDC network')
            self.validateDHCPEnabledonIsolatedVdcNetworks(orgVdcNetworkList)

            # validating whether any org vdc network is shared or not
            logger.info('Validating whether Org VDC networks are shared')
            self.validateOrgVDCNetworkShared(orgVdcNetworkList)

            # validating whether any source org vdc network is not direct network
            logger.info('Validating whether Org VDC have Direct networks.')
            self.validateOrgVDCNetworkDirect(orgVdcNetworkList)

            # get the list of services configured on source Edge Gateway
            logger.info('Getting the services configured on source Edge Gateway')
            ipsecConfigDict = self.getEdgeGatewayServices(sourceEdgeGatewayId)
            # Writing ipsec config to api data dict for further use
            self.rollback.apiData['ipsecConfigDict'] = ipsecConfigDict

            # validating nat and ipsec service ips are from sub-allocated ip pool of source edge gateway
            self.validateNatIpInSrcEdgeSuballocatedPool(sourceOrgVDCId, vcdDict.NSXVProviderVDCExternalNetwork, sourceEdgeGatewayId)

            logger.info("Validating if Independent Disks exist in Source Org VDC")
            self.validateIndependentDisksDoesNotExistsInOrgVDC(sourceOrgVDCId)

            logger.info('Validating whether media is attached to any vApp VMs')
            self.validateVappVMsMediaNotConnected(sourceOrgVDCId)

            logger.info('Successfully completed PreMigration validation tasks')
        except Exception as err:
            # Enabling source Org VDC if premigration validation fails
            if disableOrgVDC:
                self.enableSourceOrgVdc(sourceOrgVDCId)
            raise

    @isSessionExpired
    def validateDedicatedExternalNetwork(self):
        """
        Description :   Validate if the External network is dedicatedly used by any other edge gateway
        """
        try:
            # reading the data from metadata
            data = self.rollback.apiData
            if 'targetExternalNetwork' not in data.keys():
                raise Exception('Target External Network not present')
            else:
                external_network_id = data['targetExternalNetwork']['id']
            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.VALIDATE_DEDICATED_EXTERNAL_NETWORK_FILTER.format(external_network_id))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                values = responseDict['values']
                # checking whether values is a list if not converting it into a list
                values = values if isinstance(values, list) else [values]
                # iterating all the edge gateways
                for value in values:
                    # checking whether the dedicated flag is enabled
                    if value['edgeGatewayUplinks'][0]['dedicated']:
                        raise Exception('Edge Gateway {} are using dedicated external network {} and hence new edge gateway cannot be created'.format(value['name'], data['targetExternalNetwork']['name']))
                logger.debug('Validated Successfully, No other edge gateways are using dedicated external network')
            else:
                raise Exception("Failed to retrieve edge gateway uplinks")
        except Exception:
            raise

    def deleteSession(self):
        """
        Description :   Deletes the current session / log out the current user
        """
        try:
            logger.debug("Deleting the current user session (Log out current user)")
            # url to get the current user session of vcloud director
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.CURRENT_SESSION)
            # get api call to get the current user session details of vcloud director
            getResponse = self.restClientObj.get(url, self.headers)
            getResponseDict = getResponse.json()
            if getResponse.status_code == requests.codes.ok:
                # url to delete the current user session of vcloud director
                url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                    vcdConstants.DELETE_CURRENT_SESSION.format(getResponseDict['id']))
                # delete api call to delete the current user session of vcloud director
                deleteResponse = self.restClientObj.delete(url, self.headers)
                if deleteResponse.status_code == requests.codes.no_content:
                    # successful log out of current vmware cloud director user
                    logger.debug("Successfully logged out VMware cloud director user")
                else:
                    # failure in current vmware cloud director user log out
                    deleteResponseDict = deleteResponse.json()
                    raise Exception("Failed to log out current user of VMware Cloud Director: {}".format(deleteResponseDict['message']))
            else:
                # failure in retrieving the details of current user session of vmware cloud director
                raise Exception("Failed to retrieve current user session details of VMware Cloud Director, so can't log out current user: {}".format(getResponseDict['message']))
        except Exception:
            raise

    @isSessionExpired
    def getEdgeGatewayDnsConfig(self, edgeGatewayId, validation=True):
        """
        Description :   Gets the DNS Configuration details of the specified Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            # url to fetch edge gateway details
            getUrl = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                   vcdConstants.UPDATE_EDGE_GATEWAY_BY_ID.format(edgeGatewayId))
            getResponse = self.restClientObj.get(getUrl, headers=self.headers)
            if getResponse.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(getResponse.content)
                edgeGatewayDict = responseDict['EdgeGateway']
                # checking if use default route for dns relay is enabled on edge gateway, if not then return
                if edgeGatewayDict['Configuration']['UseDefaultRouteForDnsRelay'] != 'true':
                    return []
            logger.debug("Getting DNS Services Configuration Details of Source Edge Gateway")
            # url to get dhcp config details of specified edge gateway
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_DNS_CONFIG_BY_ID.format(edgeGatewayId))
            # call to get api to get dns config details of specified edge gateway
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                # checking if dns exists
                if responseDict['dns'].get('dnsViews'):
                    if responseDict['dns']['dnsViews']['dnsView']:
                        # returning the dns details
                        logger.debug("DNS configuration of Source Edge Gateway retrieved successfully")
                        if not validation:
                            return responseDict['dns']['dnsViews']['dnsView']['forwarders']
                        return []
                    if not validation:
                        return responseDict
                    return []
            else:
                return ["Failed to retrieve DNS configuration of Source Edge Gateway with error code {}".format(response.status_code)]
        except Exception:
            raise

    def _checkVappIsEmpty(self, vApp):
        """
        Description :   Send get request for vApp and check if vApp has VM or not in response
        Parameters  :   vApp - data related to a vApp (DICT)
        """
        try:
            vAppResponse = self.restClientObj.get(vApp['@href'], self.headers)
            responseDict = xmltodict.parse(vAppResponse.content)
            # checking if the vapp has vms present in it
            if not responseDict['VApp'].get('Children'):
                return True
        except Exception:
            raise

    def validateNoEmptyVappsExistInSourceOrgVDC(self, sourceOrgVDCId):
        """
        Description :   Validates that there are no empty vapps in source org vdc
                        If found atleast single empty vapp in source org vdc then raises exception
        """
        try:
            emptyvAppList = list()
            sourceVappsList = self.getSourceOrgVDCvAppsList(sourceOrgVDCId)
            if not sourceVappsList:
                return

            # iterating over the source vapps
            for vApp in sourceVappsList:
                # spawn thread for check empty vApp task
                self.thread.spawnThread(self._checkVappIsEmpty, vApp, saveOutputKey=vApp['@name'])
            # halt the main thread till all the threads complete execution
            self.thread.joinThreads()
            if self.thread.stop():
                raise Exception("Validation failed, empty vapp/s exist in Source Org VDC")
            for vAppName, status in self.thread.returnValues.items():
                if status == True:
                    emptyvAppList.append(vAppName)
            if emptyvAppList:
                raise Exception('No VM exist in vApp: {}'.format(','.join(emptyvAppList)))
            else:
                logger.debug("Validated successfully, no empty vapps exist in Source Org VDC")
        except Exception:
            raise

    def validateHardwareVersion(self):
        """
        Description :   Validates Hardware version of Source Provider VDC and Target Provider VDC
        """
        try:
            # Reading api data from metadata
            data = self.rollback.apiData
            highestSourceVersion = 0
            highestSourceVersionName = str()
            highestTargetVersionName = str()
            for eachSourceVersionDetail in data['sourceProviderVDC']['Capabilities']['SupportedHardwareVersions']['SupportedHardwareVersion']:
                [name, currentVersion] = eachSourceVersionDetail['@name'].split('-')
                if int(currentVersion) > highestSourceVersion:
                    highestSourceVersion = int(currentVersion)
                highestSourceVersionName = '-'.join([name, str(highestSourceVersion)])
            highestTargetVersion = 0
            for eachTargetVersionDetail in data['targetProviderVDC']['Capabilities']['SupportedHardwareVersions']['SupportedHardwareVersion']:
                [name, currentVersion] = eachTargetVersionDetail['@name'].split('-')
                if int(currentVersion) > highestTargetVersion:
                    highestTargetVersion = int(currentVersion)
                highestTargetVersionName = '-'.join([name, str(highestTargetVersion)])
            if highestSourceVersion > highestTargetVersion:
                raise Exception(
                    'Hardware version on both Source Provider VDC and Target Provider VDC are not compatible, either both should be same or target PVDC hardware version'
                    ' should be greater than source PVDC hardware version. Source Provider VDC: {} and Target Provider VDC is: {}'.format(
                        highestSourceVersionName, highestTargetVersionName))
            else:
                logger.debug('Hardware version on both Source Provider VDC and Target Provider VDC are compatible')
        except Exception:
            raise

    def validateTargetOrgVDCState(self, targetOrgVDCId):
        """
        Description:    Validates that target Org VDC state is enabled or not
        Parameters:     targetOrgVDCId      - target Org VDC Id (STRING)
        """
        try:
            logger.debug('Getting target Org VDC details - {}'.format(targetOrgVDCId))
            # splitting the target org vdc id as per the requirements of xml api
            targetOrgVdcId = targetOrgVDCId.split(':')[-1]
            # url to retrieve the specified provider vdc details
            url = '{}{}'.format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                   vcdConstants.ORG_VDC_BY_ID.format(targetOrgVdcId))
            # get api call retrieve the specified provider vdc details
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                if responseDict['AdminVdc']['@id'] == targetOrgVDCId and responseDict['AdminVdc']['IsEnabled'] == "true":
                    logger.debug('Target Org VDC is enabled')
                    return
                else:
                    raise Exception("Target Org VDC is not enabled. Please enable it.")
        except Exception:
            raise

    @isSessionExpired
    def getCatalogMedia(self, orgId):
        """
        Description : Get all media objects of specific Organization
        Parameters  : orgId - Organization Id (STRING)
        """
        try:
            # url to get the media info of specified organization
            url = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                vcdConstants.GET_MEDIA_INFO)
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader,
                       'X-VMWARE-VCLOUD-TENANT-CONTEXT': orgId}
            # get api call to retrieve the media details of organization
            response = self.restClientObj.get(url, headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                resultTotal = responseDict['total']
            pageNo = 1
            pageSizeCount = 0
            resultList = []
            logger.debug('Getting media details')
            while resultTotal > 0 and pageSizeCount < resultTotal:
                # url to get the media info of specified organization with page number and page size count
                url = "{}{}&page={}&pageSize={}&format=records".format(
                    vcdConstants.XML_API_URL.format(self.ipAddress),
                    vcdConstants.GET_MEDIA_INFO, pageNo,
                    vcdConstants.MEDIA_PAGE_SIZE)
                # get api call to retrieve the media details of organization with page number and page size count
                response = self.restClientObj.get(url, headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    resultList.extend(responseDict['record'])
                    pageSizeCount += len(responseDict['record'])
                    logger.debug('Media details result pageSize = {}'.format(pageSizeCount))
                    pageNo += 1
            logger.debug('Total media details result count = {}'.format(len(resultList)))
            logger.debug('Media details successfully retrieved')
            return resultList
        except Exception:
            raise

    @isSessionExpired
    def getvAppTemplates(self, orgId):
        """
        Description : Get all vApp Templates of specific Organization
        Parameters  : orgId - Organization Id (STRING)
        """
        try:
            # url to get vapp template info
            url = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                vcdConstants.GET_VAPP_TEMPLATE_INFO)
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader,
                       'X-VMWARE-VCLOUD-TENANT-CONTEXT': orgId}
            # get api call to retrieve the vapp template details
            response = self.restClientObj.get(url, headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                resultTotal = responseDict['total']
            pageNo = 1
            pageSizeCount = 0
            resultList = []
            logger.debug('Getting vapp template details')
            while resultTotal > 0 and pageSizeCount < resultTotal:
                # url to get the vapp template info with page number and page size count
                url = "{}{}&page={}&pageSize={}&format=records".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                                                       vcdConstants.GET_VAPP_TEMPLATE_INFO, pageNo,
                                                                       vcdConstants.VAPP_TEMPLATE_PAGE_SIZE)
                # get api call to retrieve the vapp template details with page number and page size count
                response = self.restClientObj.get(url, headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    resultList.extend(responseDict['record'])
                    pageSizeCount += len(responseDict['record'])
                    logger.debug('vApp Template details result pageSize = {}'.format(pageSizeCount))
                    pageNo += 1
            logger.debug('Total vApp Template details result count = {}'.format(len(resultList)))
            logger.debug('vApp Template details successfully retrieved')
            return resultList
        except Exception:
            raise

    @isSessionExpired
    def disableSourceAffinityRules(self):
        """
        Description :   Disables the Affinity Rules in Source Vapp
        """
        try:
            data = self.rollback.apiData
            # checking if there exists affinity rules on source org vdc
            if data['sourceVMAffinityRules']:
                sourceAffinityRules = data['sourceVMAffinityRules'] if isinstance(data['sourceVMAffinityRules'], list) else [data['sourceVMAffinityRules']]
                # iterating over the affinity rules
                for sourceAffinityRule in sourceAffinityRules:
                    affinityID = sourceAffinityRule['@id']
                    # url to enable/disable the affinity rules
                    url = vcdConstants.ENABLE_DISABLE_AFFINITY_RULES.format(self.ipAddress, affinityID)
                    filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
                    vmReferencesPayloadData = ''
                    for eachVmReference in sourceAffinityRule['VmReferences']['VmReference']:
                        payloadDict = {'vmHref': eachVmReference['@href'],
                                       'vmId': eachVmReference['@id'],
                                       'vmName': eachVmReference['@name'],
                                       'vmType': eachVmReference['@type']}
                        payloadData = self.vcdUtils.createPayload(filePath,
                                                                  payloadDict,
                                                                  fileType='yaml',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.VM_REFERENCES_TEMPLATE_NAME)
                        vmReferencesPayloadData += payloadData.strip("\"")
                    isEnabled = "false"
                    payloadDict = {'affinityRuleName': sourceAffinityRule['Name'],
                                   'isEnabled': isEnabled,
                                   'isMandatory': "true" if sourceAffinityRule['IsMandatory'] == "true" else "false",
                                   'polarity': sourceAffinityRule['Polarity'],
                                   'vmReferences': vmReferencesPayloadData}
                    payloadData = self.vcdUtils.createPayload(filePath,
                                                              payloadDict,
                                                              fileType='yaml',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.ENABLE_DISABLE_AFFINITY_RULES_TEMPLATE_NAME)
                    payloadData = json.loads(payloadData)

                    self.headers['Content-Type'] = vcdConstants.GENERAL_XML_CONTENT_TYPE
                    # put api call to enable / disable affinity rules
                    response = self.restClientObj.put(url, self.headers, data=payloadData)
                    responseDict = xmltodict.parse(response.content)
                    if response.status_code == requests.codes.accepted:
                        task_url = response.headers['Location']
                        # checking the status of the enabling/disabling affinity rulres task
                        self._checkTaskStatus(task_url, vcdConstants.CREATE_AFFINITY_RULE_TASK_NAME)
                        logger.debug('Affinity Rules got enabled successfully in Source')
                    else:
                        raise Exception('Failed to enable Affinity Rules in Source {} '.format(responseDict['Error']['@message']))
        except Exception:
            raise

    def enableSourceAffinityRules(self):
        """
        Description :   Enables Affinity Rules in Source VApp
        """
        try:
            logger.info("RollBack: Enable Source vApp Affinity Rules")
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # # reading the data from apiOutput.json
            # with open(fileName, 'r') as f:
            #     data = json.load(f)
            data = self.rollback.apiData
            # checking if there exists affinity rules on source org vdc
            if data['sourceVMAffinityRules']:
                sourceAffinityRules = data['sourceVMAffinityRules'] if isinstance(data['sourceVMAffinityRules'], list) else [data['sourceVMAffinityRules']]
                # iterating over the affinity rules
                for sourceAffinityRule in sourceAffinityRules:
                    affinityID = sourceAffinityRule['@id']
                    # url to enable/disable the affinity rules
                    url = vcdConstants.ENABLE_DISABLE_AFFINITY_RULES.format(self.ipAddress, affinityID)
                    filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
                    vmReferencesPayloadData = ''
                    for eachVmReference in sourceAffinityRule['VmReferences']['VmReference']:
                        payloadDict = {'vmHref': eachVmReference['@href'],
                                       'vmId': eachVmReference['@id'],
                                       'vmName': eachVmReference['@name'],
                                       'vmType': eachVmReference['@type']}
                        payloadData = self.vcdUtils.createPayload(filePath,
                                                                  payloadDict,
                                                                  fileType='yaml',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.VM_REFERENCES_TEMPLATE_NAME)
                        vmReferencesPayloadData += payloadData.strip("\"")
                    isEnabled = "true" if sourceAffinityRule['IsEnabled'] == "true" else "false"
                    payloadDict = {'affinityRuleName': sourceAffinityRule['Name'],
                                   'isEnabled': isEnabled,
                                   'isMandatory': "true" if sourceAffinityRule['IsMandatory'] == "true" else "false",
                                   'polarity': sourceAffinityRule['Polarity'],
                                   'vmReferences': vmReferencesPayloadData}
                    payloadData = self.vcdUtils.createPayload(filePath,
                                                              payloadDict,
                                                              fileType='yaml',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.ENABLE_DISABLE_AFFINITY_RULES_TEMPLATE_NAME)
                    payloadData = json.loads(payloadData)

                    self.headers['Content-Type'] = vcdConstants.GENERAL_XML_CONTENT_TYPE
                    # put api call to enable / disable affinity rules
                    response = self.restClientObj.put(url, self.headers, data=payloadData)
                    responseDict = xmltodict.parse(response.content)
                    if response.status_code == requests.codes.accepted:
                        task_url = response.headers['Location']
                        # checking the status of the enabling/disabling affinity rulres task
                        self._checkTaskStatus(task_url, vcdConstants.CREATE_AFFINITY_RULE_TASK_NAME)
                        logger.debug('Affinity Rules got disabled successfully in Source')
                    else:
                        raise Exception('Failed to disable Affinity Rules in Source {} '.format(responseDict['Error']['@message']))
        except Exception:
            raise


    @staticmethod
    def createIpRange(startAddress, endAddress):
        """
        Description : Create an ip range
        Parameters : startAddress - Start address ip (IP)
                     endAddress -  End address ip (IP)
        """
        start = list(map(int, startAddress.split('.')))
        end = list(map(int, endAddress.split('.')))
        temp = start
        ipRange = []
        ipRange.append(startAddress)
        while temp != end:
            # incrementing the last octect by 1
            start[3] += 1
            ipRange.append(".".join(map(str, temp)))
        return ipRange

    @isSessionExpired
    def validateNatIpInSrcEdgeSuballocatedPool(self, orgVDCId, uplinkName, edgeGatewayId):
        """
        Description :   Validates the NAT service original ip address and IPsec service local ip address is from source edge gateway's sub-allocated ip pool
        Parameters  :   orgVDCId        -   source org VDC id
                        edgeGatewayId   -   source edge gateway id
        Raises      :   Exception if NAT/IPSec service ip address is not from source edge gateway's sub-allocated ip pool
                        or NAT/IPSec service  ip address is present and source edge gateway's sub-allocated ip pool is absent
        """
        try:
            logger.info("Validating whether external ip's are added in sub-allocated ip pool of source edge gateway")
            # retrieving the details of the source edge gateway
            responseDict = self.getOrgVDCEdgeGateway(orgVDCId)
            if responseDict:
                sourceEdgeGatewayDict = responseDict['values'][0]
                # getting the list instance of source edge gateway uplinks
                edgeGatewayLinks = sourceEdgeGatewayDict['edgeGatewayUplinks'] if isinstance(sourceEdgeGatewayDict['edgeGatewayUplinks'], list) else [sourceEdgeGatewayDict['edgeGatewayUplinks']]
                # setting the source edge sub-allocated ip pools range list initially to None
                sourceSuballocatedIpPoolsList = None

                # iterating over the source edge gateway uplink to find the matching link name as that of source external network(v-side external network) from userInput.yml
                for edgeGatewayLink in edgeGatewayLinks:
                    if edgeGatewayLink['uplinkName'] == uplinkName:
                        # retrieving the source edge gateway sub-allocated ip pools range list of uplink name matching with source external network name
                        sourceSuballocatedIpPoolsList = edgeGatewayLink['subnets']['values'][0]['ipRanges']['values']
                        break

                # initially creating the empty subAllocatedPoolsList
                subAllocatedPoolsList = []
                # creating a single list for all the ip-ranges in source edge gateway's sub-allocated ip pools
                for value in sourceSuballocatedIpPoolsList:
                    subAllocatedPoolsList.extend(self.createIpRange(value['startAddress'], value['endAddress']))

                errorString = ""
                gatewayId = edgeGatewayId.split(':')[-1]

                # retrieving the details of nat rules in source edge gateway
                natResponseDict = self.getEdgeGatewayNatConfig(gatewayId, validation=False)

                # checking if there exist nat rules is source edge gateway
                if natResponseDict and natResponseDict.get('natRules'):
                    # natInvalidIpList is a list of invalid nat ips rule id list, initially creating empty list
                    natInvalidIpList = list()

                    # retrieving all the nat rules present in source edge gateway
                    natRules = natResponseDict['natRules']['natRule'] if isinstance(natResponseDict['natRules']['natRule'], list) else [natResponseDict['natRules']['natRule']]

                    # retrieving only user defined nat rules in source edge gateway
                    userdefinedNatRules = [natRule for natRule in natRules if natRule['ruleType'] == 'user']

                    # iterating over each nat rule to check if its original ip address is present in subAllocatedPoolsList
                    for natRule in userdefinedNatRules:
                        ipAddress = natRule['originalAddress'] if natRule['action'] == 'dnat' else natRule['translatedAddress']
                        # if original ip address of nat rule is not in subAllocatedPoolsList then appending the rule id to  natInvalidIpList to raise the exception
                        if ipAddress not in subAllocatedPoolsList:
                            # appending the invalid ip's rule id to natInvalidIpList
                            natInvalidIpList.append(natRule['ruleId'])

                    # if natInvalidIpList is empty means no invalid ips present in nat
                    if not natInvalidIpList:
                        logger.debug("Validated Successfully, NAT Ips are present in Source Edge Gateway's sub-allocated ip pool")
                    else:
                        if subAllocatedPoolsList:
                            errorString += "The Ips used in NAT '{}' are not present in source edge gateway's sub-allocated ip pool {}\n".format(', '.join(natInvalidIpList),
                                                                                                                                                 subAllocatedPoolsList)
                        else:
                            errorString += "Source edge gateway's sub-allocated ip pool is empty, so the IPs used in NAT rules '{}' are invalid\n".format(', '.join(natInvalidIpList))

                else:
                    logger.debug("No NAT rules present on source edge gateway")

                # retrieving the details of ipsec rules in source edge gateway
                ipsecErrorList, ipsecResponseDict = self.getEdgeGatewayIpsecConfig(gatewayId)
                # checking if ipsec rules are present or not in source edge gateway
                if ipsecResponseDict:

                    # checking if ipsec is enabled on source edge gateway, if so then only validating ipsec ips else not validating
                    if ipsecResponseDict['enabled'] == "true":

                        # ipsecInvalidIpList is a list of invalid ipsec ips rule name list, initially creating empty list
                        ipsecInvalidIpList = list()

                        # retrieving the ipsec rules in source edge gateway
                        ipsecRules = ipsecResponseDict['sites']['sites'] if isinstance(ipsecResponseDict['sites']['sites'], list) else [ipsecResponseDict['sites']['sites']]

                        # iterating over each ipsec rule to check if its local ip address is present in subAllocatedPoolsList
                        for ipsecRule in ipsecRules:
                            # if local ip address of ipsec rule is not in subAllocatedPoolsList then appending the rule id name  ipsecInvalidIpList to raise the exception
                            if ipsecRule['localIp'] not in subAllocatedPoolsList:
                                # appending the name of the ipsec rule to ipsecInvalidIpList, since its ip is invalid
                                ipsecInvalidIpList.append(ipsecRule['name'])

                        # if ipsecInvalidIpList exist, means invalid ips are present in ipsec rules else successful validation
                        if ipsecInvalidIpList:
                            if subAllocatedPoolsList: # sub-allocated pool present in source edge gateway
                                errorString += "The IPs for Names {} used in IPSec are not present in source edge gateway's sub-allocated ip pool {}\n".format(', '.join(ipsecInvalidIpList),
                                                                                                                                                               subAllocatedPoolsList)
                            else: # sub-allocated pool not present in source edge gateway
                                errorString += "Source edge gateway's sub-allocated ip pool is empty, so the IPs used in IPSec rules '{}' are invalid\n".format(', '.join(ipsecInvalidIpList))

                        else: # successful validation of ipsec rules ips
                            logger.debug("Validated Successfully, IPSec Ips are present in Source Edge Gateway's sub-allocated ip pool")

                    else: # ipsec is disabled on source edge gateway
                        logger.debug("IPSec Activation Status is disabled, hence not validating ipsec ips are added in sub-allocated ip pool of source edge gateway")

                else: # no ipsec rules present in source edge gateway
                    logger.debug("No IPSec rules present on source edge gateway")

                if errorString:
                    raise Exception("Invalid external ips \n{}".format(errorString))

            else:
                raise Exception("Failed to retrieve the source edge gateway details, so can't validate external ip's are added in sub-allocated ip pool of source edge gateway")

        except Exception:
            raise