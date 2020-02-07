# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description : Module performs VMware Cloud Director validations related for NSX-V To NSX-T
"""

import json
import logging
import os
import time

import ipaddress
import xml.etree.ElementTree as ET
import requests
import xmltodict

import src.core.vcd.vcdConstants as vcdConstants

from src.commonUtils.restClient import RestAPIClient
from src.commonUtils.utils import Utilities

logger = logging.getLogger('mainLogger')


class VCDMigrationValidation():
    """
    Description : Class performing VMware Cloud Director NSX-V To NSX-T Migration validation
    """
    ENABLE_SOURCE_ORG_VDC = False
    ENABLE_AFFINITY_RULES_IN_SOURCE_VAPP = False

    def _isSessionExpired(func):
        """
        Description: Validates whether session expired or not,if expired then reconnects api session
        """
        def inner(self, *args, **kwargs):
            url = '{}session'.format(vcdConstants.XML_API_URL.format(self.ipAddress))
            response = self.restClientObj.get(url, headers=self.headers)
            if response.status_code != requests.codes.ok:
                logger.debug('Session expired!. Re-login to the vCloud Director')
                self.vcdLogin()
            return func(self, *args, **kwargs)
        return inner

    def __init__(self, ipAddress, username, password):
        """
        Description :   Initializer method of VMware Cloud Director Operations
        Parameters  :   ipAddress   -   ipAddress of the VMware vCloud Director (STRING)
                        username    -   Username of the VMware vCloud Director (STRING)
                        password    -   Password of the VMware vCloud Director (STRING)
        """
        self.ipAddress = ipAddress
        self.username = '{}@system'.format(username)
        self.password = password
        self.vcdUtils = Utilities()

    def vcdLogin(self):
        """
        Description :   Method which makes the user to login into a VMware Cloud Director for performing further VCD Operations
        Returns     :   Bearer Token    - Bearer token for authorization (TUPLE)
                        Status Code     - Status code for rest api (TUPLE)
        """
        try:
            # getting the RestAPIClient object to call the REST apis
            self.restClientObj = RestAPIClient(self.username, self.password)
            # url to create session
            url = vcdConstants.LOGIN_URL.format(self.ipAddress)
            # post api call to create sessioned login with basic authentication
            loginResponse = self.restClientObj.post(url, headers={'Accept': vcdConstants.VCD_API_HEADER}, auth=self.restClientObj.auth)
            if loginResponse.status_code == requests.codes.OK:
                logger.debug('Logged in to VMware Cloud Director {}'.format(self.ipAddress))
                # saving the returned bearer token
                self.bearerToken = 'Bearer {}'.format(loginResponse.headers['X-VMWARE-VCLOUD-ACCESS-TOKEN'])
                # creating the default headers required to fire rest api
                self.headers = {'Authorization': self.bearerToken, 'Accept': vcdConstants.VCD_API_HEADER}
                return self.bearerToken, loginResponse.status_code
            raise Exception("Failed to login to VMware Cloud Director {} with the given credentials".format(self.ipAddress))
        except Exception:
            raise

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
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
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
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            if response.status_code == requests.codes.ok:
                if os.path.exists(fileName):
                    # loading the apiOutput.json into data to save existing data if any
                    with open(fileName, 'r') as f:
                        data = json.load(f)
                if not data and saveResponse:
                    # creating 'Organization' key to save organization info
                    data = {'Organization': responseDict['AdminOrg']}
                    # writing organization info to the apiOutput.json
                    with open(fileName, 'w') as f:
                        json.dump(data, f, indent=3)
                responseDict = responseDict['AdminOrg']['Vdcs']['Vdc']
                if isinstance(responseDict, dict):
                    responseDict = [responseDict]
                for response in responseDict:
                    # checking for orgVDCName in the responseDict, if found then returning the orgVDCUrl
                    if response['@name'] == orgVDCName:
                        orgVDCUrl = response['@href']
                        logger.debug('Organization VDC {} url {} retrieved successfully'.format(orgVDCName, orgVDCUrl))
                if not orgVDCUrl:
                    raise Exception('Org VDC {} doesnot belong to this organization {}'.format(orgVDCName, orgUrl))
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
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            if response.status_code == requests.codes.ok:
                if saveResponse:
                    # loading the existing data from apiOutput.json if any
                    with open(fileName, 'r') as f:
                        data = json.load(f)
                    data[orgVDCType] = responseDict['AdminVdc']
                    # writing the details of orgVDCName to apiOutput.json
                    with open(fileName, 'w') as outputFile:
                        json.dump(data, outputFile, indent=3)
                    logger.debug('Retrieved Organization VDC {} details successfully'.format(orgVDCName))
                # returning the orgVDCName details
                return responseDict['AdminVdc']['@id']
            raise Exception("Failed to retrieve details of Organization VDC {} {}".format(orgVDCName,
                                                                                          responseDict['Error']['@message']))
        except Exception:
            raise

    @_isSessionExpired
    def validateOrgVDCFastProvisioned(self):
        """
        Description :   Validates whether fast provisioning is enabled on the Org VDC
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # checking if the source org vdc uses fast provisioning, if so raising exception
            if data['sourceOrgVDC']['UsesFastProvisioning'] == "true":
                raise Exception("Fast Provisioning enabled on source Org VDC. Will not migrate fast provisioned org vdc")
            logger.debug("Validated Succesfully, Fast Provisioning is not enabled on source Org VDC")
        except Exception:
            raise

    @_isSessionExpired
    def getExternalNetwork(self, networkName, isDummyNetwork=False):
        """
        Description :   Gets the details of external networks
        Parameters  :   networkName - Name of the external network (STRING)
                        isDummyNetwork - is the network dummy (BOOL)
        """
        try:
            logger.debug("Getting External Network {} details ".format(networkName))
            # url to get all the external networks
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EXTERNAL_NETWORKS)
            # get api call to get all the external networks
            getResponse = self.restClientObj.get(url, self.headers)
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            responseDict = getResponse.json()
            if getResponse.status_code == requests.codes.ok:
                # iterating over all the external networks
                for response in responseDict['values']:
                    # checking if networkName is present in the list, if present saving the specified network's details to apiOutput.json
                    if response['name'] == networkName:
                        key = 'targetExternalNetwork' if response['networkBackings']['values'][0]['backingType'] == 'NSXT_TIER0' else 'sourceExternalNetwork'
                        # loading exiting deta from apiOuptut.json
                        with open(fileName, 'r') as f:
                            data = json.load(f)
                        if isDummyNetwork:
                            key = 'dummyExternalNetwork'
                        data[key] = response
                        # writing specified networkName's details to apiOutput.json
                        with open(fileName, 'w') as f:
                            json.dump(data, f, indent=3)
                        logger.debug("Retrieved External Network {} details Successfully".format(networkName))
                        # returning the id of networkName
                        return response['id']
            raise Exception('Failed to get External network {} details {}'.format(networkName,
                                                                                  responseDict['message']))
        except Exception:
            raise

    @_isSessionExpired
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
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            if response.status_code == requests.codes.ok:
                key = 'targetProviderVDC' if isNSXTbacked else 'sourceProviderVDC'
                # loading existing data from apiOutput.json
                with open(fileName, 'r') as f:
                    data = json.load(f)
                data[key] = responseDict['ProviderVdc']
                # writing specified provider vdc's data to apiOutput.json
                with open(fileName, 'w') as f:
                    json.dump(data, f, indent=3)
                logger.debug(
                    "Provider VDC {} details retrieved successfully".format(responseDict['ProviderVdc']['@name']))
                return
            raise Exception('Failed to get Provider VDC details')
        except Exception:
            raise

    @staticmethod
    def validateOrgVDCNSXVbacked(sourceProviderVDCId, isNSXTbacked):
        """
        Description : Validate whether source Org VDC is NSX-V backed
        Parameters : sourceProviderVDCId    - source ProviderVDC id (STRING)
                     isNSXTbacked           - True if provider VDC is NSX-T backed else False (BOOL)
        """
        try:
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.jaon
            with open(fileName, 'r') as f:
                data = json.load(f)
            providerVDCId = data['sourceOrgVDC']['ProviderVdcReference']['@id']
            # checking if source provider vdc is nsx-v backed, if not then raising exception
            if providerVDCId == sourceProviderVDCId and not isNSXTbacked:
                logger.debug("Validated successfully source Org VDC {} is NSX-V backed.".format(data['sourceOrgVDC']['@name']))
                return
            raise Exception("Source Org VDC {} is not NSX-V backed.".format(data['sourceOrgVDC']['@name']))
        except Exception:
            raise

    @_isSessionExpired
    def validateTargetProviderVdc(self):
        """
        Description :   Validates whether the target Provider VDC is Enabled
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # checking if target provider vdc is enabled, if not raising exception
            if data['targetProviderVDC']['IsEnabled'] != "true":
                raise Exception("Target Provider VDC is not enabled")
            logger.debug("Validated successfully target Provider VDC is enabled")
        except Exception:
            raise

    @_isSessionExpired
    def disableOrgVDC(self, orgVDCId, isSourceDisable=True):
        """
        Description :   Disable the Organization vdc
        Parameters  :   orgVDCId - Id of the source/target organization vdc (STRING)
                        isSourceDisable - True if source org vdc has to be disabled else False i.e target org vdc will be disabled (BOOL)
        """
        try:
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            isEnabled = data['sourceOrgVDC']['IsEnabled']
            orgVDCName = data['sourceOrgVDC']['@name']
            if isSourceDisable:
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
            else:
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

    def getOrgVDCPlacementPolicies(self, sourceOrgVDCId):
        """
        Description :   Gets the org vdc placement policies
        Parameters  :   sourceOrgVDCId - Id of the source org vdc (STRING)
        """
        try:
            namedVmGroupsList = []
            orgVdcId = sourceOrgVDCId.split(':')[-1]
            # url to retrieve the specified org vdc compute policies
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_COMPUTE_POLICY.format(orgVdcId))
            # get api call to retrieve the specified org vdc compute policies
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            if response.status_code == requests.codes.ok:
                # loading existing data from apiOutput.json
                with open(fileName, 'r') as f:
                    data = json.load(f)
                data['sourceOrgVDCComputePolicyList'] = responseDict['VdcComputePolicyReferences']['VdcComputePolicyReference']
                # writing compute policy details of source irg vdc to apiOutput.json
                with open(fileName, 'w') as f:
                    json.dump(data, f, indent=3)
                namedVmGroupsDict = {}
                # getting the compute policies of the source org vdc
                vdcComputePolicyList = responseDict['VdcComputePolicyReferences']['VdcComputePolicyReference'] if isinstance(responseDict['VdcComputePolicyReferences']['VdcComputePolicyReference'], list) else [responseDict['VdcComputePolicyReferences']['VdcComputePolicyReference']]
                # iterating over the source org vdc compute policies
                for responseData in vdcComputePolicyList:
                    # handling only the non system compute policies
                    if responseData['@name'] != 'System Default':
                        # get api call to retrieve the compute policy details
                        responseDict = self.restClientObj.get(responseData['@href'], self.headers)
                        if responseDict.status_code == requests.codes.ok:
                            responseDict = responseDict.json()
                            namedVmGroupsList = []
                            for response in responseDict['namedVmGroups']:
                                for data in response:
                                    namedVmGroupsList.append((data['name'], data['id']))
                            namedVmGroupsDict[responseData['@href']] = namedVmGroupsList
            return namedVmGroupsDict
        except Exception:
            raise

    @_isSessionExpired
    def validateVMPlacementPolicy(self, sourceOrgVDCId):
        """
        Description : Validate whether source Org VDC placement policy exist in target PVDC
        Parameters  : sourceOrgVDCId   - Id of the source org vdc (STRING)
        """
        try:
            targetPVDCComputePolicyList = []
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            orgVdcId = sourceOrgVDCId.split(':')[-1]
            # url to retrieve compute policies of source org vdc
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_COMPUTE_POLICY.format(orgVdcId))
            # get api call to retrieve source org vdc compute policies
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                # laoding existing apiOutput.json data
                with open(fileName, 'r') as f:
                    data = json.load(f)
                data['sourceOrgVDCComputePolicyList'] = responseDict['VdcComputePolicyReferences']['VdcComputePolicyReference']
                # writing source org vdc compute policies to apiOutput.json
                with open(fileName, 'w') as f:
                    json.dump(data, f, indent=3)
            sourceOrgVDCName = data['sourceOrgVDC']['@name']
            targetProviderVDCName = data['targetProviderVDC']['@name']
            targetProviderVDCId = data['targetProviderVDC']['@id']
            sourcePolicyList = data['sourceOrgVDCComputePolicyList']
            sourceComputePolicyList = [sourcePolicyList] if isinstance(sourcePolicyList, dict) else sourcePolicyList
            allOrgVDCComputePolicesList = self.getOrgVDCComputePolicies()
            orgVDCComputePolicesList = [allOrgVDCComputePolicesList] if isinstance(allOrgVDCComputePolicesList, dict) else allOrgVDCComputePolicesList
            # iterating over the org vdc compute policies
            for eachComputePolicy in orgVDCComputePolicesList:
                # checking if the org vdc compute policy's provider vdc is same as target provider vdc
                if eachComputePolicy["pvdcId"] == targetProviderVDCId:
                    # iterating over the source org vdc compute policies
                    for computePolicy in sourceComputePolicyList:
                        if computePolicy['@name'] == eachComputePolicy['name']:
                            targetPVDCComputePolicyList.append(eachComputePolicy)
            # creating list of source org vdc compute policies excluding system default
            sourceOrgVDCComputePolicyList = [sourceComputePolicy for sourceComputePolicy in sourceComputePolicyList if sourceComputePolicy['@name'] != 'System Default']
            sourceOrgVDCPlacementPolicyList = []
            # iterating over source org vdc compute policies
            for vdcComputePolicy in sourceOrgVDCComputePolicyList:
                # get api call to retrieve compute policy details
                response = self.restClientObj.get(vdcComputePolicy['@href'], self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    if not responseDict['isSizingOnly']:
                        sourceOrgVDCPlacementPolicyList.append(vdcComputePolicy)
            if len(sourceOrgVDCPlacementPolicyList) != len(targetPVDCComputePolicyList):
                raise Exception('Target PVDC - {} doesnot have source Org VDC - {} placement policies in it.'.format(targetProviderVDCName,
                                                                                                                     sourceOrgVDCName))
            logger.debug("Validated successfully, source Org VDC placement policy exist in target PVDC")
        except Exception:
            # setting the enable source org vdc flag
            self.ENABLE_SOURCE_ORG_VDC = True
            raise

    @_isSessionExpired
    def validateStorageProfiles(self):
        """
        Description :   Validate storage profiles of source org vdc with target provider vdc
        """
        try:
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # retrieving source org vdc storage profiles
            sourceOrgVDCStorageProfile = [data['sourceOrgVDC']['VdcStorageProfiles']['VdcStorageProfile']] if isinstance(data['sourceOrgVDC']['VdcStorageProfiles']['VdcStorageProfile'], dict) else data['sourceOrgVDC']['VdcStorageProfiles']['VdcStorageProfile']
            # retrieving target provider vdc storage profiles
            targetPVDCStorageProfile = [data['targetProviderVDC']['StorageProfiles']['ProviderVdcStorageProfile']] if isinstance(data['targetProviderVDC']['StorageProfiles']['ProviderVdcStorageProfile'], dict) else data['targetProviderVDC']['StorageProfiles']['ProviderVdcStorageProfile']
            # creating list of source org vdc storage profiles found in target provider vdc
            storagePoliciesFound = [sourceDict['@name'] for sourceDict in sourceOrgVDCStorageProfile for targetDict in
                                    targetPVDCStorageProfile if sourceDict['@name'] == targetDict['@name']]
            logger.debug("Storage Profiles Found in target Provider VDC are {}".format(storagePoliciesFound))
            # checking the length of profiles on source org vdc & storage profiles found on target provider vdc
            if len(sourceOrgVDCStorageProfile) != len(storagePoliciesFound):
                raise Exception("Storage profiles in Target PVDC should be same as those in Source Org VDC")
            logger.info("Validated successfully, storage Profiles in target PVDC are same as those of source Org VDC")
        except Exception:
            # setting the enable source org vdc flag which is used to in roll back
            self.ENABLE_SOURCE_ORG_VDC = True
            raise

    @_isSessionExpired
    def validateExternalNetworkSubnets(self):
        """
        Description :  Validate the external networks subnet configuration
        """
        try:
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
            # comparing the source and target external network subnet configuration
            sourceExternalGateway = data['sourceExternalNetwork']['subnets']['values'][0]['gateway']
            sourceExternalPrefixLength = data['sourceExternalNetwork']['subnets']['values'][0]['prefixLength']
            targetExternalGateway = data['targetExternalNetwork']['subnets']['values'][0]['gateway']
            targetExternalPrefixLength = data['targetExternalNetwork']['subnets']['values'][0]['prefixLength']
            sourceNetworkAddress = ipaddress.ip_network('{}/{}'.format(sourceExternalGateway, sourceExternalPrefixLength), strict=False)
            targetNetworkAddress = ipaddress.ip_network('{}/{}'.format(targetExternalGateway, targetExternalPrefixLength), strict=False)
            if sourceNetworkAddress != targetNetworkAddress:
                raise Exception('Source and target External Networks have different subnets.')
            logger.debug('Validated successfully, source and target External Networks have same subnets.')
        except Exception:
            # setting the enable source org vdc flag which is used to in roll back
            self.ENABLE_SOURCE_ORG_VDC = True
            raise

    @_isSessionExpired
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
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            if response.status_code == requests.codes.ok:
                with open(fileName, 'r') as f:
                    data = json.load(f)
                data['sourceVMAffinityRules'] = responseDict['VmAffinityRules']['VmAffinityRule'] if responseDict['VmAffinityRules'].get('VmAffinityRule', None) else {}
                # writing source org vdc affinity rules to apiOutput.json
                with open(fileName, 'w') as f:
                    json.dump(data, f, indent=3)
                logger.debug("Retrieved Source Org VDC affinity rules Successfully")
                return
            raise Exception("Failed to retrieve VM Affinity rules of source Org VDC")
        except Exception:
            # setting the enable source org vdc flag which is used to in roll back
            self.ENABLE_SOURCE_ORG_VDC = True
            raise

    @_isSessionExpired
    def enableOrDisableSourceAffinityRules(self, sourceOrgVdcId, enable=False):
        """
        Description :   Enable / Disable Affinity Rules in Source VApp
        Parameters  :   sourceOrgId   -   ID of the source Org VDC (STRING)
                        enable        -   Defaults to False meaning Disable the affinity rules on the source Org VDC (BOOL)
                                      -   True meaning Enable the affinity rules on the source Org VDC (BOOL)
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # sourcevdcid = data['sourceOrgVDC']['@id']
            sourcevdcid = sourceOrgVdcId.split(':')[-1]
            # checking if there exists affinity rules on source org vdc
            if data['sourceVMAffinityRules']:
                sourceAffinityRules = data['sourceVMAffinityRules'] if isinstance(data['sourceVMAffinityRules'], list) else [data['sourceVMAffinityRules']]
                # iterating over the affinity rules
                for sourceAffinityRule in sourceAffinityRules:
                    affinityID = sourceAffinityRule['@id']
                    # affinityIDList.append(affinityID)
                    # url to enable/disable the affinity rules
                    url = "{}{}".format(vcdConstants.AFFINITY_URL.format(self.ipAddress, sourcevdcid), affinityID)
                    # creating the payload data using xml tree
                    vmAffinityRule = ET.Element('VmAffinityRule',
                                                {"xmlns": 'http://www.vmware.com/vcloud/v1.5'})
                    name = ET.SubElement(vmAffinityRule, 'Name')
                    name.text = sourceAffinityRule['Name']
                    isEnabled = ET.SubElement(vmAffinityRule, 'IsEnabled')
                    if enable is False:
                        isEnabled.text = "false"
                    if enable:
                        isEnabled.text = "true" if sourceAffinityRule['IsEnabled'] == "true" else "false"
                    isMandatory = ET.SubElement(vmAffinityRule, 'IsMandatory')
                    isMandatory.text = sourceAffinityRule['IsMandatory']
                    polarity = ET.SubElement(vmAffinityRule, 'Polarity')
                    polarity.text = sourceAffinityRule['Polarity']
                    vmReferences = ET.SubElement(vmAffinityRule, 'VmReferences')
                    for eachVmReference in sourceAffinityRule['VmReferences']['VmReference']:
                        ET.SubElement(vmReferences, 'VmReference', href=eachVmReference['@href'],
                                      id=eachVmReference['@id'], name=eachVmReference['@name'],
                                      type=eachVmReference['@type'])

                    payloadData = ET.tostring(vmAffinityRule, encoding='utf-8', method='xml')
                    # put api call to enable / disable affinity rules
                    response = self.restClientObj.put(url, self.headers, data=str(payloadData, 'utf-8'))
                    responseDict = xmltodict.parse(response.content)
                    if response.status_code == requests.codes.accepted:
                        task_url = response.headers['Location']
                        # checking the status of the enabling/disabling affinity rulres task
                        self._checkTaskStatus(task_url, vcdConstants.CREATE_AFFINITY_RULE_TASK_NAME)
                        updateString = "enabled" if enable else "disabled"
                        logger.debug('Affinity Rules got {} successfully in Source'.format(updateString))
                    else:
                        updateString = "enable" if enable else "disable"
                        raise Exception('Failed to {} Affinity Rules in Source {} '.format(updateString, responseDict['Error']['@message']))
        except Exception:
            # setting the enable source org vdc flag which is used to in roll back
            self.ENABLE_SOURCE_ORG_VDC = True
            raise

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

    @_isSessionExpired
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
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
            if not responseDict['values']:
                raise Exception('Source Edge gateway doesnot exist for that org VDC.')
            data['sourceEdgeGateway'] = responseDict['values'][0]
            with open(fileName, 'w') as f:
                json.dump(data, f, indent=3)
            logger.debug("Validated Successfully, Single Edge Gateway exist in Source Org VDC")
            return responseDict['values'][0]['id']
        except Exception:
            # setting the enable source org vdc and enable affinity rules in source vapp flags which are used to in roll back
            self.ENABLE_SOURCE_ORG_VDC = True
            self.ENABLE_AFFINITY_RULES_IN_SOURCE_VAPP = True
            raise

    @_isSessionExpired
    def getOrgVDCNetworks(self, orgVDCId, orgVDCNetworkType, saveResponse=True):
        """
        Description :   Gets the details of all the Organizational VDC Networks for specific org VDC
        Parameters  :   orgVDCId            - source Org VDC Id (STRING)
                        orgVDCNetworkType   - type of Org VDC Network (STRING)
        Returns     :   Org VDC Networks object (LIST)
        """
        try:
            logger.debug("Getting Org VDC network details")
            # url to retrieve all the org vdc networks of the specified org vdc
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_ORG_VDC_NETWORKS)
            # get api call to retrieve all the org vdc networks of the specified org vdc
            response = self.restClientObj.get(url, self.headers)
            responseDict = response.json()

            orgVDCNetworkList = []
            # iterating over the org vdc networks
            for response in responseDict['values']:
                if response['orgVdc']['id'] == orgVDCId:
                    orgVDCNetworkList.append(response)
            logger.debug('Org VDC network details retrieved successfully')
            if saveResponse:
                # api output file
                fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
                with open(fileName, 'r') as f:
                    data = json.load(f)
                data[orgVDCNetworkType] = orgVDCNetworkList
                # writing the specified org vdc's networks to apiOutput.json
                with open(fileName, 'w') as f:
                    json.dump(data, f, indent=3)
            return orgVDCNetworkList
        except Exception:
            raise

    @_isSessionExpired
    def validateDHCPEnabledonIsolatedVdcNetworks(self, orgVdcNetworkList):
        """
        Description : Validate that DHCP is not enabled on isolated Org VDC Network
        Parameters  : orgVdcNetworkList - Org VDC's network list for a specific Org VDC (LIST)
        """
        try:
            # iterating over the org vdc network list
            for orgVdcNetwork in orgVdcNetworkList:
                # checking only for isolated Org VDC Network
                if orgVdcNetwork['networkType'] == 'ISOLATED':
                    url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                           vcdConstants.ALL_ORG_VDC_NETWORKS,
                                           vcdConstants.DHCP_ENABLED_FOR_ORG_VDC_NETWORK_BY_ID.format(orgVdcNetwork['id']))
                    # get api call to retrieve org vdc networks on which dhcp is enabled
                    response = self.restClientObj.get(url, self.headers)
                    responseDict = response.json()
                    # checking for enabled parameter in response
                    if responseDict['enabled']:
                        raise Exception("DHCP is enabled on source Isolated Org VDC Network - {}".format(orgVdcNetwork['name']))
            logger.debug("Validated Successfully, DHCP is not enabled on source Isolated Org VDC Network.")
        except Exception:
            # setting the enable source org vdc and enable affinity rules in source vapp flags which are used to in roll back
            self.ENABLE_SOURCE_ORG_VDC = True
            self.ENABLE_AFFINITY_RULES_IN_SOURCE_VAPP = True
            raise

    @_isSessionExpired
    def validateOrgVDCNetworkShared(self, orgVdcNetworkList):
        """
        Description :   Validates if Org VDC Networks are not Shared
        Parameters  :   orgVdcNetworkList   -   list of org vdc network list (LIST)
        """
        try:
            # iterating over the org vdc networks
            for orgVdcNetwork in orgVdcNetworkList:
                # checking only for isolated Org VDC Network
                if bool(orgVdcNetwork['shared']):
                    raise Exception("Org VDC Network {} is a shared network. No shared networks should exist.".format(orgVdcNetwork['name']))
            logger.debug("Validated Successfully, No Source Org VDC Networks are shared")
        except Exception:
            # setting the enable source org vdc and enable affinity rules in source vapp flags which are used to in roll back
            self.ENABLE_SOURCE_ORG_VDC = True
            self.ENABLE_AFFINITY_RULES_IN_SOURCE_VAPP = True
            raise

    @_isSessionExpired
    def validateOrgVDCNetworkDirect(self, orgVdcNetworkList):
        """
        Description :   Validates if Source Org VDC Networks are not direct networks
        Parameters  :   orgVdcNetworkList   -   list of org vdc network list (LIST)
        """
        try:
            for orgVdcNetwork in orgVdcNetworkList:
                if orgVdcNetwork['networkType'] == 'DIRECT':
                    raise Exception("Direct network {} exist in source Org VDC. Direct networks cant be migrated to target Org VDC".format(orgVdcNetwork['name']))
            logger.debug("Validated Successfully, No direct networks exist in Source Org VDC")
        except Exception:
            # setting the enable source org vdc and enable affinity rules in source vapp flags which are used to in roll back
            self.ENABLE_SOURCE_ORG_VDC = True
            self.ENABLE_AFFINITY_RULES_IN_SOURCE_VAPP = True
            raise

    @_isSessionExpired
    def getEdgeGatewayServices(self, edgeGatewayId):
        """
        Description :   Gets the IPSEC Configuration details on the Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            gatewayId = edgeGatewayId.split(':')[-1]
            # getting the dhcp config details of specified edge gateway
            dhcpConfigDict = self.getEdgeGatewayDhcpConfig(gatewayId)
            # getting the firewall config details of specified edge gateway
            firewallConfigDict = self.getEdgeGatewayFirewallConfig(gatewayId)
            # getting the nat config details of specified edge gateway
            natConfigDict = self.getEdgeGatewayNatConfig(gatewayId)
            # getting the ipsec config details of specified edge gateway
            ipsecConfigDict = self.getEdgeGatewayIpsecConfig(gatewayId)
            # getting the bgp config details of specified edge gateway
            bgpConfigDict = self.getEdgegatewayBGPconfig(gatewayId)
            # getting the routing config details of specified edge gateway
            routingConfigDict = self.getEdgeGatewayRoutingConfig(gatewayId)
            # getting the load balancer config details of specified edge gateway
            self.getEdgeGatewayLoadBalancerConfig(gatewayId)
            # getting the l2vpn config details of specified edge gateway
            self.getEdgeGatewayL2VPNConfig(gatewayId)
            # getting the sslvpn config details of specified edge gateway
            self.getEdgeGatewaySSLVPNConfig(gatewayId)
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
            data['sourceEdgeGatewayDHCP'] = dhcpConfigDict
            data['sourceEdgeGatewayFirewall'] = firewallConfigDict
            data['sourceEdgeGatewayNAT'] = natConfigDict
            data['sourceEdgeGatewayRouting'] = routingConfigDict
            # writing all the above config details to apiOutput.json
            with open(fileName, 'w') as f:
                json.dump(data, f, indent=3)
            logger.debug("Source Edge Gateway services configuration retrieved successfully")
            return bgpConfigDict, ipsecConfigDict
        except Exception:
            # setting the enable source org vdc and enable affinity rules in source vapp flags which are used to in roll back
            self.ENABLE_SOURCE_ORG_VDC = True
            self.ENABLE_AFFINITY_RULES_IN_SOURCE_VAPP = True
            raise

    def validateIndependentDisksDoesNotExistsInOrgVDC(self, orgVDCId):
        """
        Description :   Validates if the Independent disks does not exists in the specified Org VDC(probably source Org VDC)
                        If exists, then raising an exception
        Parameters  :   orgVDCId    -   Id of the Org VDC (STRING)
        Returns     :   True        -   If Independent disks doesnot exist in Org VDC (BOOL)
        """
        try:
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
                            raise Exception("Independent Disks Exist In Source Org VDC.")
                    logger.debug("Validated Successfully, Independent Disks do not exist in Source Org VDC")
                else:
                    # if single resource entity, checking if independent disks exist, if so raising exception
                    if responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']['@type'] == vcdConstants.INDEPENDENT_DISKS_EXIST_IN_ORG_VDC_TYPE:
                        raise Exception("Independent Disks Exist In Source Org VDC.")
                    logger.debug("Validated Successfully, Independent Disks do not exist in Source Org VDC")
            else:
                logger.debug("No resource entity is available in source Org VDC.")
        except Exception:
            # setting the enable source org vdc and enable affinity rules in source vapp flags which are used to in roll back
            self.ENABLE_SOURCE_ORG_VDC = True
            self.ENABLE_AFFINITY_RULES_IN_SOURCE_VAPP = True
            raise

    @_isSessionExpired
    def getEdgeGatewayDhcpConfig(self, edgeGatewayId):
        """
        Description :   Gets the DHCP Configuration details of the specified Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            logger.debug("Getting DHCP Services Configuration Details of Source Edge Gateway")
            # url to get dhcp config details of specified edge gateway
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_DHCP_CONFIG_BY_ID.format(edgeGatewayId))
            # relay url to get dhcp config details of specified edge gateway
            relayurl = "{}{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                         vcdConstants.NETWORK_EDGES,
                                         vcdConstants.EDGE_GATEWAY_DHCP_CONFIG_BY_ID.format(edgeGatewayId),
                                         vcdConstants.EDGE_GATEWAY_DHCP_RELAY_CONFIG_BY_ID)
            # call to get api to get dhcp config details of specified edge gateway
            response = self.restClientObj.get(url, self.headers)
            # call to get api to get dhcp relay config details of specified edge gateway
            relayresponse = self.restClientObj.get(relayurl, self.headers)
            if relayresponse.status_code == requests.codes.ok:
                relayresponsedict = xmltodict.parse(relayresponse.content)
                # checking if relay is configured in dhcp, if so raising exception
                if relayresponsedict['relay'] is not None:
                    raise Exception('Relay is configured in dhcp source edge gateway')
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                # checking if static binding is configured in dhcp, if so raising exception
                if responseDict['dhcp']['staticBindings'] is not None:
                    raise Exception("Static binding is in DHCP configuration of Source Edge Gateway.")
                logger.debug("DHCP configuration of Source Edge Gateway retrieved successfully")
                # returning the dhcp details
                return responseDict['dhcp']
            raise Exception("Failed to retrieve DHCP configuration of Source Edge Gateway.")
        except Exception:
            raise

    @_isSessionExpired
    def getEdgeGatewayFirewallConfig(self, edgeGatewayId):
        """
        Description :   Gets the Firewall Configuration details of the specified Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            logger.debug("Getting Firewall Services Configuration Details of Source Edge Gateway")
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
                    groupingobjects = []
                    for firewall in userDefinedFirewall:
                        if firewall.get('application'):
                            if firewall['application'].get('service'):
                                if isinstance(firewall['application']['service'], list):
                                    services = firewall['application']['service']
                                else:
                                    services = [firewall['application']['service']]
                                for service in services:
                                    if service['protocol'] == "tcp" or service['protocol'] == "udp":
                                        if service['port'] == "any":
                                            raise Exception('Any as a TCP/UDP port is not supported in target firewall')
                        if firewall.get('source'):
                            if firewall['source'].get('vnicGroupId'):
                                raise Exception('Vnic group is present in this firewall rule id: {}'.format(firewall['id']))
                            if firewall['source'].get('groupingObjectId'):
                                if isinstance(firewall['source']['groupingObjectId'], list):
                                    groupingobjects = firewall['source']['groupingObjectId']
                                else:
                                    groupingobjects = [firewall['source']['groupingObjectId']]
                            for groupingobject in groupingobjects:
                                if "ipset" not in groupingobject:
                                    raise Exception('The object type in this firewall rule {} is not supported.'.format(firewall['id']))
                        if firewall.get('destination'):
                            if firewall['destination'].get('vnicGroupId'):
                                raise Exception('Vnic group is present in this firewall rule id: {}'.format(firewall['id']))
                            if firewall['destination'].get('groupingObjectId'):
                                if isinstance(firewall['destination']['groupingObjectId'], list):
                                    groupingobjects = firewall['destination']['groupingObjectId']
                                else:
                                    groupingobjects = [firewall['destination']['groupingObjectId']]
                            for groupingobject in groupingobjects:
                                if "ipset" not in groupingobject:
                                    raise Exception('The object type in this firewall rule {} is not supported.'.format(firewall['id']))
                    return userDefinedFirewall
                raise Exception('Firewall is disabled in source')
            raise Exception("Failed to retrieve the Firewall Configurations of Source Edge Gateway")
        except Exception:
            raise

    @_isSessionExpired
    def getEdgeGatewayNatConfig(self, edgeGatewayId):
        """
        Description :   Gets the NAT Configuration details of the specified Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            logger.debug("Getting NAT Services Configuration Details of Source Edge Gateway")
            # url to retrieve the nat config details of the specified edge gateway
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_NAT_CONFIG_BY_ID.format(edgeGatewayId))
            # get api call to retrieve the nat config details of the specified edge gateway
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                logger.debug("NAT configuration of Source Edge Gateway retrieved successfully")
                # checking if nat64 rules are present, if not raising exception
                if responseDict['nat']['nat64Rules'] is not None:
                    raise Exception('Nat64 rule is configured in source but not supported in Target')
                # checking if nat rules are present
                if responseDict['nat']['natRules'] is not None:
                    natrules = responseDict['nat']['natRules']['natRule']
                    natrules = natrules if isinstance(natrules, list) else [natrules]
                    # iterating over the nat rules
                    for natrule in natrules:
                        if natrule['action'] == "dnat" and "-" in natrule['translatedAddress']:
                            raise Exception('Range of IPs found in this DNAT rule {} and range cannot be used in target edge gateway'.format(natrule['ruleId']))
                        return responseDict['nat']
                return
            raise Exception('Failed to retrieve the NAT Configurations of Source Edge Gateway')
        except Exception:
            raise

    @_isSessionExpired
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
                    raise Exception('SSLVPN service is configured in the Source but not supported in the Target')
        except Exception:
            raise

    @_isSessionExpired
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
                    raise Exception("L2VPN service is configured in the Source but not supported in the Target")
        except Exception:
            raise

    @_isSessionExpired
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
                    raise Exception("Load Balancer service is configured in the Source but not supported in the Target")
        except Exception:
            raise

    @_isSessionExpired
    def getEdgeGatewayRoutingConfig(self, edgeGatewayId):
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
                # checking if routing is enabled, if so raising exception
                if responseDict['routing']['ospf']['enabled'] == "true":
                    raise Exception("OSPF routing protocal is configured in the Source but not supported in the Target")
                logger.debug("Routing configuration of Source Edge Gateway retrieved Successfully")
                return responseDict['routing']
        except Exception:
            raise

    @_isSessionExpired
    def getEdgeGatewayIpsecConfig(self, edgeGatewayId):
        """
        Description :   Gets the IPSEC Configuration details on the Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
            logger.debug("Getting IPSEC Services Configuration Details of Source Edge Gateway")
            # url to retrieve the ipsec config info
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_IPSEC_CONFIG.format(edgeGatewayId))
            # get api call to retrieve the ipsec config info
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                if responseDict['ipsec']['sites'] is not None:
                    sites = responseDict['ipsec']['sites']['site']
                    sourceIPsecSite = sites if isinstance(sites, list) else [sites]
                    # iterating over source ipsec sites
                    for eachsourceIPsecSite in sourceIPsecSite:
                        # raising exception if ipsecSessionType is not equal to policybasedsession
                        if eachsourceIPsecSite['ipsecSessionType'] != "policybasedsession":
                            raise Exception('IPSEC rule is having routebased sessiom type which is not supported')
                    logger.debug("IPSEC configuration of Source Edge Gateway retrieved successfully")
                    return responseDict['ipsec']
                return
            raise Exception("Failed to retrieve the IPSEC Configurations of Source Edge Gateway ")
        except Exception:
            raise

    @_isSessionExpired
    def getEdgegatewayBGPconfig(self, edgeGatewayId):
        """
        Description :   Gets the BGP Configuration details on the Edge Gateway
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        try:
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
                    logger.debug("BGP configuration of Source Edge Gateway retrieved successfully")
                    # returning bdp config details dict
                    return responseDict['bgp']
                return
            raise Exception("Failed to retrieve the BGP Configurations of Source Edge Gateway ")
        except Exception:
            raise

    @_isSessionExpired
    def _checkTaskStatus(self, taskUrl, taskName, returnOutput=False):
        """
        Description : Checks status of a task in VDC
        Parameters  : taskUrl   - Url of the task monitored (STRING)
                      taskName  - Name of the task monitored (STRING)
        """
        if self.headers.get("Content-Type", None):
            del self.headers['Content-Type']
        timeout = 0.0
        # Get the task details
        output = ''
        try:
            while timeout < vcdConstants.VCD_CREATION_TIMEOUT:
                logger.debug("Checking status for task : {}".format(taskName))
                response = self.restClientObj.get(url=taskUrl, headers=self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = xmltodict.parse(response.content)
                    responseDict = responseDict["Task"]
                    if returnOutput:
                        output = responseDict['@operation']
                        output = output[output.find("(") + 1:output.find(")")]
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
            raise Exception('Task {} could not complete in the allocated time.'.format(taskName))
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
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # enabling the source org vdc only if it was previously enabled, else not
            if data['sourceOrgVDC']['IsEnabled'] == "true":
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

    def validateSourceSuspendedVMsInVapp(self):
        """
        Description :   Validates that there exists no VMs in suspended state in Source Org VDC
                        If found atleast single VM in suspended state then raises exception
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            if not data["sourceOrgVDC"].get('ResourceEntities'):
                return
            # retrieving the resource entities of source org vdc
            sourceOrgVDCEntityList = data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'] if isinstance(data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'], list) else [data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']]
            # retrieving the vapps of source org vdc
            sourceVappsList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            # iterating over the source vapps
            for vApp in sourceVappsList:
                vAppResponse = self.restClientObj.get(vApp['@href'], self.headers)
                responseDict = xmltodict.parse(vAppResponse.content)
                # checking if the vapp has vms present in it
                if not responseDict['VApp'].get('Children'):
                    logger.debug('Source vApp {} has no VM present in it.'.format(vApp['@name']))
                    continue
                # retrieving vms of the vapp
                vmList = responseDict['VApp']['Children']['Vm'] if isinstance(responseDict['VApp']['Children']['Vm'], list) else [responseDict['VApp']['Children']['Vm']]
                # iterating over the vms in the vapp
                for vm in vmList:
                    if vm["@status"] == "3":
                        raise Exception("VM is in suspended state, can't migrate")
            logger.debug("Validated Succesfully, No Suspended VMs in Source Vapps")
        except Exception:
            raise

    def validateNoVappNetworksExist(self):
        """
        Description :   Validates there exists no vapp's own network
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            if not data["sourceOrgVDC"].get('ResourceEntities'):
                return
            sourceOrgVDCEntityList = data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'] if isinstance(data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'], list) else [data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']]
            # retrieving the vapps
            vAppList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            # iterating over the source vapps
            for vApp in vAppList:
                vAppNetworkList = []
                # get api call to retrieve the vapp details
                response = self.restClientObj.get(vApp['@href'], self.headers)
                responseDict = xmltodict.parse(response.content)
                vAppData = responseDict['VApp']
                # checking if the networkConfig is present in vapp's NetworkConfigSection
                if vAppData['NetworkConfigSection'].get('NetworkConfig'):
                    vAppNetworkList = vAppData['NetworkConfigSection']['NetworkConfig'] if isinstance(vAppData['NetworkConfigSection']['NetworkConfig'], list) else [vAppData['NetworkConfigSection']['NetworkConfig']]
                    if vAppNetworkList:
                        # iterating over the source vapp network list
                        for vAppNetwork in vAppNetworkList:
                            if vAppNetwork['Configuration'].get('ParentNetwork'):
                                # if parent network is present, then name of parent network and name of the network itself should be same, else raising exception since it's a vapp network
                                if vAppNetwork['@networkName'] != vAppNetwork['Configuration']['ParentNetwork']['@name']:
                                    raise Exception("Vapp Network {} exist in vApp {}".format(vAppNetwork['@networkName'], vApp['@name']))
                            else:
                                # if parent network is absent then raising exception only if the  network gateway is not dhcp
                                if vAppNetwork['Configuration']['IpScopes']['IpScope']['Gateway'] != '196.254.254.254':
                                    raise Exception("Vapp Network {} exist in vApp {}".format(vAppNetwork['@networkName'],
                                                                                              vApp['@name']))
                            logger.debug("Validated successfully {} network within vApp {} is not a Vapp Network".format(vAppNetwork['@networkName'], vApp['@name']))
        except Exception:
            raise

    def validateVappVMsMediaNotConnected(self):
        """
        Description :   Validates none VM's media is connected from any of the Source vApps
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading apiOutput.json data
            with open(fileName, 'r') as f:
                data = json.load(f)
            if not data["sourceOrgVDC"].get('ResourceEntities'):
                return
            sourceOrgVDCEntityList = data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'] if isinstance(data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'], list) else [data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']]
            # creating source vapp list
            sourceVappList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            # iterating over the source vapps
            for sourceVapp in sourceVappList:
                hrefVapp = sourceVapp['@href']
                # get api call to retrieve vapp details
                response = self.restClientObj.get(hrefVapp, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = xmltodict.parse(response.content)
                    # checking if vapp has vms in it
                    if responseDict['VApp'].get('Children'):
                        vmList = responseDict['VApp']['Children']['Vm'] if isinstance(responseDict['VApp']['Children']['Vm'], list) else [responseDict['VApp']['Children']['Vm']]
                        # iterating over vms in the vapp
                        for vm in vmList:
                            mediaSettings = vm['VmSpecSection']['MediaSection']['MediaSettings']
                            # iterating over the list of media settings of vm
                            for mediaSetting in mediaSettings:
                                # checking for the ISO media type that should be disconnected, else raising exception
                                if mediaSetting['MediaType'] == "ISO":
                                    if mediaSetting['MediaState'] != "DISCONNECTED":
                                        raise Exception("Source vApp - {} VM - {} has media state connected. Can't migrate those vm's".format(sourceVapp['@name'], vm['@name']))
                            logger.debug("Validated successfully that media of source vm {} is not connected".format(vm['@name']))
                    else:
                        logger.debug("Source vApp {} has no VMs in it".format(sourceVapp['@name']))
        except Exception:
            raise

    def validateNoStandaloneVMsExistInSourceOrgVDC(self):
        """
        Description :   Validates that there are no standalone VMs in source org vdc
                        If found atleast single standalone VM in source org vdc then raises exception
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            if not data["sourceOrgVDC"].get('ResourceEntities'):
                return
            # retrieving the resource entities of source org vdc
            sourceOrgVDCEntityList = data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'] if isinstance(data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'], list) else [data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']]
            # retrieving the vapps of source org vdc
            sourceVappsList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            # iterating over the source vapps
            for vApp in sourceVappsList:
                vAppResponse = self.restClientObj.get(vApp['@href'], self.headers)
                responseDict = xmltodict.parse(vAppResponse.content)
                # if vapp's autoNature attribute is set to true states that it's a standalone vm
                if responseDict['VApp']['autoNature'] == "true":
                    raise Exception("Standalone VM {} exist in Source Org VDC. Migration of Standalone VM is not supported".format(responseDict['VApp']['@name']))
            logger.debug("Validated successfully, no Standalone VMs exist in Source Org VDC")
        except Exception:
            raise

    def validateNetworkPools(self, isSource=True):
        """
        Description :   Validates the source/target network pools are VXLAN/GENEVE backed
                        For source network pools the backing type should be VXLAN
                        For target network pools the backing type should be GENEVE
                        Raising exception if not matching with the respective backing type
        Parameters  :   isSource    -   Defaults to True meaning validate the source org vdc network pools (BOOL)
                                        if set False meaning validate the target org vdc network pools
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            if isSource:
                # retrieving the network pools of the source
                if data['sourceProviderVDC'].get('NetworkPoolReferences'):
                    networkPools = data['sourceProviderVDC']['NetworkPoolReferences']['NetworkPoolReference'] if isinstance(data['sourceProviderVDC']['NetworkPoolReferences']['NetworkPoolReference'], list) else [data['sourceProviderVDC']['NetworkPoolReferences']['NetworkPoolReference']]
                else:
                    logger.debug("No Network pools associated with Source Org VDC")
                    return
            else:
                # retrieving the network pools of the target
                if data['targetProviderVDC'].get('NetworkPoolReferences'):
                    networkPools = data['targetProviderVDC']['NetworkPoolReferences']['NetworkPoolReference'] if isinstance(data['targetProviderVDC']['NetworkPoolReferences']['NetworkPoolReference'], list) else [data['targetProviderVDC']['NetworkPoolReferences']['NetworkPoolReference']]
                else:
                    logger.debug("No Network pools associated with Target Org VDC")
                    return
            # iterating over the network pools
            for networkPool in networkPools:
                # get api call to retrieve the info of either network pool
                networkPoolResponse = self.restClientObj.get(networkPool['@href'], self.headers)
                networkPoolDict = xmltodict.parse(networkPoolResponse.content)
                if isSource:
                    # checking if the source network pools are VXLAN backed
                    if networkPoolDict['vmext:VMWNetworkPool']['@xsi:type'] == vcdConstants.VXLAN_NETWORK_POOL_TYPE:
                        logger.debug("Validated Successfully, source network pool {} is VXLAN backed".format(networkPoolDict['vmext:VMWNetworkPool']['@name']))
                    else:
                        raise Exception("Source network pool {} is not VXLAN backed".format(networkPoolDict['vmext:VMWNetworkPool']['@name']))
                else:
                    # checking if the target network pools are GENEVE backed
                    if networkPoolDict['vmext:VMWNetworkPool']['@xsi:type'] == vcdConstants.GENEVE_NETWORK_POOL_TYPE:
                        logger.debug("Validated Successfully, target network pool {} is GENEVE backed".format(networkPoolDict['vmext:VMWNetworkPool']['@name']))
                    else:
                        raise Exception("Target network pool {} is not GENEVE backed".format(networkPoolDict['vmext:VMWNetworkPool']['@name']))
        except Exception:
            raise

    def preMigrationValidation(self, vcdDict):
        """
        Description : Pre migration validation tasks
        Parameters  : vcdDict   -   dictionary of the vcd details (DICTIONARY)
        """
        try:
            self.vcdLogin()
            # getting the organization details
            logger.info('Getting the Organization - {} details.'.format(vcdDict['Organization']['OrgName']))
            orgUrl = self.getOrgUrl(vcdDict['Organization']['OrgName'])

            # getting the source organization vdc details from the above organization
            logger.info('Getting the source Organization VDC - {} details.'.format(vcdDict['SourceOrgVDC']['OrgVDCName']))
            sourceOrgVDCId = self.getOrgVDCDetails(orgUrl, vcdDict['SourceOrgVDC']['OrgVDCName'], 'sourceOrgVDC')

            # validate that there are no standalone vms in source org vdc
            logger.info('Validate Standalone VMs doesnot exist in Source Org VDC')
            self.validateNoStandaloneVMsExistInSourceOrgVDC()

            # validating the source org vdc doesnot have any suspended state vms in any of the vapps
            logger.info('Validate suspended state VMs doesnot exist in any of the Source vApps')
            self.validateSourceSuspendedVMsInVapp()

            # validating the source vapp vms are not connected to media
            logger.info('Validate Source vApp vms are not connected to media')
            self.validateVappVMsMediaNotConnected()

            # validating that No vApps have its own vApp Networks
            logger.info('Validate vApps have no vApp Networks')
            self.validateNoVappNetworksExist()

            # validate org vdc fast provisioned
            logger.info('Validating whether source Org VDC is fast provisioned')
            self.validateOrgVDCFastProvisioned()

            # getting the source External Network details
            logger.info('Getting the source External Network - {} details.'.format(vcdDict['NSXVProviderVDC']['ExternalNetwork']))
            self.getExternalNetwork(vcdDict['NSXVProviderVDC']['ExternalNetwork'])

            # getting the target External Network details
            logger.info('Getting the target External Network - {} details.'.format(vcdDict['NSXTProviderVDC']['ExternalNetwork']))
            self.getExternalNetwork(vcdDict['NSXTProviderVDC']['ExternalNetwork'])

            # getting the source dummy External Network details
            logger.info('Getting the source dummy External Network - {} details.'.format(vcdDict['NSXVProviderVDC']['DummyExternalNetwork']))
            self.getExternalNetwork(vcdDict['NSXVProviderVDC']['DummyExternalNetwork'], isDummyNetwork=True)

            # validating whether edge gateway have dedicated external network
            logger.info('Validating whether other Edge gateways are using dedicated external network')
            self.validateDedicatedExternalNetwork()

            # getting the source provider VDC details and checking if its NSX-V backed
            logger.info('Getting the source Provider VDC - {} details.'.format(vcdDict['NSXVProviderVDC']['ProviderVDCName']))
            sourceProviderVDCId, isNSXTbacked = self.getProviderVDCId(vcdDict['NSXVProviderVDC']['ProviderVDCName'])
            self.getProviderVDCDetails(sourceProviderVDCId, isNSXTbacked)

            # validating the source network pool is VXLAN backed
            logger.info("Validate Source Network Pools are VXLAN backed")
            self.validateNetworkPools()

            # validating whether source org vdc is NSX-V backed
            logger.info('Validate whether source Org VDC is NSX-V backed')
            self.validateOrgVDCNSXVbacked(sourceProviderVDCId, isNSXTbacked)

            #  getting the target provider VDC details and checking if its NSX-T backed
            logger.info('Getting the target Provider VDC - {} details.'.format(vcdDict['NSXTProviderVDC']['ProviderVDCName']))
            targetProviderVDCId, isNSXTbacked = self.getProviderVDCId(vcdDict['NSXTProviderVDC']['ProviderVDCName'])
            self.getProviderVDCDetails(targetProviderVDCId, isNSXTbacked)

            # validating the target network pool is GENEVE backed
            logger.info("Validate Target Network Pools are GENEVE backed")
            self.validateNetworkPools(isSource=False)

            # validating if the target provider vdc is enabled or not
            logger.info('Validating Target Provider VDC {} is enabled'.format(vcdDict['NSXTProviderVDC']['ProviderVDCName']))
            self.validateTargetProviderVdc()

            # disable the source Org VDC so that operations cant be performed on it
            logger.info('Disable the source Org VDC - {}'.format(vcdDict['SourceOrgVDC']['OrgVDCName']))
            self.disableOrgVDC(sourceOrgVDCId)

            # validating the source org vdc placement policies exist in target PVDC also
            logger.info('Validating whether source org vdc - {} placement policies are present in target PVDC'.format(vcdDict['SourceOrgVDC']['OrgVDCName']))
            self.validateVMPlacementPolicy(sourceOrgVDCId)

            # validating whether source and target P-VDC have same vm storage profiles
            logger.info('Validating whether source Org VDC and target Provider VDC have same storage profiles')
            self.validateStorageProfiles()

            # validating whether same subnet exist in source and target External networks
            logger.info('Validating source and target External networks have same subnets')
            self.validateExternalNetworkSubnets()

            # get the affinity rules of source Org VDC
            logger.info('Getting the VM affinity rules of source Org VDC {}'.format(vcdDict['SourceOrgVDC']['OrgVDCName']))
            self.getOrgVDCAffinityRules(sourceOrgVDCId)

            # disabling Affinity rules
            logger.info('Disabling source Org VDC affinity rules if its already enabled.')
            self.enableOrDisableSourceAffinityRules(sourceOrgVDCId, enable=False)

            # validate single Edge gateway exist in source Org VDC
            logger.info('Validate whether single Edge gateway exist in source Org VDC {}.'.format(vcdDict['SourceOrgVDC']['OrgVDCName']))
            sourceEdgeGatewayId = self.validateSingleEdgeGatewayExistForOrgVDC(sourceOrgVDCId)

            # getting the source Org VDC networks
            logger.info('Getting the Org VDC networks of source Org VDC {}'.format(vcdDict['SourceOrgVDC']['OrgVDCName']))
            orgVdcNetworkList = self.getOrgVDCNetworks(sourceOrgVDCId, 'sourceOrgVDCNetworks')

            # validate whether DHCP is enabled on source Isolated Org VDC network
            logger.info('Validate whether DHCP is enabled on source Isolated Org VDC network')
            self.validateDHCPEnabledonIsolatedVdcNetworks(orgVdcNetworkList)

            # validate whether any org vdc network is shared or not
            logger.info('Validate whether Org VDC networks are shared')
            self.validateOrgVDCNetworkShared(orgVdcNetworkList)

            # validate whether any source org vdc network is not direct network
            logger.info('Validate whether Org VDC have Direct networks.')
            self.validateOrgVDCNetworkDirect(orgVdcNetworkList)

            # get the list of services configured on source Edge Gateway
            logger.info('Getting the services configured on source Edge Gateway')
            bgpConfigDict, ipsecConfigDict = self.getEdgeGatewayServices(sourceEdgeGatewayId)

            logger.info("Validating if Independent Disks exist in Source Org VDC")
            self.validateIndependentDisksDoesNotExistsInOrgVDC(sourceOrgVDCId)

            return sourceOrgVDCId, orgVdcNetworkList, sourceEdgeGatewayId, bgpConfigDict, ipsecConfigDict
        except Exception as err:
            # rolling back
            logger.error('Error occured while performing source validation - {}'.format(err))
            if self.ENABLE_SOURCE_ORG_VDC:
                logger.info("RollBack: Enable Source Org VDC")
                self.enableSourceOrgVdc(sourceOrgVDCId)
            if self.ENABLE_AFFINITY_RULES_IN_SOURCE_VAPP:
                logger.info("RollBack: Enable Source vApp Affinity Rules")
                self.enableOrDisableSourceAffinityRules(sourceOrgVDCId, enable=True)
            raise

    def validateDedicatedExternalNetwork(self):
        """
        Description :   Validate if the External network is dedicatedly used by any other edge gateway
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            external_network_id = data['targetExternalNetwork']['id']
            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.VALIDATE_DEDICATED_EXTERNAL_NETWORK_FILTER.format(external_network_id))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                values = responseDict['values']
                # checking whether values is a list if not converting it into a list
                if isinstance(values, list):
                    values = values
                else:
                    values = [values]
            # iterating all the edge gateways
            for value in values:
                # checking whether the dedicated flag is enabled
                if value['edgeGatewayUplinks'][0]['dedicated']:
                    raise Exception('Edge Gateway {} are using dedicated external network {} and hence new edge gateway cannot be created'.format(value['name'], data['targetExternalNetwork']['name']))
            logger.debug('Validated Successfully, No other edge gateways are using dedicated external network')
        except Exception:
            raise
