# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which performs the VMware Cloud Director NSX-V to NSX-T Migration Operations
"""

import logging
import json
import os

import xml.etree.ElementTree as ET
import requests
import xmltodict

import src.core.vcd.vcdConstants as vcdConstants

from src.core.vcd.vcdValidations import VCDMigrationValidation

logger = logging.getLogger('mainLogger')


class VCloudDirectorOperations(VCDMigrationValidation):
    """
    Description: Class that performs the VMware Cloud Director NSX-V to NSX-T Migration Operations
    """
    DELETE_TARGET_ORG_VDC = False
    DELETE_TARGET_EDGE_GATEWAY = False
    DELETE_TARGET_ORG_VDC_NETWORKS = False
    CLEAR_NSX_T_BRIDGING = False

    def _isSessionExpired(func):
        """
        Description : Validates whether session expired or not,if expired then reconnects api session
        """
        def inner(self, *args, **kwargs):
            url = '{}session'.format(vcdConstants.XML_API_URL.format(self.ipAddress))
            response = self.restClientObj.get(url, headers=self.headers)
            if response.status_code != requests.codes.ok:
                logger.debug('Session expired!. Re-login to the vCloud Director')
                self.vcdLogin()
            return func(self, *args, **kwargs)
        return inner

    @_isSessionExpired
    def createOrgVDC(self):
        """
        Description :   Creates an Organization VDC
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # organization id
            orgCompleteId = data['Organization']['@id']
            orgId = orgCompleteId.split(':')[-1]
            # retrieving organization url
            orgUrl = data['Organization']['@href']
            # retrieving source org vdc and target provider vdc data
            sourceOrgVDCPayloadDict = data["sourceOrgVDC"]
            targetPVDCPayloadDict = data['targetProviderVDC']

            # Creating a XML Tree to create payload
            createVdcParams = ET.Element('CreateVdcParams',
                                         {"xmlns":'http://www.vmware.com/vcloud/v1.5',
                                          "xmlns:extension_v1.5":'http://www.vmware.com/vcloud/extension/v1.5',
                                          "name":data["sourceOrgVDC"]["@name"]+'-t'})
            allocModel = ET.SubElement(createVdcParams, 'AllocationModel')
            allocModel.text = data['sourceOrgVDC']['AllocationModel']
            compCapacity = ET.SubElement(createVdcParams, 'ComputeCapacity')
            cpu = ET.SubElement(compCapacity, 'Cpu')
            units = ET.SubElement(cpu, 'Units')
            units.text = data['sourceOrgVDC']['ComputeCapacity']['Cpu']['Units']
            allocated = ET.SubElement(cpu, 'Allocated')
            allocated.text = data['sourceOrgVDC']['ComputeCapacity']['Cpu']['Allocated']
            limit = ET.SubElement(cpu, 'Limit')
            limit.text = data['sourceOrgVDC']['ComputeCapacity']['Cpu']['Limit']
            reserved = ET.SubElement(cpu, 'Reserved')
            reserved.text = data['sourceOrgVDC']['ComputeCapacity']['Cpu']['Reserved']
            used = ET.SubElement(cpu, 'Used')
            used.text = data['sourceOrgVDC']['ComputeCapacity']['Cpu']['Used']
            memory = ET.SubElement(compCapacity, 'Memory')
            mUnits = ET.SubElement(memory, 'Units')
            mUnits.text = data['sourceOrgVDC']['ComputeCapacity']['Memory']['Units']
            mAllocated = ET.SubElement(memory, 'Allocated')
            mAllocated.text = data['sourceOrgVDC']['ComputeCapacity']['Memory']['Allocated']
            mLimit = ET.SubElement(memory, 'Limit')
            mLimit.text = data['sourceOrgVDC']['ComputeCapacity']['Memory']['Limit']
            mReserved = ET.SubElement(memory, 'Reserved')
            mReserved.text = data['sourceOrgVDC']['ComputeCapacity']['Memory']['Reserved']
            mUsed = ET.SubElement(memory, 'Used')
            mUsed.text = data['sourceOrgVDC']['ComputeCapacity']['Memory']['Used']
            nicQuota = ET.SubElement(createVdcParams, 'NicQuota')
            nicQuota.text = data['sourceOrgVDC']['NicQuota']
            networkQuota = ET.SubElement(createVdcParams, 'NetworkQuota')
            networkQuota.text = data['sourceOrgVDC']['NetworkQuota']
            vmQuota = ET.SubElement(createVdcParams, 'VmQuota')
            vmQuota.text = data['sourceOrgVDC']['VmQuota']
            isEnabled = ET.SubElement(createVdcParams, 'IsEnabled')
            isEnabled.text = "true"
            targetPVDCPayloadList = [targetPVDCPayloadDict['StorageProfiles']['ProviderVdcStorageProfile']] if isinstance(targetPVDCPayloadDict['StorageProfiles']['ProviderVdcStorageProfile'], dict) else targetPVDCPayloadDict['StorageProfiles']['ProviderVdcStorageProfile']
            sourceOrgVDCPayloadList = [sourceOrgVDCPayloadDict['VdcStorageProfiles']['VdcStorageProfile']] if isinstance(sourceOrgVDCPayloadDict['VdcStorageProfiles']['VdcStorageProfile'], dict) else sourceOrgVDCPayloadDict['VdcStorageProfiles']['VdcStorageProfile']
            # iterating over the source org vdc storage profiles
            for eachStorageProfile in sourceOrgVDCPayloadList:
                vdcStorageProfile = ET.SubElement(createVdcParams, 'VdcStorageProfile')
                orgVDCStorageProfileDetails = self.getOrgVDCStorageProfileDetails(eachStorageProfile['@id'])
                vspEnabled = ET.SubElement(vdcStorageProfile, 'Enabled')
                vspEnabled.text = "true" if orgVDCStorageProfileDetails['AdminVdcStorageProfile']['Enabled'] == "true" else "false"
                vspUnits = ET.SubElement(vdcStorageProfile, 'Units')
                vspUnits.text = 'MB'
                vspLimit = ET.SubElement(vdcStorageProfile, 'Limit')
                vspLimit.text = str(orgVDCStorageProfileDetails['AdminVdcStorageProfile']['Limit'])
                vspDefault = ET.SubElement(vdcStorageProfile, 'Default')
                vspDefault.text = "true" if orgVDCStorageProfileDetails['AdminVdcStorageProfile']['Default'] == "true" else "false"
                for eachSP in targetPVDCPayloadList:
                    if eachStorageProfile['@name'] == eachSP['@name']:
                        ET.SubElement(vdcStorageProfile, 'ProviderVdcStorageProfile',
                                      href=eachSP['@href'], name=eachSP['@name'])
                        break
            resourceGuaranteedMemory = ET.SubElement(createVdcParams, 'ResourceGuaranteedMemory')
            resourceGuaranteedMemory.text = data['sourceOrgVDC']['ResourceGuaranteedMemory']
            resourceGuaranteedCpu = ET.SubElement(createVdcParams, 'ResourceGuaranteedCpu')
            resourceGuaranteedCpu.text = data['sourceOrgVDC']['ResourceGuaranteedCpu']
            vCpuInMhz = ET.SubElement(createVdcParams, 'VCpuInMhz')
            vCpuInMhz.text = data['sourceOrgVDC']['VCpuInMhz']
            isThinProvision = ET.SubElement(createVdcParams, 'IsThinProvision')
            isThinProvision.text = data['sourceOrgVDC']['IsThinProvision']
            ET.SubElement(createVdcParams,
                          'NetworkPoolReference',
                          href=targetPVDCPayloadDict['NetworkPoolReferences']['NetworkPoolReference']['@href'],
                          id=targetPVDCPayloadDict['NetworkPoolReferences']['NetworkPoolReference']['@id'],
                          type=targetPVDCPayloadDict['NetworkPoolReferences']['NetworkPoolReference']['@type'],
                          name=targetPVDCPayloadDict['NetworkPoolReferences']['NetworkPoolReference']['@name'])

            ET.SubElement(createVdcParams,
                          'ProviderVdcReference',
                          href=targetPVDCPayloadDict['@href'],
                          id=targetPVDCPayloadDict['@id'],
                          type=targetPVDCPayloadDict['@type'],
                          name=targetPVDCPayloadDict['@name'])
            usesFastProvisioning = ET.SubElement(createVdcParams, 'UsesFastProvisioning')
            usesFastProvisioning.text = data['sourceOrgVDC']['UsesFastProvisioning']
            # retrieving org vdc compute policies
            allOrgVDCComputePolicesList = self.getOrgVDCComputePolicies()
            isSizingPolicy = False
            # getting the vm sizing policy of source org vdc
            sourceSizingPoliciesList = self.getVmSizingPoliciesOfOrgVDC(data['sourceOrgVDC']['@id'])
            if isinstance(sourceSizingPoliciesList, dict):
                sourceSizingPoliciesList = [sourceSizingPoliciesList]
            # iterating over the source org vdc vm sizing policies and check the default compute policy is sizing policy
            for eachPolicy in sourceSizingPoliciesList:
                if eachPolicy['id'] == data['sourceOrgVDC']['DefaultComputePolicy']['@id'] and eachPolicy['name'] != 'System Default':
                    # set sizing policy to true if default compute policy is sizing
                    isSizingPolicy = True
            if data['sourceOrgVDC']['DefaultComputePolicy']['@name'] != 'System Default' and not isSizingPolicy:
                # Getting the href of the compute policy if not 'System Default' as default compute policy
                orgVDCComputePolicesList = [allOrgVDCComputePolicesList] if isinstance(allOrgVDCComputePolicesList, dict) else allOrgVDCComputePolicesList
                # iterating over the org vdc compute policies
                for eachComputPolicy in orgVDCComputePolicesList:
                    if eachComputPolicy["name"] == data['sourceOrgVDC']['DefaultComputePolicy']['@name'] and \
                            eachComputPolicy["pvdcId"] == data['targetProviderVDC']['@id']:
                        href = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                vcdConstants.VDC_COMPUTE_POLICIES,
                                                eachComputPolicy["id"])
                        ET.SubElement(createVdcParams, 'DefaultComputePolicy',
                                      {"href": href, "id": eachComputPolicy["id"],
                                       "name": data['sourceOrgVDC']['DefaultComputePolicy']['@name']})
                        break
                else:  # for else (loop else)
                    raise Exception("No Target Compute Policy found with same name as Source Org VDC default Compute Policy and belonging to the target Provider VDC.")
            # if sizing policy is set, default compute policy is vm sizing polciy
            if isSizingPolicy:
                ET.SubElement(createVdcParams, 'DefaultComputePolicy',
                              {"href": data['sourceOrgVDC']['DefaultComputePolicy']['@href'],
                               "id": data['sourceOrgVDC']['DefaultComputePolicy']['@id'],
                               "name": data['sourceOrgVDC']['DefaultComputePolicy']['@name']})
            isElastic = ET.SubElement(createVdcParams, 'IsElastic')
            isElastic.text = data['sourceOrgVDC']['IsElastic']
            includeMemoryOverhead = ET.SubElement(createVdcParams, 'IncludeMemoryOverhead')
            includeMemoryOverhead.text = data['sourceOrgVDC']['IncludeMemoryOverhead']

            # ET.dump(createVdcParams)
            payloadData = ET.tostring(createVdcParams, encoding='utf-8', method='xml')

            # url to create org vdc
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.CREATE_ORG_VDC.format(orgId))
            self.headers["Content-Type"] = vcdConstants.XML_CREATE_VDC_CONTENT_TYPE
            # post api to create org vdc
            response = self.restClientObj.post(url, self.headers, data=str(payloadData, 'utf-8'))
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.created:
                taskId = responseDict["AdminVdc"]["Tasks"]["Task"]
                if isinstance(taskId, dict):
                    taskId = [taskId]
                for task in taskId:
                    if task["@operationName"] == vcdConstants.CREATE_VDC_TASK_NAME:
                        taskUrl = task["@href"]
                if taskUrl:
                    # checking the status of the task of creating the org vdc
                    self._checkTaskStatus(taskUrl, vcdConstants.CREATE_VDC_TASK_NAME)
                logger.info('Target Org VDC {} created successfully'.format(data["sourceOrgVDC"]["@name"]+'-t'))
                # returning the id of the created org vdc
                return self.getOrgVDCDetails(orgUrl, responseDict['AdminVdc']['@name'], 'targetOrgVDC')
            raise Exception('Failed to create target Org VDC. Errors {}.'.format(responseDict['Error']['@message']))
        except Exception:
            raise

    def getOrgVDCMetadata(self, orgVDCId):
        """
        Description :   Gets Metadata in the specified Organization VDC
        Parameters  :   orgVDCId    -   Id of the Organization VDC (STRING)
        """
        try:
            orgVDCId = orgVDCId.split(':')[-1]
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.META_DATA_IN_ORG_VDC_BY_ID.format(orgVDCId))
            response = self.restClientObj.get(url, self.headers)
            return response
        except Exception:
            raise

    def createMetaDataInOrgVDC(self, orgVDCId, metadataKey, metadataValue):
        """
        Description :   Creates/Updates Metadata in the specified Organization VDC
                        If the specified key doesnot already exists in Org VDC then creates new (Key, Value) pair
                        Else updates the specified existing key with the new metadatValue
        Parameters  :   orgVDCId        -   Id of the Organization VDC (STRING)
                        metadataKey     -   Metadata key (STRING)
                        metadataValue   -   Metadata value for the metadata key (STRING)
        """
        try:
            # spliting org vdc id as per the requirement of xml api
            orgVDCId = orgVDCId.split(':')[-1]
            # url to create meta data in org vdc
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.META_DATA_IN_ORG_VDC_BY_ID.format(orgVDCId))
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
            payloadDict = {'key': metadataKey, 'value': metadataValue}
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
                if task["@operationName"] == vcdConstants.CREATE_METADATA_IN_ORG_VDC_TASK_NAME:
                    taskUrl = task["@href"]
                if taskUrl:
                    # checking the status of the creating meta data in org vdc task
                    self._checkTaskStatus(taskUrl, vcdConstants.CREATE_METADATA_IN_ORG_VDC_TASK_NAME)
                logger.debug("Created Metadata {}-{} in Org VDC {} successfully".format(metadataKey, metadataValue, orgVDCId))
                return response
            raise Exception("Failed to create the Metadata in Org VDC: {}".format(responseDict['Error']['@message']))
        except Exception:
            raise

    @_isSessionExpired
    def createEdgeGateway(self, bgpConfigDict):
        """
        Description :   Creates an Edge Gateway in the specified Organization VDC
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            externalDict = data['targetExternalNetwork']
            sourceExternalDict = data['sourceExternalNetwork']
            sourceEdgeGatewayDict = data['sourceEdgeGateway']
            external_network_id = externalDict['id']
            uplinks = sourceEdgeGatewayDict['edgeGatewayUplinks']
            ipAddressRangeList = []
            externalNetworkIpRangeList = []
            self.isExternalNetworkUpdated = False
            for uplink in uplinks:
                if uplink['uplinkName'] == sourceExternalDict['name']:
                    if uplink['subnets']['values'][0]['ipRanges']:
                        for ipRange in uplink['subnets']['values'][0]['ipRanges']['values']:
                            ipPoolDict = {}
                            ipPoolDict['startAddress'] = ipRange['startAddress']
                            ipPoolDict['endAddress'] = ipRange['endAddress']
                            ipAddressRangeList.append(ipPoolDict)
            if ipAddressRangeList:
                externalDict['subnets']['values'][0]['ipRanges']['values'].extend(ipAddressRangeList)
                url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EXTERNAL_NETWORKS, external_network_id)
                # put api call to get all the external networks
                self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                payloadData = json.dumps(externalDict)
                response = self.restClientObj.put(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    # checking the status of the creating org vdc network task
                    self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_EXTERNAL_NETWORK_NAME)
                    logger.debug('Target External network {} updated successfully with sub allocated ip pools.'.format(externalDict['name']))
                    self.isExternalNetworkUpdated = True
                else:
                    errorResponse = response.json()
                    raise Exception('Failed to update External network {} with sub allocated ip pools - {}'.format(externalDict['name'], errorResponse['message']))
            # edge gateway create URL
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS)
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
            # creating payload dictionary
            payloadDict = {'edgeGatewayName': data['sourceEdgeGateway']['name'],
                           'edgeGatewayDescription': data['sourceEdgeGateway']['description'],
                           'orgVDCName': data['targetOrgVDC']['@name'],
                           'orgVDCId': data['targetOrgVDC']['@id'],
                           'orgName': data['Organization']['@name'],
                           'orgId': data['Organization']['@id'],
                           'externalNetworkId': externalDict['id'],
                           'externalNetworkName': externalDict['name'],
                           'externalNetworkGateway': externalDict['subnets']['values'][0]['gateway'],
                           'externalNetworkprefixLength': externalDict['subnets']['values'][0]['prefixLength'],
                           # 'externalNetworkStartAddress': sourceEdgeGatewayDict['edgeGatewayUplinks'][0]['subnets']['values'][0]['ipRanges']['values'][0]['startAddress'] if sourceEdgeGatewayDict['edgeGatewayUplinks'][0]['subnets']['values'][0]['ipRanges']['values'] else "",
                           # 'externalNetworkEndAddress': sourceEdgeGatewayDict['edgeGatewayUplinks'][0]['subnets']['values'][0]['ipRanges']['values'][0]['endAddress'] if sourceEdgeGatewayDict['edgeGatewayUplinks'][0]['subnets']['values'][0]['ipRanges']['values'] else "",
                           'nsxtManagerName': externalDict['networkBackings']['values'][0]['networkProvider']['name'],
                           'nsxtManagerId': externalDict['networkBackings']['values'][0]['networkProvider']['id']
                           }
            if bgpConfigDict is None or bgpConfigDict['enabled'] != "true":
                payloadDict['dedicated'] = False
            else:
                payloadDict['dedicated'] = True
            # creating payload data
            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.CREATE_ORG_VDC_EDGE_GATEWAY_TEMPLATE)
            self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
            # only sub allocated ip pools exist the add it target edg geateway payload
            if self.isExternalNetworkUpdated:
                payloadData = json.loads(payloadData)
                subIpPoolList = []
                for ipRange in ipAddressRangeList:
                    ipPoolDict = {}
                    ipPoolDict['startAddress'] = ipRange['startAddress']
                    ipPoolDict['endAddress'] = ipRange['endAddress']
                    subIpPoolList.append(ipPoolDict)
                payloadData['edgeGatewayUplinks'][0]['subnets']['values'][0]['ipRanges'] = {}
                payloadData['edgeGatewayUplinks'][0]['subnets']['values'][0]['ipRanges']['values'] = subIpPoolList
                payloadData = json.dumps(payloadData)
                logger.debug('Updating target edge gateway payload with sub allocated ip pools.')
            # post api to create edge gateway
            response = self.restClientObj.post(url, self.headers, data=payloadData)
            if response.status_code == requests.codes.accepted:
                taskUrl = response.headers['Location']
                # checking the status of creating target edge gateway task
                self._checkTaskStatus(taskUrl, vcdConstants.CREATE_EDGE_GATEWAY_TASK_NAME)
                logger.debug('Target Edge Gateway created successfully.')
                # getting the edge gateway details of the target org vdc
                responseDict = self.getOrgVDCEdgeGateway(data['targetOrgVDC']['@id'])
                data['targetEdgeGateway'] = responseDict['values'][0]
                with open(fileName, 'w') as f:
                    json.dump(data, f, indent=3)
                return responseDict['values'][0]['id']
            errorResponse = response.json()
            raise Exception('Failed to create target Org VDC Edge Gateway - {}'.format(errorResponse['message']))
        except Exception:
            # setting delete target org vdc flag if any exception occured
            self.DELETE_TARGET_ORG_VDC = True
            raise

    @_isSessionExpired
    def createOrgVDCNetwork(self):
        """
        Description : Create Org VDC Networks in the specified Organization VDC
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            sourceOrgVDCNetworks = data['sourceOrgVDCNetworks']
            targetOrgVDC = data['targetOrgVDC']
            targetEdgeGateway = data['targetEdgeGateway']
            # org vdc network create URL
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_ORG_VDC_NETWORKS)
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
            for sourceOrgVDCNetwork in sourceOrgVDCNetworks:
                # creating payload dictionary
                payloadDict = {'orgVDCNetworkName': sourceOrgVDCNetwork['name'],
                               'orgVDCNetworkDescription': sourceOrgVDCNetwork['description'],
                               'orgVDCNetworkGateway': sourceOrgVDCNetwork['subnets']['values'][0]['gateway'],
                               'orgVDCNetworkPrefixLength': sourceOrgVDCNetwork['subnets']['values'][0]['prefixLength'],
                               'orgVDCNetworkDNSSuffix': sourceOrgVDCNetwork['subnets']['values'][0]['dnsSuffix'],
                               'orgVDCNetworkDNSServer1': sourceOrgVDCNetwork['subnets']['values'][0]['dnsServer1'],
                               'orgVDCNetworkDNSServer2': sourceOrgVDCNetwork['subnets']['values'][0]['dnsServer2'],

                               'orgVDCNetworkType': sourceOrgVDCNetwork['networkType'],
                               'orgVDCName': targetOrgVDC['@name'],
                               'orgVDCId': targetOrgVDC['@id']}
                if sourceOrgVDCNetwork['networkType'] == "ISOLATED":
                    payloadDict.update({'edgeGatewayName': "", 'edgeGatewayId': "", 'edgeGatewayConnectionType': ""})
                else:
                    payloadDict.update({'edgeGatewayName': targetEdgeGateway['name'],
                                        'edgeGatewayId': targetEdgeGateway['id']})
                # creating payload data
                payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                          componentName=vcdConstants.COMPONENT_NAME,
                                                          templateName=vcdConstants.CREATE_ORG_VDC_NETWORK_TEMPLATE)
                if sourceOrgVDCNetwork['networkType'] == "ISOLATED":
                    payloadData = json.loads(payloadData)
                    payloadData['connection'] = {}
                    payloadData = json.dumps(payloadData)
                if not sourceOrgVDCNetwork['subnets']['values'][0]['ipRanges']['values']:
                    payloadData = json.loads(payloadData)
                    payloadData['subnets']['values'][0]['ipRanges']['values'] = None
                    payloadData = json.dumps(payloadData)
                else:
                    ipRangeList = []
                    for ipRange in sourceOrgVDCNetwork['subnets']['values'][0]['ipRanges']['values']:
                        ipPoolDict = {}
                        ipPoolDict['startAddress'] = ipRange['startAddress']
                        ipPoolDict['endAddress'] = ipRange['endAddress']
                        ipRangeList.append(ipPoolDict)
                    payloadData = json.loads(payloadData)
                    payloadData['subnets']['values'][0]['ipRanges']['values'] = ipRangeList
                    payloadData = json.dumps(payloadData)
                self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                # post api to create org vdc network
                response = self.restClientObj.post(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    # checking the status of the creating org vdc network task
                    self._checkTaskStatus(taskUrl, vcdConstants.CREATE_ORG_VDC_NETWORK_TASK_NAME)
                    logger.debug('Target Org VDC Network {} created successfully.'.format(sourceOrgVDCNetwork['name']))
                    # saving the org vdc network details to apiOutput.json
                    self.getOrgVDCNetworks(targetOrgVDC['@id'], 'targetOrgVDCNetworks', saveResponse=True)
                else:
                    errorResponse = response.json()
                    raise Exception('Failed to create target Org VDC Network {} - {}'.format(sourceOrgVDCNetwork['name'],
                                                                                             errorResponse['message']))
        except:
            # setting delete target org vdc & delete target edge gateway flag
            self.DELETE_TARGET_ORG_VDC = True
            self.DELETE_TARGET_EDGE_GATEWAY = True
            raise

    @_isSessionExpired
    def deleteOrgVDC(self, orgVDCId):
        """
        Description :   Deletes the specified Organization VDC
        Parameters  :   orgVDCId  -   Id of the Organization VDC that is to be deleted (STRING)
        """
        try:
            # splitting the org vdc id as per the requirement of the xml api
            orgVDCId = orgVDCId.split(':')[-1]
            # url to delete the org vdc
            url = "{}{}?force=true&recursive=true".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                                          vcdConstants.ORG_VDC_BY_ID.format(orgVDCId))
            # delete api to delete the org vdc
            response = self.restClientObj.delete(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.accepted:
                task = responseDict["Task"]
                if task["@operationName"] == vcdConstants.DELETE_ORG_VDC_TASK_NAME:
                    taskUrl = task["@href"]
                if taskUrl:
                    # checking the status of deleting org vdc task
                    self._checkTaskStatus(taskUrl, vcdConstants.DELETE_ORG_VDC_TASK_NAME)
                    logger.debug('Organization VDC deleted successfully.')
                    return
            else:
                raise Exception('Failed to delete source Org VDC {}'.format(responseDict['Error']['@message']))
        except Exception:
            raise

    @_isSessionExpired
    def deleteOrgVDCNetworks(self, orgVDCId, source=True):
        """
        Description :   Deletes all Organization VDC Networks from the specified OrgVDC
        Parameters  :   orgVDCId  -   Id of the Organization VDC (STRING)
                        source    -   Defaults to True meaning delete the NSX-V backed Org VDC Networks (BOOL)
                                      If set to False meaning delete the NSX-t backed Org VDC Networks (BOOL)
        """
        try:
            orgVDCNetworksErrorList = []
            orgVDCNetworksList = self.getOrgVDCNetworks(orgVDCId, 'sourceOrgVDCNetworks', saveResponse=False)
            # iterating over the org vdc network list
            for orgVDCNetwork in orgVDCNetworksList:
                # url to delete the org vdc network
                url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                    vcdConstants.DELETE_ORG_VDC_NETWORK_BY_ID.format(orgVDCNetwork['id']))
                response = self.restClientObj.delete(url, self.headers)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    if source:
                        # state check for NSX-V backed Org VDC
                        if orgVDCNetwork['networkType'] == 'ISOLATED':
                            # checking the status of deleting isolated network task
                            self._checkTaskStatus(taskUrl, vcdConstants.DELETE_ORG_VDC_ISOLATED_NETWORK_TASK_NAME)
                        else:
                            # checking the status of deleting routed network task
                            self._checkTaskStatus(taskUrl, vcdConstants.DELETE_ORG_VDC_ROUTED_NETWORK_TASK_NAME)
                        logger.debug('Organization VDC Network deleted successfully.')
                    else:
                        # state check for NSX-t backed Org VDC
                        self._checkTaskStatus(taskUrl, vcdConstants.DELETE_ORG_VDC_ROUTED_NETWORK_TASK_NAME)
                else:
                    logger.debug('Failed to delete Organization VDC Network {}.{}'.format(orgVDCNetwork['name'],
                                                                                          response.json()['message']))
                    orgVDCNetworksErrorList.append(orgVDCNetwork['name'])
            if orgVDCNetworksErrorList:
                raise Exception('Failed to delete Org VDC networks {} - as it is in use'.format(orgVDCNetworksErrorList))
        except Exception:
            raise

    @_isSessionExpired
    def deleteNsxVBackedOrgVDCEdgeGateways(self, orgVDCId):
        """
        Description :   Deletes all the Edge Gateways in the specified NSX-V Backed OrgVDC
        Parameters  :   orgVDCId  -   Id of the Organization VDC (STRING)
        """
        try:
            # retrieving the details of the org vdc edge gateway
            responseDict = self.getOrgVDCEdgeGateway(orgVDCId)
            if responseDict['values']:
                orgVDCEdgeGateway = responseDict['values'][0]
                orgVDCEdgeGatewayId = orgVDCEdgeGateway['id'].split(':')[-1]
                # url to fetch edge gateway details
                getUrl = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                       vcdConstants.UPDATE_EDGE_GATEWAY_BY_ID.format(orgVDCEdgeGatewayId))
                getResponse = self.restClientObj.get(getUrl, headers=self.headers)
                if getResponse.status_code == requests.codes.ok:
                    responseDict = xmltodict.parse(getResponse.content)
                    edgeGatewayDict = responseDict['EdgeGateway']
                    # checking if distributed routing is enabled on edge gateway, if so disabling it
                    if edgeGatewayDict['Configuration']['DistributedRoutingEnabled'] == 'true':
                        self.disableDistributedRoutingOnOrgVdcEdgeGateway(orgVDCEdgeGateway['id'])
                # url to delete the edge gateway
                deleteUrl = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                          vcdConstants.UPDATE_EDGE_GATEWAY_BY_ID.format(orgVDCEdgeGatewayId))
                # delete api to delete edge gateway
                delResponse = self.restClientObj.delete(deleteUrl, self.headers)
                if delResponse.status_code == requests.codes.accepted:
                    taskUrl = delResponse.headers['Location']
                    # checking the status of deleting nsx-v backed edge gateway task
                    self._checkTaskStatus(taskUrl, vcdConstants.DELETE_NSX_V_BACKED_ORG_VDC_EDGE_GATEWAY_TASK_NAME)
                    logger.debug('Source Org VDC Edge Gateway deleted successfully.')
                else:
                    delResponseDict = xmltodict.parse(delResponse.content)
                    raise Exception('Failed to delete Edge gateway {}:{}'.format(orgVDCEdgeGateway['name'],
                                                                                 delResponseDict['Error']['@message']))
            else:
                logger.warning('Edge Gateway doesnot exist')
        except Exception:
            raise

    @_isSessionExpired
    def deleteNsxTBackedOrgVDCEdgeGateways(self, orgVDCId):
        """
        Description :   Deletes all the Edge Gateways in the specified NSX-t Backed OrgVDC
        Parameters  :   orgVDCId  -   Id of the Organization VDC (STRING)
        """
        try:
            # retrieving the details of the org vdc edge gateway
            responseDict = self.getOrgVDCEdgeGateway(orgVDCId)
            if responseDict['values']:
                orgVDCEdgeGateway = responseDict['values'][0]
                # url to fetch edge gateway details
                url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                    vcdConstants.UPDATE_EDGE_GATEWAYS_BY_ID.format(orgVDCEdgeGateway['id']))
                # delete api to delete the nsx-t backed edge gateway
                response = self.restClientObj.delete(url, self.headers)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    # checking the status of deleting the nsx-t backed edge gateway
                    self._checkTaskStatus(taskUrl, vcdConstants.DELETE_NSX_T_BACKED_ORG_VDC_EDGE_GATEWAY_TASK_NAME)
                    logger.debug('Target Org VDC Edge Gateway deleted successfully.')
                else:
                    raise Exception('Failed to delete Edge gateway {}:{}'.format(orgVDCEdgeGateway['name'],
                                                                                 response.json()['message']))
            else:
                logger.warning('Edge Gateway doesnot exist')
        except Exception:
            raise

    @_isSessionExpired
    def disconnectSourceOrgVDCNetwork(self, orgVDCNetworkList):
        """
        Description : Disconnect source Org VDC network from edge gateway
        Parameters  : orgVdcNetworkList - Org VDC's network list for a specific Org VDC (LIST)
        """
        try:
            logger.debug("Disconnecting Source Org VDC Network from Edge Gateway")
            orgVDCNetworksErrorList = []
            # iterating over the org vdc network list
            for orgVdcNetwork in orgVDCNetworkList:
                # checking only for nat routed Org VDC Network
                if orgVdcNetwork['networkType'] == "NAT_ROUTED":
                    # url to disconnect org vdc networks
                    url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                           vcdConstants.ALL_ORG_VDC_NETWORKS, orgVdcNetwork['id'])
                    response = self.restClientObj.get(url, self.headers)
                    responseDict = response.json()
                    # creating payload data as per the requirements
                    responseDict['connection'] = None
                    responseDict['networkType'] = 'ISOLATED'
                    del responseDict['status']
                    del responseDict['lastTaskFailureMessage']
                    # del(responseDict['guestVlanTaggingAllowed'])
                    del responseDict['retainNicResources']
                    del responseDict['crossVdcNetworkId']
                    del responseDict['crossVdcNetworkLocationId']
                    del responseDict['totalIpCount']
                    del responseDict['usedIpCount']
                    payloadDict = json.dumps(responseDict)
                    self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                    # put api to disconnect the org vdc networks
                    apiResponse = self.restClientObj.put(url, self.headers, data=payloadDict)
                    if apiResponse.status_code == requests.codes.accepted:
                        taskUrl = apiResponse.headers['Location']
                        # checking the status of the disconnecting org vdc network task
                        self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_ORG_VDC_NETWORK_TASK_NAME)
                        logger.debug('Org VDC Network {} disconnected successfully.'.format(orgVdcNetwork['name']))
                    else:
                        logger.debug('Failed to disconnect Org VDC Network {}.'.format(orgVdcNetwork['name']))
                        orgVDCNetworksErrorList.append(orgVdcNetwork['name'])
                if orgVDCNetworksErrorList:
                    raise Exception('Failed to disconnect Org VDC Networks {}'.format(orgVDCNetworksErrorList))
        except Exception:
            raise

    @_isSessionExpired
    def reconnectOrDisconnectSourceEdgeGateway(self, sourceEdgeGatewayId, connect=True):
        """
        Description :  Disconnect source Edge Gateways from the specified OrgVDC
        Parameters  :   sourceEdgeGatewayId -   Id of the Organization VDC Edge gateway (STRING)
                        connect             -   Defaults to True meaning reconnects the source edge gateway (BOOL)
                                            -   if set False meaning disconnects the source edge gateway (BOOL)
        """
        try:
            orgVDCEdgeGatewayId = sourceEdgeGatewayId.split(':')[-1]
            # url to disconnect/reconnect the source edge gateway
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.UPDATE_EDGE_GATEWAY_BY_ID.format(orgVDCEdgeGatewayId))
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
            # retrieving the details of the edge gateway
            response = self.restClientObj.get(url, headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                if not responseDict['configuration']['gatewayInterfaces']['gatewayInterface'][0]['connected']:
                    logger.warning('Source Edge Gateway external network uplink - {} is already in disconnected state.'.format(responseDict['name']))
                    return
                # establishing/disconnecting the edge gateway as per the connect flag
                if not connect:
                    responseDict['configuration']['gatewayInterfaces']['gatewayInterface'][0]['connected'] = False
                else:
                    responseDict['configuration']['gatewayInterfaces']['gatewayInterface'][0]['connected'] = True
                    responseDict['configuration']['gatewayInterfaces']['gatewayInterface'].pop()
                payloadData = json.dumps(responseDict)
                acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
                self.headers["Content-Type"] = vcdConstants.XML_UPDATE_EDGE_GATEWAY
                headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader,
                           'Content-Type': vcdConstants.JSON_UPDATE_EDGE_GATEWAY}
                # updating the details of the edge gateway
                response = self.restClientObj.put(url, headers, data=payloadData)
                responseData = response.json()
                if response.status_code == requests.codes.accepted:
                    if responseData["operationName"] == vcdConstants.UPDATE_EDGE_GATEWAY_TASK_NAME:
                        taskUrl = responseData["href"]
                    if taskUrl:
                        # checking the status of connecting/disconnecting the edge gateway
                        self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_EDGE_GATEWAY_TASK_NAME)
                        logger.debug('Source Edge Gateway updated successfully.')
                        return
                else:
                    raise Exception('Failed to update source Edge Gateway {}'.format(responseData['message']))
        except:
            raise

    @_isSessionExpired
    def reconnectTargetEdgeGateway(self):
        """
        Description : Reconnect Target Edge Gateway to T0 router
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            targetEdgeGateway = data['targetEdgeGateway']
            payloadDict = targetEdgeGateway
            del payloadDict['status']
            payloadDict['edgeGatewayUplinks'][0]['connected'] = True
            # edge gateway update URL
            url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS, targetEdgeGateway['id'])
            # creating the payload data
            payloadData = json.dumps(payloadDict)
            self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
            # put api to reconnect the target edge gateway
            response = self.restClientObj.put(url, self.headers, data=payloadData)
            if response.status_code == requests.codes.accepted:
                taskUrl = response.headers['Location']
                # checking the status of the reconnecting target edge gateway task
                self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_EDGE_GATEWAY_OPENAPI_TASK_NAME)
                logger.debug('Target Org VDC Edge Gateway {} reconnected successfully.'.format(targetEdgeGateway['name']))
                return
            raise Exception('Failed to reconnect target Org VDC Edge Gateway {} {}'.format(targetEdgeGateway['name'],
                                                                                           response.json()['message']))
        except:
            raise

    @_isSessionExpired
    def getPortgroupInfo(self, orgVdcNetworkList):
        """
        Description : Get Portgroup Info
        Parameters  : orgVdcNetworkList - List of source org vdc networks (LIST)
        """
        try:
            # url to get the port group details
            url = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                vcdConstants.GET_PORTGROUP_INFO)
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
            # retrieving the details of the port group
            response = self.restClientObj.get(url, headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                resultTotal = responseDict['total']
            pageNo = 1
            pageSizeCount = 0
            resultList = []
            logger.debug('Getting portgroup details')
            while resultTotal > 0 and pageSizeCount < resultTotal:
                url = "{}{}&page={}&pageSize={}&format=records".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                                                       vcdConstants.GET_PORTGROUP_INFO, pageNo,
                                                                       vcdConstants.PORT_GROUP_PAGE_SIZE)
                response = self.restClientObj.get(url, headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    resultList.extend(responseDict['record'])
                    pageSizeCount += len(responseDict['record'])
                    logger.debug('Portgroup details result pageSize = {}'.format(pageSizeCount))
                    pageNo += 1
            logger.debug('Total Portgroup details result count = {}'.format(len(resultList)))
            logger.debug('Portgroup details successfully retrieved')
            networkList = [response for response in resultList if
                           response['networkName'] != '--']
            updatedNetworkList = [response for response in networkList if response['scopeType'] not in ['-1', '1']]
            portGroupList = [elem for elem in updatedNetworkList if
                             elem['networkName'] in list(value['name'] for value in orgVdcNetworkList)]
            return portGroupList
        except:
            # setting the delete target org vdc, delete target edge gateway, delete target org vdc network flags required for roll back
            self.DELETE_TARGET_ORG_VDC = True
            self.DELETE_TARGET_EDGE_GATEWAY = True
            self.DELETE_TARGET_ORG_VDC_NETWORKS = True
            raise

    @_isSessionExpired
    def composevApp(self):
        """
        Description :   Compose placeholder vApp
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # getting list instance of resources in the source org vdc
            sourceOrgVDCEntityList = data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'] if isinstance(data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'], list) else [data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']]
            # retrieving target org vdc data
            targetOrgVDCId = data["targetOrgVDC"]["@id"].split(':')[-1]
            targetOrgVDCNetworkList = data['targetOrgVDCNetworks'] if data.get('targetOrgVDCNetworks') else []
            # rettrieving list of source vapps
            vAppList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
            # iterating over the source vapps
            for vApp in vAppList:
                networkList = []
                # retrieving the startup info of the source vapps
                self.getVappStartupSectionInfo(vApp['@href'], saveResponse=True)
                response = self.restClientObj.get(vApp['@href'], self.headers)
                responseDict = xmltodict.parse(response.content)
                vAppData = responseDict['VApp']
                # cehcking for the 'NetworkConfig' in 'NetworkConfigSection' of vapp
                if vAppData['NetworkConfigSection'].get('NetworkConfig'):
                    vAppNetworkList = vAppData['NetworkConfigSection']['NetworkConfig'] if isinstance(vAppData['NetworkConfigSection']['NetworkConfig'], list) else [vAppData['NetworkConfigSection']['NetworkConfig']]
                    # retrieving the network details list of same name networks from source & target
                    networkList = [(network, vAppNetwork)  for network in targetOrgVDCNetworkList for vAppNetwork in vAppNetworkList if vAppNetwork['@networkName'] == network['name']]
                # if networks present
                if networkList:
                    xmlPayloadData = ''
                    # iterating over the network list
                    for network, vAppNetwork in networkList:
                        # creating payload dictionary with network details
                        networkName = "{}network/{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                                            network["id"].split(':')[-1])
                        payloadDict = {'networkName': network['name'],
                                       'parentNetwork': networkName, 'fenceMode': vAppNetwork['Configuration']['FenceMode']}
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.COMPOSE_VAPP_NETWORK_CONFIG_TEMPLATE)
                        xmlPayloadData += payloadData.strip("\"")
                    payloadDict = {'vAppName': vApp['@name'] + '-t', 'networkConfig': xmlPayloadData}
                    # creating payload data
                    payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.COMPOSE_VAPP_TEMPLATE)
                else:
                    # creating payload dictioney without network details, since no networks present
                    payloadDict = {'vAppName': vApp['@name'] + '-t'}
                    # creating payload data
                    payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.COMPOSE_VAPP_NONETWORK_TEMPLATE)
                payloadData = json.loads(payloadData)
                # url to compose vapp in target org vdc
                url = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                    vcdConstants.COMPOSE_VAPP_IN_ORG_VDC.format(targetOrgVDCId))
                self.headers["Content-Type"] = vcdConstants.XML_COMPOSE_VAPP
                # post api call to compose vapps in target org vdc
                response = self.restClientObj.post(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.created:
                    responseDict = xmltodict.parse(response.content)
                    taskId = responseDict["VApp"]["Tasks"]["Task"]
                    if isinstance(taskId, dict):
                        taskId = [taskId]
                    for task in taskId:
                        if task["@operationName"] == vcdConstants.COMPOSE_VAPP_TASK_NAME:
                            taskUrl = task["@href"]
                    if taskUrl:
                        # checking for the status of the composing vapp task
                        self._checkTaskStatus(taskUrl, vcdConstants.COMPOSE_VAPP_TASK_NAME)
                else:
                    responseDict = xmltodict.parse(response.content)
                    raise Exception('Failed to create target vApp {} - {}'.format(vApp['@name'],
                                                                                  responseDict['Error']['@message']))
            return vAppList
        except:
            raise

    @_isSessionExpired
    def recomposeTargetvApp(self):
        """
        Description : Recompose target vApp
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # retrieving the list instance of resource entities in source org vdc
            sourceOrgVDCEntityList = data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'] if isinstance(data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'], list) else [data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']]
            # retrieving the target org vdc details from apiOutput.json
            targetOrgVDCDict = data["targetOrgVDC"]
            sourceVappList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if
                              vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            # get api call to retrieve the details of the target org vdc
            response = self.restClientObj.get(targetOrgVDCDict['@href'], self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                if not responseDict['AdminVdc']['ResourceEntities']:
                    raise Exception("Failed to get target vApp details.")
                # retrieving target org vdc resource entity list
                targetOrgVDCEntityList = responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'] if isinstance(responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'], list) else [responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']]
                # retrieving target vapp list
                targetVappList = [vAppEntity for vAppEntity in targetOrgVDCEntityList if vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            # retrieving over the source vapps
            for vApp in sourceVappList:
                vmInVappList = []
                # get api call to retrieve the info of source vapp
                response = self.restClientObj.get(vApp['@href'], self.headers)
                responseDict = xmltodict.parse(response.content)
                # checking for the 'Children' key in vapp to find if vapp has any vms present in it
                if not responseDict['VApp'].get('Children'):
                    logger.warning('Source vApp {} has no VM present in it.'.format(vApp['@name']))
                    # going to the next vapp if no vms found in this vapp
                    continue
                # retrieving the list of vms in this vapp
                vmList = responseDict['VApp']['Children']['Vm']
                if isinstance(vmList, list):
                    # iterating over the vms in vapp more than one vms
                    for vm in vmList:
                        # retrieving the compute policy of vm
                        computePolicyName = vm['ComputePolicy']['VmPlacementPolicy']['@name'] if vm['ComputePolicy'].get('VmPlacementPolicy') else None
                        # retrieving the sizing policy of vm
                        if vm['ComputePolicy'].get('VmSizingPolicy'):
                            if vm['ComputePolicy']['VmSizingPolicy']['@name'] != 'System Default':
                                sizingPolicyHref = vm['ComputePolicy']['VmSizingPolicy']['@href']
                            else:
                                # get the target System Default policy id
                                defaultSizingPolicy = self.getVmSizingPoliciesOfOrgVDC(targetOrgVDCDict['@id'], isTarget=True)
                                if defaultSizingPolicy:
                                    defaultSizingPolicyId = defaultSizingPolicy[0]['id']
                                    sizingPolicyHref = "{}{}/{}".format(
                                        vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                        vcdConstants.VDC_COMPUTE_POLICIES, defaultSizingPolicyId)
                                else:
                                    sizingPolicyHref = None
                        else:
                            sizingPolicyHref = None
                        # gathering the vm's data required to create payload data and appending the dict to the 'vmInVappList' list
                        vmInVappList.append({'name': vm['@name'], 'network': vm['NetworkConnectionSection']['NetworkConnection']['@network'],
                                             'href': vm['@href'], 'networkConnectionSection': vm['NetworkConnectionSection'],
                                             'storageProfileHref': vm['StorageProfile']['@href'], 'state': responseDict['VApp']['@status'],
                                             'computePolicyName': computePolicyName, 'sizingPolicyHref': sizingPolicyHref})
                else:
                    # if single vm in the vapp
                    vm = vmList
                    # retrieving the compute policy of vm
                    computePolicyName = vm['ComputePolicy']['VmPlacementPolicy']['@name'] if vm['ComputePolicy'].get('VmPlacementPolicy') else None
                    # retrieving the sizing policy of vm
                    if vm['ComputePolicy'].get('VmSizingPolicy'):
                        if vm['ComputePolicy']['VmSizingPolicy']['@name'] != 'System Default':
                            sizingPolicyHref = vm['ComputePolicy']['VmSizingPolicy']['@href']
                        else:
                            # get the target System Default policy id
                            defaultSizingPolicy = self.getVmSizingPoliciesOfOrgVDC(targetOrgVDCDict['@id'], isTarget=True)
                            if defaultSizingPolicy:
                                defaultSizingPolicyId = defaultSizingPolicy[0]['id']
                                sizingPolicyHref = "{}{}/{}".format(
                                    vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                    vcdConstants.VDC_COMPUTE_POLICIES, defaultSizingPolicyId)
                            else:
                                sizingPolicyHref = None
                    else:
                        sizingPolicyHref = None
                    # gathering the vm's data required to create payload data and appending the dict to the 'vmInVappList' list
                    vmInVappList.append({'name': vm['@name'], 'network': vm['NetworkConnectionSection']['NetworkConnection']['@network'],
                                         'href': vm['@href'], 'networkConnectionSection': vm['NetworkConnectionSection'],
                                         'storageProfileHref': vm['StorageProfile']['@href'], 'state': responseDict['VApp']['@status'],
                                         'computePolicyName': computePolicyName, 'sizingPolicyHref': sizingPolicyHref})
                # saving the 'vmInVappList' into vApp['vm'] which contain list of vms
                vApp['vm'] = vmInVappList
                # iterating over the target vapp list
                for item1 in targetVappList:
                    # checking for the same name vapps in source and target vapps
                    # eg: if source vapp name is 'testvapp' then target vapp name will be 'testvapp-t'
                    if vApp['@name']+'-t' == item1['@name']:
                        vApp['targetVapp'] = item1
                # for item in sourceVappList:
                #     for item1 in targetVappList:
                #         if item['@name']+'-t' == item1['@name']:
                #             item['targetVapp'] = item1
                #
                # for vApp in sourceVappList:
                filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
                # iterating over the above saved vms list of source vapp
                for vm in vApp['vm']:
                    logger.info('Recomposing VM - {} into target vApp - {}'.format(vm['name'], vApp['targetVapp']['@name']))
                    # url to recompose the vapp
                    url = "{}/{}".format(vApp['targetVapp']['@href'],
                                         vcdConstants.RECOMPOSE_VAPP_API)
                    # checking for the 'IpAddress' attribute if present
                    if vm['networkConnectionSection']['NetworkConnection'].get('IpAddress'):
                        ipAddress = vm['networkConnectionSection']['NetworkConnection']['IpAddress']
                    else:
                        ipAddress = ""
                    # check whether the vapp state is powered on i.e 4 then poweron else poweroff
                    if vm['state'] != "4":
                        state = "false"
                    else:
                        state = "true"
                    # handling the case:- if both compute policy & sizing policy are absent
                    if not vm["computePolicyName"] and not vm['sizingPolicyHref']:
                        payloadDict = {'vmHref': vm['href'], 'networkName': vm['network'],
                                       'ipAddress': ipAddress, 'state': state,
                                       'connected': vm['networkConnectionSection']['NetworkConnection']['IsConnected'],
                                       'macAddress': vm['networkConnectionSection']['NetworkConnection']['MACAddress'],
                                       'allocationModel': vm['networkConnectionSection']['NetworkConnection']['IpAddressAllocationMode'],
                                       'adapterType': vm['networkConnectionSection']['NetworkConnection']['NetworkAdapterType'],
                                       'storageProfileHref': vm['storageProfileHref']}
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.RECOMPOSE_VAPP_TEMPLATE)
                    # handling the case:- if either policy is present
                    else:
                        # handling the case:- if compute policy is present and sizing policy is absent
                        if vm["computePolicyName"] and not vm['sizingPolicyHref']:
                            # retrieving the org vdc compute policy
                            allOrgVDCComputePolicesList = self.getOrgVDCComputePolicies()
                            # getting the list instance of compute policies of org vdc
                            orgVDCComputePolicesList = [allOrgVDCComputePolicesList] if isinstance(allOrgVDCComputePolicesList, dict) else allOrgVDCComputePolicesList
                            # iterating over the org vdc compute policies
                            for eachComputPolicy in orgVDCComputePolicesList:
                                # checking if the org vdc compute policy name is same as the source vm's applied compute policy & org vdc compute policy id is same as that of target provider vdc's id
                                if eachComputPolicy["name"] == vm["computePolicyName"] and \
                                        eachComputPolicy["pvdcId"] == data['targetProviderVDC']['@id']:
                                    # creating the href of compute policy that should be passed in the payload data for recomposing the vapp
                                    href = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                            vcdConstants.VDC_COMPUTE_POLICIES,
                                                            eachComputPolicy["id"])
                            # if vm's compute policy does not match with org vdc compute policy or org vdc compute policy's id does not match with target provider vdc's id then href will be set none
                            # resulting into raising the exception that source vm's applied placement policy is absent in target org vdc
                            if not href:
                                raise Exception('Could not find placement policy {} in target Org VDC.'.format(vm["computePolicyName"]))
                            # creating the payload dictionary
                            payloadDict = {'vmHref': vm['href'], 'networkName': vm['network'],
                                           'ipAddress': ipAddress, 'state': state,
                                           'connected': vm['networkConnectionSection']['NetworkConnection']['IsConnected'],
                                           'macAddress': vm['networkConnectionSection']['NetworkConnection']['MACAddress'],
                                           'allocationModel': vm['networkConnectionSection']['NetworkConnection']['IpAddressAllocationMode'],
                                           'adapterType': vm['networkConnectionSection']['NetworkConnection']['NetworkAdapterType'],
                                           'storageProfileHref': vm['storageProfileHref'],
                                           'vmPlacementPolicyHref': href}
                            # creating the payload data
                            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                                      templateName=vcdConstants.RECOMPOSE_PLACEMENT_POLICY_VAPP_TEMPLATE)
                        # handling the case:- if sizing policy is present and compute policy is absent
                        elif vm['sizingPolicyHref'] and not vm["computePolicyName"]:
                            # creating the payload dictionary
                            payloadDict = {'vmHref': vm['href'], 'networkName': vm['network'],
                                           'ipAddress': ipAddress, 'state': state,
                                           'connected': vm['networkConnectionSection']['NetworkConnection']['IsConnected'],
                                           'macAddress': vm['networkConnectionSection']['NetworkConnection']['MACAddress'],
                                           'allocationModel': vm['networkConnectionSection']['NetworkConnection']['IpAddressAllocationMode'],
                                           'adapterType': vm['networkConnectionSection']['NetworkConnection']['NetworkAdapterType'],
                                           'storageProfileHref': vm['storageProfileHref'],
                                           'sizingPolicyHref': vm['sizingPolicyHref']}
                            # creating the pauload data
                            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                                      templateName=vcdConstants.RECOMPOSE_SIZING_POLICY_VAPP_TEMPLATE)
                        # handling the case:- if both policies are present
                        elif vm['sizingPolicyHref'] and vm["computePolicyName"]:
                            # retrieving the org vdc compute policy
                            allOrgVDCComputePolicesList = self.getOrgVDCComputePolicies()
                            # getting the list instance of compute policies of org vdc
                            orgVDCComputePolicesList = [allOrgVDCComputePolicesList] if isinstance(allOrgVDCComputePolicesList, dict) else allOrgVDCComputePolicesList
                            # iterating over the org vdc compute policies
                            for eachComputPolicy in orgVDCComputePolicesList:
                                # checking if the org vdc compute policy name is same as the source vm's applied compute policy & org vdc compute policy id is same as that of target provider vdc's id
                                if eachComputPolicy["name"] == vm["computePolicyName"] and \
                                        eachComputPolicy["pvdcId"] == data['targetProviderVDC']['@id']:
                                    # creating the href of compute policy that should be passed in the payload data for recomposing the vapp
                                    href = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                            vcdConstants.VDC_COMPUTE_POLICIES,
                                                            eachComputPolicy["id"])
                            # if vm's compute policy does not match with org vdc compute policy or org vdc compute policy's id does not match with target provider vdc's id then href will be set none
                            # resulting into raising the exception that source vm's applied placement policy is absent in target org vdc
                            if not href:
                                raise Exception('Could not find placement policy {} in target Org VDC.'.format(vm["computePolicyName"]))
                            # creating the payload dictionary
                            payloadDict = {'vmHref': vm['href'], 'networkName': vm['network'],
                                           'ipAddress': ipAddress, 'state': state,
                                           'connected': vm['networkConnectionSection']['NetworkConnection']['IsConnected'],
                                           'macAddress': vm['networkConnectionSection']['NetworkConnection']['MACAddress'],
                                           'allocationModel': vm['networkConnectionSection']['NetworkConnection'][
                                               'IpAddressAllocationMode'],
                                           'adapterType': vm['networkConnectionSection']['NetworkConnection'][
                                               'NetworkAdapterType'],
                                           'storageProfileHref': vm['storageProfileHref'],
                                           'vmPlacementPolicyHref': href, 'sizingPolicyHref': vm['sizingPolicyHref']}
                            # creating the pauload data
                            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                                      templateName=vcdConstants.RECOMPOSE_COMPUTE_POLICY_VAPP_TEMPLATE)
                    payloadData = json.loads(payloadData)
                    self.headers["Content-Type"] = vcdConstants.XML_RECOMPOSE_VAPP
                    # post api call to recompose source vapp into target vapps
                    response = self.restClientObj.post(url, self.headers, data=payloadData)
                    responseDict = xmltodict.parse(response.content)
                    if response.status_code == requests.codes.accepted:
                        task = responseDict["Task"]
                        if task["@operationName"] == vcdConstants.RECOMPOSE_VAPP_TASK:
                            taskUrl = task["@href"]
                        if taskUrl:
                            # checking the status of recomposing vapps task
                            self._checkTaskStatus(taskUrl, vcdConstants.RECOMPOSE_VAPP_TASK)
                            logger.info('Recomposed target vApp - {} successfully with VM - {}.'.format(vApp['targetVapp']['@name'], vm['name']))
                    else:
                        raise Exception('Failed to recompose vApp with errors {}'.format(responseDict['Error']['@message']))
        except Exception:
            raise

    def getOrgVDCStorageProfileDetails(self, orgVDCStorageProfileId):
        """
        Description :   Gets the details of the specified Org VDC Storage Profile ID
        Parameters  :   orgVDCStorageProfileId -   ID of the Org VDC Storage Profile (STRING)
        Returns     :   Details of the Org VDC Storage Profile (DICTIONARY)
        """
        try:
            logger.debug("Getting Org VDC Storage Profile details of {}".format(orgVDCStorageProfileId))
            # splitting the orgVDCStorageProfileId as per the requirement of the xml api call
            orgVDCStorageProfileId = orgVDCStorageProfileId.split(':')[-1]
            # url to get the vdc storage profile of specified id
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.VCD_STORAGE_PROFILE_BY_ID.format(orgVDCStorageProfileId))
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            return responseDict
        except Exception:
            raise

    def getSourceVappVmMacAddress(self):
        """
        Description - Get source vapp vm mac address
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # retrieving the resource entity list of the source org vdc
            sourceOrgVDCEntityList = data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'] if isinstance(data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'], list) else [data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']]
            # retrieving the source vapp list
            sourceVappList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if
                              vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            vmInVappList = []
            # iterating over the source vapps
            for vApp in sourceVappList:
                response = self.restClientObj.get(vApp['@href'], self.headers)
                responseDict = xmltodict.parse(response.content)
                # checking for the vms in the vapp
                if responseDict['VApp'].get('Children'):
                    # retrieving the list of vms in the vapp
                    vmList = responseDict['VApp']['Children']['Vm']
                    if isinstance(vmList, list):
                        # if multiple vms in vapp, iterating over the vms
                        for vm in vmList:
                            # checking if vm is attached to any network
                            if vm.get('NetworkConnectionSection'):
                                vmInVappList.append(vm['NetworkConnectionSection']['NetworkConnection']['MACAddress'])
                            else:
                                logger.warning('vApp {} vm doesnot have any network attached to it'.format(vApp['@name']))
                    else:
                        # if single vm in vapp
                        vm = vmList
                        # checking if vm is attached to any network
                        if vm.get('NetworkConnectionSection'):
                            vmInVappList.append(vm['NetworkConnectionSection']['NetworkConnection']['MACAddress'])
                        else:
                            logger.warning('vApp {} vm doesnot have any network attached to it'.format(vApp['@name']))
                else:
                    logger.warning('vApp {} doesnot have any vm in it'.format(vApp['@name']))
            if vmInVappList:
                # writing the vm mac address details to the log
                logger.debug('Source vapp vm mac address details - {}'.format(vmInVappList))
            return vmInVappList
        except Exception:
            raise

    def createACL(self):
        """
        Description : Create ACL on Org VDC
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # retrieving the source org vdc id & target org vdc is
            sourceOrgVDCId = data["sourceOrgVDC"]['@id'].split(':')[-1]
            targetOrgVDCId = data["targetOrgVDC"]['@id'].split(':')[-1]
            # url to get the access control in org vdc
            url = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                vcdConstants.GET_ACCESS_CONTROL_IN_ORG_VDC.format(sourceOrgVDCId))
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
            # get api call to retrieve the access control details in source org vdc
            response = self.restClientObj.get(url, headers)
            data = json.loads(response.content)
            if not data['accessSettings']:
                logger.debug('ACL doesnot exist on source Org VDC')
                return
            # url to create access control in target org vdc
            url = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                vcdConstants.CREATE_ACCESS_CONTROL_IN_ORG_VDC.format(targetOrgVDCId))
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader,
                       'Content-Type': vcdConstants.CONTROL_ACCESS_CONTENT_TYPE}
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
            # creating the payload dictionary
            payloadDict = {'isShared': data['isSharedToEveryone'],
                           'everyoneAccess': data['everyoneAccessLevel'] if data['everyoneAccessLevel'] else "Null"}
            # creating the payload data
            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.CREATE_ORG_VDC_ACCESS_CONTROL_TEMPLATE)
            accessSettingsList = []
            # iterating over the access settings of source org vdc
            for subjectData in data['accessSettings']['accessSetting']:
                userData = {"subject": {"href": subjectData['subject']['href']}, "accessLevel": subjectData['accessLevel']}
                accessSettingsList.append(userData)
            jsonData = json.loads(payloadData)
            # attaching the access settings to the payload data
            jsonData['accessSettings'] = {'accessSetting': accessSettingsList}
            payloadData = json.dumps(jsonData)
            # put api to create access control in target org vdc
            response = self.restClientObj.put(url, headers, data=payloadData)
            if response.status_code != requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                raise Exception('Failed to create target ACL on target Org VDC {}'.format(responseDict['Error']['@message']))
            logger.info('Successfully created ACL on target Org vdc')
        except Exception:
            self.DELETE_TARGET_ORG_VDC = True
            raise

    def createVDCPlacementPolicy(self, namedVMGroupDict):
        """
        Description :   creates org vdc placement policy
        """
        try:
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            targetProviderVDCName = data['targetProviderVDC']['@name']
            targetProviderVDCId = data['targetProviderVDC']['@id']
            # url to the resource pool info
            url = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                vcdConstants.GET_RESOURCEPOOL_INFO)
            # get api call to retrieve resource pool info
            response = self.restClientObj.get(url, headers=self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                # retrieving the hrefs of resource pool records whose provider is target provider vdc
                resourcePoolHref = [response['@href'] for response in responseDict['QueryResultRecords']['ResourcePoolRecord'] if response['@providerName'] == targetProviderVDCName]
            if resourcePoolHref:
                # retrieving the resource pool id
                resourcePoolId = resourcePoolHref[0].split('/')[-1]
            else:
                return
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
            targetNamedVMGroupList = []

            # iterating over the named vm group dict
            for href, namedVMGroups in namedVMGroupDict.items():
                if not namedVMGroups:
                    # if no vm groups are present then setting empty targetNamedVMGroupList
                    targetNamedVMGroupList = []
                else:
                    # iterating over the named vm groups
                    for namedVMGroup in namedVMGroups:
                        payloadDict = {'vmGroupName': namedVMGroup[0]+'-'+namedVMGroup[1]}
                        # creating payload data
                        payloadData = self.vcdUtils.createPayload(filePath,
                                                                  payloadDict,
                                                                  fileType='yaml',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.CREATE_VMGROUP_TEMPLATE)
                        payloadData = json.loads(payloadData)
                        # url to create vm groups
                        url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                            vcdConstants.CREATE_VMGROUPS.format(resourcePoolId))
                        self.headers["Content-Type"] = vcdConstants.XML_CREATE_VMGROUPS_CONTENT_TYPE
                        # post api call to create vm groups
                        response = self.restClientObj.post(url, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            responseDict = xmltodict.parse(response.content)
                            task = responseDict["Task"]
                            if task["@operationName"] == vcdConstants.CREATE_VMGROUP_TASK:
                                taskUrl = task["@href"]
                            if taskUrl:
                                # checking the status of creating the vm group task
                                self._checkTaskStatus(taskUrl, vcdConstants.CREATE_VMGROUP_TASK)
                                logger.debug('VM Group {} created successfully'.format(payloadDict['vmGroupName']))
                        else:
                            responseDict = xmltodict.parse(response.content)
                            raise Exception('Error occured while creating vm groups {}.'.format(responseDict['Error']['@message']))
                        # url to get the vm group info
                        url = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                            vcdConstants.GET_VMGROUP_INFO)
                        # get api call to retrieve the vm group info
                        response = self.restClientObj.get(url, headers=self.headers)
                        if response.status_code == requests.codes.ok:
                            responseDict = xmltodict.parse(response.content)
                            # retrieving the target vm group list
                            targetVMGroupList = [response for response in responseDict['QueryResultRecords']['VmGroupsRecord'] if response['@vmGroupName'] == payloadDict['vmGroupName']]
                        vmGroupName = targetVMGroupList[0]['@vmGroupName']
                        vmGroupId = targetVMGroupList[0]['@vmGroupId']
                        targetNamedVMGroupList.append({"name": vmGroupName, "id": "urn:vcloud:namedVmGroup:"+vmGroupId})
                # get api call to retrieve the vm group info
                response = self.restClientObj.get(href, headers=self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    payloadDict = responseDict
                    del payloadDict['id']
                    payloadDict['pvdcId'] = targetProviderVDCId
                    payloadDict['namedVmGroups'] = [targetNamedVMGroupList]
                    payloadData = json.dumps(payloadDict)
                    # create vdc compute policy
                    url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                        vcdConstants.VDC_COMPUTE_POLICIES)
                    self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                    # post api call to create vdc compute policy
                    response = self.restClientObj.post(url, self.headers, data=payloadData)
                    if response.status_code == requests.codes.created:
                        logger.debug('Successfully created vdc compute coplicy in target org vdc')
                    else:
                        errorDict = response.json()
                        raise Exception('Failed to create vdc compute policy in target PVDC - {}'.format(errorDict['message']))
        except:
            raise

    def applyVDCPlacementPolicy(self):
        """
        Description : Applying VM placement policy on vdc
        """
        try:
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            computePolicyHrefList = []
            # retrieving the target org vdc id, target provider vdc id & compute policy list of source from apiOutput.json
            targetOrgVDCId = data['targetOrgVDC']['@id'].split(':')[-1]
            targetProviderVDCId = data['targetProviderVDC']['@id']
            if not data.get('sourceOrgVDCComputePolicyList'):
                logger.debug('No source Org VDC compute Policy exist')
                return
            sourcePolicyList = data['sourceOrgVDCComputePolicyList']
            # getting list instance of sourcePolicyList
            sourceComputePolicyList = [sourcePolicyList] if isinstance(sourcePolicyList, dict) else sourcePolicyList
            allOrgVDCComputePolicesList = self.getOrgVDCComputePolicies()
            # getting list instance of org vdc compute policies
            orgVDCComputePolicesList = [allOrgVDCComputePolicesList] if isinstance(allOrgVDCComputePolicesList, dict) else allOrgVDCComputePolicesList
            # iterating over the org vdc compute policies
            for eachComputePolicy in orgVDCComputePolicesList:
                if eachComputePolicy["pvdcId"] == targetProviderVDCId:
                    # if compute policy's id is same as target provider vdc id and compute policy is not the system default
                    if eachComputePolicy["name"] != 'System Default':
                        # iterating over the source compute policies
                        for computePolicy in sourceComputePolicyList:
                            if computePolicy['@name'] == eachComputePolicy['name'] and eachComputePolicy['name'] != data['targetOrgVDC']['DefaultComputePolicy']['@name']:
                                # creating the href of the org vdc compute policy
                                href = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                        vcdConstants.VDC_COMPUTE_POLICIES,
                                                        eachComputePolicy["id"])
                                computePolicyHrefList.append({'href': href})
            # url to get the compute policy details of target org vdc
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_COMPUTE_POLICY.format(targetOrgVDCId))
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
            # get api call to retrieve the target org vdc compute policy details
            response = self.restClientObj.get(url, headers)
            data = json.loads(response.content)
            alreadyPresentComputePoliciesList = []
            payloadDict = {}
            for computePolicy in data['vdcComputePolicyReference']:
                if computePolicy['href'] not in computePolicyHrefList:
                    # getting the list of compute policies which are already
                    alreadyPresentComputePoliciesList.append({'href': computePolicy['href'], 'id': computePolicy['id'], 'name': computePolicy['name']})
            payloadDict['vdcComputePolicyReference'] = alreadyPresentComputePoliciesList + computePolicyHrefList
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader, 'Content-Type': vcdConstants.GENERAL_JSON_CONTENT_TYPE}
            # creating the payload data
            payloadData = json.dumps(payloadDict)
            response = self.restClientObj.put(url, headers, data=payloadData)
            if response.status_code == requests.codes.ok:
                logger.debug('Successfully applied vm placement policy on target VDC')
            else:
                raise Exception('Failed to apply vm placement policy on target VDC {}'.format(response.json()['message']))
        except Exception:
            # setting the delete target org vdc flag
            self.DELETE_TARGET_ORG_VDC = True
            raise

    def getVappAccessControlDetails(self, vAppHref):
        """
        Description :   Gets the access control details of the specified href
        Parameters  :   vAppHref    -   Href of the vApp whose details are to be fetched (STRING)
        """
        try:
            # url to get the vapp access control details
            url = "{}{}".format(vAppHref, vcdConstants.ACCESS_CONTROL)
            # get api call to retrieve vapp access control details
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                logger.debug("Retrieved the vApp Access Control Details successfully")
                return response
            raise Exception("Failed to retrieve the vApp Access Control Details {}".format(responseDict['Error']['@message']))
        except Exception:
            raise

    @staticmethod
    def getSourceOrgVDCvAppsList():
        """
        Description :   Retrieves the list of vApps in the Source Org VDC
        Returns     :   Returns Source vapps list (LIST)
        """
        try:
            logger.debug("Getting Source Org VDC vApps List")
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # getting list instance of resource entities of source org vdc
            sourceOrgVDCEntityList = [data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']] if isinstance(data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'], dict) else data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']
            # getting list of source vapps
            sourceVappList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if
                              vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            return sourceVappList
        except Exception:
            raise

    def getTargetOrgVDCvAppsList(self):
        """
        Description :   Retrieves the list of vApps in the Target Org VDC
        Returns     :   Returns target vapps list (LIST)
        """
        try:
            logger.debug("Getting Target Org VDC vApps List")
            targetVappList = []
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # retrieving the target org vdc details from apiOutput.json
            targetOrgVDCDict = data["targetOrgVDC"]
            # get api call to retrieve the target org vdc details
            response = self.restClientObj.get(targetOrgVDCDict['@href'], self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                if not responseDict['AdminVdc']['ResourceEntities']:
                    raise Exception("Failed to get source vApp details.")
                # getting resource entity list of target org vdc
                targetOrgVDCEntityList = responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'] if isinstance(responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'], list) else [responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']]
                # getting vapp list of target org vdc
                targetVappList = [vAppEntity for vAppEntity in targetOrgVDCEntityList if
                                  vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
                return targetVappList
            raise Exception("Failed to retrieve Target Org VDC vApp List {}".format(responseDict['Error']['@message']))
        except Exception:
            raise

    def createVappAccessControlInTargetVapp(self):
        """
        Description :   Replicates the Access Control from Source vApp into Target vApp
        """
        try:
            # getting list of source vapps
            sourceVappList = self.getSourceOrgVDCvAppsList()
            # getting list of target vapps
            targetVappList = self.getTargetOrgVDCvAppsList()
            # getting list of vapps with same name from source & target
            vAppList = [(sourceVapp, targetVapp) for sourceVapp in sourceVappList for targetVapp in targetVappList if
                        sourceVapp['@name'] + '-t' == targetVapp['@name']]
            # iterating over the vapps
            for sourcevApp, targetvApp in vAppList:
                # getting the source vapps access control details
                srcVappResponse = self.getVappAccessControlDetails(sourcevApp['@href'])
                # url to create access control in target vapp
                url = "{}{}".format(targetvApp['@href'],
                                    vcdConstants.VAPP_ACCESS_CONTROL_SETTINGS)
                # post api call to create access control in target vapps
                response = self.restClientObj.post(url, self.headers, data=srcVappResponse.content)
                if response.status_code == requests.codes.ok:
                    logger.debug("Replicated Same Access Control Settings into Target Vapp {} as Source vApp Successfully".format(targetvApp['@name']))
                else:
                    errorDict = xmltodict.parse(response.content)
                    raise Exception("Failed to replicate Access Control into Target Vapp {} {}".format(targetvApp['@name'],
                                                                                                       errorDict['Error']['@message']))
        except Exception:
            raise

    def getVappOwner(self, vAppHref):
        """
        Description :   Gets the Owner of the specified vAppHref
        Parameters  :   vAppHref    -   Href of a vApp (STRING)
        """
        try:
            # url to get vapp's owner
            url = "{}{}".format(vAppHref,
                                vcdConstants.VAPP_OWNER)
            # get api call to get vapp owner details
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                return responseDict['Owner']['User']
            errorDict = xmltodict.parse(response.content)
            raise Exception("Failed to retrieve vApp Owner {}".format(errorDict['Error']['@message']))
        except Exception:
            raise

    def changeVAppOwner(self):
        """
        Description :   Updates the User Owner of the specified VApp with the User specified in the userHref link
        """
        try:
            # getting source vapps list
            sourceVappList = self.getSourceOrgVDCvAppsList()
            # getting target vapps list
            targetVappList = self.getTargetOrgVDCvAppsList()
            # getting list of vapps with same name in source & target
            vAppList = [(sourceVapp, targetVapp) for sourceVapp in sourceVappList for targetVapp in targetVappList if
                        sourceVapp['@name'] + '-t' == targetVapp['@name']]
            # iterating over the vapps
            for (srcVapp, tgtVapp) in vAppList:
                # getting the owner details of source vapp
                owner = self.getVappOwner(srcVapp['@href'])
                # skipping if the owner is system
                if owner['@name'] == 'system':
                    continue
                # url to update the owner settings in the target vapp
                url = "{}{}".format(tgtVapp['@href'],
                                    vcdConstants.VAPP_OWNER)
                filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
                payloadDict = {'userHref': owner['@href']}
                # creating payload data
                payloadData = self.vcdUtils.createPayload(filePath,
                                                          payloadDict,
                                                          fileType='yaml',
                                                          componentName=vcdConstants.COMPONENT_NAME,
                                                          templateName=vcdConstants.CHANGE_VAPP_OWNER_TEMPLATE)
                payloadData = json.loads(payloadData)
                # put api call to update the target vapps owner settings
                response = self.restClientObj.put(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.no_content:
                    logger.debug("Changed the Owner of vApp {} successfully".format(tgtVapp['@name']))
                else:
                    errorDict = xmltodict.parse(response.content)
                    raise Exception("Failed to change the Owner of vApp {} {}".format(tgtVapp['@name'],
                                                                                      errorDict['Error']['@message']))
        except Exception:
            raise

    def getVappLeaseSettings(self, vAppHref):
        """
        Description :   Gets the Lease Settings of the specified vAppHref
        Parameters  :   vAppHref    -   Href of a vApp (STRING)
        """
        try:
            # url to get the lease settings of the vapp
            url = "{}{}".format(vAppHref,
                                vcdConstants.VAPP_LEASE_SETTINGS)
            # get api call to retrieve the lease settings of a vapp
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                return responseDict['LeaseSettingsSection']
            raise Exception("Failed to retrieve vApp Lease Settings {}".format(responseDict['Error']['@message']))
        except Exception:
            raise

    def renewVappLeaseSettings(self):
        """
        Description :   Renews the Lease Settings of the all target VApps as per Source vApps
        """
        try:
            # getting the source vapp list
            sourceVappList = self.getSourceOrgVDCvAppsList()
            # getting the target vapp list
            targetVappList = self.getTargetOrgVDCvAppsList()
            # getting list of vapps with same name in source & target
            vAppList = [(sourceVapp, targetVapp) for sourceVapp in sourceVappList for targetVapp in targetVappList if
                        sourceVapp['@name'] + '-t' == targetVapp['@name']]
            # iterating over the vapps
            for (srcVapp, tgtVapp) in vAppList:
                # retrieving the source vapps lease settings
                leaseSettings = self.getVappLeaseSettings(srcVapp['@href'])
                # url to update the target vapps lease settings
                url = "{}{}".format(tgtVapp['@href'],
                                    vcdConstants.VAPP_LEASE_SETTINGS)
                filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
                payloadDict = {'deploymentLeaseInSeconds': leaseSettings['DeploymentLeaseInSeconds'],
                               'storageLeaseInSeconds': leaseSettings['StorageLeaseInSeconds']}
                # creating the payload using the format in the template.yml
                payloadData = self.vcdUtils.createPayload(filePath,
                                                          payloadDict,
                                                          fileType='yaml',
                                                          componentName=vcdConstants.COMPONENT_NAME,
                                                          templateName=vcdConstants.RENEW_VAPP_LEASE_SETTINGS_TEMPLATE)
                payloadData = json.loads(payloadData)
                # put api call to update the lease settings in the target vapps
                response = self.restClientObj.put(url, self.headers, data=payloadData)
                responseDict = xmltodict.parse(response.content)
                if response.status_code == requests.codes.accepted:
                    task = responseDict["Task"]
                    if task["@operationName"] == vcdConstants.RENEW_VAPP_LEASE_SETTINGS_TASK_NAME:
                        taskUrl = task["@href"]
                    if taskUrl:
                        # checking the status of the updating lease settings on target vapps task
                        self._checkTaskStatus(taskUrl, vcdConstants.RENEW_VAPP_LEASE_SETTINGS_TASK_NAME)
                    logger.debug("Lease Settings of VApp {} renewed successfully".format(tgtVapp['@name']))
                else:
                    raise Exception("Failed to renew Lease Settings of VApp {} {}".format(tgtVapp['@name'],
                                                                                          responseDict['Error']['@message']))
        except Exception:
            raise

    def getVappMetadata(self, vAppHref):
        """
        Description :   Gets the Metadata of the specified vAppHref
        Parameters  :   vAppHref    -   Href of a vApp (STRING)
        """
        try:
            url = "{}{}".format(vAppHref,
                                vcdConstants.METADATA_IN_VAPP)
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                return responseDict['Metadata']
            raise Exception("Failed to retrieve vApp Metadata {}".format(responseDict['Error']['@message']))
        except Exception:
            raise

    def createMetadataInVapp(self):
        """
        Description :   Create a new metadata in specified vApp with the specified  metadataKey & metadataValue
        """
        try:
            sourceVappList = self.getSourceOrgVDCvAppsList()
            targetVappList = self.getTargetOrgVDCvAppsList()
            vAppList = [(sourceVapp, targetVapp) for sourceVapp in sourceVappList for targetVapp in targetVappList if sourceVapp['@name'] + '-t' == targetVapp['@name']]

            for (srcVapp, tgtVapp) in vAppList:
                metadata = self.getVappMetadata(srcVapp['@href'])
                if isinstance(metadata["MetadataEntry"], dict):
                    metadata["MetadataEntry"] = [metadata["MetadataEntry"]]
                for eachMetadata in metadata["MetadataEntry"]:
                    url = "{}{}".format(tgtVapp['@href'],
                                        vcdConstants.METADATA_IN_VAPP)
                    filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
                    payloadDict = {'metadataKey': eachMetadata['Key'],
                                   'metadataValue': eachMetadata['TypedValue']['Value'],
                                   'typedValueDatatype': eachMetadata['TypedValue']['@xsi:type']}
                    payloadData = self.vcdUtils.createPayload(filePath,
                                                              payloadDict,
                                                              fileType='yaml',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.CREATE_VAPP_METADATA_TEMPLATE)

                    payloadData = json.loads(payloadData)
                    self.headers["Content-Type"] = vcdConstants.GENERAL_XML_CONTENT_TYPE
                    response = self.restClientObj.post(url, self.headers, data=payloadData)
                    responseDict = xmltodict.parse(response.content)
                    if response.status_code == requests.codes.accepted:
                        task = responseDict["Task"]
                        if task["@operationName"] == vcdConstants.CREATE_METADATA_IN_VAPP_TASK_NAME:
                            taskUrl = task["@href"]
                        if taskUrl:
                            self._checkTaskStatus(taskUrl, vcdConstants.CREATE_METADATA_IN_VAPP_TASK_NAME)
                        logger.debug("Created Metadata {} in vApp {} successfully".format(eachMetadata['Key'], tgtVapp['@name']))
                    else:
                        raise Exception("Failed to create Metadata {} in vApp {} {}".format(eachMetadata['Key'],
                                                                                            tgtVapp['@name'],
                                                                                            responseDict['Error']['@message']))
        except Exception:
            raise

    @_isSessionExpired
    def enableTargetAffinityRules(self):
        """
        Description :   Enable Affinity Rules in Target VDC
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
            # reading the data from the apiOutput.json
            targetOrgVdcId = data['targetOrgVDC']['@id']
            targetvdcid = targetOrgVdcId.split(':')[-1]
            # checking if affinity rules present in source
            if data['sourceVMAffinityRules']:
                sourceAffinityRules = data['sourceVMAffinityRules'] if isinstance(data['sourceVMAffinityRules'], list) else [data['sourceVMAffinityRules']]
                # iterating over the source affinity rules
                for sourceAffinityRule in sourceAffinityRules:
                    affinityID = sourceAffinityRule['@id']
                    # url to update the affinity rules in the target
                    url = "{}{}".format(vcdConstants.AFFINITY_URL.format(self.ipAddress, targetvdcid), affinityID)
                    # creating the paylaod data using xml tree
                    vmAffinityRule = ET.Element('VmAffinityRule',
                                                {"xmlns": 'http://www.vmware.com/vcloud/v1.5'})
                    name = ET.SubElement(vmAffinityRule, 'Name')
                    name.text = sourceAffinityRule['Name']
                    isEnabled = ET.SubElement(vmAffinityRule, 'IsEnabled')
                    isEnabled.text = "true" if sourceAffinityRule['IsEnabled'] == "true" else "false"
                    isMandatory = ET.SubElement(vmAffinityRule, 'IsMandatory')
                    isMandatory.text = sourceAffinityRule['IsMandatory']
                    polarity = ET.SubElement(vmAffinityRule, 'Polarity')
                    polarity.text = sourceAffinityRule['Polarity']
                    vmReferences = ET.SubElement(vmAffinityRule, 'VmReferences')
                    for eachVmReference in sourceAffinityRule['VmReferences']['VmReference']:
                        ET.SubElement(vmReferences, 'VmReference',
                                      href=eachVmReference['@href'], id=eachVmReference['@id'],
                                      name=eachVmReference['@name'], type=eachVmReference['@type'])

                    payloadData = ET.tostring(vmAffinityRule, encoding='utf-8', method='xml')
                    # put api call to update the affinity rules in the target
                    response = self.restClientObj.put(url, self.headers, data=str(payloadData, 'utf-8'))
                    responseDict = xmltodict.parse(response.content)
                    if response.status_code == requests.codes.accepted:
                        task_url = response.headers['Location']
                        # checking the status of updating affinity rules in the target task
                        self._checkTaskStatus(task_url, vcdConstants.CREATE_AFFINITY_RULE_TASK_NAME)
                        logger.debug('Affinity Rules got updated successfully in Target')
                    else:
                        raise Exception('Failed to update Affinity Rules in Target {}'.format(responseDict['Error']['@message']))
        except Exception:
            raise

    @_isSessionExpired
    def ejectMedia(self):
        """
        Description : Ejecting media from vm
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            sourceOrgVDCEntityList = data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'] if isinstance(data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'], list) else [data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']]
            sourceVappList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if
                              vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            # For future use need to get confirmation from Thomas
            # mediaList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if
            #               vAppEntity['@type'] == vcdConstants.TYPE_VAPP_MEDIA]
            # iterating over the source vapps
            for sourceVapp in sourceVappList:
                hrefVapp = sourceVapp['@href']
                # get api call to retrieve the details of a source vapp
                response = self.restClientObj.get(hrefVapp, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = xmltodict.parse(response.content)
                    # cehcking the vapp has vms present in it
                    if responseDict['VApp'].get('Children'):
                        vmList = responseDict['VApp']['Children']['Vm'] if isinstance(responseDict['VApp']['Children']['Vm'], list) else [responseDict['VApp']['Children']['Vm']]
                        filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
                        # iterating over the vms in the source vapp
                        for vm in vmList:
                            vmId = vm['@id']
                            vmId = vmId.split(':')[-1]
                            # getting the meida settings of the source vm
                            mediaSettings = vm['VmSpecSection']['MediaSection']['MediaSettings'] if isinstance(vm['VmSpecSection']['MediaSection']['MediaSettings'], list) else [vm['VmSpecSection']['MediaSection']['MediaSettings']]
                            # iterating over the multiple media settings of source vm
                            for mediaSetting in mediaSettings:
                                # checking that media state is not disconnected
                                if mediaSetting['MediaState'] != "DISCONNECTED":
                                    mediaImage = mediaSetting['MediaImage']
                                    mediaId = mediaImage['@id']
                                    mediaId = mediaId.split(':')[-1]
                                    payloadDict = {
                                        "href": mediaImage['@href'],
                                        "id": mediaId,
                                        "name": mediaImage['@name']
                                    }
                                    # creating the payload data
                                    payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                                              templateName=vcdConstants.EJECT_MEDIA_TEMPLATE)
                                    payloadData = json.loads(payloadData)
                                    # url to eject media of source vm
                                    url = "{}".format(vcdConstants.EJECT_MEDIA_URL.format(self.ipAddress, vmId))
                                    # post api call to eject media of source vm
                                    response = self.restClientObj.post(url, self.headers, data=payloadData)
                                    if response.status_code == requests.codes.accepted:
                                        task_url = response.headers['Location']
                                        # checking the status of ejecting the source media task
                                        self._checkTaskStatus(task_url, vcdConstants.EJECT_MEDIA_TASK_NAME)
                                        logger.debug('Media got ejected successfully')
                                    else:
                                        response = response.json()
                                        raise Exception('Failed to Eject media {} '.format(response['message']))
            logger.info('Media got ejected successfully')
        except Exception:
            raise

    def renameOrgVDC(self, sourceOrgVDCName, targetVDCId):
        """
        Description :   Renames the target Org VDC
        Parameters  :   sourceOrgVDCName    - name of the source org vdc (STRING)
                        targetVDCId         - id of the target org vdc (STRING)
        """
        try:
            # splitting the target org vdc id as per the requirement of xml api
            targetVDCId = targetVDCId.split(':')[-1]
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
            # url to get the target org vdc details
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(targetVDCId))
            # get api call to retrieve the target org vdc details
            response = self.restClientObj.get(url, headers=headers)
            responseDict = response.json()
            # creating the payload data by just changing the name of org vdc same as source org vdc
            responseDict['name'] = sourceOrgVDCName
            payloadData = json.dumps(responseDict)
            headers['Content-Type'] = vcdConstants.VDC_RENAME_CONTENT_TYPE
            # put api call to update the target org vdc name
            response = self.restClientObj.put(url, headers=headers, data=payloadData)
            responseData = response.json()
            if response.status_code == requests.codes.accepted:
                if responseData["operationName"] == vcdConstants.RENAME_ORG_VDC:
                    taskUrl = responseData["href"]
                if taskUrl:
                    # checking the status of renaming target org vdc task
                    self._checkTaskStatus(taskUrl, vcdConstants.RENAME_ORG_VDC)
                    logger.debug('Renamed Org VDC to {} successfully'.format(responseDict['name']))
                return response
            raise Exception("Failed to rename the Org VDC {}".format(responseData['message']))
        except Exception:
            raise

    def getVappStartupSectionInfo(self, vAppHref, saveResponse=False):
        """
        Description :   Gets the startup information of the specified Virtual Application
        Parameters  :   vAppHref        -   href of the vapp (STRING)
                        saveResponse    -   True if response is to be saved in json file (BOOL)
                                            False otherwise (BOOL)
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            if os.path.exists(fileName):
                with open(fileName, 'r') as f:
                    data = json.load(f)
            # url to get the startup section of the vapp
            url = "{}{}".format(vAppHref,
                                vcdConstants.VAPP_STARTUP_SECTION)
            # get api call to retrieve the vapp startup section details
            response = self.restClientObj.get(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.ok:
                if saveResponse:
                    # cehcking if the startup section exists in the vapp
                    if data.get('StartupSection'):
                        data['StartupSection'].append({vAppHref: responseDict['ovf:StartupSection']})
                    else:
                        data['StartupSection'] = [{vAppHref: responseDict['ovf:StartupSection']}]
                    # writing the startup section details of the vapp to the apiOutput.json
                    with open(fileName, 'w') as f:
                        json.dump(data, f, indent=3)
                return responseDict['ovf:StartupSection']
        except Exception:
            raise

    def createVappStartupSection(self):
        """
        Description :   Replicates the startup section from the source vApp into target vApp
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # getting the source vapp list
            sourceVappList = self.getSourceOrgVDCvAppsList()
            # getting the target vapp list
            targetVappList = self.getTargetOrgVDCvAppsList()
            # getting list of vapps with same name in source & target
            vAppList = [(sourceVapp, targetVapp) for sourceVapp in sourceVappList for targetVapp in targetVappList if
                        sourceVapp['@name'] + '-t' == targetVapp['@name']]
            startupSectionList = data['StartupSection']
            # iterating over the vapps in source & target
            for (srcVapp, tgtVapp) in vAppList:
                # iterating over the startup section list of source vapps
                for startupSectionDict in startupSectionList:
                    # iterating over key, values of startup section dict of source vaps
                    for vAppHref, startupSection in startupSectionDict.items():
                        # checking if same source vapp & target vapp
                        if vAppHref == srcVapp['@href']:
                            # skipping the vapp if no startup section in source vapp
                            if not startupSection.get('ovf:Item'):
                                logger.warning('Start and stop order is not configured for source vApp - {}'.format(srcVapp['@name']))
                                return
                            # creating the payload data using the xml tree
                            logger.debug('Creating Start and stop order for target vApp {}'.format(tgtVapp['@name']))
                            ovfStartup = ET.Element("ovf:StartupSection",
                                                    {"xmlns:ovf": startupSection['@xmlns:ovf'],
                                                     "xmlns:vssd": startupSection['@xmlns:vssd'],
                                                     "xmlns:common": startupSection['@xmlns:common'],
                                                     "xmlns:rasd": startupSection['@xmlns:rasd'],
                                                     "xmlns:vmw": startupSection['@xmlns:vmw'],
                                                     "xmlns:vmext": startupSection['@xmlns:vmext'],
                                                     "xmlns:ovfenv": startupSection['@xmlns:ovfenv']})
                            ovfInfo = ET.SubElement(ovfStartup, "ovf:Info")
                            ovfInfo.text = startupSection["ovf:Info"]
                            if isinstance(startupSection['ovf:Item'], dict):
                                startupSection['ovf:Item'] = [startupSection['ovf:Item']]
                            for eachItem in startupSection['ovf:Item']:
                                ET.SubElement(ovfStartup, "ovf:Item",
                                              {"ovf:id": eachItem['@ovf:id'],
                                               "ovf:order": eachItem['@ovf:order'],
                                               "ovf:startAction": eachItem['@ovf:startAction'],
                                               "ovf:startDelay": eachItem['@ovf:startDelay'],
                                               "ovf:stopAction": eachItem['@ovf:stopAction'],
                                               "ovf:stopDelay": eachItem['@ovf:stopDelay']})
                            payloadData = ET.tostring(ovfStartup, encoding='utf-8', method='xml')
                            # url to update the startup section in target vapps
                            url = "{}{}".format(tgtVapp['@href'], vcdConstants.VAPP_STARTUP_SECTION)
                            # put api call to update the startup section in the target vapps
                            response = self.restClientObj.put(url, self.headers, data=str(payloadData, 'utf-8'))
                            if response.status_code == requests.codes.accepted:
                                taskUrl = response.headers['Location']
                                # checking the status of the updating startup section of target vapp task
                                self._checkTaskStatus(taskUrl, vcdConstants.VAPP_STARTUP_TASK_NAME)
                                logger.debug('Created Startup Section in vApp {} successfully'.format(tgtVapp['@name']))
                            else:
                                errorMessage = xmltodict.parse(response.content)
                                raise Exception("Failed to create Startup Section in vApp {} - {}".format(tgtVapp['@name'],
                                                                                                          errorMessage['Error']['@message']))
        except Exception:
            raise

    def renameTargetOrgVDCVapps(self, targetVDCId):
        """
        Description :   Renames all the vApps in the specified target Org VDC as those in source Org VDC
        Parameters  :   targetVDCId -   id of the target org vdc (STRING)
        """
        try:
            # splitting thr target org vdc id as per the xml api requirements
            targetVDCId = targetVDCId.split(':')[-1]
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
            # url to get the target org vdc details
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(targetVDCId))
            # get api call to retrieve the target org vdc details
            response = self.restClientObj.get(url, headers=headers)
            responseDict = response.json()
            # getting the resource entity list of target org vdc
            targetOrgVDCEntityList = [responseDict['resourceEntities']['resourceEntity']] if isinstance(responseDict['resourceEntities']['resourceEntity'], dict) else responseDict['resourceEntities']['resourceEntity']
            # getting the vapps list of the target org vdc
            targetVappList = [vAppEntity for vAppEntity in targetOrgVDCEntityList if
                              vAppEntity['type'] == vcdConstants.TYPE_VAPP]
            # iterating over the target vapps
            for tgtVapp in targetVappList:
                # checking if the target vapp's name endwith -t
                if tgtVapp['name'].endswith('-t'):
                    # getting the startup section info of the target vapp, since required to create payload data to rename vapps
                    startupDetails = self.getVappStartupSectionInfo(tgtVapp['href'])
                    # since vapp name ends with -t, removing -t from the name
                    vAppName = tgtVapp['name'][0: len(tgtVapp['name']) - 2]
                    # creating the payload data using xml tree
                    recomposeVappParams = ET.Element('RecomposeVAppParams',
                                                     {"xmlns":'http://www.vmware.com/vcloud/v1.5',
                                                      "name": vAppName,
                                                      "xmlns:ovf": "http://schemas.dmtf.org/ovf/envelope/1"})
                    instantiationParams = ET.SubElement(recomposeVappParams, 'InstantiationParams')
                    startupSection = ET.SubElement(instantiationParams, "ovf:StartupSection")
                    ET.SubElement(startupSection, "ovf:Info")
                    if "ovf:Item" in startupDetails:
                        if isinstance(startupDetails["ovf:Item"], dict):
                            startupDetails["ovf:Item"] = [startupDetails["ovf:Item"]]
                        for eachVm in startupDetails["ovf:Item"]:
                            ET.SubElement(startupSection, "ovf:Item",
                                          {"ovf:id": eachVm["@ovf:id"],
                                           "ovf:order": eachVm["@ovf:order"],
                                           "ovf:startAction": eachVm["@ovf:startAction"],
                                           "ovf:startDelay": eachVm["@ovf:startDelay"],
                                           "ovf:stopAction": eachVm["@ovf:stopAction"],
                                           "ovf:stopDelay": eachVm["@ovf:stopDelay"]})
                    payloadData = ET.tostring(recomposeVappParams, encoding='utf-8', method='xml')
                    self.headers["Content-Type"] = vcdConstants.GENERAL_XML_CONTENT_TYPE
                    # url to rename the target vapp
                    url = "{}/{}".format(tgtVapp['href'],
                                         vcdConstants.RECOMPOSE_VAPP_API)
                    # post api call to rename the target vapp
                    response = self.restClientObj.post(url, self.headers, data=str(payloadData, 'utf-8'))
                    responseDict = xmltodict.parse(response.content)
                    if response.status_code == requests.codes.accepted:
                        task = responseDict["Task"]
                        if task["@operationName"] == vcdConstants.RECOMPOSE_VAPP_TASK:
                            taskUrl = task["@href"]
                        if taskUrl:
                            # checking the status of the renaming target vapps task
                            self._checkTaskStatus(taskUrl, vcdConstants.RECOMPOSE_VAPP_TASK)
                        logger.debug("Renamed vApp to {} successfully".format(vAppName))
                    else:
                        raise Exception("Failed to rename the vApp to {} {}".format(vAppName,
                                                                                    responseDict['Error']['@message']))
        except Exception:
            raise

    def getVmSizingPoliciesOfOrgVDC(self, orgVdcId, isTarget=False):
        """
        Description :   Fetches the list of vm sizing policies assigned to the specified Org VDC
        Parameters  :   orgVdcId    -   ID of the org VDC (STRING)
                        isTarget - True if its target Org VDC else False
        """
        try:
            logger.debug("Getting the VM Sizing Policy of Org VDC {}".format(orgVdcId))
            # url to retrieve the vm sizing policy details of the vm
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_VM_SIZING_POLICY.format(orgVdcId))
            # get api call to retrieve the vm sizing policy of the vm
            response = self.restClientObj.get(url, headers=self.headers)
            responseDict = response.json()
            if response.status_code == requests.codes.ok:
                logger.debug("Retrieved the VM Sizing Policy of Org VDC {} successfully".format(orgVdcId))
                if not isTarget:
                    # getting the source vm sizing policy excluding the policy named 'System Default'
                    sourceOrgVDCSizingPolicyList = [response for response in responseDict['values'] if response['name'] != 'System Default']
                else:
                    # getting the source vm sizing policy for the policy named 'System Default'
                    sourceOrgVDCSizingPolicyList = [response for response in responseDict['values'] if response['name'] == 'System Default']
                return sourceOrgVDCSizingPolicyList
            raise Exception("Failed to retrieve VM Sizing Policies of Organization VDC {} {}".format(orgVdcId,
                                                                                                     responseDict['message']))
        except Exception:
            raise

    def applyVDCSizingPolicy(self):
        """
        Description :   Assigns the VM Sizing Policy to the specified OrgVDC
        """
        try:
            # api output file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # retrieving the target org vdc name & id
            targetOrgVdcName = data['targetOrgVDC']['@name']
            targetOrgVdcId = data['targetOrgVDC']['@id']
            # retrieving the source org vdc id
            sourceOrgVdcId = data['sourceOrgVDC']['@id']
            # retrieving the source org vdc vm sizing policy
            sourceSizingPoliciesList = self.getVmSizingPoliciesOfOrgVDC(sourceOrgVdcId)
            if isinstance(sourceSizingPoliciesList, dict):
                sourceSizingPoliciesList = [sourceSizingPoliciesList]
            # iterating over the source org vdc vm sizing policies
            for eachPolicy in sourceSizingPoliciesList:
                # url to assign sizing policies to the target org vdc
                url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                    vcdConstants.ASSIGN_COMPUTE_POLICY_TO_VDC.format(eachPolicy['id']))
                payloadDict = [{"name": targetOrgVdcName,
                                "id": targetOrgVdcId}]
                # creating the payload data
                payloadData = json.dumps(payloadDict)
                self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                # post api call to assign the sizing policies to the target org vdc
                response = self.restClientObj.post(url, headers=self.headers, data=payloadData)
                if response.status_code == requests.codes.ok:
                    logger.debug("VM Sizing Policy {} assigned to Org VDC {} successfully".format(eachPolicy['name'],
                                                                                                  targetOrgVdcName))
                else:
                    raise Exception("Failed to assign VM Sizing Policy {} to Org VDC {} {}".format(eachPolicy['name'],
                                                                                                   targetOrgVdcName,
                                                                                                   response.json()['message']))
        except Exception:
            self.DELETE_TARGET_ORG_VDC = True
            raise

    def deleteOrgVDCvApps(self, sourceOrgVDCId):
        """
        Description :   Delete Org VDC apps
        Parameters  :   sourceOrgVDCId  -   id of the source org vdc (STRING)
        """
        try:
            # splitting the org vdc id as per the requirements of the xml api
            orgVDCId = sourceOrgVDCId.split(':')[-1]
            # url to get the  source org vdc details
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(orgVDCId))
            # get api call to retrieve the source org vdc details
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                # checking if no resource entities present, if so returning
                if responseDict['AdminVdc']['ResourceEntities'] is None:
                    return
                # getting source org vdc enttity list
                sourceOrgVDCEntityList = responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'] if isinstance(responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'], list) else [responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']]
                # getting source vapp list
                vAppList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
                # iterating over the source vapps
                for vApp in vAppList:
                    logger.info("Deleting vApp {} from source Org VDC {}".format(vApp['@name'], responseDict['AdminVdc']['@name']))
                    # delete api call to delete the source vapp
                    response = self.restClientObj.delete(vApp['@href'], self.headers)
                    vAppResponseDict = xmltodict.parse(response.content)
                    if response.status_code == requests.codes.accepted:
                        task = vAppResponseDict["Task"]
                        if task["@operationName"] == vcdConstants.DELETE_VAPP_TASK_NAME:
                            taskUrl = task["@href"]
                        if taskUrl:
                            # checking the status of deleting the source vapp task
                            self._checkTaskStatus(taskUrl, vcdConstants.DELETE_VAPP_TASK_NAME)
                        logger.info("Deleted vApp {} from source Org VDC {} successfully".format(vApp['@name'],
                                                                                                 responseDict['AdminVdc']['@name']))
                    else:
                        raise Exception("Failed to delete vApp {} in source Org VDC {} {}".format(vApp['@name'],
                                                                                                  responseDict['AdminVdc']['@name'],
                                                                                                  vAppResponseDict['Error']['@message']))
        except Exception:
            raise

    def disconnectTargetOrgVDCNetwork(self):
        """
        Description : Disconnect target Org VDC networks
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # rading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # retrieving the target org vdc network list
            targetOrgVDCNetworkList = data['targetOrgVDCNetworks']
            for vdcNetwork in targetOrgVDCNetworkList:
                # handling only the routed networks
                if vdcNetwork['networkType'] == "NAT_ROUTED":
                    vdcNetworkID = vdcNetwork['id']
                    # url to disconnect the target org vdc network
                    url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                           vcdConstants.ALL_ORG_VDC_NETWORKS,
                                           vdcNetworkID)
                    # creating the payload data
                    vdcNetwork['connection'] = None
                    vdcNetwork['networkType'] = 'ISOLATED'
                    payloadData = json.dumps(vdcNetwork)
                    self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                    # put api call to disconnect the target org vdc network
                    response = self.restClientObj.put(url, self.headers, data=payloadData)
                    if response.status_code == requests.codes.accepted:
                        taskUrl = response.headers['Location']
                        # checking the status of disconnecting the target org vdc network task
                        self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_ORG_VDC_NETWORK_TASK_NAME)
                        logger.debug('Disconnected target Org VDC network - {} successfully.'.format(vdcNetwork['name']))
                    else:
                        response = response.json()
                        raise Exception('Failed to disconnect target Org VDC network {} - {}'.format(vdcNetwork['name'],
                                                                                                     response['message']))
        except Exception:
            # setting delete target org vdc, delete target edge gateway & delete target org vdc networks required for rollback
            self.DELETE_TARGET_ORG_VDC = True
            self.DELETE_TARGET_EDGE_GATEWAY = True
            self.DELETE_TARGET_ORG_VDC_NETWORKS = True
            raise

    def reconnectOrgVDCNetworks(self, source=True):
        """
        Description :   Reconnects the Org VDC networks of source/ target Org VDC
        Parameters  :   source  -   Defaults to True meaning reconnect the Source Org VDC Networks (BOOL)
                                -   if False meaning reconnect the Target Org VDC Networks (BOOL)
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from the apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # checking whether to reconnect the org vdc  networks of source or target, and getting the org vdc networks as per the source flag
            if source:
                OrgVDCNetworkList = data['sourceOrgVDCNetworks'] if isinstance(data['sourceOrgVDCNetworks'], list) else [data['sourceOrgVDCNetworks']]
            else:
                OrgVDCNetworkList = data['targetOrgVDCNetworks'] if isinstance(data['targetOrgVDCNetworks'], list) else [data['targetOrgVDCNetworks']]
            # iterating over the org vdc networks
            for vdcNetwork in OrgVDCNetworkList:
                # handling only routed networks
                if vdcNetwork['networkType'] == "NAT_ROUTED":
                    vdcNetworkID = vdcNetwork['id']
                    # url to reconnect the org vdc network
                    url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                           vcdConstants.ALL_ORG_VDC_NETWORKS,
                                           vdcNetworkID)
                    # creating payload using data from apiOutput.json
                    payloadData = json.dumps(vdcNetwork)
                    self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                    # put api call to reconnect the org vdc
                    response = self.restClientObj.put(url, self.headers, data=payloadData)
                    srcTgt = "source" if source else "target"
                    if response.status_code == requests.codes.accepted:
                        taskUrl = response.headers['Location']
                        # checking the status of recoonecting the specified org vdc
                        self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_ORG_VDC_NETWORK_TASK_NAME)
                        logger.debug('Reconnected {} Org VDC network - {} successfully.'.format(srcTgt, vdcNetwork['name']))
                    else:
                        response = response.json()
                        raise Exception('Failed to reconnect {} Org VDC network {} - {}'.format(srcTgt, vdcNetwork['name'],
                                                                                                response['message']))
        except Exception:
            raise

    def disableDistributedRoutingOnOrgVdcEdgeGateway(self, orgVDCEdgeGatewayId):
        """
        Description :   Disables the Distributed Routing on the specified edge gateway
        Parameters  :   orgVDCEdgeGatewayId -   ID of the edge gateway (STRING)
        """
        try:
            # splitting the edge gateway id as per the requuirements of xml api
            edgeGatewayId = orgVDCEdgeGatewayId.split(':')[-1]
            # url to disable distributed routing on specified edge gateway
            url = "{}{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                  vcdConstants.UPDATE_EDGE_GATEWAY_BY_ID.format(edgeGatewayId),
                                  vcdConstants.DISABLE_EDGE_GATEWAY_DISTRIBUTED_ROUTING)
            # post api call to disable distributed routing on the specified edge gateway
            response = self.restClientObj.post(url, self.headers)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.accepted:
                task = responseDict["Task"]
                if task["@operationName"] == vcdConstants.DISABLE_EDGE_GATEWAY_DISTRIBUTED_ROUTING_TASK_NAME:
                    taskUrl = task["@href"]
                if taskUrl:
                    # checking the status of disabling the edge gateway
                    self._checkTaskStatus(taskUrl, vcdConstants.DISABLE_EDGE_GATEWAY_DISTRIBUTED_ROUTING_TASK_NAME)
                logger.debug("Disabled Distributed Routing on source edge gateway successfully")
            else:
                raise Exception("Failed to disable Distributed Routing on source edge gateway {}".format(responseDict['Error']['@message']))
        except Exception:
            raise

    @_isSessionExpired
    def configureDHCP(self):
        """
        Description : Configure DHCP on Target Org VDC networks
        """
        try:
            logger.debug("Configuring DHCP on Target Org VDC Networks")
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading the data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # checking if dhcp is enabled on source edge gateway
            if data['sourceEdgeGatewayDHCP']['enabled'] != "true":
                logger.debug('DHCP service is not enabled or configured in Source')
                return
            # retrieving the dhcp rules of the source edge gateway
            dhcpRules = data['sourceEdgeGatewayDHCP']['ipPools']['ipPool'] if isinstance(data['sourceEdgeGatewayDHCP']['ipPools']['ipPool'], list) else [data['sourceEdgeGatewayDHCP']['ipPools']['ipPool']]
            # iterating over the source edge gateway dhcp rules
            for iprange in dhcpRules:
                start = iprange['ipRange'].split('-')[0]
                end = iprange['ipRange'].split('-')[-1]
                # iterating over the target org vdc networks
                for vdcNetwork in data['targetOrgVDCNetworks']:
                    # handling only the routed networks
                    if vdcNetwork['networkType'] == "NAT_ROUTED":
                        # checking the first three octets of source ip range with first three octets of target networks,
                        # first three octets are same then configuring dhcp on target
                        dhcp_check_list = start.split('.')
                        dhcp_check_list.pop()
                        dhcp_check = '.'.join(dhcp_check_list)
                        for gateway in vdcNetwork['subnets']['values']:
                            vdcNetwork_check_list = gateway['gateway'].split('.')
                            vdcNetwork_check_list.pop()
                            vdcNetwork_check = '.'.join(vdcNetwork_check_list)
                            if dhcp_check == vdcNetwork_check:
                                vdcNetworkID = vdcNetwork['id']
                                # creating payload data
                                payloaddict = {
                                    'enabled': data['sourceEdgeGatewayDHCP']['enabled'],
                                    "dhcpPools": [
                                        {
                                            "enabled": "true",
                                            "ipRange": {
                                                "startAddress": start,
                                                "endAddress": end
                                            },
                                            "defaultLeaseTime": 0
                                        }
                                    ]
                                }
                                if iprange['leaseTime'] == "infinite":
                                    payloaddict['dhcpPools'][0]['maxLeaseTime'] = 2592000
                                else:
                                    payloaddict['dhcpPools'][0]['maxLeaseTime'] = iprange['leaseTime']
                                # url to configure dhcp on target org vdc networks
                                url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                       vcdConstants.ALL_ORG_VDC_NETWORKS,
                                                       vcdConstants.DHCP_ENABLED_FOR_ORG_VDC_NETWORK_BY_ID.format(vdcNetworkID))
                                payloadData = json.dumps(payloaddict)
                                self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                                # put api call to configure dhcp on target org vdc networks
                                response = self.restClientObj.put(url, self.headers, data=payloadData)
                                if response.status_code == requests.codes.accepted:
                                    taskUrl = response.headers['Location']
                                    # checking the status of configuring the dhcp on target org vdc networks task
                                    self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_ORG_VDC_NETWORK_TASK_NAME)
                                    logger.debug('DHCP pool created successfully.')
                                else:
                                    response = response.json()
                                    raise Exception('Failed to create DHCP  - {}'.format(response['message']))
        except:
            raise

    def prepareTargetVDC(self, orgVdcNetworkList, bgpConfigDict):
        """
        Description :   Preparing Target VDC
        Parameters  :   orgVdcNetworkList   -   list of org vdc networks (LIST)
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
            sourceOrgVDCId = data['sourceOrgVDC']['@id']

            # creating target Org VDC
            logger.info('Creating target Org VDC')
            targetOrgVDCId = self.createOrgVDC()
            logger.info('Successfully created target Org VDC')

            # applying the vm placement policy on target org vdc
            logger.info('Applying vm placement policy on target Org vdc')
            self.applyVDCPlacementPolicy()

            # applying the vm sizing policy on target org vdc
            logger.info('Applying vm sizing policy on target Org vdc')
            self.applyVDCSizingPolicy()

            # checking the acl on target org vdc
            logger.info('Checking ACL on target Org vdc')
            self.createACL()

            # creating target Org VDC Edge Gateway
            logger.info('Creating target Org VDC Edge Gateway.')
            self.createEdgeGateway(bgpConfigDict)
            logger.info('Successfully created target Org VDC Edge Gateway.')

            # only if source org vdc networks exist
            if orgVdcNetworkList:
                # creating target Org VDC networks
                logger.info('Creating target Org VDC Networks')
                self.createOrgVDCNetwork()
                logger.info('Successfully created target Org VDC Networks.')

                # disconnecting target Org VDC networks
                logger.info('Disconnecting target Org VDC Networks.')
                self.disconnectTargetOrgVDCNetwork()
                logger.info('Successfully disconnected target Org VDC Networks.')
            else:
                logger.debug('Skipping Target Org VDC Network creation as no source Org VDC network exist.')

            # get the portgroup of source org vdc networks
            logger.info('Get the portgroup of source org vdc networks.')
            portGroupList = self.getPortgroupInfo(orgVdcNetworkList)

            logger.info('Retrieved the portgroup of source org vdc networks.')
            return targetOrgVDCId, portGroupList

        except Exception as err:
            # rolling back
            logger.error('Error occured while preparing Target - {}'.format(err))
            logger.info("RollBack: Enable Source Org VDC")
            self.enableSourceOrgVdc(sourceOrgVDCId)
            logger.info("RollBack: Enable Source vApp Affinity Rules")
            self.enableOrDisableSourceAffinityRules(sourceOrgVDCId, enable=True)
            if self.DELETE_TARGET_ORG_VDC_NETWORKS:
                logger.info("RollBack: Delete Target Org VDC Networks")
                self.deleteOrgVDCNetworks(targetOrgVDCId, source=False)
            if self.DELETE_TARGET_EDGE_GATEWAY:
                logger.info("RollBack: Delete Target Edge Gateway")
                self.deleteNsxTBackedOrgVDCEdgeGateways(targetOrgVDCId)
            if self.DELETE_TARGET_ORG_VDC:
                logger.info("RollBack: Delete Target Org VDC")
                self.deleteOrgVDC(targetOrgVDCId)
            raise

    def configureTargetVDC(self, orgVdcNetworkList, sourceEdgeGatewayId):
        """
        Description :   Configuring Target VDC
        Parameters  :   orgVdcNetworkList   -   list of org vdc networks (LIST)
                        sourceEdgeGatewayId -   id of the source edge gateway (STRING)
        """
        try:
            if orgVdcNetworkList:
                # disconnecting source org vdc networks from edge gateway
                logger.info('Disconnecting source routed Org VDC Networks from source Edge gateway.')
                self.disconnectSourceOrgVDCNetwork(orgVdcNetworkList)
                logger.info('Successfully disconnected routed source Org VDC Networks from source Edge gateway.')

            # connecting dummy uplink to edge gateway
            logger.info('Connecting dummy uplink to source Edge gateway.')
            self.connectUplinkSourceEdgeGateway(sourceEdgeGatewayId)
            logger.info('Successfully connected dummy uplink to source Edge gateway.')

            # disconnecting source org vdc edge gateway from external
            logger.info('Disconnecting source Edge gateway from external network.')
            self.reconnectOrDisconnectSourceEdgeGateway(sourceEdgeGatewayId, connect=False)

            if orgVdcNetworkList:
                # reconnecting target Org VDC networks
                logger.info('Reconnecting target Org VDC Networks.')
                self.reconnectOrgVDCNetworks(source=False)
                logger.info('Successfully reconnected target Org VDC Networks.')
            # configuring dhcp service target Org VDC networks
            self.configureDHCP()

            # reconnecting target org vdc edge gateway from T0
            logger.info('Reconnecting target Edge gateway to T0 router.')
            self.reconnectTargetEdgeGateway()
            logger.info('Successfully reconnected target Edge gateway to T0 router.')
        except Exception:
            raise

    def migrateCatalogItems(self, sourceOrgVDCId, targetOrgVDCId, orgUrl):
        """
        Description : Migrating Catalog Items - vApp Templates and Media & deleting catalog thereafter
        Parameters  :   sourceOrgVDCId  - source Org VDC id (STRING)
                        targetOrgVDCId  - target Org VDC id (STRING)
                        orgUrl          - Organization url (STRING)
        """
        try:
            # getting the source vApp template and media details
            sourceOrgVDCId = sourceOrgVDCId.split(':')[-1]
            # url to get the details of source org vdc
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(sourceOrgVDCId))
            # get api call to retrieve the source org vdc details
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                # checking if no resource entities present, if so returning
                if responseDict['AdminVdc']['ResourceEntities'] is None:
                    return
                # getting the resource entity list of source org vdc
                sourceOrgVDCEntityList = responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'] if isinstance(responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'], list) else [responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']]
                # retrieving the source vapp template list
                sourceVappTemplateList = [vAppTemplateEntity for vAppTemplateEntity in sourceOrgVDCEntityList if
                                          vAppTemplateEntity['@type'] == vcdConstants.TYPE_VAPP_TEMPLATE]
                # retrieving the source vapp media list
                sourceVappMediaList = [vAppMediaEntity for vAppMediaEntity in sourceOrgVDCEntityList if
                                       vAppMediaEntity['@type'] == vcdConstants.TYPE_VAPP_MEDIA]
                # getting the target storage profile details
                targetOrgVDCId = targetOrgVDCId.split(':')[-1]
                # url to get target org vdc details
                url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                    vcdConstants.ORG_VDC_BY_ID.format(targetOrgVDCId))
                # get api call to retrieve the target org vdc details
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = xmltodict.parse(response.content)
                    # retrieving target org vdc storage profiles list
                    targetOrgVDCStorageList = responseDict['AdminVdc']['VdcStorageProfiles']['VdcStorageProfile'] if isinstance(responseDict['AdminVdc']['VdcStorageProfiles']['VdcStorageProfile'], list) else [responseDict['AdminVdc']['VdcStorageProfiles']['VdcStorageProfile']]
                storageProfileHref = ''
                # iterating over the target org vdc storage profiles
                for eachStorageProfile in targetOrgVDCStorageList:
                    # fetching the details of the storage profile
                    orgVDCStorageProfileDetails = self.getOrgVDCStorageProfileDetails(eachStorageProfile['@id'])
                    # checking if the storage profile is the default one
                    if orgVDCStorageProfileDetails['AdminVdcStorageProfile']['Default'] == "true":
                        storageProfileHref = eachStorageProfile['@href']
                        break
                # getting the organization catalog details
                response = self.restClientObj.get(orgUrl, headers=self.headers)
                responseDict = xmltodict.parse(response.content)
                orgId = responseDict['AdminOrg']['@id'].split(':')[-1]
                # if no catalogs exist
                if not responseDict['AdminOrg'].get("Catalogs"):
                    return
                # getting the catalog details
                catalogDetails = responseDict['AdminOrg']["Catalogs"]["CatalogReference"] if isinstance(responseDict['AdminOrg']["Catalogs"]["CatalogReference"], list) else [responseDict['AdminOrg']["Catalogs"]["CatalogReference"]]
                # getting all the vapp templates for organization
                vAppTemplateList = self.getvAppTemplates(orgId)
                # getting all the media for organization
                vAppMediaList = self.getCatalogMedia(orgId)
                vAppTemplateDetails = [vAppTemplate for vAppTemplate in vAppTemplateList for sourceVappTemplate in sourceVappTemplateList if sourceVappTemplate['@name'] == vAppTemplate['name']]
                vAppMediaDetails = [vAppMedia for vAppMedia in vAppMediaList for sourceVappMedia in sourceVappMediaList if sourceVappMedia['@name'] == vAppMedia['name']]
                # getting the catlogs from the corresponding vapptemplates and media
                catalogTemplateList = []
                # iterating over vapp template details to append catalog name in catalogTemplateList if not already in catalogTemplateList
                for vAppTemplate in vAppTemplateDetails:
                    if vAppTemplate['catalogName'] not in catalogTemplateList:
                        catalogTemplateList.append(vAppTemplate['catalogName'])
                # iterating over vapp media details to append catalog name in catalogTemplateList if not already in catalogTemplateList
                for vAppMedia in vAppMediaDetails:
                    if vAppMedia['catalogName'] not in catalogTemplateList:
                        catalogTemplateList.append(vAppMedia['catalogName'])
                # url to create target catalog
                catalogUrl = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                           vcdConstants.CREATE_CATALOG.format(orgId))
                filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
                # iterating over all the catalog templates
                for catalogName in catalogTemplateList:
                    logger.debug('Starting to migrate Catalog - {}'.format(catalogName))
                    # creating target catalogs for migration
                    payloadDict = {'catalogName': catalogName +'-t', 'storageProfileHref': storageProfileHref}
                    # creating the payload data
                    payloadData = self.vcdUtils.createPayload(filePath,
                                                              payloadDict,
                                                              fileType='yaml',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.CREATE_CATALOG_TEMPLATE)
                    payloadData = json.loads(payloadData)
                    self.headers["Content-Type"] = vcdConstants.XML_CREATE_CATALOG
                    # post api call to create target catalogs
                    response = self.restClientObj.post(catalogUrl, self.headers, data=payloadData)
                    if response.status_code == requests.codes.created:
                        logger.debug('Catalog {} created successfully'.format(catalogName+'-t'))
                        responseDict = xmltodict.parse(response.content)
                        # getting the newly created target catalog id
                        catalogId = responseDict["AdminCatalog"]["@id"].split(':')[-1]
                    else:
                        raise Exception('Failed to create Catalog {}'.format(catalogName+'-t'))
                    if catalogId:
                        # getting source catalog items
                        vApptemplateMoveUrl = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                                            vcdConstants.MOVE_VAPP.format(catalogId))
                        if self.headers.get("Content-Type", None):
                            del self.headers['Content-Type']
                        catalogHref = [catalogDetail['@href'] for catalogDetail in catalogDetails if catalogDetail['@name'] == catalogName]
                        catalogHref = catalogHref[0]
                        acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
                        headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
                        response = self.restClientObj.get(catalogHref, headers)
                        responseDict = response.json()
                        if responseDict['catalogItems'] is None:
                            return
                        if response.status_code == requests.codes.ok:
                            catalogItemList = responseDict['catalogItems']['catalogItem'] if isinstance(responseDict['catalogItems']['catalogItem'], list) else [responseDict['catalogItems']['catalogItem']]
                        else:
                            raise Exception('Failed to retrieve catalog item info of catalog {} - {}'.format(catalogName, responseDict['message']))
                        # moving catalog item from the above catalog item list to target catalog created above
                        for catalogItem in catalogItemList:
                            logger.debug('Starting to move catalog item.')
                            # creating payload data to move vapp template
                            payloadDict = {'catalogItemName': catalogItem['name'], 'catalogItemHref': catalogItem['href']}
                            payloadData = self.vcdUtils.createPayload(filePath,
                                                                      payloadDict,
                                                                      fileType='yaml',
                                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                                      templateName=vcdConstants.MOVE_VAPP_TEMPLATE)
                            payloadData = json.loads(payloadData)
                            # post api call to move vapp templates
                            response = self.restClientObj.post(vApptemplateMoveUrl, self.headers, data=payloadData)
                            responseDict = xmltodict.parse(response.content)
                            if response.status_code == requests.codes.accepted:
                                task = responseDict["Task"]
                                taskUrl = task["@href"]
                                if taskUrl:
                                    # checking the status of moving catalog item task
                                    self._checkTaskStatus(taskUrl, task["@operationName"])
                                logger.debug("Catalog Item {} moved successfully".format(catalogItem['name']))
                            else:
                                raise Exception('Failed to move catalog item - {}'.format(responseDict['Error']['@message']))
                        # deleting catalog
                        logger.debug('Deleting catalog {}'.format(catalogName))
                        # url to delete the catalog
                        deleteCatalogUrl = '{}?recursive=true&force=true'.format(catalogHref)
                        # delete api call to delete the catalog
                        response = self.restClientObj.delete(deleteCatalogUrl, self.headers)
                        responseDict = xmltodict.parse(response.content)
                        if response.status_code == requests.codes.accepted:
                            task = responseDict["Task"]
                            if task["@operationName"] == vcdConstants.DELETE_CATALOG_TASK:
                                taskUrl = task["@href"]
                            if taskUrl:
                                # checking the status of deleting the catalog task
                                self._checkTaskStatus(taskUrl, vcdConstants.DELETE_CATALOG_TASK)
                            logger.debug("Catalog {} deleted successfully".format(catalogName))
                        else:
                            raise Exception('Failed to delete catalog {} - {}'.format(catalogName,
                                                                                      responseDict['Error']['@message']))
        except Exception:
            raise

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
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader, 'X-VMWARE-VCLOUD-TENANT-CONTEXT': orgId}
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
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader, 'X-VMWARE-VCLOUD-TENANT-CONTEXT': orgId}
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
                url = "{}{}&page={}&pageSize={}&format=records".format(vcdConstants.XML_API_URL.format(self.ipAddress),
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

    @_isSessionExpired
    def powerOffSourceVapp(self, sourceOrgVDCId):
        """
        Description :   Power off source vApp
        Parameters  :   sourceOrgVDCId  -   id of the source org vdc (STRING)
        """
        try:
            # splitting the org vdc id as per the xml api requirements
            orgVDCId = sourceOrgVDCId.split(':')[-1]
            # url to retrieve the source org vdc details
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(orgVDCId))
            # get api call to retrieve the source org vdc details
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                # checking if no resource entities present, if so returning
                if responseDict['AdminVdc']['ResourceEntities'] is None:
                    return
                # getting list instance of source org vdc resource entities
                sourceOrgVDCEntityList = responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'] if isinstance(responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'], list) else [responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']]
                # getting vapp of source org vdc
                vAppList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if
                            vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
                filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
                # creating payload data
                payloadDict = {'action': "powerOff"}
                payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                          componentName=vcdConstants.COMPONENT_NAME,
                                                          templateName=vcdConstants.UNDEPLOY_VAPP_TEMPLATE)
                payloadData = json.loads(payloadData)
                # iterating over the source vapps
                for vApp in vAppList:
                    self.headers["Content-Type"] = vcdConstants.XML_UNDEPLOY_VAPP
                    # url to power-off the vapp
                    url = "{}/{}".format(vApp['@href'],
                                         vcdConstants.POWER_OFF_VAPP)
                    # post api call to power-off the vapp
                    response = self.restClientObj.post(url, self.headers, data=payloadData)
                    responseDict = xmltodict.parse(response.content)
                    if response.status_code == requests.codes.accepted:
                        task = responseDict["Task"]
                        if task["@operationName"] == vcdConstants.UNDEPLOY_VAPP_TASK:
                            taskUrl = task["@href"]
                        if taskUrl:
                            # checking the status of powering-off the source vapp task
                            self._checkTaskStatus(taskUrl, vcdConstants.UNDEPLOY_VAPP_TASK)
                        logger.debug("Successfully powered-off the source vapp {}".format(vApp['@name']))
                    else:
                        # handling the case of empty vapps, since empty vapps(vapps with no vms in it) do not have power-off option
                        operationString = vcdConstants.CHECK_STRING_FOR_EMPTY_VAPPS.format(vApp['@name'])
                        if operationString in responseDict['Error']['@message']:
                            logger.debug("The power-off operation could not be executed on source vApp since vApp '{}' is not running as there are no vms present in it.".format(vApp['@name']))
                        # handling all the errors other than empty vapp power-off
                        else:
                            raise Exception('Failed to power off source vApp {}'.format(vApp['@name']))
        except:
            raise

    @staticmethod
    def getSourceEdgeGatewayMacAddress(portGroupList, interfacesList):
        """
        Description :   Get source edge gateway mac address for source org vdc network portgroups
        Parameters  :   portGroupList   -   source org vdc networks corresponding portgroup details (LIST)
                        interfacesList  -   Interfaces details of source edge gateway (LIST)
        Returns     :   macAddressList  -   list of mac addresses (LIST)
        """
        logger.debug("Getting Source Edge Gateway Mac Address")
        macAddressList = []
        for portGroup in portGroupList:
            for nicDetail in interfacesList:
                # comparing source org vdc network portgroup moref and edge gateway interface details
                if portGroup['moref'] == nicDetail['value']['backing']['network']:
                    macAddressList.append(nicDetail['value']['mac_address'])
        return macAddressList

    @staticmethod
    def checkIfSourceVappsExist():
        """
        Description :   Checks if there exist atleast a single vapp in source org vdc
        Returns     :   True    -   if found atleast single vapp (BOOL)
                        False   -   if not a single vapp found in source org vdc (BOOL)
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            if not data["sourceOrgVDC"].get('ResourceEntities'):
                logger.debug('No resource entities found in source Org VDC')
                return False
            # getting list instance of resources in the source org vdc
            sourceOrgVDCEntityList = data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'] if isinstance(data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity'], list) else [data["sourceOrgVDC"]['ResourceEntities']['ResourceEntity']]
            vAppList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            if len(vAppList) >= 1:
                return True
            return False
        except Exception:
            raise

    def migrateVapps(self):
        """
        Description : Migrating vApps i.e composing target placeholder vapps and recomposing target vapps
        """
        try:
            # handling the case if there exist no vapps in source org vdc
            # if no source vapps are present then skipping all the below steps as those are not required
            if not self.checkIfSourceVappsExist():
                logger.debug("No Vapps in Source Org VDC, hence skipping migrateVapps task.")
                return

            # create placeholder vapps in target Org VDC
            logger.info('Creating placeholder vApps in target Org VDC.')
            self.composevApp()
            logger.info('Successfully created placeholder vApps in target Org VDC.')

            # create target vApp access control
            logger.info('Creating Access Control in target vApps.')
            self.createVappAccessControlInTargetVapp()

            # change target vApp Owner
            logger.info('Changing target vApps owner.')
            self.changeVAppOwner()

            # renew target vApp Lease
            logger.info('Renew target vApp lease settings.')
            self.renewVappLeaseSettings()

            # recompose target vApp by adding source vm
            logger.info('Recomposing target vApps with source vApp vm.')
            self.recomposeTargetvApp()
            logger.info('Recomposed target vApps with source vApp vm.')

            # configuring Affinity rules
            logger.info('Configuring target Org VDC affinity rules')
            self.enableTargetAffinityRules()

            # creating the startup section for target vapps
            logger.info('Creating the Startup Section for target vApps')
            self.createVappStartupSection()
        except Exception:
            raise

    def getEdgeVmId(self, edgeGatewayId):
        """
        Description : Method to get edge VM ID
        Parameters : edgeGatewayId - Edge gateway ID (STRING)
        Returns : edgeVmId - Edge Gateway VM ID (STRING)
        """
        try:
            logger.debug("Getting Edge VM ID")
            orgVDCEdgeGatewayId = edgeGatewayId.split(':')[-1]
            # url to retrieve the firewall config details of edge gateway
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_STATUS.format(orgVDCEdgeGatewayId))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                # Convert XML data to dictionary
                edgeNetworkDict = xmltodict.parse(response.content)
                # Get the edge gateway VM ID
                # if edge ha is configured, then the response is list
                if isinstance(edgeNetworkDict[vcdConstants.EDGE_GATEWAY_STATUS_KEY][vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY][vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY], list):
                    edgeVmId = [edgeNetworkData for edgeNetworkData in edgeNetworkDict[vcdConstants.EDGE_GATEWAY_STATUS_KEY][vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY][vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY] if
                                edgeNetworkData['haState'] == 'active']
                    if edgeVmId:
                        edgeVmId = edgeVmId[0]["id"]
                    else:
                        raise Exception('Could not find the edge vm id for source edge gateway {}'.format(edgeGatewayId))
                else:
                    edgeVmId = edgeNetworkDict[vcdConstants.EDGE_GATEWAY_STATUS_KEY][vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY][vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY]["id"]
                return edgeVmId
            errorDict = xmltodict.parse(response.content)
            raise Exception("Failed to get edge gateway status. Error - {}".format(errorDict['error']['details']))
        except Exception:
            raise

    def connectUplinkSourceEdgeGateway(self, sourceEdgeGatewayId):
        """
        Description :  Connect another uplink to source Edge Gateways from the specified OrgVDC
        Parameters  :   sourceEdgeGatewayId -   Id of the Organization VDC Edge gateway (STRING)
        """
        try:
            logger.debug("Connecting another uplink to source Edge Gateway")
            orgVDCEdgeGatewayId = sourceEdgeGatewayId.split(':')[-1]
            # url to connect uplink the source edge gateway
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.UPDATE_EDGE_GATEWAY_BY_ID.format(orgVDCEdgeGatewayId))
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
            # retrieving the details of the edge gateway
            response = self.restClientObj.get(url, headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                gatewayInterfaces = responseDict['configuration']['gatewayInterfaces']['gatewayInterface']
                if len(gatewayInterfaces) == 9:
                    raise Exception('No more uplinks present on source Edge Gateway to connect dummy External Uplink.')
                # get the dummy external network details
                fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
                # reading data from apiOutput.json
                with open(fileName, 'r') as f:
                    data = json.load(f)
                dummyExternalNetwork = data['dummyExternalNetwork']
                filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
                # creating the dummy external network link
                networkId = dummyExternalNetwork['id'].split(':')[-1]
                networkHref = "{}network/{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress), networkId)
                # creating the payload data for adding dummy external network
                payloadDict = {'edgeGatewayUplinkName': dummyExternalNetwork['name'],
                               'networkHref': networkHref,
                               'uplinkGateway': dummyExternalNetwork['subnets']['values'][0]['gateway'],
                               'prefixLength': dummyExternalNetwork['subnets']['values'][0]['prefixLength'],
                               'uplinkIpAddress': dummyExternalNetwork['subnets']['values'][0]['ipRanges']['values'][0]['startAddress']}
                payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                          componentName=vcdConstants.COMPONENT_NAME,
                                                          templateName=vcdConstants.CONNECT_ADDITIONAL_UPLINK_EDGE_GATEWAY_TEMPLATE)
                payloadData = json.loads(payloadData)
                gatewayInterfaces.append(payloadData)
                responseDict['configuration']['gatewayInterfaces']['gatewayInterface'] = gatewayInterfaces
                payloadData = json.dumps(responseDict)
                acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
                self.headers["Content-Type"] = vcdConstants.XML_UPDATE_EDGE_GATEWAY
                headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader,
                           'Content-Type': vcdConstants.JSON_UPDATE_EDGE_GATEWAY}
                # updating the details of the edge gateway
                response = self.restClientObj.put(url, headers, data=payloadData)
                responseData = response.json()
                if response.status_code == requests.codes.accepted:
                    if responseData["operationName"] == vcdConstants.UPDATE_EDGE_GATEWAY_TASK_NAME:
                        taskUrl = responseData["href"]
                    if taskUrl:
                        # checking the status of renaming target org vdc task
                        self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_EDGE_GATEWAY_TASK_NAME)
                        logger.debug('Connected dummy uplink to source Edge gateway {} successfully'.format(responseDict['name']))
                        return
                raise Exception("Failed to connect dummy uplink to source Edge gateway {} with error {}".format(responseDict['name'], responseData['message']))
        except Exception:
            raise

    def updateSourceExternalNetwork(self, networkName, subIpPools):
        """
        Description : Update Source External Network sub allocated ip pools
        Parameters : networkName: source external network name (STRING)
                     subIpPools: source edge gateway sub allocated ip pools
        """
        try:
            # url to get all the external networks
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EXTERNAL_NETWORKS)
            # get api call to get all the external networks
            getResponse = self.restClientObj.get(url, self.headers)
            responseDict = getResponse.json()
            if getResponse.status_code == requests.codes.ok:
                # iterating over all the external networks
                for response in responseDict['values']:
                    # checking if networkName is present in the list,
                    if response['name'] == networkName:
                        # getting the external network sub allocated pools
                        externalRanges = response['subnets']['values'][0]['ipRanges']['values']
                        externalRangeList = []
                        # creating range of source external network pool range
                        for externalRange in externalRanges:
                            externalRangeList.extend(self.createIpRange(externalRange['startAddress'], externalRange['endAddress']))
                        # creating range of source edge gateway sub allocated pool range
                        subIpRangeList = []
                        for ipRange in subIpPools:
                            subIpRangeList.extend(self.createIpRange(ipRange['startAddress'], ipRange['endAddress']))
                        # removing the sub allocated ip pools of source edge gateway from source external network
                        for ip in subIpRangeList:
                            externalRangeList.remove(ip)
                        # getting the source edge gateway sub allocated ip pool after removing used ips i.e source edge gateway
                        result = self.createExternalNetworkSubPoolRangePayload(externalRangeList)
                        response['subnets']['values'][0]['ipRanges']['values'] = result
                        payloadData = json.dumps(response)
                        payloadData = json.loads(payloadData)
                        payloadData = json.dumps(payloadData)
                        url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                               vcdConstants.ALL_EXTERNAL_NETWORKS, response['id'])
                        # put api call to update the external networks ip allocation
                        self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                        apiResponse = self.restClientObj.put(url, self.headers, data=payloadData)
                        if apiResponse.status_code == requests.codes.accepted:
                            taskUrl = apiResponse.headers['Location']
                            # checking the status of the creating org vdc network task
                            self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_SOURCE_EXTERNAL_NETWORK_NAME)
                            logger.debug('Updating external network sub allocated ip pool {}'.format(networkName))
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

    @staticmethod
    def createExternalNetworkSubPoolRangePayload(externalNetworkPoolRangeList):
        """
        Description : Create external network sub ip pool range payload
        Parameters : externalNetworkPoolRangeList - external network pool range (LIST)
        """
        resultData = []
        total = 1
        for ipAddress in externalNetworkPoolRangeList:
            startAddress = ipAddress
            if total == len(externalNetworkPoolRangeList):
                nextAddress = startAddress
            else:
                nextAddress = externalNetworkPoolRangeList[total]
            start = list(map(int, startAddress.split('.')))
            next = list(map(int, nextAddress.split('.')))
            if start[3] + 1 == next[3]:
                resultData.append({'startAddress': startAddress, 'endAddress': nextAddress})
            else:
                resultData.append({'startAddress': startAddress, 'endAddress': startAddress})
            total += 1
        return resultData
