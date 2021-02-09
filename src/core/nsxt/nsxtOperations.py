# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: NSXT Module which performs the Bridging Operations
"""

import copy
from functools import wraps
import inspect
import logging
import json
import os
import re
import requests
import time

import src.core.nsxt.nsxtConstants as nsxtConstants


from src.constants import rootDir
from src.commonUtils.sshUtils import SshUtils
from src.commonUtils.restClient import RestAPIClient
from src.commonUtils.utils import Utilities
from src.core.vcd.vcdValidations import description

logger = logging.getLogger('mainLogger')


def remediate(func):
    """
        Description : decorator to save task status and save metadata in Org VDC after task is performed successfully
    """
    @wraps(func)
    def inner(self, *args, **kwargs):
        if self.rollback.metadata.get(func.__name__) or \
                self.rollback.metadata.get(inspect.stack()[2].function, {}).get(func.__name__):
            return

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
            # Saving metadata in source org VDC
            self.vcdObj.saveMetadataInOrgVdc()
            return result
        except Exception as err:
            raise err
    return inner


class NSXTOperations():
    """
    Description: Class that performs the NSXT bridging Operations
    """
    def __init__(self, ipAddress, username, password, rollback, vcdObj, verify):
        """
        Description :   Initializer method of NSXT Operations
        Parameters  :   ipAddress   -   ipaddress of the nsxt (STRING)
                        username    -   Username of the nsxt (STRING)
                        password    -   Password of the nsxt (STRING)
                        verify      -   whether to verify the server's TLS certificate (BOOLEAN)
        """
        self.ipAddress = ipAddress
        self.password = password
        self.nsxtUtils = Utilities()
        self.username = username
        self.verify = verify
        self.rollback = rollback
        self.vcdObj = vcdObj

    def getComponentData(self, componentApi, componentName=None):
        """
        Description   : This function validates the presence of the component in NSX-T
        Parameters    : componentApi    -   API to get the details of the component (STRING)
                        componentName   -   Display-Name of the component (STRING)
        Returns       : componentData if the component with the same display name is already present (DICTIONARY)
        """
        try:
            logger.debug("Fetching NSXT component data")
            componentData = {}
            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, componentApi)
            response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                responseData = json.loads(response.content)
                if nsxtConstants.NSX_API_RESULTS_KEY in responseData.keys():
                    responseData = responseData[nsxtConstants.NSX_API_RESULTS_KEY]
                # If componentName not provided return the whole response dict
                if not componentName:
                    return responseData
                if not isinstance(responseData, list):
                    responseData = [responseData]
                # Iterate through the response for the componentName
                for component in responseData:
                    if component[nsxtConstants.NSX_API_DISPLAY_NAME_KEY] == componentName:
                        componentData = component
                        logger.debug("NSXT Component Name : {}".format(componentName))
                        return componentData
            logger.debug("Failed to get nsxt component details with name {}".format(componentName))
            return componentData
        except Exception:
            raise

    def getNsxtComponentIdByName(self, componentApi, componentName):
        """
        Description : Get ID of NSX-T component id by name
        Parameters  : componentApi  -   API to get the details of the component (STRING)
                      componentName -   Display-Name of the component (STRING)
        Return      : Return ID of NSX-T component id (STRING)
        Raises      : Raises an exception if failed to get id of NSX-T component (EXCEPTION)
        """
        try:
            logger.debug("Getting Component id by Name {}".format(componentName))
            componentData = self.getComponentData(componentApi=componentApi, componentName=componentName)
            if componentData:
                return componentData["id"]
            msg = "Does not found id of nsx-t component: {}".format(componentName)
            logger.error(msg)
            raise Exception(msg)
        except Exception:
            raise

    @description("creation of Bridge Endpoint Profile")
    @remediate
    def createBridgeEndpointProfile(self, edgeClusterNameList, portgroupList):
        """
        Description : Create Bridge Endpoint Profile for the members of edge Cluster
        Parameters  : edgeClusterNameList   -   List of names of the edge cluster participating in bridging (LIST)
                      portgroupList         - List containing details of vxlan backed logical switch (LIST)
        """
        try:
            logger.info('Configuring NSXT Bridging.')
            logger.info('Creating Bridge Endpoint Profile.')
            bridgeEndpointProfileList = []
            logger.debug("Retrieving ID of edge cluster/s: {}".format(', '.join(edgeClusterNameList)))

            edgeClusterMembers = []
            for edgeClusterName in edgeClusterNameList:
                edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                        edgeClusterName)
                if edgeClusterData:
                    list(map(lambda member: member.update({'edgeClusterId': edgeClusterData['id']}),
                             edgeClusterData['members']))
                    edgeClusterMembers += edgeClusterData['members'] if isinstance(edgeClusterData['members'], list)\
                        else [edgeClusterData['members']]
                else:
                    raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))

            filePath = os.path.join(nsxtConstants.NSXT_ROOT_DIRECTORY, 'template.json')
            logger.debug("Successfully retrieved edge Cluster data of {}".format(', '.join(edgeClusterNameList)))
            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.CREATE_BRIDGE_ENDPOINT_PROFILE)
            # taking only the edge transport nodes which match the count of source portgroup details
            edgeNodePortgroupList = zip(edgeClusterMembers, portgroupList)
            for data, _ in edgeNodePortgroupList:
                payloadDict = {'bridgeEndpointProfileName': 'Bridge-Endpoint-Profile-{}'.format(data['transport_node_id']),
                               'edgeClusterId': data['edgeClusterId']}
                payloadData = self.nsxtUtils.createPayload(filePath, payloadDict, fileType='json', componentName=nsxtConstants.COMPONENT_NAME,
                                                           templateName=nsxtConstants.CREATE_BRIDGE_ENDPOINT_PROFILE_COMPONENT_NAME)
                payloadData = json.loads(payloadData)
                payloadData['edge_cluster_member_indexes'] = [data['member_index']]
                payloadData = json.dumps(payloadData)
                response = self.restClientObj.post(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth,
                                                   data=payloadData)
                if response.status_code == requests.codes.created:
                    logger.debug('Bridge Endpoint Profile {} created successfully.'.format(payloadDict['bridgeEndpointProfileName']))
                    bridgeEndpointProfileId = json.loads(response.content)["id"]
                    bridgeEndpointProfileList.append(bridgeEndpointProfileId)
                else:
                    raise Exception('Failed to create Bridge Endpoint Profile. Errors {}.'.format(response.content))
            logger.info('Successfully created Bridge Endpoint Profile.')
        except Exception:
            raise

    @description("creation of Bridge Uplink Host Profile")
    @remediate
    def createUplinkProfile(self):
        """
        Description : Creates a uplink profile
        Returns     : uplinkProfileId   -   ID of the uplink profile created (STRING)
        """
        try:
            logger.info('Creating Bridge Uplink Host Profile.')
            filePath = os.path.join(nsxtConstants.NSXT_ROOT_DIRECTORY, 'template.json')
            if not self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                         componentName=nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME):
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                             nsxtConstants.HOST_SWITCH_PROFILE_API)
                payloadDict = {'uplinkProfileName': nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME}
                # create payload for host profile creation
                payload = self.nsxtUtils.createPayload(filePath=filePath, fileType="json",
                                                       componentName=nsxtConstants.COMPONENT_NAME,
                                                       templateName=nsxtConstants.CREATE_UPLINK_PROFILE,
                                                       payloadDict=payloadDict)
                payload = json.loads(payload)
                payload["teaming"]["active_list"].append(dict(uplink_type="PNIC", uplink_name="Uplink1"))
                payload = json.dumps(payload)
                # REST POST call to create uplink profile
                response = self.restClientObj.post(url=url, headers=nsxtConstants.NSXT_API_HEADER, data=payload, auth=self.restClientObj.auth)
                if response.status_code == requests.codes.created:
                    logger.debug("Successfully created uplink profile {}".format(nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME))
                    uplinkProfileId = json.loads(response.content)["id"]
                    logger.info('Successfully created Bridge Uplink Host Profile.')
                    return uplinkProfileId
                msg = "Failed to create uplink profile {}.".format(nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)
                logger.error(msg)
                raise Exception(msg, response.status_code)
            msg = "Uplink {} already exists.".format(nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)
            logger.error(msg)
            raise Exception(msg)
        except Exception:
            raise

    @description("addition of Bridge Transport Zone to Bridge Edge Transport Nodes")
    @remediate
    def updateEdgeTransportNodes(self, edgeClusterNameList, portgroupList, transportZoneName):
        """
        Description: Update Edge Transport Node
        Parameters:  edgeClusterNameList    - List of names of the edge cluster participating in bridging (LIST)
                     portgroupList          - List containing details of vxlan backed logical switch (LIST)
                     transportZoneName      - Name of the bridge transport zone (STRING)
        """
        try:
            logger.info('Adding Bridge Transport Zone to Bridge Edge Transport Nodes.')
            uplinkProfileData = self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                                      componentName=nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)

            transportZoneData = self.getComponentData(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName)

            logger.debug("Retrieving ID of edge cluster: {}".format(', '.join(edgeClusterNameList)))
            edgeClusterMembers = []
            for edgeClusterName in edgeClusterNameList:
                edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                        edgeClusterName)
                if edgeClusterData:
                    edgeClusterMembers += edgeClusterData['members'] if isinstance(edgeClusterData['members'], list) \
                        else [edgeClusterData['members']]
                else:
                    raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))

            edgeNodePortgroupList = zip(edgeClusterMembers, portgroupList)
            for data, portGroup in edgeNodePortgroupList:
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                             nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(data['transport_node_id']))
                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    edgeNodeData = json.loads(response.content)
                    logger.debug("Updating Edge Transport Node {}".format(edgeNodeData['display_name']))
                    hostSwitchSpec = edgeNodeData["host_switch_spec"]["host_switches"]
                    # get the last used uplink
                    lastUsedUplink = hostSwitchSpec[-1]['pnics'][-1]['device_name']
                    # get the next unused uplink
                    nextUnusedUplink = re.sub('\d', lambda x: str(int(x.group(0)) + 1), lastUsedUplink)
                    newHostSwitchSpec = {"host_switch_name": transportZoneData['host_switch_name'],
                                         "host_switch_profile_ids": [{"key": "UplinkHostSwitchProfile", "value": uplinkProfileData['id']}],
                                         "pnics": [{"device_name": nextUnusedUplink, "uplink_name": uplinkProfileData['teaming']['active_list'][0]['uplink_name']}],
                                         "is_migrate_pnics": False,
                                         "ip_assignment_spec": {"resource_type": "AssignedByDhcp"}}
                    hostSwitchSpec.append(newHostSwitchSpec)
                    transportZoneList = edgeNodeData['transport_zone_endpoints']
                    newTransportZoneList = {"transport_zone_id": transportZoneData['id'],
                                            "transport_zone_profile_ids": edgeNodeData['transport_zone_endpoints'][0]['transport_zone_profile_ids']}
                    transportZoneList.append(newTransportZoneList)
                    dataNetworkList = edgeNodeData['node_deployment_info']['deployment_config']['vm_deployment_config']['data_network_ids']
                    # since nsxt 3.0 null coming in data_network_ids while getting edge transport node details
                    if None in dataNetworkList:
                        dataNetworkList.remove(None)
                    newDataNetworkList = portGroup['moref']
                    dataNetworkList.append(newDataNetworkList)
                    edgeNodeData["host_switch_spec"]["host_switches"] = hostSwitchSpec
                    edgeNodeData["transport_zone_endpoints"] = transportZoneList
                    edgeNodeData['node_deployment_info']['deployment_config']['vm_deployment_config']['data_network_ids'] = dataNetworkList
                    del edgeNodeData['_create_time']
                    del edgeNodeData['_last_modified_user']
                    del edgeNodeData['_last_modified_time']
                    revision = edgeNodeData['_revision']
                    edgeNodeData['_revision'] = revision
                    url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                 nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(edgeNodeData['node_id']))
                    payloadDict = json.dumps(edgeNodeData)
                    response = self.restClientObj.put(url=url, headers=nsxtConstants.NSXT_API_HEADER, data=payloadDict,
                                                      auth=self.restClientObj.auth)
                    if response.status_code == requests.codes.ok:
                        logger.debug("Successfully updated Edge Transport node {}".format(edgeNodeData['display_name']))
                    else:
                        msg = "Failed to update Edge Transport node {} with error {}.".format(edgeNodeData['display_name'], response.json()['error_message'])
                        logger.error(msg)
                        raise Exception(msg)
                else:
                    msg = "Failed to get Edge Transport node {} with error {}.".format(data['transport_node_id'], response.json()['error_message'])
                    logger.error(msg)
                    raise Exception(msg)
            logger.info('Successfully added Bridge Transport Zone to Bridge Edge Transport Nodes.')
        except Exception:
            raise

    @description("attaching bridge endpoint profile to Logical Switch")
    @remediate
    def attachBridgeEndpointSegment(self, edgeClusterNameList, portgroupList, transportZoneName, targetOrgVDCNetworks):
        """
        Description : Attach Bridge Endpoint to logical segments
        Parameters  : edgeClusterNameList - List of names of the edge cluster participating in bridging (LIST)
                      portgroupList       - List containing details of vxlan backed logical switch (LIST)
                      transportZoneName   - Name of the bridge transport zone (STRING)
        """
        try:
            logger.info('Attaching bridge endpoint profile to Logical Switch.')
            transportZoneId = self.getNsxtComponentIdByName(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName)
            data = self.rollback.apiData
            switchList = []
            for orgVdcNetwork in targetOrgVDCNetworks:
                networkData = self.getComponentData(componentApi=nsxtConstants.CREATE_LOGICAL_SWITCH_API,
                                                    componentName=orgVdcNetwork['name'] + '-' + orgVdcNetwork['id'].split(':')[-1])
                switchTags = [data for data in networkData['tags'] if orgVdcNetwork['backingNetworkId'] in data['tag']]

                if switchTags:
                    switchList.append((networkData['display_name'], networkData['id'], orgVdcNetwork['networkType']))

            edgeSwitchList = []
            for item in portgroupList:
                for item1 in switchList:
                    if item['networkName']+'-v2t' in item1[0]:
                        edgeSwitchList.append((item, item1[1], item1[2]))

            bridgeEndpointUrl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.CREATE_BRIDGE_ENDPOINT_API)
            logicalPorturl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.CREATE_LOGICAL_SWITCH_PORT_API)
            filePath = os.path.join(nsxtConstants.NSXT_ROOT_DIRECTORY, 'template.json')
            edgeNodeList = []
            logger.debug("Retrieving ID of edge cluster: {}".format(', '.join(edgeClusterNameList)))
            edgeClusterMembers = []
            for edgeClusterName in edgeClusterNameList:
                edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                        edgeClusterName)
                if edgeClusterData:
                    edgeClusterMembers += edgeClusterData['members'] if isinstance(edgeClusterData['members'], list)\
                        else [edgeClusterData['members']]
                else:
                    raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))

            edgeNodeSwitchList = zip(edgeClusterMembers, edgeSwitchList)
            for data, geneveLogicalSwitch in edgeNodeSwitchList:
                edgeNodeId = data['transport_node_id']
                bridgeProfileDict = self.getComponentData(componentApi=nsxtConstants.CREATE_BRIDGE_ENDPOINT_PROFILE)
                bridgeProfile = [bridgeProfile for bridgeProfile in bridgeProfileDict if edgeNodeId in bridgeProfile['display_name']]
                if not bridgeProfile:
                    continue
                payloadDict = {'BridgeEndpointName': 'Bridge-Endpoint-{}'.format(edgeNodeId),
                               'bridgeEndpointProfileId': bridgeProfile[0]['id'],
                               'transportZoneId': transportZoneId}
                payloadData = self.nsxtUtils.createPayload(filePath, payloadDict, fileType='json',
                                                           componentName=nsxtConstants.COMPONENT_NAME,
                                                           templateName=nsxtConstants.CREATE_BRIDGE_ENDPOINT_TEMPLATE)
                response = self.restClientObj.post(url=bridgeEndpointUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                   auth=self.restClientObj.auth,
                                                   data=payloadData)
                if response.status_code == requests.codes.created:
                    logger.debug('Bridge Endpoint {} created'.format(payloadDict['BridgeEndpointName']))
                    bridgeEndpointId = json.loads(response.content)["id"]
                    payloadDict = {'logicalSwitchId': geneveLogicalSwitch[1],
                                   'bridgeProfileId': bridgeEndpointId}
                    payloadData = self.nsxtUtils.createPayload(filePath, payloadDict, fileType='json',
                                                               componentName=nsxtConstants.COMPONENT_NAME,
                                                               templateName=nsxtConstants.CREATE_LOGICAL_SWITCH_PORT_TEMPLATE)
                    response = self.restClientObj.post(url=logicalPorturl, headers=nsxtConstants.NSXT_API_HEADER,
                                                       auth=self.restClientObj.auth,
                                                       data=payloadData)
                    if response.status_code == requests.codes.created:
                        logger.debug('Bridge Endpoint profile attached to Logical switch {}'.format(geneveLogicalSwitch[1]))
                        if geneveLogicalSwitch[2] == 'NAT_ROUTED':
                            edgeNodeList.append(edgeNodeId)
                        self.rollback.apiData['edgeNodeList'] = edgeNodeList
                    else:
                        raise Exception('Failed to attach Bridge Endpoint Profile to logical switch {}.'.format(geneveLogicalSwitch[1]))
                else:
                    logger.debug('Failed to create Bridge Endpoint')
                    raise Exception('Failed to create Bridge Endpoint')
            logger.info('Successfully attached bridge endpoint profile to Logical Switch.')
            logger.info('Successfully configured NSXT Bridging.')
            return
        except Exception:
            raise

    @description("verification of Bridge Connectivity")
    @remediate
    def verifyBridgeConnectivity(self, vcdObj, vcenterObj):
        """
        Description :   Verifying bridge connectivity by checking on edge nodes whether it has learned source edge gateway mac address
        Parameters  :   vcdObj - Object of vcdOperations module (Object)
                        vcenterObj - Object of vcenterApis module (Object)
        """
        try:
            logger.info('Verifying bridging connectivity')
            # Sleeping for 180 seconds before verifying bridging connectivity
            time.sleep(180)
            # get source edge gateway vm id
            edgeVMIdList = vcdObj.getEdgeVmId()

            sourceEdgeGatewayMacAddressList = []
            for edgeVMId in edgeVMIdList:
                # get routed network interface details of the nsx-v edge vm using vcenter api's
                interfaceDetails = vcenterObj.getEdgeVmNetworkDetails(edgeVMId)

                # get the source edge gateway mac address for routed networks
                sourceEdgeGatewayMacAddressList += vcdObj.getSourceEdgeGatewayMacAddress(interfaceDetails)

            edgeNodeList = copy.deepcopy(self.rollback.apiData['edgeNodeList'])
            macAddressList = []
            for edgeNode in edgeNodeList:
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                             nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(edgeNode))
                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    edgeNodeData = json.loads(response.content)
                    url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                 nsxtConstants.CREATE_BRIDGE_ENDPOINT_PROFILE)
                    response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                      auth=self.restClientObj.auth)
                    if response.status_code == requests.codes.ok:
                        data = json.loads(response.content)
                        bridgeEndpointProfile = [response for response in data['results'] if edgeNodeData['id'] in response['display_name']]
                        if bridgeEndpointProfile:
                            bridgeEndpointProfileId = bridgeEndpointProfile[0]['id']
                        else:
                            raise Exception('Could not find the the bridge endpoint profile mapped with Edge node {}'.format(edgeNodeData['id']))
                    url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                 nsxtConstants.CREATE_BRIDGE_ENDPOINT_API)
                    response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                      auth=self.restClientObj.auth)
                    if response.status_code == requests.codes.ok:
                        data = json.loads(response.content)
                        bridgeEndpoint = [response for response in data['results'] if response['bridge_endpoint_profile_id'] == bridgeEndpointProfileId]
                        if bridgeEndpoint:
                            bridgeEndpointId = bridgeEndpoint[0]['id']
                        else:
                            raise Exception('Could not find the the bridge endpoint attached with Bridge endpoint profile {}'.format(bridgeEndpointProfileId))
                    sshObj = SshUtils(edgeNodeData['node_deployment_info']['ip_addresses'][0], 'admin', self.password)
                    cmd = 'get l2bridge-port {} mac-sync-table'.format(bridgeEndpointId)
                    output = sshObj.runCmdOnSsh(cmd, 150)
                    output = output.decode().split('\n')
                    logger.debug('Bridge ports mac sync table - {}'.format(output))
                    regex = re.compile('MAC    ')
                    output = [''.join(x.split()) for x in output if regex.match(x)]
                    macAddressOutput = ''.join(output)
                    if output:
                        macAddressList.append(macAddressOutput)
            macAddressList = [macAddress for macAddress in macAddressList]
            verifiedOutput = [sourceEdgeGatewayMac for sourceEdgeGatewayMac in sourceEdgeGatewayMacAddressList for macAddress in macAddressList if sourceEdgeGatewayMac in macAddress]
            # if edge node and mac address present then only validate
            if edgeNodeList and sourceEdgeGatewayMacAddressList:
                if verifiedOutput and len(verifiedOutput) == len(sourceEdgeGatewayMacAddressList):
                    logger.debug('Bridging Connectivity checks successful. Source Edge gateway MAC address learned by edge transport nodes')
                    logger.info('Successfully verified bridging connectivity')
                else:
                    errorMessage = 'Bridging Connectivity checks failed. Source Edge gateway MAC address could not learned by edge nodes'
                    logger.error(errorMessage)
                    raise Exception(errorMessage)
            else:
                logger.warning('Not verifiying bridge connectivity checks as all networks are Isolated.')
        except Exception:
            raise

    def clearBridging(self, orgVDCNetworkList, rollback=False):
        """
        Description :   Remove Logical switch ports, Bridge Endpoint, Bridge Endpoint Profiles, edge transport nodes etc
        Parameters  :   orgVDCNetworkList     - List containing org vdc network details (LIST)
        """
        try:
            if rollback:
                logger.info("RollBack: Clearing NSX-T Bridging")
            switchList = []
            logicalPorturl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                    nsxtConstants.CREATE_LOGICAL_SWITCH_PORT_API)
            response = self.restClientObj.get(url=logicalPorturl, headers=nsxtConstants.NSXT_API_HEADER,
                                              auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                logicalPortsList = json.loads(response.content)
                logicalPortsList = logicalPortsList['results']
            # getting the logical switch id of the corresponding org vdc network
            for orgVdcNetwork in orgVDCNetworkList:
                networkData = self.getComponentData(componentApi=nsxtConstants.CREATE_LOGICAL_SWITCH_API,
                                                    componentName=orgVdcNetwork['name']+ '-' + orgVdcNetwork['id'].split(':')[-1])
                switchTags = [data for data in networkData['tags'] if orgVdcNetwork['backingNetworkId'] in data['tag']]

                if switchTags:
                    switchList.append((networkData['display_name'], networkData['id']))
            # get the attached bridge endpoint id from logical switch ports
            bridgeEndpointIdList = [logicalPort['attachment']['id'] for logicalPort in logicalPortsList for switch in switchList if switch[1] == logicalPort['logical_switch_id'] and
                                    logicalPort['attachment']['attachment_type'] == 'BRIDGEENDPOINT']
            # get the logical port id
            logicalPortList = [logicalPort['id'] for logicalPort in logicalPortsList for switch in
                               switchList if switch[1] == logicalPort['logical_switch_id'] and
                               logicalPort['attachment']['attachment_type'] == 'BRIDGEENDPOINT']
            # detach the logical switch port
            for logicalSwitchPort in logicalPortList:
                logicalSwitchPorturl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.DELETE_LOGICAL_SWITCH_PORT_API.format(logicalSwitchPort))
                response = self.restClientObj.delete(url=logicalSwitchPorturl, headers=nsxtConstants.NSXT_API_HEADER,
                                                     auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    logger.debug('Logical Switch Port {} detached from Bridge successfully'.format(logicalSwitchPort))
                else:
                    responseData = json.loads(response.content)
                    msg = 'Failed to detach Logical Switch Port {} from Bridge - {}'.format(logicalSwitchPort, responseData['error_message'])
                    raise Exception(msg)
            # get the bridge endpoint
            if bridgeEndpointIdList:
                bridgeEndpointProfileIdResults = []
                for bridgeEndpoint in bridgeEndpointIdList:
                    bridgeEndpointUrl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                               nsxtConstants.GET_BRIDGE_ENDPOINT_BY_ID_API.format(bridgeEndpoint))
                    response = self.restClientObj.get(url=bridgeEndpointUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                      auth=self.restClientObj.auth)
                    # delete the bridge endpoint
                    if response.status_code == requests.codes.ok:
                        bridgeEndpointResult = json.loads(response.content)
                        # getting the bridge endpoint profile id from a bridge endpoint
                        bridgeEndpointProfileIdResults.append(bridgeEndpointResult['bridge_endpoint_profile_id'])
                        response = self.restClientObj.delete(url=bridgeEndpointUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                             auth=self.restClientObj.auth)
                        if response.status_code == requests.codes.ok:
                            logger.debug('Bridge Endpoint {} deleted successfully'.format(bridgeEndpoint))
                        else:
                            responseData = json.loads(response.content)
                            msg = 'Failed to delete Bridge Endpoint {} - {}'.format(bridgeEndpoint, responseData['error_message'])
                            raise Exception(msg)
                edgeTransportNodeList = []
                # get the bridge endpoint profile
                for bridgeEndpointProfileId in bridgeEndpointProfileIdResults:
                    bridgeEndpointProfileUrl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                                      nsxtConstants.GET_BRIDGE_ENDPOINT_PROFILE_BY_ID_API.format(bridgeEndpointProfileId))
                    response = self.restClientObj.get(url=bridgeEndpointProfileUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                      auth=self.restClientObj.auth)
                    # delete the bridge endpoint profile
                    if response.status_code == requests.codes.ok:
                        bridgeEndpointProfileResult = json.loads(response.content)
                        transportNodeId = re.sub('Bridge-Endpoint-Profile-', '', bridgeEndpointProfileResult['display_name'])
                        # getting the edge transport node from a bridge endpoint profile
                        if transportNodeId not in edgeTransportNodeList:
                            edgeTransportNodeList.append(transportNodeId)
                        response = self.restClientObj.delete(url=bridgeEndpointProfileUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                             auth=self.restClientObj.auth)
                        if response.status_code == requests.codes.ok:
                            logger.debug('Bridge Endpoint profile {} deleted Successfully'.format(bridgeEndpointProfileResult['display_name']))
                        else:
                            responseData = json.loads(response.content)
                            msg = 'Failed to delete Bridge Endpoint Profile {} - {}'.format(bridgeEndpointProfileResult['display_name'], responseData['error_message'])
                            raise Exception(msg)
                # updating the transport node details inside edgeTransportNodeList
                for edgeTransportNode in edgeTransportNodeList:
                    url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                 nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(edgeTransportNode))
                    response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                      auth=self.restClientObj.auth)
                    if response.status_code == requests.codes.ok:
                        edgeNodeData = json.loads(response.content)
                        logger.debug("Updating Edge Transport Node {} by removing Bridge Transport zone".format(edgeNodeData['display_name']))
                        hostSwitchSpec = edgeNodeData["host_switch_spec"]["host_switches"]
                        hostSwitchSpec.pop()
                        transportZoneList = edgeNodeData['transport_zone_endpoints']
                        transportZoneList.pop()
                        dataNetworkList = edgeNodeData['node_deployment_info']['deployment_config']['vm_deployment_config']['data_network_ids']
                        dataNetworkList.pop()
                        edgeNodeData["host_switch_spec"]["host_switches"] = hostSwitchSpec
                        edgeNodeData["transport_zone_endpoints"] = transportZoneList
                        edgeNodeData['node_deployment_info']['deployment_config']['vm_deployment_config'][
                            'data_network_ids'] = dataNetworkList
                        del edgeNodeData['_create_time']
                        del edgeNodeData['_last_modified_user']
                        del edgeNodeData['_last_modified_time']
                        revision = edgeNodeData['_revision']
                        edgeNodeData['_revision'] = revision
                        url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                     nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(
                                                                         edgeNodeData['node_id']))
                        payloadDict = json.dumps(edgeNodeData)
                        response = self.restClientObj.put(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                          data=payloadDict,
                                                          auth=self.restClientObj.auth)
                        if response.status_code == requests.codes.ok:
                            logger.debug(
                                "Successfully updated Edge Transport node {} by removing Bridge Transport zone".format(edgeNodeData['display_name']))
                        else:
                            msg = "Failed to update Edge Transport node {}.".format(edgeNodeData['display_name'])
                            logger.error(msg)
                            raise Exception(msg)
                    else:
                        msg = "Failed to get Edge Transport node {}.".format(edgeTransportNode)
                        logger.error(msg)
                        raise Exception(msg)
            # getting the host switch profile details
            hostSwitchProfileData = self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                                          componentName=nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)
            if hostSwitchProfileData:
                hostSwitchProfileId = hostSwitchProfileData['id']
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                             nsxtConstants.DELETE_HOST_SWITCH_PROFILE_API.format(hostSwitchProfileId))
                response = self.restClientObj.delete(url, headers=nsxtConstants.NSXT_API_HEADER,
                                                     auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    logger.debug('Host Switch Profile {} deleted successfully'.format(hostSwitchProfileId))
                else:
                    responseData = json.loads(response.content)
                    msg = 'Failed to delete Host Switch Profile {} - {}'.format(hostSwitchProfileId, responseData['error_message'])
                    raise Exception(msg)
        except Exception:
            raise

    def getComputeManagers(self):
        """
        Description :    Get the list of all Compute managers
        """
        try:
            # getting the RestAPIClient object to call the REST apis
            self.restClientObj = RestAPIClient(self.username, self.password, self.verify)
            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.LIST_COMPUTE_MANAGERS)
            response = self.restClientObj.get(url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                logger.debug("Successfully logged into NSX-T {}".format(self.ipAddress))
            elif response.status_code == requests.codes.forbidden:
                errorDict = response.json()
                logger.error(errorDict['error_message'] +
                             'The account will be locked out for 15 minutes after the fifth consecutive failed login attempt.')
                raise Exception('Failed to login to NSX-T with the given credentials.')
        except Exception:
            raise

    def configureNSXTBridging(self, edgeClusterNameList, transportZoneName, targetOrgVdcNetworkList):
        """
        Description :   Configure NSXT bridging
        Parameters  :   edgeClusterNameList  - List of NSX-T edge cluster names required for bridging (STRING)
                        transportZoneName - NSX-T transport zone name required for bridging (STRING)
                        targetOrgVdcNetworkList - Target Org VDC network list (LIST)
        """
        try:
            data = self.rollback.apiData
            portGroupList = data.get('portGroupList')

            # create bridge endpoint profile
            self.createBridgeEndpointProfile(edgeClusterNameList, portGroupList)

            # create host uplink profile for bridge n-vds
            self.createUplinkProfile()

            # add bridge transport to bridge edge transport nodes
            self.updateEdgeTransportNodes(edgeClusterNameList, portGroupList, transportZoneName)

            # # attach bridge endpoint profile to logical switch
            self.attachBridgeEndpointSegment(edgeClusterNameList, portGroupList, transportZoneName, targetOrgVdcNetworkList)
        except Exception:
            raise

    def validateBridgeUplinkProfile(self):
        """
        Description :   Validates that the bridge-uplink-profile doesnot already exists
                        If exists raises exception
        """
        try:
            if not self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                         componentName=nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME):
                logger.debug("Validated successfully that the {} does not exist".format(nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME))
            else:
                msg = "Host Switch Profile uplink - '{}' already exists.".format(nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)
                raise Exception(msg)
        except Exception:
            raise

    def validateOrgVdcNetworksAndEdgeTransportNodes(self, edgeClusterNameList, orgVdcNetworkList):
        """
        Description :   Validates the number of networks in source Org Vdc match with the number of Edge Transport Nodes in the specified cluster name
        Parameters  :   edgeClusterNameList     -   List of names of the cluster (STRING)
                        orgVdcNetworkList   -   Source Org VDC Network List (LIST)
        """
        try:
            logger.debug("Retrieving ID of edge cluster: {}".format(', '.join(edgeClusterNameList)))
            edgeTransportNodeList = []
            edgeClusterNotFound = []
            for edgeClusterName in edgeClusterNameList:
                edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                        edgeClusterName)
                if not edgeClusterData:
                    edgeClusterNotFound.append(edgeClusterName)
                else:
                    edgeTransportNodeList += edgeClusterData['members'] \
                        if isinstance(edgeClusterData['members'], list) else [edgeClusterData['members']]

            if edgeClusterNotFound:
                raise Exception(
                    "Edge Cluster '{}' do not exist in NSX-T, so can't validate org VDC networks and transport nodes".format(
                        ', '.join(edgeClusterNotFound)))

            if len(orgVdcNetworkList) <= len(edgeTransportNodeList):
                logger.debug("Validated successfully the number of source Org VDC networks are equal/less than the number of Edge Transport Nodes in the cluster {}".format(edgeClusterName))
            else:
                raise Exception("Number of Source Org VDC Networks should always be equal/less than the number of Edge Transport Nodes in the cluster {}".format(edgeClusterName))
        except Exception:
            self.ENABLE_SOURCE_ORG_VDC_AFFINITY_RULES = True
            raise

    def fetchEdgeClusterIdForTier0Gateway(self, tier0GatewayName):
        """
            Description :   Get edge cluster name for tier-0 gateway
            Parameters  :   tier0GatewayName -  Name of tier-0 gateway (STRING)
        """
        try:
            tier0GatewayData = self.getComponentData(nsxtConstants.LOGICAL_ROUTER_API,
                                                    tier0GatewayName)

            if not tier0GatewayData:
                raise Exception(
                    "TIER-0 Gateway '{}' does not exist in NSX-T".format(tier0GatewayName))
            else:
                return tier0GatewayData['edge_cluster_id']
        except:
            raise

    def fetchEdgeClusterDetails(self, edgeClusterName):
        """
            Description :   Validate whether edge cluster exists and return its details
            Parameters  :   edgeClusterName -   List of names of the cluster (STRING)
        """
        try:
            edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                    edgeClusterName)
            if not edgeClusterData:
                raise Exception(
                    "Edge Cluster '{}' does not exist in NSX-T".format(edgeClusterName))
            else:
                return edgeClusterData
        except:
            raise



    def validateEdgeNodesNotInUse(self, edgeClusterNameList):
        """
        Description :   Validates that None Edge Transport Nodes are in use in the specified Edge Cluster
        Parameters  :   edgeClusterNameList -   List of names of the cluster (STRING)
        """
        try:
            hostSwitchNameList = list()
            logger.debug("Retrieving ID of edge cluster: {}".format(', '.join(edgeClusterNameList)))
            edgeTransportNodeList = []
            edgeClusterNotFound = []
            for edgeClusterName in edgeClusterNameList:
                edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                        edgeClusterName)
                if not edgeClusterData:
                    edgeClusterNotFound.append(edgeClusterName)
                else:
                    edgeTransportNodeList += edgeClusterData['members'] \
                        if isinstance(edgeClusterData['members'], list) else [edgeClusterData['members']]

            if edgeClusterNotFound:
                raise Exception(
                    "Edge Cluster '{}' do not exist in NSX-T, so can't validate org VDC networks and transport nodes".format(
                        ', '.join(edgeClusterNotFound)))

            for tranportNode in edgeTransportNodeList:
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                             nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(tranportNode['transport_node_id']))
                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    if responseDict.get('host_switch_spec'):
                        hostSwitchSpec = responseDict["host_switch_spec"]["host_switches"]
                        for hostSwitch in hostSwitchSpec:
                            for pnics in hostSwitch["pnics"]:
                                if pnics["device_name"] == nsxtConstants.PNIC_NAME:
                                    hostSwitchNameList.append(responseDict['display_name'])
                    else:
                        raise Exception('Host switch specification not available')
                else:
                    raise Exception('Failed to fetch transport node details')
            if hostSwitchNameList:
                raise Exception("Transport Node: {} already in use".format(','.join(hostSwitchNameList)))
            else:
                logger.debug("Validated successfully that any of Transport Nodes from cluster/s {} are not in use".format(', '.join(edgeClusterNameList)))
        except Exception:
            raise

    def validateTransportZoneExistsInNSXT(self, transportZoneName):
        """
        Description :   Validates that the specified transport zone exists in the NSXT
        Parameters  :   transportZoneName -   Name of the cluster (STRING)
        """
        try:
            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.TRANSPORT_ZONE_API)
            response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                transportZonesList = responseDict['results'] if isinstance(responseDict['results'], list) else [responseDict['results']]
                for transportZone in transportZonesList:
                    if transportZone['display_name'] == transportZoneName:
                        logger.debug("Validated successfully, transport zone '{}' exists in NSX-T".format(transportZoneName))
                        break
                else:
                    raise Exception("Transport Zone '{}' doesnot exist in NSX-T".format(transportZoneName))
        except Exception:
            raise

    def getTier0LocaleServicesDetails(self, tier0GatewayName):
        try:
            localeServicesUrl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.GET_LOCALE_SERVICES_API.format(tier0GatewayName))
            response = self.restClientObj.get(url=localeServicesUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                              auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                if responseDict['result_count'] > 1:
                    raise Exception('More than one local services present')
                else:
                    return responseDict['results'][0]
            else:
                raise Exception('Failed to get tier0 locale services details')
        except Exception:
            raise

    def getTier0GatewayDetails(self, tier0GatewayName):
        """
        Description: Get Tier-0 gateway bgp routing details
        Parameters: tier0GatewayName - Name of tier-0 gateway (STRING)
        """
        try:
            tier0localeServices = self.getTier0LocaleServicesDetails(tier0GatewayName)
            bgpRoutingConfigUrl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.BGP_ROUTING_CONFIG_API.format(tier0GatewayName,tier0localeServices['id']))
            response = self.restClientObj.get(url=bgpRoutingConfigUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                              auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                return responseDict
            else:
                raise Exception('Failed to get Tier0 gateway details')
        except Exception:
            raise
