# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: NSXT Module which performs the Bridging Operations
"""

import logging
import json
import os
import re
import requests

import src.core.nsxt.nsxtConstants as nsxtConstants

from src.constants import rootDir
from src.commonUtils.sshUtils import SshUtils
from src.commonUtils.restClient import RestAPIClient
from src.commonUtils.utils import Utilities

logger = logging.getLogger('mainLogger')


class NSXTOperations():
    """
    Description: Class that performs the NSXT bridging Operations
    """
    CLEAR_NSX_T_BRIDGING = False
    ENABLE_SOURCE_ORG_VDC_AFFINITY_RULES = False

    def __init__(self, ipAddress, username, password):
        """
        Description :   Initializer method of NSXT Operations
        Parameters  :   ipAddress   -   ipaddress of the nsxt (STRING)
                        username    -   Username of the nsxt (STRING)
                        password    -   Password of the nsxt (STRING)
        """
        self.ipAddress = ipAddress
        self.password = password
        self.nsxtUtils = Utilities()
        self.restClientObj = RestAPIClient(username, password)

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

    def createBridgeEndpointProfile(self, edgeClusterName):
        """
        Description : Create Bridge Endpoint Profile for the members of edge Cluster
        Parameters  : EdgeClusterName   -   Name of the edge cluster participating in bridging (LIST)
        """
        try:
            bridgeEndpointProfileList = []
            logger.debug("Retrieving ID of edge cluster: {}".format(edgeClusterName))
            edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                    edgeClusterName)
            filePath = os.path.join(nsxtConstants.NSXT_ROOT_DIRECTORY, 'template.json')
            if edgeClusterData:
                logger.debug("Successfully retrieved edge Cluster data of {}".format(edgeClusterName))
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.CREATE_BRIDGE_ENDPOINT_PROFILE)
                for data in edgeClusterData['members']:
                    payloadDict = {'bridgeEndpointProfileName': 'Bridge-Endpoint-Profile-{}'.format(data['transport_node_id']),
                                   'edgeClusterId': edgeClusterData['id']}
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
            else:
                raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))
        except Exception:
            raise

    def createUplinkProfile(self):
        """
        Description : Creates a uplink profile
        Returns     : uplinkProfileId   -   ID of the uplink profile created (STRING)
        """
        try:
            logger.debug("Creating bridge uplink profile")
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
                    return uplinkProfileId
                msg = "Failed to create uplink profile {}.".format(nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)
                logger.error(msg)
                raise Exception(msg, response.status_code)
            msg = "Uplink {} already exists.".format(nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)
            logger.error(msg)
            raise Exception(msg)
        except Exception:
            raise

    def updateEdgeTransportNodes(self, edgeClusterName, portgroupList, transportZoneName):
        """
        Description: Update Edge Transport Node
        Parameters:  edgeClusterName    - Name of the edge cluster participating in bridging (LIST)
                     portgroupList      - List containing details of vxlan backed logical switch (LIST)
                     transportZoneName  - Name of the bridge transport zone (STRING)
        """
        try:
            uplinkProfileData = self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                                      componentName=nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)

            transportZoneData = self.getComponentData(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName)
            logger.debug("Retrieving ID of edge cluster: {}".format(edgeClusterName))
            edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                    edgeClusterName)
            edgeNodePortgroupList = zip(edgeClusterData['members'], portgroupList)
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
        except Exception:
            raise

    def attachBridgeEndpointSegment(self, edgeClusterName, portgroupList, transportZoneName):
        """
        Description : Attach Bridge Endpoint to logical segments
        Parameters  : edgeClusterName     - Name of the edge cluster participating in bridging (LIST)
                      portgroupList       - List containing details of vxlan backed logical switch (LIST)
                      transportZoneName   - Name of the bridge transport zone (STRING)
        """
        try:
            transportZoneId = self.getNsxtComponentIdByName(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName)
            fileName = os.path.join(rootDir, 'core', 'vcd', 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
            targetOrgVDCNetworks = data['targetOrgVDCNetworks']
            switchList = []
            for orgVdcNetwork in targetOrgVDCNetworks:
                networkData = self.getComponentData(componentApi=nsxtConstants.CREATE_LOGICAL_SWITCH_API,
                                                    componentName=orgVdcNetwork['name'])
                switchTags = [data for data in networkData['tags'] if orgVdcNetwork['backingNetworkId'] in data['tag']]

                if switchTags:
                    switchList.append((networkData['display_name'], networkData['id'], orgVdcNetwork['networkType']))
            edgeSwitchList = []
            for item in portgroupList:
                for item1 in switchList:
                    if item['networkName'] == item1[0]:
                        edgeSwitchList.append((item, item1[1], item1[2]))
            bridgeEndpointUrl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.CREATE_BRIDGE_ENDPOINT_API)
            logicalPorturl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.CREATE_LOGICAL_SWITCH_PORT_API)
            filePath = os.path.join(nsxtConstants.NSXT_ROOT_DIRECTORY, 'template.json')
            edgeNodeList = []
            logger.debug("Retrieving ID of edge cluster: {}".format(edgeClusterName))
            edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                    edgeClusterName)
            edgeNodeSwitchList = zip(edgeClusterData['members'], edgeSwitchList)
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
                    else:
                        raise Exception('Failed to attach Bridge Endpoint Profile to logical switch {}.'.format(geneveLogicalSwitch[1]))
                else:
                    logger.debug('Failed to create Bridge Endpoint')
                    raise Exception('Failed to create Bridge Endpoint')
            return edgeNodeList
        except Exception:
            raise

    def verifyBridgeConnectivity(self, edgeNodeList, sourceEdgeGatewayMacAddressList):
        """
        Description :   Verifying bridge connectivity by checking on edge nodes whether it has learned source edge gateway mac address
        Parameters  :   edgeNodeList                    - edge nodes on which mac address will be checked (LIST)
                        sourceEdgeGatewayMacAddressList - source edge gateway mac address list (LIST)
        """
        try:
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
                else:
                    errorMessage = 'Bridging Connectivity checks failed. Source Edge gateway MAC address could not learned by edge nodes'
                    logger.error(errorMessage)
                    raise Exception(errorMessage)
            else:
                logger.warning('Not verifiying bridge connectivity checks as all networks are Isolated.')
        except Exception:
            # handling the rollback scenario
            self.CLEAR_NSX_T_BRIDGING = True
            raise

    def clearBridging(self, orgVDCNetworkList):
        """
        Description :   Remove Logical switch ports, Bridge Endpoint, Bridge Endpoint Profiles, edge transport nodes etc
        Parameters  :   orgVDCNetworkList     - List containing org vdc network details (LIST)
        """
        try:
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
                                                    componentName=orgVdcNetwork['name'])
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
                    logger.debug('Failed to detach Logical Switch Port {} from Bridge - {}'.format(logicalSwitchPort, responseData['error_message']))
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
                            logger.debug('Failed to delete Bridge Endpoint {} - {}'.format(bridgeEndpoint, responseData['error_message']))
                edgeClusterList = []
                # get the bridge endpoint profile
                for bridgeEndpointProfileId in bridgeEndpointProfileIdResults:
                    bridgeEndpointProfileUrl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                                      nsxtConstants.GET_BRIDGE_ENDPOINT_PROFILE_BY_ID_API.format(bridgeEndpointProfileId))
                    response = self.restClientObj.get(url=bridgeEndpointProfileUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                      auth=self.restClientObj.auth)
                    # delete the bridge endpoint profile
                    if response.status_code == requests.codes.ok:
                        bridgeEndpointProfileResult = json.loads(response.content)
                        # getting the edge cluster details from a bridge endpoint profile
                        if bridgeEndpointProfileResult['edge_cluster_id'] not in edgeClusterList:
                            edgeClusterList.append(bridgeEndpointProfileResult['edge_cluster_id'])
                        response = self.restClientObj.delete(url=bridgeEndpointProfileUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                             auth=self.restClientObj.auth)
                        if response.status_code == requests.codes.ok:
                            logger.debug('Bridge Endpoint profile {} deleted Successfully'.format(bridgeEndpointProfileResult['display_name']))
                        else:
                            responseData = json.loads(response.content)
                            logger.debug('Failed to delete Bridge Endpoint Profile {} - {}'.format(bridgeEndpointProfileResult['display_name'], responseData['error_message']))
                # updating the transport node details inside edge cluster
                for edgeClusterId in edgeClusterList:
                    url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                 nsxtConstants.GET_EDGE_CLUSTER_API.format(edgeClusterId))
                    response = self.restClientObj.get(url, headers=nsxtConstants.NSXT_API_HEADER,
                                                      auth=self.restClientObj.auth)
                    edgeClusterData = response.json()
                    for data in edgeClusterData['members']:
                        url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                     nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(
                                                                         data['transport_node_id']))
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
                            msg = "Failed to get Edge Transport node {}.".format(data['transport_node_id'])
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
                    logger.debug('Failed to delete Host Switch Profile {} - {}'.format(hostSwitchProfileId, responseData['error_message']))
        except Exception:
            raise

    def getComputeManagers(self):
        """
        Description :    Get the list of all Compute managers
        """
        try:
            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.LIST_COMPUTE_MANAGERS)
            response = self.restClientObj.get(url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                logger.debug("Successfully logged into NSX-T {}".format(self.ipAddress))
            elif response.status_code == requests.codes.forbidden:
                raise Exception('Failed to login to NSX-T with the given credentials.')
        except Exception:
            raise

    def configureNSXTBridging(self, nsxtDict, portGroupList):
        """
        Description :   Configure NSXT bridging
        Parameters  :   nsxtDict        - NSX-T parameters required for bridging (DICT)
                        portGroupList   - Portgroup list containing ORG VDC networks (LIST)
        """
        try:
            transportZoneName = nsxtDict['TransportZone']['TransportZoneName']
            # create bridge endpoint profile
            logger.info('Create Bridge Endpoint Profile.')
            self.createBridgeEndpointProfile(nsxtDict['EdgeClusterName'])
            logger.info('Successfully created Bridge Endpoint Profile.')

            # create host uplink profile for bridge n-vds
            logger.info('Create Bridge Uplink Host Profile.')
            self.createUplinkProfile()
            logger.info('Successfully created Bridge Uplink Host Profile.')

            # add bridge transport to bridge edge transport nodes
            logger.info('Add Bridge Transport Zone to Bridge Edge Transport Nodes.')
            self.updateEdgeTransportNodes(nsxtDict['EdgeClusterName'], portGroupList, transportZoneName)
            logger.info('Successfully added Bridge Transport Zone to Bridge Edge Transport Nodes.')

            # attach bridge endpoint profile to logical switch
            logger.info('Attach bridge endpoint profile to Logical Switch.')
            edgeNodeList = self.attachBridgeEndpointSegment(nsxtDict['EdgeClusterName'], portGroupList, transportZoneName)
            logger.info('Successfully attached bridge endpoint profile to Logical Switch.')
            return edgeNodeList
        except Exception:
            self.CLEAR_NSX_T_BRIDGING = True
            raise

    def validateBridgeUplinkProfile(self):
        """
        Description :   Validates that the bridge-uplink-profile doesnot already exists
                        If exists raises exception
        """
        try:
            if not self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                         componentName=nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME):
                logger.debug("Validated successfully that the {} doesnot already exist".format(nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME))
            else:
                msg = "Host Switch Profile uplink - {} already exists.".format(nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)
                raise Exception(msg)
        except Exception:
            raise

    def validateOrgVdcNetworksAndEdgeTransportNodes(self, edgeClusterName, orgVdcNetworkList):
        """
        Description :   Validates the number of networks in source Org Vdc match with the number of Edge Transport Nodes in the specified cluster name
        Parameters  :   edgeClusterName     -   Name of the cluster (STRING)
                        orgVdcNetworkList   -   Source Org VDC Network List (LIST)
        """
        try:
            logger.debug("Retrieving ID of edge cluster: {}".format(edgeClusterName))
            edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                    edgeClusterName)
            edgeTransportNodeList = edgeClusterData['members'] if isinstance(edgeClusterData['members'], list) else [edgeClusterData['members']]
            if len(orgVdcNetworkList) == len(edgeTransportNodeList):
                logger.debug("Validated successfully the number of source Org VDC networks match with the number of Edge Transport Nodes in the cluster {}".format(edgeClusterName))
            else:
                raise Exception("Error: Number of Source Org VDC Networks doesnot match with the number of Edge Transport Nodes in the cluster {}".format(edgeClusterName))
        except Exception:
            self.ENABLE_SOURCE_ORG_VDC_AFFINITY_RULES = True
            raise

    def validateEdgeNodesNotInUse(self, edgeClusterName):
        """
        Description :   Validates that None Edge Transport Nodes are in use in the specified Edge Cluster
        Parameters  :   edgeClusterName -   Name of the cluster (STRING)
        """
        try:
            logger.debug("Retrieving ID of edge cluster: {}".format(edgeClusterName))
            edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                    edgeClusterName)
            edgeTransportNodeList = edgeClusterData['members'] if isinstance(edgeClusterData['members'], list) else [edgeClusterData['members']]
            for tranportNode in edgeTransportNodeList:
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                             nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(tranportNode['transport_node_id']))
                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    hostSwitchSpec = responseDict["host_switch_spec"]["host_switches"]
                    for hostSwitch in hostSwitchSpec:
                        for pnics in hostSwitch["pnics"]:
                            if pnics["device_name"] == nsxtConstants.PNIC_NAME:
                                raise Exception("Transport Node is already in use")
            logger.debug("Validated successfully that any of Transport Nodes from cluster {} are not in use".format(edgeClusterName))
        except Exception:
            raise
