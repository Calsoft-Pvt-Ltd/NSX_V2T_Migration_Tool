# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description: NSXT Module which performs the Bridging Operations
"""

import copy
import traceback
import uuid
from functools import wraps
import inspect
import logging
import json
import os
import re
import requests
import threading
import time
from pkg_resources._vendor.packaging import version
import src.core.nsxt.nsxtConstants as nsxtConstants


from src.constants import rootDir
from src.commonUtils.sshUtils import SshUtils
from src.commonUtils.restClient import RestAPIClient
from src.commonUtils.utils import Utilities, listify
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

            # Saving metadata in source org VDC
            if not self.rollback.retryRollback:
                self.vcdObj.saveMetadataInOrgVdc()
            return result
        except Exception as err:
            raise err
    return inner


def replace_unsupported_chars(text):
    """
    Description: Removes unsupported characters by replacing with empty string
    """
    for c in ";|=\\,/~@":
        text = text.replace(c, '')
    return text


class NSXTOperations():
    """
    Description: Class that performs the NSXT bridging Operations
    """
    def __init__(self, ipAddress, username, password, rollback, vcdObj, verify, edgeClusterNameList):
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
        self.apiVersion = None
        self.edgeClusterNameList = edgeClusterNameList

    def getComponentData(self, componentApi, componentName=None, usePolicyApi=False):
        """
        Description   : This function validates the presence of the component in NSX-T
        Parameters    : componentApi    -   API to get the details of the component (STRING)
                        componentName   -   Display-Name of the component (STRING)
        Returns       : componentData if the component with the same display name is already present (DICTIONARY)
        """
        try:
            logger.debug("Fetching NSXT component data")
            componentData = {}
            if usePolicyApi:
                url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), componentApi)
            else:
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

    def getNetworkData(self, componentName=None, backingNetworkingId=None):
        """
        Description   : This function validates the presence of the component in NSX-T
        Parameters    : nsxtVersion         -   NSXT version to check for interop (STRING)
                        componentName       -   Display-Name of the network (STRING)
                        backingNetworkingId -   Backing Network Id of org vdc network (STRING)
        Returns       : componentData if the component with the same display name is already present (DICTIONARY)
        """
        try:
            logger.debug("Fetching NSXT Logical-Segment data")
            url = "{}{}".format(
                nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                nsxtConstants.SEGMENT_DETAILS)

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
                    if component[nsxtConstants.NSX_API_DISPLAY_NAME_KEY] == componentName or \
                            backingNetworkingId == component['id']:
                        logger.debug("NSXT Logical Segment Name : {}".format(
                            component[nsxtConstants.NSX_API_DISPLAY_NAME_KEY]))
                        return component
            raise Exception("Failed to get NSXT Logical Segment details with name {}".format(componentName))
        except Exception:
            raise

    def getNsxtAPIVersion(self):
        """
                Description   : This function get the API version of NSX-T
                Returns       : It returns the Version of API supported by NSX-T
                """
        try:
            url = "{}{}".format(
                nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                nsxtConstants.API_VERSION)
            response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                              auth=self.restClientObj.auth)
            api_data = json.loads(response.content)
            self.apiVersion = api_data['info']['version']
        except:
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

    def checkRealizedState(self, intent_path, markedForDelete=False, timeoutForTask=300):
        """
        Description :   Check realization state after policy API is executed
        Parameters  :   intent_path - Path of object operated by executed API (STR)
                        markedForDelete - Set if DELETE method is executed (BOOL)
                        timeoutForTask - time in seconds to wait till realization of object (INT)
        """

        timeout = 0.0
        url = "{}{}".format(
            nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
            nsxtConstants.REALIZED_STATE_API.format(intent_path)
        )
        while timeout < timeoutForTask:
            logger.debug(f'Checking realization state of {intent_path}')
            response = self.restClientObj.get(
                url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)

            if response.status_code == requests.codes.ok:
                responseContent = response.json()
                if responseContent['publish_status'] == 'REALIZED' and not markedForDelete:
                    return

                if responseContent['publish_status'] == 'ERROR':
                    raise Exception(f'Realization of {intent_path} is in ERROR state')

            elif response.status_code == requests.codes.not_found:
                if markedForDelete:
                    return

                responseContent = response.json()
                raise Exception(responseContent['error_message'])

            else:
                raise Exception(f'Realization status failed with {response.status_code}')

            time.sleep(10)
            timeout += 10

        raise Exception(f'Timeout occurred while checking realization status for {intent_path}')

    @description("creation of Bridge Endpoint Profile", threadName="Bridging")
    @remediate
    def createBridgeEndpointProfile(self, portgroupList, vcdObj):
        """
        Description : Create Bridge Endpoint Profile for the members of edge Cluster
        Parameters  : edgeClusterNameList   -   List of names of the edge cluster participating in bridging (LIST)
                      portgroupList         - List containing details of vxlan backed logical switch (LIST)
        """
        try:
            logger.info('Configuring NSXT Bridging.')
            logger.info('Creating Bridge Endpoint Profile.')
            bridgeEndpointProfileList = []
            logger.debug("Retrieving ID of edge cluster/s: {}".format(', '.join(self.edgeClusterNameList)))

            edgeClusterMembers = []
            for edgeClusterName in self.edgeClusterNameList:
                edgeClusterData = self.getComponentData(nsxtConstants.GET_EDGE_CLUSTERS_API, edgeClusterName, usePolicyApi=True)
                url = "{}{}{}".format(
                    nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                    edgeClusterData['path'],
                    nsxtConstants.EDGE_PATH)
                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    responseData = json.loads(response.content)
                    resultData = responseData['results']
                    for edgeNodeData in resultData:
                        if edgeNodeData['nsx_id'] in vcdObj.rollback.apiData['taggedNodesList']:
                            edgeClusterMembers.append({'transport_node_id': edgeNodeData['nsx_id'],
                                                       'member_index': edgeNodeData['member_index'], 'edgePath': edgeNodeData['path']})
                else:
                    raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))

            filePath = os.path.join(nsxtConstants.NSXT_ROOT_DIRECTORY, 'template.json')
            logger.debug("Successfully retrieved edge Cluster data of {}".format(', '.join(self.edgeClusterNameList)))
            # taking only the edge transport nodes which match the count of source portgroup details
            edgeNodePortgroupList = zip(edgeClusterMembers, portgroupList)
            for data, _ in edgeNodePortgroupList:
                intent_path = nsxtConstants.BRIDGE_ENDPOINT_PROFILE_POLICY_PATH.format(data['transport_node_id'])
                url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), intent_path)
                edgePath = data['edgePath']
                payloadDict = {
                    'bridgeEndpointProfileName': 'Bridge-Endpoint-Profile-{}'.format(data['transport_node_id'])
                }
                payloadData = self.nsxtUtils.createPayload(filePath, payloadDict, fileType='json',
                                                          componentName=nsxtConstants.COMPONENT_NAME,
                                                          templateName=nsxtConstants.CREATE_BRIDGE_EDGE_PROFILE_COMPONENT_NAME)
                payloadData = json.loads(payloadData)
                payloadData['edge_paths'] = [edgePath]
                payloadData = json.dumps(payloadData)
                response = self.restClientObj.put(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                  auth=self.restClientObj.auth, data=payloadData)
                if response.status_code == requests.codes.ok or response.status_code == requests.codes.created:
                    self.checkRealizedState(intent_path)

                if response.status_code == requests.codes.ok or response.status_code == requests.codes.created:
                    logger.debug('Bridge Endpoint Profile {} created successfully.'.format(payloadDict['bridgeEndpointProfileName']))
                    bridgeEndpointProfileId = json.loads(response.content)["id"]
                    bridgeEndpointProfileList.append(bridgeEndpointProfileId)
                else:
                    raise Exception('Failed to create Bridge Endpoint Profile. Errors {}.'.format(response.content))
            logger.info('Successfully created Bridge Endpoint Profile.')
        except Exception:
            raise

    @description("creation of Bridge Uplink Host Profile", threadName="Bridging")
    @remediate
    def createUplinkProfile(self, vcdObj):
        """
        Description : Creates a uplink profile
        Returns     : uplinkProfileId   -   ID of the uplink profile created (STRING)
        """
        try:
            logger.info('Creating Bridge Uplink Host Profile.')
            data = vcdObj.rollback.apiData
            filePath = os.path.join(nsxtConstants.NSXT_ROOT_DIRECTORY, 'template.json')
            bridgeUplinkProfile = nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME + str(uuid.uuid4())
            if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                if not self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                             componentName=bridgeUplinkProfile, usePolicyApi=True):
                    intent_path = "{}/{}".format(nsxtConstants.HOST_SWITCH_PROFILE_API, bridgeUplinkProfile)
                    url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), intent_path)
                    payloadDict = {'uplinkProfileName': bridgeUplinkProfile,
                                   'resource_type': "PolicyUplinkHostSwitchProfile"}
                    # create payload for host profile creation
                    payload = self.nsxtUtils.createPayload(filePath=filePath, fileType="json",
                                                           componentName=nsxtConstants.COMPONENT_NAME,
                                                           templateName=nsxtConstants.CREATE_UPLINK_PROFILE,
                                                           payloadDict=payloadDict)
                    payload = json.loads(payload)
                    payload["teaming"]["active_list"].append(dict(uplink_type="PNIC", uplink_name="Uplink1"))
                    payload = json.dumps(payload)
                    # REST POST call to create uplink profile
                    response = self.restClientObj.put(url=url, headers=nsxtConstants.NSXT_API_HEADER, data=payload,
                                                      auth=self.restClientObj.auth)
                    if response.status_code == requests.codes.ok:
                        self.checkRealizedState(intent_path)
                        logger.debug("Successfully created uplink profile {}".format(bridgeUplinkProfile))
                        uplinkProfileId = json.loads(response.content)["unique_id"]
                        logger.info('Successfully created Bridge Uplink Host Profile {}'.format(bridgeUplinkProfile))
                        data['BridgingStatus']['UplinkProfileName'] = bridgeUplinkProfile
                        return uplinkProfileId
                    msg = "Failed to create uplink profile {}.".format(bridgeUplinkProfile)
                    logger.error(msg)
                    raise Exception(msg, response.status_code)
                msg = "Uplink {} already exists.".format(bridgeUplinkProfile)
                logger.error(msg)
                raise Exception(msg)
            else:
                if not self.getComponentData(componentApi=nsxtConstants.DEPRECATED_HOST_SWITCH_PROFILE_API,
                                             componentName=bridgeUplinkProfile):
                    url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                 nsxtConstants.DEPRECATED_HOST_SWITCH_PROFILE_API)
                    payloadDict = {'uplinkProfileName': bridgeUplinkProfile,
                                   'resource_type': "UplinkHostSwitchProfile"}
                    # create payload for host profile creation
                    payload = self.nsxtUtils.createPayload(filePath=filePath, fileType="json",
                                                           componentName=nsxtConstants.COMPONENT_NAME,
                                                           templateName=nsxtConstants.CREATE_UPLINK_PROFILE,
                                                           payloadDict=payloadDict)
                    payload = json.loads(payload)
                    payload["teaming"]["active_list"].append(dict(uplink_type="PNIC", uplink_name="Uplink1"))
                    payload = json.dumps(payload)
                    # REST POST call to create uplink profile
                    response = self.restClientObj.post(url=url, headers=nsxtConstants.NSXT_API_HEADER, data=payload,
                                                       auth=self.restClientObj.auth)
                    if response.status_code == requests.codes.created:
                        logger.debug("Successfully created uplink profile {}".format(bridgeUplinkProfile))
                        uplinkProfileId = json.loads(response.content)["id"]
                        logger.info('Successfully created Bridge Uplink Host Profile {}'.format(bridgeUplinkProfile))
                        data['BridgingStatus']['UplinkProfileName'] = bridgeUplinkProfile
                        return uplinkProfileId
                    msg = "Failed to create uplink profile {}.".format(bridgeUplinkProfile)
                    logger.error(msg)
                    raise Exception(msg, response.status_code)
                msg = "Uplink {} already exists.".format(bridgeUplinkProfile)
                logger.error(msg)
                raise Exception(msg)
        except Exception:
            raise

    @description("addition of Bridge Transport Zone to Bridge Edge Transport Nodes", threadName="Bridging")
    @remediate
    def updateEdgeTransportNodes(self, portgroupList, vcdObj, vCenterObj):
        """
        Description: Update Edge Transport Node
        Parameters:  edgeClusterNameList    - List of names of the edge cluster participating in bridging (LIST)
                     portgroupList          - List containing details of vxlan backed logical switch (LIST)
        """
        try:
            data = vcdObj.rollback.apiData
            transportZoneName = data['BridgingStatus']['TransportZone']
            bridgeUplinkProfile = data['BridgingStatus']['UplinkProfileName']
            logger.info('Adding Bridge Transport Zone to Bridge Edge Transport Nodes.')
            # Getting the cluster resource-pool mappings
            clusterResourcePoolMapping = vCenterObj.fetchClusterResourcePoolMapping()
            if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                uplinkProfileData = self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                                          componentName=bridgeUplinkProfile, usePolicyApi=True)

                transportZoneData = self.getComponentData(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName,  usePolicyApi=True)

                id_key = "unique_id"
            else:
                uplinkProfileData = self.getComponentData(componentApi=nsxtConstants.DEPRECATED_HOST_SWITCH_PROFILE_API,
                                                          componentName=bridgeUplinkProfile)

                transportZoneData = self.getComponentData(nsxtConstants.DEPRECATED_TRANSPORT_ZONE_API, transportZoneName)

                id_key = "id"


            logger.debug("Retrieving ID of edge cluster: {}".format(', '.join(self.edgeClusterNameList)))
            edgeClusterMembers = []
            for edgeClusterName in self.edgeClusterNameList:
                edgeClusterData = self.getComponentData(nsxtConstants.GET_EDGE_CLUSTERS_API, edgeClusterName, usePolicyApi=True)
                url = "{}{}{}".format(
                    nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                    edgeClusterData['path'],
                    nsxtConstants.EDGE_PATH)
                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    responseData = json.loads(response.content)
                    resultData = responseData['results']
                    for edgeNodeData in resultData:
                        if edgeNodeData['nsx_id'] in vcdObj.rollback.apiData['taggedNodesList']:
                            edgeClusterMembers.append({'transport_node_id': edgeNodeData['nsx_id'],
                                                       'member_index': edgeNodeData['member_index'], 'edgePath': edgeNodeData['path']})
                else:
                    raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))

            edgeNodePortgroupList = zip(edgeClusterMembers, portgroupList)
            for data, networkPortGroupList in edgeNodePortgroupList:
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
                    newHostSwitchSpec = {"host_switch_profile_ids": [{"key": "UplinkHostSwitchProfile", "value": uplinkProfileData[id_key]}],
                                         "host_switch_mode": "STANDARD",
                                         'host_switch_name': nsxtConstants.BRIDGE_TRANSPORT_ZONE_HOST_SWITCH_NAME,
                                         "pnics": [{"device_name": nextUnusedUplink, "uplink_name": uplinkProfileData['teaming']['active_list'][0]['uplink_name']}],
                                         "is_migrate_pnics": False,
                                         "ip_assignment_spec": {"resource_type": "AssignedByDhcp"},
                                         "transport_zone_endpoints": [
                                             {"transport_zone_id": transportZoneData[id_key],
                                              "transport_zone_profile_ids": hostSwitchSpec[0]['transport_zone_endpoints'][0]['transport_zone_profile_ids']
                                              }]
                                         }
                    hostSwitchSpec.append(newHostSwitchSpec)
                    dataNetworkList = edgeNodeData['node_deployment_info']['deployment_config']['vm_deployment_config']['data_network_ids']
                    # since nsxt 3.0 null coming in data_network_ids while getting edge transport node details
                    if None in dataNetworkList:
                        dataNetworkList.remove(None)
                    portgroup = self.getNetworkPortgroupForTransportNode(edgeNodeData, networkPortGroupList, clusterResourcePoolMapping, vCenterObj)
                    newDataNetworkList = portgroup["moref"]
                    dataNetworkList.append(newDataNetworkList)
                    edgeNodeData["host_switch_spec"]["host_switches"] = hostSwitchSpec
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

    def getNetworkPortgroupForTransportNode(self, edgeNodeData, networkPortGroupList, clusterResourcePoolMapping, vCenterObj):
        """
        Description : get portgroup of a network to connect to edge transport node
        Parameters  : edgeNodeData - Transport Node Data (DICT)
                      networkPortGroupList - portgroup list of network (LIST)
        """
        # Getting compute_id from edgeNodeData
        compute_id = edgeNodeData['node_deployment_info']['deployment_config']['vm_deployment_config']['compute_id']
        if 'domain' not in compute_id:
            for domain, resGroup in clusterResourcePoolMapping.items():
                if compute_id in resGroup:
                    compute_id = domain
        # Getting response using MOBS api
        response = vCenterObj.mobsApi(compute_id.strip())
        if response.status_code == requests.codes.ok:
            mobs_response = response.content
            for portGroup in networkPortGroupList:
                # Checking portgroup in Networks list of bridging edge node vSphere cluster
                if portGroup["moref"] in str(mobs_response):
                    return portGroup
        else:
            msg = "Failed to get correct MOBS API response"
            logger.error(msg)
            raise Exception(msg)

    def getTransportZoneData(self, transportZoneID):
        """
        Description : get path of Transport Zone.
        Parameters  : transportZoneID - TransportZoneID
        """
        try:
            # Adding a timeout for 10 min, until the realisation on transport zone by Policy APIs.
            timeout = time.time() + nsxtConstants.TRANSPORT_ZONE_DETAILS_TIMEOUT
            while True:
                tranzportZoneDetailsUrl = "{}{}".format(
                    nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                    nsxtConstants.TRANSPORT_ZONE_DETAILS_URL.format(transportZoneID))
                response = self.restClientObj.get(url=tranzportZoneDetailsUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                  auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    transportZoneData = json.loads(response.content)
                    return transportZoneData['path']
                else:
                    responseData = json.loads(response.content)
                    logger.debug("Failed to get Transport Zone details  {} : {}".format(transportZoneID, responseData))
                time.sleep(5)
                if time.time() > timeout:
                    raise Exception("Failed to get Transport Zone details even after 10 minutes, {} : {}".format(transportZoneID, responseData))
        except:
            raise

    @description("attaching bridge endpoint profile to Logical Switch", threadName="Bridging")
    @remediate
    def attachBridgeEndpointSegment(self, portgroupList, targetOrgVDCNetworks, vcdObj):
        """
        Description : Attach Bridge Endpoint to logical segments
        Parameters  : edgeClusterNameList - List of names of the edge cluster participating in bridging (LIST)
                      portgroupList       - List containing details of vxlan backed logical switch (LIST)
        """
        try:
            logger.info('Attaching bridge endpoint profile to Logical Switch.')
            data = vcdObj.rollback.apiData

            switchList = []
            for orgVdcNetwork in targetOrgVDCNetworks:
                if orgVdcNetwork['networkType'] != 'DIRECT' and orgVdcNetwork['networkType'] != 'OPAQUE':
                    networkData = self.getNetworkData(
                        componentName=f"{orgVdcNetwork['name']}-{orgVdcNetwork['id'].split(':')[-1]}",
                        backingNetworkingId=orgVdcNetwork['backingNetworkId'])
                    switchTags = [data for data in networkData['tags'] if
                                  orgVdcNetwork['orgVdc']['id'] in data['tag']]

                    if switchTags:
                        switchList.append((orgVdcNetwork['name'], networkData['id'], orgVdcNetwork['networkType']))

            edgeSwitchList = []
            for item in portgroupList:
                for item1 in switchList:
                    if item[0]['networkName'] + '-v2t' == item1[0]:
                        edgeSwitchList.append((item, item1[1], item1[2], item1[0]))

            if not edgeSwitchList or len(portgroupList) != len(edgeSwitchList):
                logger.debug(f'portgroupList {portgroupList}')
                logger.debug(f'switchList {switchList}')
                raise Exception('Unable to parse PortGroups')

            # Get transport Zone /infra/sites path.
            transportZoneName = data['BridgingStatus']['TransportZone']
            if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                transportZoneId = self.getComponentData(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName, usePolicyApi=True)["id"]
            else:
                transportZoneId = self.getNsxtComponentIdByName(nsxtConstants.DEPRECATED_TRANSPORT_ZONE_API, transportZoneName)
            transportZonePath = self.getTransportZoneData(transportZoneId)
            if transportZonePath is None:
                transportZonePath = nsxtConstants.TRANSPORT_ZONE_PATH.format(transportZoneId)

            edgeNodeList = []
            logger.debug("Retrieving ID of edge cluster: {}".format(', '.join(self.edgeClusterNameList)))
            edgeClusterMembers = []
            for edgeClusterName in self.edgeClusterNameList:
                edgeClusterData = self.getComponentData(nsxtConstants.GET_EDGE_CLUSTERS_API, edgeClusterName, usePolicyApi=True)
                url = "{}{}{}".format(
                    nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                    edgeClusterData['path'],
                    nsxtConstants.EDGE_PATH)
                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                  auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    responseData = json.loads(response.content)
                    resultData = responseData['results']
                    for edgeNodeData in resultData:
                        if edgeNodeData['nsx_id'] in vcdObj.rollback.apiData['taggedNodesList']:
                            edgeClusterMembers.append({'transport_node_id': edgeNodeData['nsx_id'],
                                                       'member_index': edgeNodeData['member_index'],
                                                       'edgePath': edgeNodeData['path']})
                else:
                    raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))

            edgeNodeSwitchList = zip(edgeClusterMembers, edgeSwitchList)
            for data, geneveLogicalSwitch in edgeNodeSwitchList:
                edgeNodeId = data['transport_node_id']
                bridgeProfileDict = self.getComponentData(
                    componentApi=nsxtConstants.BRIDGE_EDGE_PROFILE_DETAILS, usePolicyApi=True)
                bridgeProfile = [bridgeProfile for bridgeProfile in bridgeProfileDict if edgeNodeId in bridgeProfile['display_name']]

                if not bridgeProfile:
                    continue

                intent_path = nsxtConstants.LOGICAL_SEGMENTS_ENDPOINT.format(geneveLogicalSwitch[1])
                segmentDetailsUrl = "{}{}".format(
                    nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), intent_path)
                bridgeProfiles= []
                for profile in bridgeProfile:
                    temp_dict = {"bridge_profile_path": profile['path'],
                                 "vlan_transport_zone_path": transportZonePath,
                                 "vlan_ids": [0]  # Passing 0 as VLAN ID
                                 }
                    bridgeProfiles.append(temp_dict)
                response = self.restClientObj.get(url=segmentDetailsUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                  auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    segmentData = json.loads(response.content)
                    segmentData['bridge_profiles'] = bridgeProfiles
                    payloadData = json.dumps(segmentData)
                    response = self.restClientObj.patch(url=segmentDetailsUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                        auth=self.restClientObj.auth, data=str(payloadData))
                    if response.status_code == requests.codes.ok or response.status_code == requests.codes.created:
                        self.checkRealizedState(intent_path)
                        logger.debug('Bridge Endpoint profile attached to Logical switch {}'.format(geneveLogicalSwitch[1]))
                        if geneveLogicalSwitch[2] == 'NAT_ROUTED':
                            edgeNodeList.append(edgeNodeId)
                        self.rollback.apiData['edgeNodeList'] = edgeNodeList
                    else:
                        responseData = json.loads(response.content)
                        msg = 'Failed to attach Bridge Endpoint Profile to logical switch {} - {}.'.format(geneveLogicalSwitch[1], responseData)
                        raise Exception(msg)
                else:
                    responseData = json.loads(response.content)
                    msg = 'Failed to get segment details in attach segment {} - {}.'.format(geneveLogicalSwitch[1], responseData)
                    raise Exception(msg)

            logger.info('Successfully attached bridge endpoint profile to Logical Switch.')
            logger.info('Successfully configured NSXT Bridging.')
            return
        except Exception:
            raise

    @description("verification of Bridge Connectivity", threadName="VerifyBridging")
    @remediate
    def verifyBridgeConnectivity(self, vcdObjList, vcenterObj):
        """
        Description :   Verifying bridge connectivity by checking on edge nodes whether it has learned source edge gateway mac address
        Parameters  :   vcdObj - Object of vcdOperations module (Object)
                        vcenterObj - Object of vcenterApis module (Object)
        """
        try:
            # Suppressing paramiko transport logs
            logging.getLogger("paramiko").setLevel(logging.WARNING)

            # Replacing thread name with the name bridging
            threading.current_thread().name = "VerifyBridging"

            logger.info('Verifying bridging connectivity')
            # Sleeping for 180 seconds before verifying bridging connectivity
            time.sleep(180)
            # get source edge gateway vm id
            edgeVMIdList = [list(vcdObj.getEdgeVmId().values()) for vcdObj in vcdObjList]

            sourceEdgeGatewayMacAddressList = []
            for vcdObj, edgeVMList in zip(vcdObjList, edgeVMIdList):
                # Handling corner case for continuation message
                vcdObj.rollback.retry = True
                for edgeVMId in edgeVMList:
                    # get routed network interface details of the nsx-v edge vm using vcenter api's
                    interfaceDetails = vcenterObj.getEdgeVmNetworkDetails(edgeVMId)

                    # get the source edge gateway mac address for routed networks
                    sourceEdgeGatewayMacAddressList += vcdObj.getSourceEdgeGatewayMacAddress(interfaceDetails)

            # Replacing thread name with the name bridging
            threading.current_thread().name = "VerifyBridging"

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
                    output = sshObj.runCmdOnSsh(cmd, 150, checkExitStatus=True)
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
                logger.warning('Not verifying bridge connectivity checks as all networks are either Isolated/Distributed.')
        except Exception:
            raise
        finally:
            # Resetting thread name
            threading.current_thread().name = "MainThread"
            # Restoring paramiko log level
            logging.getLogger("paramiko").setLevel(logging.INFO)

    def clearBridging(self, orgVDCNetworkList, vcdObj, rollback=False):
        """
        Description :   Remove Logical switch ports, Bridge Endpoint, Bridge Endpoint Profiles, edge transport nodes etc
        Parameters  :   orgVDCNetworkList     - List containing org vdc network details (LIST)
        """
        # Fetching current thread name
        currentThreadName = threading.current_thread().getName()
        try:
            # Setting temporary thread name

            threading.current_thread().name = "MainThread"

            orgVDCNetworkList = list(filter(lambda network: network['networkType'] != 'DIRECT' and network['networkType'] != 'OPAQUE', orgVDCNetworkList))
            transportZoneName = vcdObj.rollback.apiData['BridgingStatus']['TransportZone']
            if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                transportZoneId = self.getComponentData(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName, usePolicyApi=True)["unique_id"]
            else:
                transportZoneId = self.getNsxtComponentIdByName(nsxtConstants.DEPRECATED_TRANSPORT_ZONE_API, transportZoneName)
            if not orgVDCNetworkList:
                return
            if rollback:
                logger.info("RollBack: Clearing NSX-T Bridging")
            switchList = []
            edgeBridgeList = []
            bridgeEndpointIdList = []
            # getting the logical switch id of the corresponding org vdc network
            for orgVdcNetwork in orgVDCNetworkList:
                if orgVdcNetwork['networkType'] != 'DIRECT' and orgVdcNetwork['networkType'] != 'OPAQUE':
                    networkData = self.getNetworkData(
                        componentName=f"{orgVdcNetwork['name']}-{orgVdcNetwork['id'].split(':')[-1]}",
                        backingNetworkingId=orgVdcNetwork['backingNetworkId'])
                    if orgVdcNetwork.get('orgVdc', None) is None:
                        switchTags = [data for data in networkData['tags'] if 'vdcGroup' in data['tag']]
                    else:
                        switchTags = [data for data in networkData['tags'] if orgVdcNetwork['orgVdc']['id'] in data['tag']]

                    if switchTags:
                        switchList.append((networkData['display_name'], networkData['id'], networkData['transport_zone_path'],
                                           networkData['path']))
                        if "bridge_profiles" in networkData.keys():
                            bridgeDetails = networkData['bridge_profiles']
                            for data in bridgeDetails:
                                edgeBridgeList.append(data['bridge_profile_path'])

            if version.parse(self.apiVersion) < version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                logicalPorturl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                        nsxtConstants.CREATE_LOGICAL_SWITCH_PORT_API)
                response = self.restClientObj.get(url=logicalPorturl, headers=nsxtConstants.NSXT_API_HEADER,
                                                auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    logicalPortsList = json.loads(response.content)
                    logicalPortsList = logicalPortsList['results']
                # get the attached bridge endpoint id from logical switch ports
                bridgeEndpointIdList = [logicalPort['attachment']['id'] for logicalPort in logicalPortsList for switch in switchList if switch[1] == logicalPort['logical_switch_id'] and
                                        logicalPort['attachment']['attachment_type'] == 'BRIDGEENDPOINT']

            # Detach the segment
            # for each segment present in switchList, we are calling detach segment API.
            for segment in switchList:
                intent_path = nsxtConstants.LOGICAL_SEGMENTS_ENDPOINT.format(segment[1])
                segmentUrl = "{}{}".format(
                    nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), intent_path)
                response = self.restClientObj.get(url=segmentUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                  auth=self.restClientObj.auth)
                if not response.status_code == requests.codes.ok:
                    raise Exception(f"Falied to get details of logical segment {segment[0]}")

                segmentData = json.loads(response.content)
                if 'bridge_profiles' in segmentData.keys():
                    del segmentData['bridge_profiles']
                del segmentData['_create_user']
                del segmentData['_create_time']
                del segmentData['_last_modified_user']
                del segmentData['_last_modified_time']
                del segmentData['_system_owned']
                del segmentData['_protection']
                del segmentData['_revision']
                payloadData = json.dumps(segmentData)

                # Detach logical segment by removing bridge_profiles
                response = self.restClientObj.patch(url=segmentUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                    auth=self.restClientObj.auth, data=str(payloadData))
                if response.status_code == requests.codes.ok or response.status_code == requests.codes.created:
                    self.checkRealizedState(intent_path)
                    logger.debug('Logical segment {} is detached from bridge successfully.'.format(segment[0]))
                else:
                    responseData = json.loads(response.content)
                    msg = 'Failed to detach Logical segment {} from Edge-Bridge - {}'.format(segment, responseData['error_message'])
                    raise Exception(msg)

            # get the bridge endpoint
            if bridgeEndpointIdList or edgeBridgeList:
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

                # delete edge bridge profile with policy API.
                for edgeBridge in edgeBridgeList:
                    edgeBridgeProfileName = edgeBridge.split('/')[-1]
                    deleteEdgeBridgeUrl = "{}{}".format(
                        nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), edgeBridge)
                    response = self.restClientObj.delete(url=deleteEdgeBridgeUrl,
                                                         headers=nsxtConstants.NSXT_API_HEADER,
                                                         auth=self.restClientObj.auth)
                    if response.status_code == requests.codes.ok:
                        self.checkRealizedState(edgeBridge, markedForDelete=True)
                        logger.debug('Edge Bridge profile {} deleted Successfully'.format(edgeBridgeProfileName))
                    else:
                        responseData = json.loads(response.content)
                        msg = 'Failed to delete Bridge Edge Profile {} - {}'.format(edgeBridgeProfileName, responseData['error_message'])
                        raise Exception(msg)

                for bridgeEndpointProfileId in bridgeEndpointProfileIdResults:
                    bridgeEndpointProfileUrl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                                      nsxtConstants.GET_BRIDGE_ENDPOINT_PROFILE_BY_ID_API.format(bridgeEndpointProfileId))
                    response = self.restClientObj.get(url=bridgeEndpointProfileUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                      auth=self.restClientObj.auth)
                    # delete the bridge endpoint profile
                    if response.status_code == requests.codes.ok:
                        bridgeEndpointProfileResult = json.loads(response.content)
                        response = self.restClientObj.delete(url=bridgeEndpointProfileUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                                             auth=self.restClientObj.auth)
                        if response.status_code == requests.codes.ok:
                            logger.debug('Bridge Endpoint profile {} deleted Successfully'.format(bridgeEndpointProfileResult['display_name']))
                        else:
                            responseData = json.loads(response.content)
                            msg = 'Failed to delete Bridge Endpoint Profile {} - {}'.format(bridgeEndpointProfileResult['display_name'], responseData['error_message'])
                            raise Exception(msg)

            # Fetching edge transport nodes from edge cluster passed in input file
            edgeTransportNodeList = []
            for edgeClusterName in self.edgeClusterNameList:
                edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                        edgeClusterName)
                if edgeClusterData:
                    edgeTransportNodeList += edgeClusterData['members'] if isinstance(edgeClusterData['members'],
                                                                                      list) \
                        else [edgeClusterData['members']]
                    edgeTransportNodeList = [member for member in edgeTransportNodeList
                                             if member['transport_node_id'] in vcdObj.rollback.apiData['taggedNodesList']]
                else:
                    raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))

            # Fetching uplink profile data
            bridgeUplinkProfile = vcdObj.rollback.apiData['BridgingStatus'].get('UplinkProfileName')
            if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                uplinkProfileData = self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                                          componentName=bridgeUplinkProfile, usePolicyApi=True)
                id_key = "unique_id"
            else:
                uplinkProfileData = self.getComponentData(componentApi=nsxtConstants.DEPRECATED_HOST_SWITCH_PROFILE_API,
                                                          componentName=bridgeUplinkProfile)
                id_key = "id"
            # updating the transport node details inside edgeTransportNodeList
            for edgeTransportNode in edgeTransportNodeList:
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                             nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(
                                                                 edgeTransportNode['transport_node_id']))

                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                  auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    edgeNodeData = json.loads(response.content)
                    logger.debug("Updating Edge Transport Node {} by removing Bridge Transport zone".format(edgeNodeData['display_name']))

                    # Check if this node was used for bridging or not
                    for switch in edgeNodeData["host_switch_spec"]["host_switches"]:
                        if switch['transport_zone_endpoints'][0]['transport_zone_id'] == transportZoneId and \
                           switch['host_switch_profile_ids'][0]['value'] == uplinkProfileData[id_key]:
                            break
                    else:
                        continue

                    hostSwitchSpec = edgeNodeData["host_switch_spec"]["host_switches"]
                    # Removing last switch for host switch specification
                    hostSwitchSpec.pop()
                    dataNetworkList = edgeNodeData['node_deployment_info']['deployment_config']['vm_deployment_config']['data_network_ids']
                    # Removing last uplink from edge transport node uplink list
                    dataNetworkList.pop()
                    edgeNodeData["host_switch_spec"]["host_switches"] = hostSwitchSpec
                    edgeNodeData['node_deployment_info']['deployment_config']['vm_deployment_config'][
                        'data_network_ids'] = dataNetworkList
                    edgeNodeData['tags'] = [tag for tag in edgeNodeData['tags'] if nsxtConstants.MIGRATION_TAG_SCOPE not in tag["scope"]]
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
                        responseData = json.loads(response.content)
                        msg = "Failed to update Edge Transport node {} - {}.".format(edgeNodeData['display_name'], responseData)
                        logger.error(msg)
                        raise Exception(msg)
                else:
                    responseData = json.loads(response.content)
                    msg = "Failed to get Edge Transport node {} - {}.".format(edgeTransportNode, responseData)
                    logger.error(msg)
                    raise Exception(msg)

            # setting taggedNodesList to empty after removing tags
            vcdObj.rollback.apiData['taggedNodesList'] = []

            # getting the host switch profile details
            if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                hostSwitchProfileData = self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                                            componentName=bridgeUplinkProfile, usePolicyApi=True)
            else:
                hostSwitchProfileData = self.getComponentData(componentApi=nsxtConstants.DEPRECATED_HOST_SWITCH_PROFILE_API,
                                                            componentName=bridgeUplinkProfile)
            if hostSwitchProfileData:
                if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                    hostSwitchProfileId = hostSwitchProfileData['unique_id']
                    intent_path = hostSwitchProfileData['path']
                    url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), intent_path)
                    response = self.restClientObj.delete(url, headers=nsxtConstants.NSXT_API_HEADER,
                                                         auth=self.restClientObj.auth)
                    if response.status_code == requests.codes.ok:
                        self.checkRealizedState(intent_path, markedForDelete=True)
                        logger.debug('Host Switch Profile {} deleted successfully'.format(hostSwitchProfileId))
                    else:
                        responseData = json.loads(response.content)
                        msg = 'Failed to delete Host Switch Profile {} - {}'.format(hostSwitchProfileId,
                                                                                    responseData['error_message'])
                        raise Exception(msg)
                else:
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
        else:
            # Resetting thread name
            threading.current_thread().name = currentThreadName

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

    def getNsxtVersion(self):
        """
        Description :    Get the version of NSX-T
        """
        url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.NSXT_VERSION)
        response = self.restClientObj.get(url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
        responseDict = response.json()
        if response.status_code == requests.codes.ok:
            if version.parse(responseDict.get('node_version')) < version.parse("3.0"):
                logger.warning("NSXT {} is not supported with current migration tool. Some features may not work as expected.".format(responseDict.get('node_version')))
            return responseDict.get('node_version')
        raise Exception('Failed to retrieve to NSX-T version due to error - {}'.format(responseDict['error_message']))

    def rollbackBridging(self, vcdObjList):
        """
            Description : Clear Bridging if configured as a part of migration
            Parameters  : vcdObjList - list of objects of vcd operations class (LIST)
                          nsxtObj    - Object of nsxt operations class (OBJECT)
        """
        try:
            # Check if bridging is configured from metadata
            if vcdObjList[0].rollback.metadata.get('configureNSXTBridging'):
                # Fetching networks list that are bridged
                bridgedNetworksList = list()
                for vcdObject in vcdObjList:
                    # getting the target org vdc urn
                    dfw = True if vcdObject.rollback.apiData.get('OrgVDCGroupID') else False
                    if vcdObject.rollback.apiData.get('targetOrgVDC', {}).get('@id'):
                        bridgedNetworksList += vcdObject.retrieveNetworkListFromMetadata(
                            vcdObject.rollback.apiData.get('targetOrgVDC', {}).get('@id'), orgVDCType='target',
                            dfwStatus=dfw)
                self.clearBridging(bridgedNetworksList, vcdObjList[0], rollback=True)
        except:
            raise
        else:
            if vcdObjList[0].rollback.metadata.get('configureNSXTBridging'):
                # If bridging rollback is successful, remove the bridging key from metadata
                vcdObjList[0].deleteMetadataApiCall(key='configureNSXTBridging-system-v2t',
                                                    orgVDCId=vcdObjList[0].rollback.apiData.get('sourceOrgVDC', {}).get('@id'))
            # Restoring thread name
            threading.current_thread().name = "MainThread"

    def configureNSXTBridging(self, vcdObjList, vCenterObj):
        """
        Description :   Configure NSXT bridging
        Parameters  :   edgeClusterNameList  - List of NSX-T edge cluster names required for bridging (STRING)
                        vcdObjList - List of objects of vcd operations class (LIST)
        """
        try:
            targetOrgVdcNetworkList, portGroupList = list(), list()
            # Iterating over vcd objects to get target org vdc networks
            for vcdObj in vcdObjList:
                # Handling corner case for continuation message
                vcdObj.rollback.retry = True
                # Fetching target VDC Id
                targetOrgVdcId = vcdObj.rollback.apiData['targetOrgVDC']['@id']
                # Getting target org vdc network list
                targetOrgVdcNetworkList += vcdObj.retrieveNetworkListFromMetadata(targetOrgVdcId, orgVDCType='target')
                # Fetching port group list
                portGroupList += vcdObj.rollback.apiData['portGroupList'] if vcdObj.rollback.apiData.get(
                    'portGroupList') else list()

            # Replacing thread name with the name bridging
            threading.current_thread().name = "Bridging"

            filteredList = copy.deepcopy(targetOrgVdcNetworkList)
            filteredList = list(filter(lambda network: network['networkType'] != 'DIRECT' and network['networkType'] != 'OPAQUE', filteredList))
            if filteredList:

                # create bridge transport zone
                self.createTransportZone(vcdObjList[0])

                # create bridge endpoint profile
                self.createBridgeEndpointProfile(portGroupList, vcdObjList[0])

                # create host uplink profile for bridge n-vds
                self.createUplinkProfile(vcdObjList[0])

                # add bridge transport to bridge edge transport nodes
                self.updateEdgeTransportNodes(portGroupList, vcdObjList[0], vCenterObj)

                # attach bridge endpoint profile to logical switch
                self.attachBridgeEndpointSegment(portGroupList, targetOrgVdcNetworkList, vcdObjList[0])
        except:
            raise
        finally:
            # Resetting thread name
            threading.current_thread().name = "MainThread"

    def validateLimitOfBridgeEndpointProfile(self, orgVdcNetworkList):
        """
        Description :   Validates whether the edge transport nodes are accessible via ssh or not
        Parameters  :   orgVdcNetworkList     -   List of org vdc networks to be bridged (LIST)
        """
        # Fetching NSXT version
        try:
            # Fetching bridge endpoint profiles from NSXT
            bridgeProfileDict = self.getComponentData(
                componentApi=nsxtConstants.BRIDGE_EDGE_PROFILE_DETAILS, usePolicyApi=True)

            # if max limit is being exceeded raise exception
            if len(orgVdcNetworkList) + len(bridgeProfileDict) > nsxtConstants.MAX_LIMIT_OF_BRIDGE_ENDPOINT_PROFILES:
                if bridgeProfileDict:
                    raise Exception("Sum of the count of org vdc networks and the bridge endpoint profiles in NSXT is more than the max limit i.e {}".format(nsxtConstants.MAX_LIMIT_OF_BRIDGE_ENDPOINT_PROFILES))
                else:
                    raise Exception("Number of networks i.e {} is more than the max limit of bridge-endpoint profiles in NSXT {}".format(len(orgVdcNetworkList), nsxtConstants.MAX_LIMIT_OF_BRIDGE_ENDPOINT_PROFILES))
        except:
            raise

    def validateDlrMacAddress(self):
        """
        Description :   Validates whether NSXT global mac address is "02:50:56:56:44:52"
        """
        url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), nsxtConstants.NSXT_GLOBALCONFIG)
        response = self.restClientObj.get(
            url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
        if response.status_code != requests.codes.ok:
            raise Exception("Fail to get response")

        data = json.loads(response.content)
        if data['vdr_mac']  == nsxtConstants.NSXT_MACGLOBAL:
            logger.warning(
                'Make sure that the MAC Address of the NSX-T Virtual Distributed Router is different than the NSX-V'
                ' Distributed Logical Router (DLR) MAC address. The L2 bridging will not work properly for routed '
                'Org VDC networks. MAC address of the NSX-T Virtual Distributed Router is set to default: '
                '"02:50:56:56:44:52"'
                'https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/migration/GUID-538774C2-DE66-4F24-B9B7-537CA2FA87E9.html '
            )

    def validateEdgeNodesDeployedOnVCluster(self, vcenterObj, vxlanBackingPresent=True):
        """
        Description :   Validates whether the edge transport nodes are accessible via ssh or not
        Parameters  :   edgeClusterNameList     -   List of names of the cluster (STRING)
                        vcenterObj - Object of vcenter api class (OBJECT)
                        vxlanBackingPresent - Flag to check is VXLAN backed network pool is present any org vdc (BOOLEAN)
        """
        try:
            # Perform validation only if VXLAN backed network pool is present in any org vdc
            if not vxlanBackingPresent:
                logger.debug("Skipping edge node deployment cluster check as no network pool is backed by VXLAN")
                return

            # fetching the agency cluster host mappings using pyvmomi
            logger.debug("Fetching the agent cluster mappings")
            agencyClusterMapping = vcenterObj.fetchAgencyClusterMapping()
            logger.debug(f"AGENT CLUSTER MAPPING: {agencyClusterMapping}")

            logger.debug("Fetching the cluster resource-pool mappings")
            clusterResourcePoolMapping = vcenterObj.fetchClusterResourcePoolMapping()
            logger.debug(f"CLUSTER RESOURCE-POOL MAPPING: {clusterResourcePoolMapping}")

            logger.debug("Retrieving data of edge transport nodes present in edge cluster: {}".format(
                ', '.join(self.edgeClusterNameList)))
            edgeTransportNodeList = []
            edgeClusterNotFound = []
            for edgeClusterName in self.edgeClusterNameList:
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

            edgeNodeNotDeployedOnVCluster = []
            for edgeNode in edgeTransportNodeList:
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                             nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(
                                                                 edgeNode['transport_node_id']))
                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                  auth=self.restClientObj.auth)

                if response.status_code == requests.codes.ok:
                    edgeNodeData = response.json()
                    computeId = edgeNodeData['node_deployment_info']['deployment_config']['vm_deployment_config']['compute_id']
                    # Iterating over cluster resource-pool mapping to check if compute id matches with any resource pool id
                    for clusterMappedToRP, rPoolList in clusterResourcePoolMapping.items():
                        if computeId.strip() in list(map(str.strip, rPoolList)):
                            clusterName = clusterMappedToRP.strip()
                            break
                    else:
                        clusterName = computeId.strip()

                    for entity in agencyClusterMapping:
                        clusterMappedToAgent, agentName = entity
                        if not isinstance(agentName, str):
                            continue
                        if clusterName.strip() == clusterMappedToAgent.strip() and agentName.strip() == "VMware Network Fabric":
                            break
                    else:
                        edgeNodeNotDeployedOnVCluster.append(edgeNodeData['display_name'])
            if edgeNodeNotDeployedOnVCluster:
                raise Exception(f"Edge Transport Node/s - '{', '.join(edgeNodeNotDeployedOnVCluster)}' are not "
                                f"deployed on v-cluster on vCenter - {vcenterObj.ipAddress}")
        except:
            raise

    def validateIfEdgeTransportNodesAreAccessibleViaSSH(self):
        """
        Description :   Validates whether the edge transport nodes are accessible via ssh or not
        Parameters  :   edgeClusterNameList     -   List of names of the cluster (STRING)
        """
        try:
            #Suppressing paramiko transport logs
            logging.getLogger("paramiko").setLevel(logging.WARNING)
            logger.debug("Retrieving data of edge transport nodes present in edge cluster: {}".format(', '.join(self.edgeClusterNameList)))
            edgeTransportNodeList = []
            edgeClusterNotFound = []
            for edgeClusterName in self.edgeClusterNameList:
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
            nodeListUnaccessible = []
            for edgeNode in edgeTransportNodeList:
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                             nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(
                                                                 edgeNode['transport_node_id']))
                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                  auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    edgeNodeData = response.json()
                    try:
                        SshUtils(edgeNodeData['node_deployment_info']['ip_addresses'][0], 'admin', self.password)
                    except Exception as err:
                        logger.debug(str(err))
                        logger.debug(traceback.format_exc())
                        nodeListUnaccessible.append(edgeNodeData['display_name'])
                else:
                    raise Exception('Failed to fetch transport node details')
            if nodeListUnaccessible:
                raise Exception(f"Either Edge Transport Node/s - '{', '.join(nodeListUnaccessible)}' are not accessible via SSH or their password is different from NSX-T manager password")
        except Exception:
            raise
        finally:
            #Restoring log level of paramiko transport logs
            logging.getLogger("paramiko").setLevel(logging.INFO)

    def fetchEdgeClusterIdForTier0Gateway(self, tier0GatewayName):
        """
            Description :   Get edge cluster name for tier-0 gateway
            Parameters  :   tier0GatewayName -  Name of tier-0 gateway (STRING)
        """
        try:
            if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                tier0GatewayData = self.getVRFdetails(tier0GatewayName)
            else:
                tier0GatewayData = self.getComponentData(nsxtConstants.LOGICAL_ROUTER_API,
                                                        tier0GatewayName)

            if not tier0GatewayData:
                raise Exception(
                    "TIER-0 Gateway '{}' does not exist in NSX-T".format(tier0GatewayName))
            else:
                if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                    return tier0GatewayData["results"][0]["edge_cluster_path"].split("/")[-1]
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

    def validateEdgeNodesNotInUse(self, inputDict, orgVdcNetworkList, vcdObjList, precheck=False):
        """
        Description :   Validates that None Edge Transport Nodes are in use in the specified Edge Cluster
        Parameters  :   edgeClusterNameList -   List of names of the cluster (STRING)
        """
        try:
            usedNode = bool()
            edgeTransportNodeList = []
            edgeClusterNotFound = []
            freeTransportNodesList = []
            usedNodeList = []
            bridgeEndpointProfileNodeList = []
            taggedNodesList = []
            migrationId = inputDict['VCloudDirector']['Organization']['OrgName'] + '-' \
                          + inputDict['VCloudDirector']['SourceOrgVDC'][0]['OrgVDCName']
            logger.debug("Retrieving ID of edge cluster: {}".format(', '.join(self.edgeClusterNameList)))
            for edgeClusterName in self.edgeClusterNameList:
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

            # fetching bridge endpoint profile list
            bridgeEndpointProfileList = self.getComponentData(nsxtConstants.CREATE_BRIDGE_ENDPOINT_PROFILE)

            for transportNode in edgeTransportNodeList:
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                             nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(transportNode['transport_node_id']))
                response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    freeTransportNodesList.append(responseDict)
                    usedNode = False
                    # edge transport node is added to freeTransportNodesList after successful GET call
                    # edge transport node is popped out of freeTransportNodesList and loop is skipped in case if -
                    # 1. Host switch named 'Bridge-nvds-v2t' exists on node
                    # 2. Bridge endpoint profile exists on node
                    # 3. edge node is already tagged with migration Id
                    hostSwitchFlag = False
                    if responseDict.get('host_switch_spec'):
                        hostSwitchSpec = responseDict["host_switch_spec"]["host_switches"]
                        for hostSwitch in hostSwitchSpec:
                            if hostSwitch["host_switch_name"] == "Bridge-nvds-v2t":
                                hostSwitchFlag = True
                    else:
                        raise Exception('Host switch specification not available')
                    if hostSwitchFlag:
                        usedNodeList.append({"name": responseDict["display_name"], "id": responseDict["node_id"]})
                        usedNode = True
                    if any([responseDict["node_id"] in bridgeEndpointProfile["display_name"] for bridgeEndpointProfile in bridgeEndpointProfileList]):
                        bridgeEndpointProfileNodeList.append({"name": responseDict["display_name"], "id": responseDict["node_id"]})
                        usedNode = True
                    if any([tag["scope"] == nsxtConstants.MIGRATION_TAG_SCOPE and tag["tag"] != migrationId for tag in responseDict.get("tags", [])]):
                        taggedNodesList.append({"name": responseDict["display_name"], "id": responseDict["node_id"]})
                        usedNode = True
                    if usedNode:
                        freeTransportNodesList.pop()
                else:
                    raise Exception('Failed to fetch transport node details with error - {}'.format(responseDict["error_message"]))

            logger.debug(
                "freeTransportNodesList = {}".format(
                    [{"name": freeNode["display_name"], "id": freeNode["node_id"]} for freeNode in freeTransportNodesList]))
            logger.debug(
                "usedTransportNodesList = {}".format(usedNodeList))
            logger.debug(
                "bridgeEndpointProfileNodeList = {}".format(bridgeEndpointProfileNodeList))
            logger.debug(
                "taggedNodesList = {}".format(taggedNodesList))

            if len(orgVdcNetworkList) > len(edgeTransportNodeList):
                raise Exception(
                    "Number of Source Org VDC Networks should always be equal/less than the number of Edge Transport "
                    "Nodes in the cluster {}".format(self.edgeClusterNameList))
            if len(orgVdcNetworkList) <= len(freeTransportNodesList):
                logger.debug("Validated org vdc networks against free nodes in edge cluster/s {}".format(
                    ', '.join(self.edgeClusterNameList)))
                if not precheck:
                    self.tagEdgeTransportNodes(vcdObjList, freeTransportNodesList[0:len(orgVdcNetworkList)], migrationId)
            else:
                exception = "Insufficient free nodes on edge clusters provided. There are {} Non Direct Networks present that requires bridging while there are {} free nodes.\n".format(len(orgVdcNetworkList), len(freeTransportNodesList))
                if usedNodeList:
                    exception = exception + "Transport Nodes {} already in use\n".format(
                        ','.join([node["name"] for node in usedNodeList]))
                if bridgeEndpointProfileNodeList:
                    exception = exception + "Transport Nodes {} has bridge endpoint profile\n".format(
                        ','.join([node["name"] for node in bridgeEndpointProfileNodeList]))
                if taggedNodesList:
                    exception = exception + "Transport Nodes {} are already tagged".format(
                        ','.join([node["name"] for node in taggedNodesList]))
                raise Exception(exception)
        except Exception:
            raise

    def tagEdgeTransportNodes(self, vcdObjList, transportNodesList, migrationId):
        """
        Description :   Tags the available edge transport nodes with migration Id
        Parameters  :   freeTransportNodesList -   List of edge nodes available for bridging (LIST)
        """
        logger.info("Tagging edge transport nodes")
        data = vcdObjList[0].rollback.apiData
        tags = (nsxtConstants.MIGRATION_TAG_SCOPE, migrationId)
        logger.debug("taggedNodesList = {}".format(
            self.updateEdgeTransportNodesTags([node["node_id"] for node in transportNodesList], tagToAdd=tags)))
        data['taggedNodesList'] = [transportNode["node_id"] for transportNode in transportNodesList]

    def untagEdgeTransportNodes(self, vcdObjList, inputDict, transportNodesIdList):
        """
        Description :   Untags the available edge transport nodes tagged with migration Id
        Parameters  :   freeTransportNodesList -   List of edge nodes id available for bridging (LIST)
        """
        logger.info("Removing migration tag from edge transport nodes")
        migrationId = inputDict['VCloudDirector']['Organization']['OrgName'] + '-' \
                      + inputDict['VCloudDirector']['SourceOrgVDC'][0]['OrgVDCName']
        logger.debug("untaggedNodesList = {}".format(
            self.updateEdgeTransportNodesTags(transportNodesIdList, tagToRemove=(nsxtConstants.MIGRATION_TAG_SCOPE, migrationId))))
        vcdObjList[0].deleteMetadataApiCall(key='taggedNodesList-v2t',
                                            orgVDCId=vcdObjList[0].rollback.apiData.get('sourceOrgVDC', {}).get('@id'))

    def updateEdgeTransportNodesTags(self, transportNodesIdList, tagToAdd=None, tagToRemove=None):
        """
        Description :   Update the edge transport node tags
        Parameters  :   transportNodesList -   Transport nodes ID list (LIST)
                        tagToAdd - List of tags to add (LIST of TUPLES)
                        tagToRemove - List of tags to remove (LIST of TUPLES)
        """
        logger.debug("Updating edge transport nodes tags")
        transportNodeList = list()
        for node in transportNodesIdList:

            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                         nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(node))
            response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                              auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
            else:
                raise Exception(
                    'Failed to fetch transport node details with error - {}'.format(responseDict["error_message"]))
            if not responseDict.get('tags'):
                responseDict['tags'] = []
            responseDict['tags'] = [tag for tag in responseDict['tags'] if (tag["scope"], tag["tag"]) not in listify(tagToRemove)] + \
                                   [{"scope": tag[0], "tag": tag[1]} for tag in listify(tagToAdd)]

            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                         nsxtConstants.UPDATE_TRANSPORT_NODE_API.format(node))
            payloadDict = json.dumps(responseDict)
            response = self.restClientObj.put(url=url, headers=nsxtConstants.NSXT_API_HEADER, data=payloadDict,
                                              auth=self.restClientObj.auth)
            responseDict = response.json()
            if response.status_code == requests.codes.ok:
                logger.debug(
                    "Successfully updated edge transport node {} tags".format(responseDict['display_name']))
                transportNodeList.append({"name": responseDict["display_name"], "id": responseDict["node_id"]})
            else:
                msg = "Failed to update Edge Transport node {} with error {}.".format(responseDict['display_name'],
                                                                                          response.json()['error_message'])
                logger.error(msg)
                raise Exception(msg)
        return transportNodeList

    def validateTransportZoneExistsInNSXT(self, transportZoneName, returnData=False):
        """
        Description :   Validates that the specified transport zone exists in the NSXT
        Parameters  :   transportZoneName -   Name of the cluster (STRING)
                        returnData - Return data of transport zone (BOOLEAN)
        """
        try:
            if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), nsxtConstants.TRANSPORT_ZONE_API)
            else:
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.DEPRECATED_TRANSPORT_ZONE_API)
            response = self.restClientObj.get(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                transportZonesList = responseDict['results'] if isinstance(responseDict['results'], list) else [responseDict['results']]
                for transportZone in transportZonesList:
                    if transportZone['display_name'] == transportZoneName:
                        if returnData:
                            return transportZone
                        logger.debug("Validated successfully, transport zone '{}' exists in NSX-T".format(transportZoneName))
                        break
                else:
                    raise Exception("Transport Zone '{}' doesnot exist in NSX-T".format(transportZoneName))
        except Exception:
            raise

    def createTransportZone(self, vcdObj):
        """
        Description :   Created bridge transport zone if it is not present in NSX-T
        """
        TransportZone = nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME + str(uuid.uuid4())
        data = vcdObj.rollback.apiData
        if data.get("BridgingStatus", {}).get("TransportZone"):
            return
        if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
            # Url to create transport zone
            intent_path = nsxtConstants.TRANSPORT_ZONE_PATH.format(TransportZone)
            url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), intent_path)
            payloadData = {
                "display_name": TransportZone,
                "tz_type": "VLAN_BACKED",
                "description": "Transport zone to be used for bridging"
            }
            payloadData = json.dumps(payloadData)
            response = self.restClientObj.put(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth,
                                                data=payloadData)
            if response.status_code == requests.codes.ok:
                logger.info('Bridge Transport Zone {} created successfully.'.format(TransportZone))
                data['BridgingStatus'] = {"TransportZone": TransportZone}
                vcdObj.saveMetadataInOrgVdc(force=True)
            else:
                raise Exception('Failed to create Bridge Transport Zone. Errors {}.'.format(response.content))
        else:
            # Url to create transport zone
            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.DEPRECATED_TRANSPORT_ZONE_API)
            payloadData = {
                        "display_name": TransportZone,
                        "transport_type": "VLAN",
                        "host_switch_name": nsxtConstants.BRIDGE_TRANSPORT_ZONE_HOST_SWITCH_NAME,
                        "description": "Transport zone to be used for bridging"
                        }
            payloadData = json.dumps(payloadData)
            response = self.restClientObj.post(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth,
                                                data=payloadData)
            if response.status_code == requests.codes.created:
                logger.info('Bridge Transport Zone {} created successfully.'.format(TransportZone))
                data['BridgingStatus'] = {"TransportZone": TransportZone}
                vcdObj.saveMetadataInOrgVdc(force=True)
            else:
                raise Exception('Failed to create Bridge Transport Zone. Errors {}.'.format(response.content))

    def deleteTransportZone(self, vcdObj, rollback=False):
        """
        Description :   Delete bridge transport zone from NSX-T
        """
        try:
            try:
                TransportZone = vcdObj.rollback.apiData.get('BridgingStatus', {}).get('TransportZone')
                if not TransportZone:
                    return
                # Validating whether the bridge transport zone exists or not
                bridgeTransportZoneData = self.validateTransportZoneExistsInNSXT(TransportZone, returnData=True)
            except Exception:
                logger.debug(f'Bridge Transport Zone {TransportZone} does not exist in NSX-T')
                logger.debug(traceback.format_exc())
                return
            if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                transportZoneId = bridgeTransportZoneData['unique_id']
                intent_path = bridgeTransportZoneData['path']
                url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), intent_path)
            else:
                transportZoneId = bridgeTransportZoneData['id']
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.DEPRECATED_TRANSPORT_ZONE_API) + f"/{transportZoneId}"
            response = self.restClientObj.delete(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                 auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                logger.debug('Successfully deleted Bridge Transport Zone - "{}"'.format(TransportZone))
                if rollback:
                    vcdObj.deleteMetadataApiCall(key='BridgingStatus-v2t',
                                                        orgVDCId=vcdObj.rollback.apiData.get('sourceOrgVDC', {}).get('@id'))
            else:
                responseData = json.loads(response.content)
                msg = 'Failed to delete Bridge Transport Zone - "{}" due to error - {}'.format(TransportZone,
                                                                                        responseData['error_message'])
                raise Exception(msg)
        except:
            raise

    def getTier0LocaleServicesDetails(self, tier0GatewayName):
        try:
            localeServicesUrl = "{}{}".format(
                nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                nsxtConstants.GET_LOCALE_SERVICES_API.format(tier0GatewayName))
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
            bgpRoutingConfigUrl = "{}{}".format(
                nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                nsxtConstants.BGP_ROUTING_CONFIG_API.format(tier0GatewayName, tier0localeServices['id']))
            response = self.restClientObj.get(url=bgpRoutingConfigUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                              auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                return responseDict
            else:
                raise Exception('Failed to get Tier0 gateway details')
        except Exception:
            raise

    def validateDirectNetworkTZ(self, transportZoneName):
        """
        Description: This method validates the TZ is present or not
        """
        try:
            if transportZoneName:
                if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                    transportZoneData = self.getComponentData(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName, usePolicyApi=True)
                else:
                    transportZoneData = self.getComponentData(nsxtConstants.DEPRECATED_TRANSPORT_ZONE_API, transportZoneName)
                if not transportZoneData:
                    return 'The Transport Zone {} is not present in the NSX-T\n'. format(transportZoneName)
                    # raise Exception('The Transport Zone {} is not present in the NSX-T'. format(transportZoneName))
            else:
                return 'The field ImportedNetworkTransportZone in the userinput is mandatory when you have dedicated direct network in NSX-V backed Org VDV. \n'
        except Exception:
            raise

    def createLogicalSegments(self, orgvdcNetwork, directTZ, vlanId):
        """
        Description: This method is used to create a logical segments with NSX-T
        Parameters: orgvdcnetwork- network details of NSX-V backed ORg VDC network
                    directTZ- Name of the TZ to be used for imported network
                    vlanid - vlan id of the external network
        """
        try:
            vdcNetworkName = replace_unsupported_chars(orgvdcNetwork['name'])
            vdcNetworkId = orgvdcNetwork['id'].split(':')[-1]
            segmentName = f"{vdcNetworkName}-{vdcNetworkId}"
            if len(segmentName) > 80:
                segmentName = f"{vdcNetworkName[:-(len(segmentName) - 80)]}-{vdcNetworkId}"
            segmentId = segmentName.replace(' ', '_')

            intent_path = nsxtConstants.LOGICAL_SEGMENTS_ENDPOINT.format(segmentId)
            url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), intent_path)
            if version.parse(self.apiVersion) >= version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
                urlTZ = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), nsxtConstants.TRANSPORT_ZONE_API)
            else:
                urlTZ = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.DEPRECATED_TRANSPORT_ZONE_API)
            responseTZ = self.restClientObj.get(url=urlTZ, headers=nsxtConstants.NSXT_API_HEADER,
                                              auth=self.restClientObj.auth)
            if responseTZ.status_code == requests.codes.ok:
                responseDict = responseTZ.json()
                for values in responseDict['results']:
                    if values['display_name'] == directTZ:
                        transportzoneId = values['id']
                        payloadDict = {
                            "display_name": segmentName,
                            "transport_zone_path": '/infra/sites/default/enforcement-points/default/transport-zones/{}'.format(transportzoneId),
                            "vlan_ids": [vlanId],
                            "description": orgvdcNetwork['description'],
                            "id": segmentId
                        }
                        payloadData = json.dumps(payloadDict)
                        response = self.restClientObj.put(url=url, headers=nsxtConstants.NSXT_API_HEADER, data=payloadData,
                                                          auth=self.restClientObj.auth)

                        if response.status_code == requests.codes.ok:
                            self.checkRealizedState(intent_path)
                            responseDict = response.json()
                            backingUniqueId = responseDict['unique_id']
                            return backingUniqueId, segmentId
                        else:
                            errorDict = response.json()
                            raise Exception('Failed to create logical segment -{}, with error {}'.format(segmentId, errorDict['error_message']))
                else:
                    raise Exception('The transport zone - {} not present in the NSX-T'.format(directTZ))
            else:
                errorResponse = responseTZ.json()
                raise Exception('Failed to get transport zone - {} details - {}'.format(directTZ, errorResponse))
        except Exception:
            raise

    def getGroupsForExclusion(self, vcdObject):
        """
        Description : Adding and Removing NSX Segment to exclusion list
        Parameters  : vcdObjList- list of objects of vcd operations class (LIST)
        """
        try:
            # Getting all networks
            networkList = list()
            dfw = True if vcdObject.rollback.apiData.get('OrgVDCGroupID') else False
            if vcdObject.rollback.apiData.get('targetOrgVDC', {}).get('@id'):
                networkList += vcdObject.retrieveNetworkListFromMetadata(
                    vcdObject.rollback.apiData.get('targetOrgVDC', {}).get('@id'), orgVDCType='target',
                    dfwStatus=dfw)
            dcGroupInfo = dict()
            orgVdcDict = dict()
            for network in networkList:
                if network['networkType'] in ['NAT_ROUTED', 'DIRECT'] and network.get('ownerRef').get('id'):
                    # Storing orgVdc if network not scoped to DC group
                    if network['orgVdc']:
                        if not orgVdcDict.get(network['orgVdc']['id']):
                            orgVdcDict[network['orgVdc']['id']] = network['orgVdc']['name']+'-Exclusion-Group'
                        continue
                    # Storing DC Group if network scoped to DC group
                    if not dcGroupInfo.get(network['ownerRef']['id']):
                        dcGroupInfo[network['ownerRef']['id']] = network['ownerRef']['name']
            return dcGroupInfo, orgVdcDict
        except Exception:
            raise

    @remediate
    def addGroupToExclusionlist(self, vcdObject):
        """
        Description: Adding nsx segments of all routed network via groups in exclusion list
        """
        if not vcdObject.rollback.apiData.get('targetOrgVDCNetworks') \
                or not vcdObject.rollback.apiData['sourceOrgVDC'].get('NoOfvApp', 0) > 0:
            return
        logger.info('Adding VMs to NSX-T DFW Exclusion list')
        dcGroupInfo, orgVdcDict = self.getGroupsForExclusion(vcdObject)
        if orgVdcDict:
            for orgVdcId, orgVdcName in orgVdcDict.items():
                    self.createGroupInExclusionList(orgVdcId, orgVdcName)
        allGroupsInfo = {**dcGroupInfo, **orgVdcDict}
        # Get exclusion list
        currentExclusionList = self.getExclusionList()
        # Update exclusion list members then update exclusion list
        for groupId, groupName in allGroupsInfo.items():
            currentExclusionList['members'].append('/infra/domains/default/groups/{}'.format(groupId.split(':')[-1]))
        self.updateExclusionList(currentExclusionList)
        logger.debug("Groups added to the exclusion list successfully")

    @remediate
    def removeGroupFromExclusionlist(self, vcdObject):
        """
        Description: Removing nsx segments of networks via group from exclusion list
        """
        if not vcdObject.rollback.apiData.get('targetOrgVDCNetworks') \
                or not vcdObject.rollback.apiData['sourceOrgVDC'].get('NoOfvApp', 0) > 0:
            return
        logger.info('Removing VMs from NSX-T DFW Exclusion list')
        dcGroupInfo, orgVdcDict = self.getGroupsForExclusion(vcdObject)
        allGroupsInfo = {**dcGroupInfo, **orgVdcDict}
        # Get exclusion list
        currentExclusionList = self.getExclusionList()
        # Update exclusion list members then update exclusion list
        for groupId, groupName in allGroupsInfo.items():
            if ('/infra/domains/default/groups/{}'.format(groupId.split(':')[-1])) in currentExclusionList.get('members'):
                currentExclusionList['members'].remove('/infra/domains/default/groups/{}'.format(groupId.split(':')[-1]))
        self.updateExclusionList(currentExclusionList)
        # Deleting extra groups created for org vdc scoped networks if any
        if orgVdcDict:
            for orgVdcId, orgVdcName in orgVdcDict.items():
                url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                                    nsxtConstants.GET_GROUP_BY_ID_API.format(orgVdcId.split(':')[-1]))
                response = self.restClientObj.delete(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                  auth=self.restClientObj.auth)
                if response.status_code == requests.codes.ok:
                    logger.debug('Successfully deleted group in exclusion list')
                else:
                    responseData = json.loads(response.content)
                    raise Exception(responseData['error_message'])
        logger.debug("Successfully removed NSX-Segment of networks via groups from the exclusion list")

    def updateExclusionList(self, currentExclusionList):
        """
        Description : Updates the current exclusion list in nsxt
        Parameters  : currentExclusionList- updated exclusion list data
        """
        # Patching the exclusion list if required
        logger.debug("Updating the Exclusion List")
        exclusionUrl = "{}{}".format(
            nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
            nsxtConstants.GET_EXCLUSIONLIST_API)
        exclusionList = json.dumps(currentExclusionList)
        response = self.restClientObj.patch(url=exclusionUrl, headers=nsxtConstants.NSXT_API_HEADER, data=exclusionList,
                                            auth=self.restClientObj.auth)
        if response.status_code == requests.codes.ok:
            logger.debug('Successfully added/removed groups in the Exclusion List')
        else:
            responseData = json.loads(response.content)
            raise Exception(responseData['error_message'])

    def getExclusionList(self):
        """
        Description: Retrieves the exclude list from nsxt
        :return: returns the exclusion list response
        """
        logger.debug("Getting the exclusion list from NSX-T")
        exclusionUrl = "{}{}".format(
            nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), nsxtConstants.GET_EXCLUSIONLIST_API)
        response = self.restClientObj.get(url=exclusionUrl, headers=nsxtConstants.NSXT_API_HEADER,
                                          auth=self.restClientObj.auth)
        if response.status_code == requests.codes.ok:
            logger.debug('Successfully retrieved ExclusionList')
        else:
            responseData = json.loads(response.content)
            raise Exception(responseData['error_message'])
        return response.json()

    def createGroupInExclusionList(self, orgVdcId, orgVdcName):
        """
        Description : Creates a group in exclusion list with name and id
        """
        # Payload for creation of group
        payload = {
            "display_name": orgVdcName,
            "expression": [
                {
                    "value": 'SYSTEM|' + orgVdcId,
                    "member_type": "Segment",
                    "key": "Tag",
                    "operator": "EQUALS",
                    "resource_type": "Condition"
                }
            ],
            "id": orgVdcId.split(':')[-1]
        }
        if version.parse(self.apiVersion) > version.parse(nsxtConstants.API_VERSION_STARTWITH_3_2):
            payload['expression'][0]["scope_operator"] = "EQUALS"

        payload = json.dumps(payload)
        url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                            nsxtConstants.GET_GROUP_BY_ID_API.format(orgVdcId.split(':')[-1]))
        response = self.restClientObj.put(url=url, headers=nsxtConstants.NSXT_API_HEADER, data=payload,
                                          auth=self.restClientObj.auth)
        if response.status_code == requests.codes.ok:
            logger.debug('Successfully created group in exclusion list')
        else:
            responseData = json.loads(response.content)
            raise Exception(responseData['error_message'])

    def deleteLogicalSegments(self):
        """
        Description: This method is used to delete logical segments with NSX-T
        """
        try:
            logicalsegments = self.rollback.apiData.get('LogicalSegments')
            if logicalsegments:
                logger.info('Rollback: Deleting logical segments')
                for segments in logicalsegments:
                    intent_path = nsxtConstants.LOGICAL_SEGMENTS_ENDPOINT.format(segments)
                    url = "{}{}".format(
                        nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress), intent_path)
                    response = self.restClientObj.delete(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
                    if response.status_code == requests.codes.ok:
                        self.checkRealizedState(intent_path, markedForDelete=True)
                        logger.debug('Logical segment - {} deleted successfully'.format(segments))
                    else:
                        responseData = json.loads(response.content)
                        msg = 'Failed to delete Logical segment {} - {}'.format(segments, responseData['error_message'])
                        raise Exception(msg)
        except Exception:
            raise

    def getNsxtVniPoolIds(self):
        """
            Description :   Fetch VNI pool ids from NSXT
            Returns     :   Set of unique VNI pool ids present in NSXT(SET)
        """
        try:
            logger.debug("Fetching NSX-T VNI Pool id's")
            # List to store the VNI pool id's
            vniPoolIds = list()

            # URL to fetch VNI pools from NSXT
            poolRetrievalUrl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                      nsxtConstants.FETCH_VNI_POOL)

            # Get API call to retrieve VNI pools from NSXT
            response = self.restClientObj.get(poolRetrievalUrl,
                                                 headers=nsxtConstants.NSXT_API_HEADER,
                                                 auth=self.restClientObj.auth)

            # Rendering JSON response from API
            responseDict = response.json()

            if response.status_code == requests.codes.ok:
                logger.debug('Successfully retrieved VNI pool ranges from NSX-T')
                # Iterating over the VNI pool ranges present in NSXT
                for result in responseDict['results']:
                    for poolRange in result['ranges']:
                        # Creating ID's from pool range and extending it to final result list
                        vniPoolIds.extend(list(range(poolRange['start'], poolRange['end'] + 1)))
            else:
                raise Exception('Failed to retrieve VNI pool ranges from NSX-T')
            # Returning unique id's
            return set(vniPoolIds)
        except:
            raise

    def isOverlayBackedSegment(self, segmentName):
        response = self.restClientObj.get(
            url="{}{}".format(
                nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                nsxtConstants.LOGICAL_SEGMENTS_ENDPOINT.format(segmentName)),
            headers=nsxtConstants.NSXT_API_HEADER,
            auth=self.restClientObj.auth)
        segment = response.json()
        if not response.status_code == requests.codes.ok:
            raise Exception(f"Failed to get details of logical segment {segmentName}: {segment['error_message']}")

        response = self.restClientObj.get(
            url="{}{}".format(
                nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                segment['transport_zone_path']),
            headers=nsxtConstants.NSXT_API_HEADER,
            auth=self.restClientObj.auth)
        tz = response.json()
        if not response.status_code == requests.codes.ok:
            raise Exception(f"Failed to get details of transport zone: {tz['transport_zone_path']}: {tz['error_message']}")

        if tz['tz_type'] == 'OVERLAY_STANDARD':
            return True

        return False

    def createNsxtManagerQos(self, qosProfileName):
        """
        Description :   Validate Edge Gateway uplinks
        Parameters  :   edgeGatewayId   -   Id of the Edge Gateway  (STRING)
        """
        url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                            nsxtConstants.NSXT_QOS_PROFILE.format(qosProfileName))
        burstSize = int(qosProfileName) * 6250
        intentPath = nsxtConstants.NSXT_QOS_PROFILE.format(qosProfileName)
        payloadDict = {"display_name": "{} Mbps".format(qosProfileName),
                       "description": "Rate profile created during NSX-V to T migration",
                       "burst_size": burstSize,
                       "committed_bandwitdth": qosProfileName,
                       "excess_action": "DROP"}
        payloadData = json.dumps(payloadDict)
        # create QOS profile for the rate limit
        response = self.restClientObj.patch(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                            auth=self.restClientObj.auth, data=str(payloadData))
        if not response.status_code == requests.codes.ok:
            raise Exception("Failed to create NSXT-Manager QOS profiles : {}".format(response.json()))
        self.checkRealizedState(intentPath)
        logger.debug("QOS profile {} created successfully.".format(qosProfileName))

    def getVRFdetails(self, vrfBackingId):
        """
        Description :   Gets VRF details
        Parameters  :   VRFbackingId   -   Id of the VRF  (STRING)
        """
        vrfId = copy.deepcopy(vrfBackingId)
        vrfId = vrfId.replace(" ", "_")
        url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                            nsxtConstants.GET_LOCALE_SERVICES_API.format(vrfId))
        response = self.restClientObj.get(url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
        responseDict = response.json()
        if response.status_code == requests.codes.ok:
            vrfData = responseDict
            return vrfData
        raise Exception("Failed to get VRF details with error - {}".format(responseDict["error_message"]))

    def createRouteRedistributionRule(self, vrfData, t0Gateway, routeRedistributionRules):
        """
        Description :   Create route redistribution rule SYSTEM-VCD-EDGE-SERVICES-REDISTRIBUTION with services
        Parameters  :   VRFData   -   Info of the VRF  (STRING)
        """
        logger.debug("Configuring route redistribution rules on VRF - '{}'".format(t0Gateway))
        intentPath = vrfData["results"][0]["path"]
        url = "{}{}".format(nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                            intentPath)
        payLoad = {
                    "route_redistribution_config": {
                        "redistribution_rules": routeRedistributionRules
                    },
                    "edge_cluster_path": vrfData["results"][0]["edge_cluster_path"]
                }
        payloadDict = json.dumps(payLoad)
        response = self.restClientObj.patch(url=url, headers=nsxtConstants.NSXT_API_HEADER, data=payloadDict, auth=self.restClientObj.auth)
        if response.status_code == requests.codes.ok:
            logger.debug("Successfully updated route redistribution rules - {} on VRF - '{}'".format(routeRedistributionRules, t0Gateway))
            return
        raise Exception("Failed to create route redistribution rules")
