# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description: NSXT Module which performs the Bridging Operations
"""

import copy
import traceback
from functools import wraps
import inspect
import logging
import json
import os
import re
import requests
import threading
import time

import src.core.nsxt.nsxtConstants as nsxtConstants


from src.constants import rootDir
from src.commonUtils.sshUtils import SshUtils
from src.commonUtils.restClient import RestAPIClient
from src.commonUtils.utils import Utilities, InterOperabilityError
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

    def getNetworkData(self, nsxtVersion, componentName=None, backingNetworkingId=None):
        """
        Description   : This function validates the presence of the component in NSX-T
        Parameters    : nsxtVersion         -   NSXT version to check for interop (STRING)
                        componentName       -   Display-Name of the network (STRING)
                        backingNetworkingId -   Backing Network Id of org vdc network (STRING)
        Returns       : componentData if the component with the same display name is already present (DICTIONARY)
        """
        try:
            logger.debug("Fetching NSXT Logical-Segment data")
            if str(nsxtVersion).startswith(nsxtConstants.API_VERSION_STARTWITH):
                url = "{}{}".format(
                    nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                    nsxtConstants.SEGMENT_DETAILS)
            else:
                url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.CREATE_LOGICAL_SWITCH_API)

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
            version = api_data['info']['version']
            return version
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
            version = self.getNsxtAPIVersion()

            edgeClusterMembers = []
            for edgeClusterName in edgeClusterNameList:
                # checks API version for Interoperability.
                if str(version).startswith(nsxtConstants.API_VERSION_STARTWITH):
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
                            edgeClusterMembers.append({'transport_node_id': edgeNodeData['nsx_id'],
                                                       'member_index': edgeNodeData['member_index'], 'edgePath': edgeNodeData['path']})
                    else:
                        raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))
                else:
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
            # taking only the edge transport nodes which match the count of source portgroup details
            edgeNodePortgroupList = zip(edgeClusterMembers, portgroupList)
            for data, _ in edgeNodePortgroupList:
                # checks API version for Interoperability.
                if str(version).startswith(nsxtConstants.API_VERSION_STARTWITH):
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

                else:
                    url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                 nsxtConstants.CREATE_BRIDGE_ENDPOINT_PROFILE)
                    payloadDict = {
                        'bridgeEndpointProfileName': 'Bridge-Endpoint-Profile-{}'.format(data['transport_node_id']),
                        'edgeClusterId': data['edgeClusterId']}
                    payloadData = self.nsxtUtils.createPayload(filePath, payloadDict, fileType='json',
                                                               componentName=nsxtConstants.COMPONENT_NAME,
                                                               templateName=nsxtConstants.CREATE_BRIDGE_ENDPOINT_PROFILE_COMPONENT_NAME)
                    payloadData = json.loads(payloadData)
                    payloadData['edge_cluster_member_indexes'] = [data['member_index']]

                    payloadData = json.dumps(payloadData)
                    response = self.restClientObj.post(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                       auth=self.restClientObj.auth, data=payloadData)
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

    @description("addition of Bridge Transport Zone to Bridge Edge Transport Nodes", threadName="Bridging")
    @remediate
    def updateEdgeTransportNodes(self, edgeClusterNameList, portgroupList):
        """
        Description: Update Edge Transport Node
        Parameters:  edgeClusterNameList    - List of names of the edge cluster participating in bridging (LIST)
                     portgroupList          - List containing details of vxlan backed logical switch (LIST)
        """
        try:
            # getting the nsxt version using openapi spec.json
            nsxtVersion = tuple()
            openApiSpecsData = self.getComponentData(componentApi=nsxtConstants.OPENAPI_SPECS_API)
            if openApiSpecsData:
                nsxtVersion = tuple(map(int, openApiSpecsData['info']['version'].split('.')))
            transportZoneName = nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME
            logger.info('Adding Bridge Transport Zone to Bridge Edge Transport Nodes.')
            uplinkProfileData = self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                                      componentName=nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)

            transportZoneData = self.getComponentData(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName)

            logger.debug("Retrieving ID of edge cluster: {}".format(', '.join(edgeClusterNameList)))
            apiVersion = self.getNsxtAPIVersion()
            edgeClusterMembers = []
            for edgeClusterName in edgeClusterNameList:
                # checks API version for Interoperability.
                if str(apiVersion).startswith(nsxtConstants.API_VERSION_STARTWITH):
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
                            edgeClusterMembers.append({'transport_node_id': edgeNodeData['nsx_id'],
                                                       'member_index': edgeNodeData['member_index'], 'edgePath': edgeNodeData['path']})
                    else:
                        raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))
                else:
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
                    newHostSwitchSpec = {"host_switch_profile_ids": [{"key": "UplinkHostSwitchProfile", "value": uplinkProfileData['id']}],
                                         "host_switch_mode": "STANDARD",
                                         'host_switch_name': nsxtConstants.BRIDGE_TRANSPORT_ZONE_HOST_SWITCH_NAME,
                                         "pnics": [{"device_name": nextUnusedUplink, "uplink_name": uplinkProfileData['teaming']['active_list'][0]['uplink_name']}],
                                         "is_migrate_pnics": False,
                                         "ip_assignment_spec": {"resource_type": "AssignedByDhcp"},
                                         "transport_zone_endpoints": [
                                             {"transport_zone_id": transportZoneData['id'],
                                              "transport_zone_profile_ids": hostSwitchSpec[0]['transport_zone_endpoints'][0]['transport_zone_profile_ids']
                                              }]
                                         }
                    hostSwitchSpec.append(newHostSwitchSpec)
                    transportZoneList = edgeNodeData['transport_zone_endpoints']
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
    def attachBridgeEndpointSegment(self, edgeClusterNameList, portgroupList, targetOrgVDCNetworks):
        """
        Description : Attach Bridge Endpoint to logical segments
        Parameters  : edgeClusterNameList - List of names of the edge cluster participating in bridging (LIST)
                      portgroupList       - List containing details of vxlan backed logical switch (LIST)
        """
        try:
            logger.info('Attaching bridge endpoint profile to Logical Switch.')
            transportZoneName = nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME
            transportZoneId = self.getNsxtComponentIdByName(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName)
            transportZonePath = self.getTransportZoneData(transportZoneId)
            data = self.rollback.apiData
            apiVersion = self.getNsxtAPIVersion()
            switchList = []
            for orgVdcNetwork in targetOrgVDCNetworks:
                if orgVdcNetwork['networkType'] != 'DIRECT' and orgVdcNetwork['networkType'] != 'OPAQUE':
                    networkData = self.getNetworkData(nsxtVersion=apiVersion,
                                                      componentName=f"{orgVdcNetwork['name']}-"
                                                                    f"{orgVdcNetwork['id'].split(':')[-1]}",
                                                      backingNetworkingId=orgVdcNetwork['backingNetworkId'])
                    # checks API version for Interoperability
                    if str(apiVersion).startswith(nsxtConstants.API_VERSION_STARTWITH):
                        switchTags = [data for data in networkData['tags'] if
                                      orgVdcNetwork['orgVdc']['id'] in data['tag']]
                    else:
                        switchTags = [data for data in networkData['tags'] if orgVdcNetwork['backingNetworkId'] in data['tag']]

                    if switchTags:
                        switchList.append((networkData['display_name'], networkData['id'], orgVdcNetwork['networkType']))

            edgeSwitchList = []
            for item in portgroupList:
                for item1 in switchList:
                    if item['networkName'] in item1[0]:
                        edgeSwitchList.append((item, item1[1], item1[2], item1[0]))
            bridgeEndpointUrl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.CREATE_BRIDGE_ENDPOINT_API)
            logicalPorturl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.CREATE_LOGICAL_SWITCH_PORT_API)
            filePath = os.path.join(nsxtConstants.NSXT_ROOT_DIRECTORY, 'template.json')

            # Get transport Zone /infra/sites path.
            if transportZonePath is None:
                transportZonePath = nsxtConstants.TRANSPORT_ZONE_PATH.format(transportZoneId)

            edgeNodeList = []
            logger.debug("Retrieving ID of edge cluster: {}".format(', '.join(edgeClusterNameList)))
            edgeClusterMembers = []
            for edgeClusterName in edgeClusterNameList:
                # checks API version for Interoperability.
                if str(apiVersion).startswith(nsxtConstants.API_VERSION_STARTWITH):
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
                            edgeClusterMembers.append({'transport_node_id': edgeNodeData['nsx_id'],
                                                       'member_index': edgeNodeData['member_index'],
                                                       'edgePath': edgeNodeData['path']})
                    else:
                        raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))
                else:
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
                # checks API version for Interoperability.
                if str(apiVersion).startswith(nsxtConstants.API_VERSION_STARTWITH):
                    bridgeProfileDict = self.getComponentData(
                        componentApi=nsxtConstants.BRIDGE_EDGE_PROFILE_DETAILS, usePolicyApi=True)
                    bridgeProfile = [bridgeProfile for bridgeProfile in bridgeProfileDict if edgeNodeId in bridgeProfile['display_name']]
                else:
                    bridgeProfileDict = self.getComponentData(componentApi=nsxtConstants.CREATE_BRIDGE_ENDPOINT_PROFILE)
                    bridgeProfile = [bridgeProfile for bridgeProfile in bridgeProfileDict if edgeNodeId in bridgeProfile['display_name']]
                if not bridgeProfile:
                    continue
                # checks API version for Interoperability.
                if str(apiVersion).startswith(nsxtConstants.API_VERSION_STARTWITH):
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
                else:
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
                        responseData = json.loads(response.content)
                        logger.debug('Failed to create Bridge Endpoint')
                        raise Exception('Failed to create Bridge Endpoint : {}'.format(responseData))
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

    def clearBridging(self, edgeClusterNameList, orgVDCNetworkList, rollback=False):
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
            transportZoneName = nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME
            transportZoneId = self.getNsxtComponentIdByName(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName)
            if not orgVDCNetworkList:
                return
            if rollback:
                logger.info("RollBack: Clearing NSX-T Bridging")
            apiVersion = self.getNsxtAPIVersion()
            switchList = []
            logicalPorturl = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress,
                                                                    nsxtConstants.CREATE_LOGICAL_SWITCH_PORT_API)
            response = self.restClientObj.get(url=logicalPorturl, headers=nsxtConstants.NSXT_API_HEADER,
                                              auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                logicalPortsList = json.loads(response.content)
                logicalPortsList = logicalPortsList['results']
            edgeBridgeList = []
            # getting the logical switch id of the corresponding org vdc network
            for orgVdcNetwork in orgVDCNetworkList:
                if orgVdcNetwork['networkType'] != 'DIRECT' and orgVdcNetwork['networkType'] != 'OPAQUE':
                    networkData = self.getNetworkData(nsxtVersion=apiVersion,
                                                      componentName=f"{orgVdcNetwork['name']}-"
                                                                    f"{orgVdcNetwork['id'].split(':')[-1]}",
                                                      backingNetworkingId=orgVdcNetwork['backingNetworkId'])
                    # checks API version for Interoperability
                    if str(apiVersion).startswith(nsxtConstants.API_VERSION_STARTWITH):
                        if orgVdcNetwork.get('orgVdc', None) is None:
                            switchTags = [data for data in networkData['tags'] if 'vdcGroup' in data['tag']]
                        else:
                            switchTags = [data for data in networkData['tags'] if orgVdcNetwork['orgVdc']['id'] in data['tag']]
                    else:
                        switchTags = [data for data in networkData['tags'] if orgVdcNetwork['backingNetworkId'] in data['tag']]

                    if switchTags:
                        if str(apiVersion).startswith(nsxtConstants.API_VERSION_STARTWITH):
                            switchList.append((networkData['display_name'], networkData['id'], networkData['transport_zone_path'],
                                               networkData['path']))
                            if "bridge_profiles" in networkData.keys():
                                bridgeDetails = networkData['bridge_profiles']
                                for data in bridgeDetails:
                                    edgeBridgeList.append(data['bridge_profile_path'])
                        else:
                            switchList.append((networkData['display_name'], networkData['id']))
            # get the attached bridge endpoint id from logical switch ports
            bridgeEndpointIdList = [logicalPort['attachment']['id'] for logicalPort in logicalPortsList for switch in switchList if switch[1] == logicalPort['logical_switch_id'] and
                                    logicalPort['attachment']['attachment_type'] == 'BRIDGEENDPOINT']


            # get the logical port id
            logicalPortList = [logicalPort['id'] for logicalPort in logicalPortsList for switch in
                               switchList if switch[1] == logicalPort['logical_switch_id'] and
                               logicalPort['attachment']['attachment_type'] == 'BRIDGEENDPOINT']
            # Detach the segment
            # checks API version for Interoperability.
            if str(apiVersion).startswith(nsxtConstants.API_VERSION_STARTWITH):
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
            else:
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
            for edgeClusterName in edgeClusterNameList:
                edgeClusterData = self.getComponentData(nsxtConstants.CREATE_EDGE_CLUSTER_API,
                                                        edgeClusterName)
                if edgeClusterData:
                    edgeTransportNodeList += edgeClusterData['members'] if isinstance(edgeClusterData['members'],
                                                                                      list) \
                        else [edgeClusterData['members']]
                else:
                    raise Exception('Edge Cluster {} not found.'.format(edgeClusterName))

            # Fetching uplink profile data
            uplinkProfileData = self.getComponentData(componentApi=nsxtConstants.HOST_SWITCH_PROFILE_API,
                                                      componentName=nsxtConstants.BRDIGE_UPLINK_PROFILE_NAME)
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
                           switch['host_switch_profile_ids'][0]['value'] == uplinkProfileData['id']:
                            break
                    else:
                        continue

                    hostSwitchSpec = edgeNodeData["host_switch_spec"]["host_switches"]
                    # Removing last switch for host switch specification
                    hostSwitchSpec.pop()
                    transportZoneList = edgeNodeData['transport_zone_endpoints']
                    dataNetworkList = edgeNodeData['node_deployment_info']['deployment_config']['vm_deployment_config']['data_network_ids']
                    # Removing last uplink from edge transport node uplink list
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
                        responseData = json.loads(response.content)
                        msg = "Failed to update Edge Transport node {} - {}.".format(edgeNodeData['display_name'], responseData)
                        logger.error(msg)
                        raise Exception(msg)
                else:
                    responseData = json.loads(response.content)
                    msg = "Failed to get Edge Transport node {} - {}.".format(edgeTransportNode, responseData)
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
            # Deleting Bridge Transport Zone after the bridging is cleared
            self.deleteTransportZone()
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
            if int(responseDict.get('node_version').split(".")[0]) < 3:
                raise InterOperabilityError('NSX-T v{} is not compatible with current migration tool'.
                                            format(responseDict.get('node_version')))
            return responseDict.get('node_version')
        raise Exception('Failed to retrieve to NSX-T version due to error - {}'.format(responseDict['error_message']))

    def rollbackBridging(self, edgeClusterNameList, vcdObjList):
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
                self.clearBridging(edgeClusterNameList, bridgedNetworksList, rollback=True)
        except:
            raise
        else:
            if vcdObjList[0].rollback.metadata.get('configureNSXTBridging'):
                # If bridging rollback is successful, remove the bridging key from metadata
                vcdObjList[0].deleteMetadataApiCall(key='configureNSXTBridging-system-v2t',
                                                    orgVDCId=vcdObjList[0].rollback.apiData.get('sourceOrgVDC', {}).get('@id'))
            # Restoring thread name
            threading.current_thread().name = "MainThread"

    def configureNSXTBridging(self, edgeClusterNameList, vcdObjList):
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
                self.createTransportZone()

                # create bridge endpoint profile
                self.createBridgeEndpointProfile(edgeClusterNameList, portGroupList)

                # create host uplink profile for bridge n-vds
                self.createUplinkProfile()

                # add bridge transport to bridge edge transport nodes
                self.updateEdgeTransportNodes(edgeClusterNameList, portGroupList)

                # attach bridge endpoint profile to logical switch
                self.attachBridgeEndpointSegment(edgeClusterNameList, portGroupList, targetOrgVdcNetworkList)
        except:
            raise
        finally:
            # Resetting thread name
            threading.current_thread().name = "MainThread"

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

    def validateLimitOfBridgeEndpointProfile(self, orgVdcNetworkList):
        """
        Description :   Validates whether the edge transport nodes are accessible via ssh or not
        Parameters  :   orgVdcNetworkList     -   List of org vdc networks to be bridged (LIST)
        """
        # Fetching NSXT version
        apiVersion = self.getNsxtAPIVersion()
        try:
            # checks API version for Interoperability.
            if str(apiVersion).startswith(nsxtConstants.API_VERSION_STARTWITH):
                # Fetching bridge endpoint profiles from NSXT
                bridgeProfileDict = self.getComponentData(
                    componentApi=nsxtConstants.BRIDGE_EDGE_PROFILE_DETAILS, usePolicyApi=True)
            else:
                # Fetching bridge endpoint profiles from NSXT
                bridgeProfileDict = self.getComponentData(componentApi=nsxtConstants.CREATE_BRIDGE_ENDPOINT_PROFILE)

            # if max limit is being exceeded raise exception
            if len(orgVdcNetworkList) + len(bridgeProfileDict) > nsxtConstants.MAX_LIMIT_OF_BRIDGE_ENDPOINT_PROFILES:
                if bridgeProfileDict:
                    raise Exception("Sum of the count of org vdc networks and the bridge endpoint profiles in NSXT is more than the max limit i.e {}".format(nsxtConstants.MAX_LIMIT_OF_BRIDGE_ENDPOINT_PROFILES))
                else:
                    raise Exception("Number of networks i.e {} is more than the max limit of bridge-endpoint profiles in NSXT {}".format(len(orgVdcNetworkList), nsxtConstants.MAX_LIMIT_OF_BRIDGE_ENDPOINT_PROFILES))
        except:
            raise

    def validateEdgeNodesDeployedOnVCluster(self, edgeClusterNameList, vcenterObj, vxlanBackingPresent=True):
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
            logger.debug(f"CLUSTER RESOURCE-POOL MAPPING: {agencyClusterMapping}")

            logger.debug("Retrieving data of edge transport nodes present in edge cluster: {}".format(
                ', '.join(edgeClusterNameList)))
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
                        if clusterName.strip() == clusterMappedToAgent.strip() and agentName.strip() == "VMware Network Fabric":
                            break
                    else:
                        edgeNodeNotDeployedOnVCluster.append(edgeNodeData['display_name'])
            if edgeNodeNotDeployedOnVCluster:
                raise Exception(f"Edge Transport Node/s - '{', '.join(edgeNodeNotDeployedOnVCluster)}' are not "
                                f"deployed on v-cluster on vCenter - {vcenterObj.ipAddress}")
        except:
            raise

    def validateIfEdgeTransportNodesAreAccessibleViaSSH(self, edgeClusterNameList):
        """
        Description :   Validates whether the edge transport nodes are accessible via ssh or not
        Parameters  :   edgeClusterNameList     -   List of names of the cluster (STRING)
        """
        try:
            #Suppressing paramiko transport logs
            logging.getLogger("paramiko").setLevel(logging.WARNING)
            logger.debug("Retrieving data of edge transport nodes present in edge cluster: {}".format(', '.join(edgeClusterNameList)))
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
            orgVdcNetworkList = [network for network in orgVdcNetworkList if network['networkType'] != 'DIRECT']
            if len(orgVdcNetworkList) <= len(edgeTransportNodeList):
                logger.debug("Validated successfully the number of source Org VDC networks are equal/less than the number of Edge Transport Nodes in the cluster {}".format(edgeClusterName))
            else:
                raise Exception("Number of Source Org VDC Networks should always be equal/less than the number of Edge Transport Nodes in the cluster {}".format(edgeClusterName))
        except Exception:
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

    def validateTransportZoneExistsInNSXT(self, transportZoneName, returnData=False):
        """
        Description :   Validates that the specified transport zone exists in the NSXT
        Parameters  :   transportZoneName -   Name of the cluster (STRING)
                        returnData - Return data of transport zone (BOOLEAN)
        """
        try:
            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.TRANSPORT_ZONE_API)
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

    def createTransportZone(self):
        """
        Description :   Created bridge transport zone if it is not present in NSX-T
        """
        try:
            # Validating whether the bridge transport zone exists or not
            self.validateTransportZoneExistsInNSXT(nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME)
        except Exception:
            # Url to create transport zone
            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.TRANSPORT_ZONE_API)
            payloadData = {
                        "display_name": nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME,
                        "transport_type": "VLAN",
                        "host_switch_name": nsxtConstants.BRIDGE_TRANSPORT_ZONE_HOST_SWITCH_NAME,
                        "description": "Transport zone to be used for bridging"
                      }
            payloadData = json.dumps(payloadData)
            response = self.restClientObj.post(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth,
                                               data=payloadData)
            if response.status_code == requests.codes.created:
                logger.debug(
                    'Bridge Transport Zone {} created successfully.'.format(nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME))
            else:
                raise Exception('Failed to create Bridge Transport Zone. Errors {}.'.format(response.content))
        else:
            logger.debug(f'Bridge Transport Zone {nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME} is already present in NSX-T')

    def deleteTransportZone(self):
        """
        Description :   Delete bridge transport zone from NSX-T
        """
        try:
            try:
                # Validating whether the bridge transport zone exists or not
                bridgeTransportZoneData = self.validateTransportZoneExistsInNSXT(nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME, returnData=True)
            except Exception:
                logger.debug(f'Bridge Transport Zone {nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME} does not exist in NSX-T')
                logger.debug(traceback.format_exc())
                return
            transportZoneId = bridgeTransportZoneData['id']
            url = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.TRANSPORT_ZONE_API) + f"/{transportZoneId}"
            response = self.restClientObj.delete(url=url, headers=nsxtConstants.NSXT_API_HEADER,
                                                 auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                logger.debug('Successfully deleted Bridge Transport Zone - "{}"'.format(nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME))
            else:
                responseData = json.loads(response.content)
                msg = 'Failed to Bridge Transport Zone - "{}" due to error - {}'.format(nsxtConstants.BRIDGE_TRANSPORT_ZONE_NAME,
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
                transportZoneData = self.getComponentData(nsxtConstants.TRANSPORT_ZONE_API, transportZoneName)
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
            vdcNetworkName = orgvdcNetwork['name']
            vdcNetworkId = orgvdcNetwork['id'].split(':')[-1]
            segmentId = ''
            if len(vdcNetworkName)+len(vdcNetworkId)+1 > 80:
                charsTodelete = abs(len(vdcNetworkName)+len(vdcNetworkId)+1-80)
                charList = list(vdcNetworkName)
                for i in range(0, charsTodelete):
                    charList.pop()
                name = "".join(charList)
                segmentName = name+'-'+vdcNetworkId
            else:
                segmentName = vdcNetworkName+'-'+vdcNetworkId
            segmentId = segmentName.replace(' ', '_')
            url = "{}{}".format(
                nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                nsxtConstants.LOGICAL_SEGMENTS_ENDPOINT.format(segmentId))
            urlTZ = nsxtConstants.NSXT_HOST_API_URL.format(self.ipAddress, nsxtConstants.TRANSPORT_ZONE_API)
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

    def deleteLogicalSegments(self):
        """
        Description: This method is used to delete logical segments with NSX-T
        """
        try:
            logicalsegments = self.rollback.apiData.get('LogicalSegments')
            if logicalsegments:
                logger.info('Rollback: Deleting logical segments')
                for segments in logicalsegments:
                    url = "{}{}".format(
                        nsxtConstants.NSXT_HOST_POLICY_API.format(self.ipAddress),
                        nsxtConstants.LOGICAL_SEGMENTS_ENDPOINT.format(segments))
                    response = self.restClientObj.delete(url=url, headers=nsxtConstants.NSXT_API_HEADER, auth=self.restClientObj.auth)
                    if response.status_code == requests.codes.ok:
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