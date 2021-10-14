# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description: Module which performs the VMware Cloud Director NSX-V to NSX-T Migration Operations
"""

import ipaddress
import logging
import json
import re
import time
import os
import copy
import sys
import prettytable
import requests
import threading
import traceback
import xmltodict
from itertools import zip_longest
from functools import reduce
from collections import defaultdict
from src.commonUtils.utils import Utilities
import src.constants as mainConstants
import src.core.vcd.vcdConstants as vcdConstants

from src.core.vcd.vcdValidations import (
    isSessionExpired, description, remediate, remediate_threaded, METADATA_SAVE_FALSE, getSession)
from src.core.vcd.vcdConfigureEdgeGatewayServices import ConfigureEdgeGatewayServices
logger = logging.getLogger('mainLogger')


class VCloudDirectorOperations(ConfigureEdgeGatewayServices):
    """
    Description: Class that performs the VMware Cloud Director NSX-V to NSX-T Migration Operations
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.targetStorageProfileMap = dict()
        self.sourceDisksData = None
        self.targetDisksData = None
        vcdConstants.VCD_API_HEADER = vcdConstants.VCD_API_HEADER.format(self.version)
        vcdConstants.GENERAL_JSON_CONTENT_TYPE = vcdConstants.GENERAL_JSON_CONTENT_TYPE.format(self.version)
        vcdConstants.OPEN_API_CONTENT_TYPE = vcdConstants.OPEN_API_CONTENT_TYPE.format(self.version)

    @description("creation of target Org VDC Edge Gateway")
    @remediate
    def createEdgeGateway(self, inputDict, vdcDict, nsxObj):
        """
        Description :   Creates an Edge Gateway in the specified Organization VDC
        """
        try:
            if not self.rollback.apiData['sourceEdgeGateway']:
                logger.debug('Skipping Target Edge Gateway creation as no source '
                             'Edge Gateway exist.')
                # If source Edge Gateway are not present, target Edge Gateway will also be empty
                self.rollback.apiData['targetEdgeGateway'] = list()
                return

            logger.info('Creating target Org VDC Edge Gateway')
            # reading data from apiOutput.json
            data = self.rollback.apiData

            # Acquiring lock as only one operation can be performed on an external network at a time
            self.lock.acquire(blocking=True)
            logger.debug("Updating Target External network {} with sub allocated ip pools".format(vdcDict["ExternalNetwork"]))
            # getting details of ip ranges used in source edge gateways
            edgeGatewaySubnetDict = {}
            for edgeGateway in copy.deepcopy(data['sourceEdgeGateway']):
                for edgeGatewayUplink in edgeGateway['edgeGatewayUplinks']:
                    for subnet in edgeGatewayUplink['subnets']['values']:
                        # Getting value of primary ip
                        primaryIp = subnet.get('primaryIp')
                        # Creating ip range for primary ip
                        subIpRange = [{'startAddress': primaryIp, 'endAddress': primaryIp}]
                        networkAddress = ipaddress.ip_network('{}/{}'.format(subnet['gateway'], subnet['prefixLength']),
                                                              strict=False)
                        if networkAddress in edgeGatewaySubnetDict:
                            edgeGatewaySubnetDict[networkAddress].extend(subnet['ipRanges']['values'])
                        else:
                            edgeGatewaySubnetDict[networkAddress] = subnet['ipRanges']['values']

                        # adding primary ip to sub alloacated ip pool
                        if primaryIp and ipaddress.ip_address(primaryIp) in networkAddress:
                            edgeGatewaySubnetDict[networkAddress].extend(subIpRange)

            # Getting target external network details
            externalDict = self.getExternalNetwork(vdcDict["ExternalNetwork"])
            external_network_id = externalDict['id']
            for index, subnet in enumerate(externalDict['subnets']['values']):
                subnetOfTargetExtNetToUpdate = ipaddress.ip_network(
                    '{}/{}'.format(subnet['gateway'], subnet['prefixLength']), strict=False)
                # if no ip present to update of corrensponding subnet skip the operation
                if not edgeGatewaySubnetDict.get(subnetOfTargetExtNetToUpdate):
                    continue
                externalDict['subnets']['values'][index]['ipRanges']['values'].extend(
                    edgeGatewaySubnetDict.get(subnetOfTargetExtNetToUpdate))

            # url to update external network properties
            url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                   vcdConstants.ALL_EXTERNAL_NETWORKS, external_network_id)
            # put api call to update external netowork
            self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
            payloadData = json.dumps(externalDict)

            response = self.restClientObj.put(url, self.headers, data=payloadData)
            if response.status_code == requests.codes.accepted:
                taskUrl = response.headers['Location']
                # checking the status of the updating external network task
                self._checkTaskStatus(taskUrl=taskUrl)
                logger.debug('Target External network {} updated successfully with sub allocated ip pools.'.format(
                    externalDict['name']))
                self.isExternalNetworkUpdated = True
            else:
                errorResponse = response.json()
                raise Exception('Failed to update External network {} with sub allocated ip pools - {}'.format(
                    externalDict['name'], errorResponse['message']))
            # Releasing lock
            self.lock.release()

            # getting the edge gateway details of the target org vdc
            targetEdgeGatewayNames = [edgeGateway['name'] for edgeGateway in
                                      self.getOrgVDCEdgeGateway(data['targetOrgVDC']['@id'])['values']]

            for sourceEdgeGatewayDict in copy.deepcopy(data['sourceEdgeGateway']):
                if sourceEdgeGatewayDict['name'] in targetEdgeGatewayNames:
                    continue

                # Checking if default edge gateway is configured on edge gateway
                sourceEdgeGatewayId = sourceEdgeGatewayDict['id'].split(':')[-1]
                defaultGatewayData = self.getEdgeGatewayAdminApiDetails(sourceEdgeGatewayId, returnDefaultGateway=True)
                if isinstance(defaultGatewayData, list):
                    raise Exception(
                        'Default gateway is not configured on edge gateway - {}'.format(sourceEdgeGatewayDict['name']))
                defaultGateway = defaultGatewayData.get('gateway')

                bgpConfigDict = self.getEdgegatewayBGPconfig(sourceEdgeGatewayId, validation=False)
                data = self.rollback.apiData
                externalDict = self.getExternalNetwork(vdcDict["ExternalNetwork"])
                # edge gateway create URL
                url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS)
                filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
                # creating payload dictionary
                payloadDict = {'edgeGatewayName': sourceEdgeGatewayDict['name'],
                               'edgeGatewayDescription': sourceEdgeGatewayDict[
                                   'description'] if sourceEdgeGatewayDict.get('description') else '',
                               'orgVDCName': data['targetOrgVDC']['@name'],
                               'orgVDCId': data['targetOrgVDC']['@id'],
                               'orgName': data['Organization']['@name'],
                               'orgId': data['Organization']['@id'],
                               'externalNetworkId': externalDict['id'],
                               'externalNetworkName': externalDict['name'],
                               'nsxtManagerName': externalDict['networkBackings']['values'][0]['networkProvider'][
                                   'name'],
                               'nsxtManagerId': externalDict['networkBackings']['values'][0]['networkProvider']['id']
                               }

                if (isinstance(bgpConfigDict, tuple) and not bgpConfigDict[0]) or not bgpConfigDict or bgpConfigDict['enabled'] != "true":
                    payloadDict['dedicated'] = False
                else:
                    payloadDict['dedicated'] = True
                # creating payload data
                payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                          componentName=vcdConstants.COMPONENT_NAME,
                                                          templateName=vcdConstants.CREATE_ORG_VDC_EDGE_GATEWAY_TEMPLATE)

                # adding sub allocated ip pool in edge gateway payload
                subnetData = []

                # Adding primary ip in sub - allocated pool of egde gateway
                for uplink in sourceEdgeGatewayDict['edgeGatewayUplinks']:
                    for subnet in uplink['subnets']['values']:
                        # Getting value of primary ip
                        primaryIp = subnet.get('primaryIp')
                        # Creating ip range for primary ip
                        subIpRange = [{'startAddress': primaryIp, 'endAddress': primaryIp}]

                        networkAddress = ipaddress.ip_network('{}/{}'.format(subnet['gateway'], subnet['prefixLength']),
                                                              strict=False)
                        # adding primary ip to sub alloacated ip pool
                        if primaryIp and ipaddress.ip_address(primaryIp) in networkAddress:
                            subnet['ipRanges']['values'].extend(subIpRange)

                    subnetData += uplink['subnets']['values']

                # Setting primary ip to be used for edge gateway creation
                for subnet in subnetData:
                    if subnet['gateway'] == defaultGateway:
                        continue
                    else:
                        subnet['primaryIp'] = None

                payloadData = json.loads(payloadData)
                payloadData['edgeGatewayUplinks'][0]['subnets'] = {}
                payloadData['edgeGatewayUplinks'][0]['subnets']['values'] = subnetData

                # Checking if edge cluster is specified in user input yaml
                if vdcDict.get('EdgeGatewayDeploymentEdgeCluster'):
                    # Fetch edge cluster id
                    edgeClusterId = nsxObj.fetchEdgeClusterDetails(vdcDict["EdgeGatewayDeploymentEdgeCluster"]).get('id')
                else:
                    tier0RouterName = \
                    data['targetExternalNetwork']['networkBackings']['values'][0]['name']
                    edgeClusterId = nsxObj.fetchEdgeClusterIdForTier0Gateway(tier0RouterName)

                # Create edge cluster config payload for edge gateway
                edgeClusterConfigPayload = {"edgeClusterConfig":
                                                {"primaryEdgeCluster":
                                                     {"backingId": edgeClusterId}}}
                # Updating edge cluster configuration payload in edge gateway creation payload
                payloadData.update(edgeClusterConfigPayload)

                if float(self.version) < float(vcdConstants.API_VERSION_ZEUS):
                    payloadData['orgVdc'] = {
                        "name": data['targetOrgVDC']['@name'],
                        "id": data['targetOrgVDC']['@id'],
                    }
                else:
                    payloadData['ownerRef'] = {
                        "name": data['targetOrgVDC']['@name'],
                        "id": data['targetOrgVDC']['@id'],
                    }
                payloadData = json.dumps(payloadData)

                self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                # post api to create edge gateway
                response = self.restClientObj.post(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    # checking the status of creating target edge gateway task
                    self._checkTaskStatus(taskUrl=taskUrl)
                    logger.debug('Target Edge Gateway created successfully.')
                else:
                    errorResponse = response.json()
                    raise Exception(
                        'Failed to create target Org VDC Edge Gateway - {}'.format(errorResponse['message']))
            # getting the edge gateway details of the target org vdc
            responseDict = self.getOrgVDCEdgeGateway(data['targetOrgVDC']['@id'])
            data['targetEdgeGateway'] = responseDict['values']
            return [value['id'] for value in responseDict['values']]
        except Exception:
            raise
        finally:
            try:
                # Releasing the lock
                self.lock.release()
                logger.debug("Lock released by thread - '{}'".format(threading.currentThread().getName()))
            except RuntimeError:
                pass

    @description("creation of target Org VDC Networks")
    @remediate
    def createOrgVDCNetwork(self, orgVDCIDList, sourceOrgVDCNetworks, inputDict, vdcDict, nsxObj):
        """
        Description : Create Org VDC Networks in the specified Organization VDC
        """
        try:
            segmetList = list()
            # Check if overlay id's are to be cloned or not
            cloneOverlayIds = inputDict['VCloudDirector'].get('CloneOverlayIds')

            logger.info('Creating target Org VDC Networks')
            data = self.rollback.apiData
            targetOrgVDC = data['targetOrgVDC']
            targetEdgeGateway = data['targetEdgeGateway']
            # org vdc network create URL
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_ORG_VDC_NETWORKS)
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')

            # getting target org vdc network name list
            targetOrgVDCNetworksList = [network['name'] for network in self.getOrgVDCNetworks(targetOrgVDC['@id'], 'targetOrgVDCNetworks', saveResponse=False)]

            for sourceOrgVDCNetwork in sourceOrgVDCNetworks:
                overlayId = None
                # Fetching overlay id of the org vdc network, if CloneOverlayIds parameter is set to true
                if cloneOverlayIds:
                    # URL to fetch overlay id of source org vdc networks
                    overlayIdUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                 vcdConstants.ORG_VDC_NETWORK_ADDITIONAL_PROPERTIES.format(
                                                     sourceOrgVDCNetwork['id']
                                                 ))
                    # Getting response from API call
                    response = self.restClientObj.get(overlayIdUrl, self.headers)
                    # Fetching JSON response from API call
                    responseDict = response.json()
                    if response.status_code == requests.codes.ok:
                        logger.debug(
                            'Fetched source org vdc network "{}" overlay id successfully.'.format(
                                sourceOrgVDCNetwork['name']))
                        overlayId = responseDict.get('overlayId')
                    else:
                        raise Exception(
                            'Failed to fetch source org vdc network "{}" overlay id  due to error- "{}"'.format(
                                sourceOrgVDCNetwork['name'], responseDict['message']))

                # Handled remediation in case of network creation failure
                if sourceOrgVDCNetwork['name'] + '-v2t' in targetOrgVDCNetworksList:
                    continue
                if sourceOrgVDCNetwork['networkType'] == "DIRECT":
                    segmentid, payloadData = self.createDirectNetworkPayload(orgVDCIDList, inputDict, vdcDict, nsxObj, orgvdcNetowork=sourceOrgVDCNetwork, parentNetworkId=sourceOrgVDCNetwork['parentNetworkId'])
                    if segmentid:
                        segmetList.append(segmentid)
                else:
                    # creating payload dictionary
                    payloadDict = {'orgVDCNetworkName': sourceOrgVDCNetwork['name'] + '-v2t',
                                   'orgVDCNetworkDescription': sourceOrgVDCNetwork[
                                       'description'] if sourceOrgVDCNetwork.get('description') else '',
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
                elif sourceOrgVDCNetwork['networkType'] != "DIRECT":
                    edgeGatewayName = sourceOrgVDCNetwork['connection']['routerRef']['name']
                    edgeGatewayId = \
                    list(filter(lambda edgeGatewayData: edgeGatewayData['name'] == edgeGatewayName, targetEdgeGateway))[
                        0]['id']
                    payloadDict.update({'edgeGatewayName': edgeGatewayName,
                                        'edgeGatewayId': edgeGatewayId})
                if sourceOrgVDCNetwork['networkType'] != "DIRECT":
                    # creating payload data
                    payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.CREATE_ORG_VDC_NETWORK_TEMPLATE, apiVersion=self.version)

                #Loading JSON payload data to python Dict Structure
                payloadData = json.loads(payloadData)

                if float(self.version) < float(vcdConstants.API_VERSION_ZEUS):
                    payloadData['orgVdc'] = {
                        "name": targetOrgVDC['@name'],
                        "id": targetOrgVDC['@id']
                    }
                else:
                    payloadData['ownerRef'] = {
                        "name": targetOrgVDC['@name'],
                        "id": targetOrgVDC['@id']
                    }
                if sourceOrgVDCNetwork['networkType'] == "ISOLATED":
                    payloadData['connection'] = {}
                if not sourceOrgVDCNetwork['subnets']['values'][0]['ipRanges']['values']:
                    payloadData['subnets']['values'][0]['ipRanges']['values'] = None
                elif sourceOrgVDCNetwork['networkType'] != "DIRECT":
                    ipRangeList = []
                    for ipRange in sourceOrgVDCNetwork['subnets']['values'][0]['ipRanges']['values']:
                        ipPoolDict = {}
                        ipPoolDict['startAddress'] = ipRange['startAddress']
                        ipPoolDict['endAddress'] = ipRange['endAddress']
                        ipRangeList.append(ipPoolDict)
                    payloadData['subnets']['values'][0]['ipRanges']['values'] = ipRangeList

                # Handling code for dual stack networks
                if sourceOrgVDCNetwork.get('enableDualSubnetNetwork', None):
                    payloadData['subnets'] = sourceOrgVDCNetwork['subnets']
                    payloadData['enableDualSubnetNetwork'] = True

                # Adding overlay id in payload if cloneOverlayIds parameter is set to True and
                # if overlay id exists for corresponding org vdc network
                if cloneOverlayIds and overlayId:
                    payloadData.update({'overlayId': overlayId})

                # Setting headers for the OPENAPI requests
                self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE

                payloadData = json.dumps(payloadData)
                # post api to create org vdc network
                response = self.restClientObj.post(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    # checking the status of the creating org vdc network task
                    self._checkTaskStatus(taskUrl=taskUrl)
                    logger.debug('Target Org VDC Network {} created successfully.'.format(sourceOrgVDCNetwork['name']))
                else:
                    errorResponse = response.json()
                    raise Exception(
                        'Failed to create target Org VDC Network {} - {}'.format(sourceOrgVDCNetwork['name'],
                                                                                 errorResponse['message']))
            if segmetList:
                self.rollback.apiData['LogicalSegments'] = segmetList
            # saving the org vdc network details to apiOutput.json
            self.getOrgVDCNetworks(targetOrgVDC['@id'], 'targetOrgVDCNetworks', saveResponse=True)
            logger.info('Successfully created target Org VDC Networks.')
            conflictNetwork = self.rollback.apiData.get('ConflictNetworks')
            if conflictNetwork:
                networkList = list()
                targetnetworks = self.retrieveNetworkListFromMetadata(targetOrgVDC['@id'], dfwStatus=False, orgVDCType='target')
                for targetnetwork in targetnetworks:
                    for network in conflictNetwork:
                        if network['name'] + '-v2t' == targetnetwork['name']:
                            # networkIds = list(filter(lambda network: network['name']+'-v2t' == targetnetwork['name'], conflictNetwork))[0]
                            networkList.append({'name': network['name'], 'id': targetnetwork['id'], 'shared': network['shared']})
                self.rollback.apiData['ConflictNetworks'] = networkList
        except:
            raise

    @isSessionExpired
    def deleteOrgVDC(self, orgVDCId, rollback=False):
        """
        Description :   Deletes the specified Organization VDC
        Parameters  :   orgVDCId  -   Id of the Organization VDC that is to be deleted (STRING)
        """
        try:
            if rollback and not self.rollback.metadata.get(
                    "prepareTargetVDC", {}).get("createOrgVDC"):
                return

            if rollback:
                logger.info("RollBack: Deleting Target Org-Vdc")
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
                taskUrl = task["@href"]
                if taskUrl:
                    # checking the status of deleting org vdc task
                    self._checkTaskStatus(taskUrl=taskUrl)
                    logger.debug('Organization VDC deleted successfully.')
                    return
            else:
                raise Exception('Failed to delete target Org VDC {}'.format(responseDict['Error']['@message']))
        except Exception:
            raise

    @isSessionExpired
    def deleteOrgVDCNetworks(self, orgVDCId, source=True, rollback=False):
        """
        Description :   Deletes all Organization VDC Networks from the specified OrgVDC
        Parameters  :   orgVDCId  -   Id of the Organization VDC (STRING)
                        source    -   Defaults to True meaning delete the NSX-V backed Org VDC Networks (BOOL)
                                      If set to False meaning delete the NSX-t backed Org VDC Networks (BOOL)
        """
        try:
            # Check if org vdc networks were created or not
            if not self.rollback.metadata.get("prepareTargetVDC", {}).get("createOrgVDCNetwork"):
                return

            if rollback:
                logger.info("RollBack: Deleting Target Org VDC Networks")
            orgVDCNetworksErrorList = []

            dfwStatus = False
            if rollback:
                dfwStatus = True if self.rollback.apiData.get('OrgVDCGroupID') else False

            orgVDCNetworksList = self.getOrgVDCNetworks(orgVDCId, 'sourceOrgVDCNetworks', dfwStatus=dfwStatus, saveResponse=False)
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
                            self._checkTaskStatus(taskUrl=taskUrl)
                        else:
                            # checking the status of deleting routed network task
                            self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug('Organization VDC Network deleted successfully.')
                    else:
                        # state check for NSX-t backed Org VDC
                        self._checkTaskStatus(taskUrl=taskUrl)
                else:
                    logger.debug('Failed to delete Organization VDC Network {}.{}'.format(orgVDCNetwork['name'],
                                                                                          response.json()['message']))
                    orgVDCNetworksErrorList.append(orgVDCNetwork['name'])
            if orgVDCNetworksErrorList:
                raise Exception(
                    'Failed to delete Org VDC networks {} - as it is in use'.format(orgVDCNetworksErrorList))
        except Exception:
            raise

    @isSessionExpired
    def deleteNsxVBackedOrgVDCEdgeGateways(self, orgVDCId):
        """
        Description :   Deletes all the Edge Gateways in the specified NSX-V Backed OrgVDC
        Parameters  :   orgVDCId  -   Id of the Organization VDC (STRING)
        """
        try:
            # retrieving the details of the org vdc edge gateway
            responseDict = self.getOrgVDCEdgeGateway(orgVDCId)
            if responseDict['values']:
                for orgVDCEdgeGateway in responseDict['values']:
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
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug('Source Org VDC Edge Gateway deleted successfully.')
                    else:
                        delResponseDict = xmltodict.parse(delResponse.content)
                        raise Exception('Failed to delete Edge gateway {}:{}'.format(orgVDCEdgeGateway['name'],
                                                                                     delResponseDict['Error'][
                                                                                         '@message']))
            else:
                logger.warning("Target Edge Gateway doesn't exist")
        except Exception:
            raise

    @isSessionExpired
    def deleteNsxTBackedOrgVDCEdgeGateways(self, orgVDCId):
        """
        Description :   Deletes all the Edge Gateways in the specified NSX-t Backed OrgVDC
        Parameters  :   orgVDCId  -   Id of the Organization VDC (STRING)
        """
        try:
            # Locking thread. When Edge gateways from multiple org VDC having IPSEC enabled are rolled back at the same
            # time, target edge gateway deletion fails.
            self.lock.acquire(blocking=True)

            # Check if org vdc edge gateways were created or not
            if not self.rollback.metadata.get("prepareTargetVDC", {}).get("createEdgeGateway"):
                return

            logger.info("RollBack: Deleting Target Edge Gateway")
            # retrieving the details of the org vdc edge gateway
            responseDict = self.getOrgVDCEdgeGateway(orgVDCId)
            if responseDict['values']:
                for orgVDCEdgeGateway in responseDict['values']:
                    # url to fetch edge gateway details
                    url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                        vcdConstants.UPDATE_EDGE_GATEWAYS_BY_ID.format(orgVDCEdgeGateway['id']))
                    # delete api to delete the nsx-t backed edge gateway
                    response = self.restClientObj.delete(url, self.headers)
                    if response.status_code == requests.codes.accepted:
                        taskUrl = response.headers['Location']
                        # checking the status of deleting the nsx-t backed edge gateway
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug('Target Org VDC Edge Gateway deleted successfully.')
                    else:
                        raise Exception('Failed to delete Edge gateway {}:{}'.format(orgVDCEdgeGateway['name'],
                                                                                     response.json()['message']))
            else:
                logger.warning('Target Edge Gateway do not exist')
        except Exception:
            raise
        finally:
            # Releasing thread lock
            try:
                self.lock.release()
            except RuntimeError:
                pass

    @description("disconnection of source routed Org VDC Networks from source Edge gateway")
    @remediate
    def disconnectSourceOrgVDCNetwork(self, orgVDCNetworkList, sourceEdgeGatewayId, rollback=False):
        """
        Description : Disconnect source Org VDC network from edge gateway
        Parameters  : orgVdcNetworkList - Org VDC's network list for a specific Org VDC (LIST)
                      rollback - key that decides whether to perform rollback or not (BOOLEAN)
        """
        # list of networks disconnected successfully
        networkDisconnectedList = []
        orgVDCNetworksErrorList = []

        try:
            # Check if source org vdc network disconenction was performed
            if rollback and (self.rollback.metadata.get("configureTargetVDC") == None and self.rollback.executionResult.get("configureTargetVDC") == None):
                return

            if not sourceEdgeGatewayId:
                logger.debug('Skipping disconnecting/reconnecting soruce org VDC '
                             'networks as edge gateway does not exists')
                return

            if not rollback:
                logger.info('Disconnecting source routed Org VDC Networks from source Edge gateway.')
            else:
                logger.info('Rollback: Reconnecting Source Org VDC Network to Edge Gateway')
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
                    if rollback:
                        responseDict['connection'] = orgVdcNetwork['connection']
                        responseDict['networkType'] = 'NAT_ROUTED'
                    payloadDict = json.dumps(responseDict)
                    self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                    # put api to disconnect the org vdc networks
                    apiResponse = self.restClientObj.put(url, self.headers, data=payloadDict)
                    if apiResponse.status_code == requests.codes.accepted:
                        taskUrl = apiResponse.headers['Location']
                        # checking the status of the disconnecting org vdc network task
                        self._checkTaskStatus(taskUrl=taskUrl)
                        if not rollback:
                            logger.debug(
                                'Source Org VDC Network {} disconnected successfully.'.format(orgVdcNetwork['name']))
                            # saving network on successful disconnection to list
                            networkDisconnectedList.append(orgVdcNetwork)
                        else:
                            logger.debug(
                                'Source Org VDC Network {} reconnected successfully.'.format(orgVdcNetwork['name']))
                    else:
                        if rollback:
                            logger.debug('Rollback: Failed to reconnect Source Org VDC Network {}.'.format(
                                orgVdcNetwork['name']))
                        else:
                            logger.debug(
                                'Failed to disconnect Source Org VDC Network {} due to error.'.format(orgVdcNetwork['name'], ))
                        orgVDCNetworksErrorList.append(orgVdcNetwork['name'])
                if orgVDCNetworksErrorList:
                    raise Exception('Failed to disconnect Org VDC Networks {}'.format(orgVDCNetworksErrorList))
        except Exception as exception:
            # reconnecting the networks in case of disconnection failure
            if networkDisconnectedList:
                self.disconnectSourceOrgVDCNetwork(networkDisconnectedList, sourceEdgeGatewayId, rollback=True)
            raise exception

    @description("disconnection of source Edge gateway from external network")
    @remediate
    def reconnectOrDisconnectSourceEdgeGateway(self, sourceEdgeGatewayIdList, connect=True):
        """
        Description :  Disconnect source Edge Gateways from the specified OrgVDC
        Parameters  :   sourceEdgeGatewayId -   Id of the Organization VDC Edge gateway (STRING)
                        connect             -   Defaults to True meaning reconnects the source edge gateway (BOOL)
                                            -   if set False meaning disconnects the source edge gateway (BOOL)
        """
        try:
            # Check if services configuration or network switchover was performed or not
            if connect and not self.rollback.metadata.get("configureTargetVDC", {}).get("reconnectOrDisconnectSourceEdgeGateway"):
                return

            if not sourceEdgeGatewayIdList:
                logger.debug('Skipping disconnecting/reconnecting source Edge '
                             'gateway from external network as it does not exists')
                return

            if not connect:
                logger.info('Disconnecting source Edge gateway from external network.')
            else:
                logger.info('Rollback: Reconnecting source Edge gateway to external network.')

            for sourceEdgeGatewayId in sourceEdgeGatewayIdList:
                # Fetching edge gateway details from metadata corresponding to edge gateway id
                edgeGatewaydata = \
                    list(filter(lambda edgeGatewayData: edgeGatewayData['id'] == sourceEdgeGatewayId,
                                copy.deepcopy(self.rollback.apiData['sourceEdgeGateway'])))[0]
                orgVDCEdgeGatewayId = sourceEdgeGatewayId.split(':')[-1]
                # url to disconnect/reconnect the source edge gateway
                url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                    vcdConstants.UPDATE_EDGE_GATEWAY_BY_ID.format(orgVDCEdgeGatewayId))
                acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
                headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
                # retrieving the details of the edge gateway
                response = self.restClientObj.get(url, headers)
                responseDict = response.json()
                if response.status_code == requests.codes.ok:
                    if not responseDict['configuration']['gatewayInterfaces']['gatewayInterface'][0][
                        'connected'] and not connect:
                        logger.warning(
                            'Source Edge Gateway external network uplink - {} is already in disconnected state.'.format(
                                responseDict['name']))
                        continue
                    # establishing/disconnecting the edge gateway as per the connect flag
                    if not connect:
                        for i in range(len(responseDict['configuration']['gatewayInterfaces']['gatewayInterface'])):
                            if responseDict['configuration']['gatewayInterfaces']['gatewayInterface'][i]['interfaceType'] == 'uplink' and \
                                    responseDict['configuration']['gatewayInterfaces']['gatewayInterface'][i]['name'] != self.rollback.apiData['dummyExternalNetwork']['name']:
                                responseDict['configuration']['gatewayInterfaces']['gatewayInterface'][i]['connected'] = False
                    elif any([data['connected'] for data in edgeGatewaydata['edgeGatewayUplinks']]):
                        for i in range(len(responseDict['configuration']['gatewayInterfaces']['gatewayInterface'])):
                            if responseDict['configuration']['gatewayInterfaces']['gatewayInterface'][i][
                                'interfaceType'] == 'uplink' and responseDict['configuration']['gatewayInterfaces']['gatewayInterface'][i]['name'] != \
                                    self.rollback.apiData['dummyExternalNetwork']['name']:
                                responseDict['configuration']['gatewayInterfaces']['gatewayInterface'][i]['connected'] = True

                        for index, uplink in enumerate(responseDict['configuration']['gatewayInterfaces']['gatewayInterface']):
                            if uplink['interfaceType'] == 'internal':
                                responseDict['configuration']['gatewayInterfaces']['gatewayInterface'].pop(index)
                                #responseDict['configuration']['gatewayInterfaces']['gatewayInterface'].pop()
                    else:
                        continue
                    payloadData = json.dumps(responseDict)
                    acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
                    self.headers["Content-Type"] = vcdConstants.XML_UPDATE_EDGE_GATEWAY
                    headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader,
                               'Content-Type': vcdConstants.JSON_UPDATE_EDGE_GATEWAY}
                    # updating the details of the edge gateway
                    response = self.restClientObj.put(url + '/action/updateProperties', headers, data=payloadData)
                    responseData = response.json()
                    if response.status_code == requests.codes.accepted:
                        taskUrl = responseData["href"]
                        if taskUrl:
                            # checking the status of connecting/disconnecting the edge gateway
                            self._checkTaskStatus(taskUrl=taskUrl)
                            logger.debug('Source Edge Gateway updated successfully.')
                            continue
                    else:
                        raise Exception('Failed to update source Edge Gateway {}'.format(responseData['message']))
                else:
                    raise Exception("Failed to get edge gateway '{}' details due to error - {}".format(
                        responseDict['name'], responseDict['message']))
        except:
            raise

    @description("Reconnection of target Edge gateway to T0 router")
    @remediate
    def reconnectTargetEdgeGateway(self):
        """
        Description : Reconnect Target Edge Gateway to T0 router
        """
        try:
            if not self.rollback.apiData['targetEdgeGateway']:
                logger.debug('Skipping reconnecting target Edge gateway to T0 router'
                             ' as it does not exists')
                return

            logger.info('Reconnecting target Edge gateway to T0 router.')
            data = self.rollback.apiData
            for targetEdgeGateway in data['targetEdgeGateway']:
                payloadDict = targetEdgeGateway
                del payloadDict['status']
                if self.rollback.apiData.get('OrgVDCGroupID', {}).get(targetEdgeGateway['id']):
                    ownerRef = self.rollback.apiData['OrgVDCGroupID'].get(targetEdgeGateway['id'])
                    payloadDict['ownerRef'] = {'id': ownerRef}
                payloadDict['edgeGatewayUplinks'][0]['connected'] = True
                # edge gateway update URL
                url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                       targetEdgeGateway['id'])
                # creating the payload data
                payloadData = json.dumps(payloadDict)
                self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                # put api to reconnect the target edge gateway
                response = self.restClientObj.put(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    # checking the status of the reconnecting target edge gateway task
                    self._checkTaskStatus(taskUrl=taskUrl)
                    logger.debug(
                        'Target Org VDC Edge Gateway {} reconnected successfully.'.format(targetEdgeGateway['name']))
                    continue
                else:
                    raise Exception(
                        'Failed to reconnect target Org VDC Edge Gateway {} {}'.format(targetEdgeGateway['name'],
                                                                                       response.json()['message']))
            logger.info('Successfully reconnected target Edge gateway to T0 router.')
        except:
            raise

    @description("getting the portgroup of source org vdc networks")
    @remediate
    def getPortgroupInfo(self, orgVdcNetworkList):
        """
        Description : Get Portgroup Info
        Parameters  : orgVdcNetworkList - List of source org vdc networks (LIST)
        """
        try:
            logger.info('Getting the portgroup of source org vdc networks.')
            data = self.rollback.apiData

            # Fetching name and ids of all the org vdc networks
            networkIdList, networkNameList = set(), set()
            for orgVdcNetwork in orgVdcNetworkList:
                networkIdList.add(orgVdcNetwork['id'].split(":")[-1])
                networkNameList.add(orgVdcNetwork['name'])

            allPortGroups = self.fetchAllPortGroups()
            # Iterating over all the port groups to find the portgroups linked to org vdc network
            portGroupDict = {portGroup['network'].split('/')[-1]: portGroup
                             for portGroup in allPortGroups
                             if portGroup['networkName'] != '--' and
                             portGroup['scopeType'] not in ['-1', '1'] and
                             portGroup['networkName'] in networkNameList and
                             portGroup['network'].split('/')[-1] in networkIdList}

            # Saving portgroups data to metadata data structure
            data['portGroupList'] = list(portGroupDict.values())
            logger.info('Retrieved the portgroup of source org vdc networks.')
            return
        except:
            raise

    @isSessionExpired
    def createMoveVappVmPayload(self, vApp, targetOrgVDCId, rollback=False):
        """
        Description : Create vApp vm payload for move vApp api
        Parameters : vApp - dict containing source vApp details
                     targetOrgVDCId - target Org VDC Id (STRING)
                     rollback - whether to rollback vapp from T2V (BOOLEAN)
        """
        try:
            xmlPayloadData = ''
            data = self.rollback.apiData
            if rollback:
                targetStorageProfileList = [
                    data["sourceOrgVDC"]['VdcStorageProfiles']['VdcStorageProfile']] if isinstance(
                    data["sourceOrgVDC"]['VdcStorageProfiles']['VdcStorageProfile'], dict) else \
                data["sourceOrgVDC"]['VdcStorageProfiles']['VdcStorageProfile']
            else:
                targetStorageProfileList = [
                    data["targetOrgVDC"]['VdcStorageProfiles']['VdcStorageProfile']] if isinstance(
                    data["targetOrgVDC"]['VdcStorageProfiles']['VdcStorageProfile'], dict) else \
                data["targetOrgVDC"]['VdcStorageProfiles']['VdcStorageProfile']
            vmInVappList = []
            # get api call to retrieve the info of source vapp
            response = self.restClientObj.get(vApp['@href'], self.headers)
            responseDict = xmltodict.parse(response.content)
            if not responseDict['VApp'].get('Children'):
                return
            targetSizingPolicyOrgVDCUrn = 'urn:vcloud:vdc:{}'.format(targetOrgVDCId)
            # checking whether the vapp children vm are single/multiple
            if isinstance(responseDict['VApp']['Children']['Vm'], list):
                vmList = responseDict['VApp']['Children']['Vm']
            else:
                vmList = [responseDict['VApp']['Children']['Vm']]
            # iterating over the vms in vapp
            for vm in vmList:
                # retrieving the compute policy of vm
                computePolicyName = vm['ComputePolicy']['VmPlacementPolicy']['@name'] if vm['ComputePolicy'].get(
                    'VmPlacementPolicy') else None
                # retrieving the sizing policy of vm
                if vm['ComputePolicy'].get('VmSizingPolicy'):
                    if vm['ComputePolicy']['VmSizingPolicy']['@name'] != 'System Default':
                        sizingPolicyHref = vm['ComputePolicy']['VmSizingPolicy']['@href']
                    else:
                        # get the target System Default policy id
                        defaultSizingPolicy = self.getVmSizingPoliciesOfOrgVDC(targetSizingPolicyOrgVDCUrn,
                                                                               isTarget=True)
                        if defaultSizingPolicy:
                            defaultSizingPolicyId = defaultSizingPolicy[0]['id']
                            sizingPolicyHref = "{}{}/{}".format(
                                vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.VDC_COMPUTE_POLICIES, defaultSizingPolicyId)
                        else:
                            sizingPolicyHref = None
                else:
                    sizingPolicyHref = None
                storageProfileList = [storageProfile for storageProfile in targetStorageProfileList if
                                      storageProfile['@name'] == vm['StorageProfile']['@name']]
                if storageProfileList:
                    storageProfileHref = storageProfileList[0]['@href']
                else:
                    storageProfileHref = ''
                # gathering the vm's data required to create payload data and appending the dict to the 'vmInVappList' list
                vmInVappList.append(
                    {'name': vm['@name'], 'description': vm['Description'] if vm.get('Description') else '',
                     'href': vm['@href'], 'networkConnectionSection': vm['NetworkConnectionSection'],
                     'storageProfileHref': storageProfileHref, 'state': responseDict['VApp']['@status'],
                     'computePolicyName': computePolicyName, 'sizingPolicyHref': sizingPolicyHref,
                     'primaryNetworkConnectionIndex': vm['NetworkConnectionSection']['PrimaryNetworkConnectionIndex']})
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
            # iterating over the above saved vms list of source vapp
            for vm in vmInVappList:
                logger.debug('Getting VM - {} details'.format(vm['name']))
                # check whether the vapp state is powered on i.e 4 then poweron else poweroff
                if vm['state'] != "4":
                    state = "false"
                else:
                    state = "true"
                # checking multiple network connection details inside vm are single/multiple
                if isinstance(vm['networkConnectionSection']['NetworkConnection'], list):
                    networkConnectionList = vm['networkConnectionSection']['NetworkConnection']
                else:
                    networkConnectionList = [vm['networkConnectionSection']['NetworkConnection']]
                networkConnectionPayloadData = ''
                # creating payload for mutiple/single network connections in a vm
                for networkConnection in networkConnectionList:
                    if networkConnection['@network'] == 'none':
                        networkName = 'none'
                    else:
                        if rollback:
                            # remove the appended -v2t from network name
                            networkName = networkConnection['@network'].replace('-v2t', '')
                        else:
                            networkName = networkConnection['@network'] + '-v2t'
                    # checking for the 'IpAddress' attribute if present
                    if networkConnection.get('IpAddress'):
                        ipAddress = networkConnection['IpAddress']
                    else:
                        ipAddress = ""
                    payloadDict = {'networkName': networkName, 'ipAddress': ipAddress,
                                   'connected': networkConnection['IsConnected'],
                                   'macAddress': networkConnection['MACAddress'],
                                   'allocationModel': networkConnection['IpAddressAllocationMode'],
                                   'adapterType': networkConnection['NetworkAdapterType'],
                                   'networkConnectionIndex': networkConnection['NetworkConnectionIndex']
                                   }
                    payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.VAPP_VM_NETWORK_CONNECTION_SECTION_TEMPLATE)
                    networkConnectionPayloadData += payloadData.strip("\"")
                # handling the case:- if both compute policy & sizing policy are absent
                if not vm["computePolicyName"] and not vm['sizingPolicyHref']:
                    payloadDict = {'vmHref': vm['href'], 'vmDescription': vm['description'], 'state': state,
                                   'storageProfileHref': vm['storageProfileHref'],
                                   'vmNetworkConnectionDetails': networkConnectionPayloadData,
                                   'primaryNetworkConnectionIndex': vm['primaryNetworkConnectionIndex']}
                    payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.MOVE_VAPP_VM_TEMPLATE)
                # handling the case:- if either policy is present
                else:
                    # handling the case:- if compute policy is present and sizing policy is absent
                    if vm["computePolicyName"] and not vm['sizingPolicyHref']:
                        # retrieving the org vdc compute policy
                        allOrgVDCComputePolicesList = self.getOrgVDCComputePolicies()
                        # getting the list instance of compute policies of org vdc
                        orgVDCComputePolicesList = [allOrgVDCComputePolicesList] if isinstance(
                            allOrgVDCComputePolicesList, dict) else allOrgVDCComputePolicesList
                        if rollback:
                            targetProviderVDCid = data['sourceProviderVDC']['@id']
                        else:
                            targetProviderVDCid = data['targetProviderVDC']['@id']
                        # iterating over the org vdc compute policies
                        for eachComputPolicy in orgVDCComputePolicesList:
                            # checking if the org vdc compute policy name is same as the source vm's applied compute policy & org vdc compute policy id is same as that of target provider vdc's id
                            if eachComputPolicy["name"] == vm["computePolicyName"] and \
                                    eachComputPolicy["pvdcId"] == targetProviderVDCid:
                                # creating the href of compute policy that should be passed in the payload data for recomposing the vapp
                                href = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                        vcdConstants.VDC_COMPUTE_POLICIES,
                                                        eachComputPolicy["id"])
                        # if vm's compute policy does not match with org vdc compute policy or org vdc compute policy's id does not match with target provider vdc's id then href will be set none
                        # resulting into raising the exception that source vm's applied placement policy is absent in target org vdc
                        if not href:
                            raise Exception(
                                'Could not find placement policy {} in target Org VDC.'.format(vm["computePolicyName"]))
                        # creating the payload dictionary
                        payloadDict = {'vmHref': vm['href'], 'vmDescription': vm['description'], 'state': state,
                                       'storageProfileHref': vm['storageProfileHref'],
                                       'vmPlacementPolicyHref': href,
                                       'vmNetworkConnectionDetails': networkConnectionPayloadData,
                                       'primaryNetworkConnectionIndex': vm['primaryNetworkConnectionIndex']}
                        # creating the payload data
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.MOVE_VAPP_VM_PLACEMENT_POLICY_TEMPLATE)
                    # handling the case:- if sizing policy is present and compute policy is absent
                    elif vm['sizingPolicyHref'] and not vm["computePolicyName"]:
                        # creating the payload dictionary
                        payloadDict = {'vmHref': vm['href'], 'vmDescription': vm['description'], 'state': state,
                                       'storageProfileHref': vm['storageProfileHref'],
                                       'sizingPolicyHref': vm['sizingPolicyHref'],
                                       'vmNetworkConnectionDetails': networkConnectionPayloadData,
                                       'primaryNetworkConnectionIndex': vm['primaryNetworkConnectionIndex']}
                        # creating the pauload data
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.MOVE_VAPP_VM_SIZING_POLICY_TEMPLATE)
                    # handling the case:- if both policies are present
                    elif vm['sizingPolicyHref'] and vm["computePolicyName"]:
                        # retrieving the org vdc compute policy
                        allOrgVDCComputePolicesList = self.getOrgVDCComputePolicies()
                        # getting the list instance of compute policies of org vdc
                        orgVDCComputePolicesList = [allOrgVDCComputePolicesList] if isinstance(
                            allOrgVDCComputePolicesList, dict) else allOrgVDCComputePolicesList
                        if rollback:
                            targetProviderVDCid = data['sourceProviderVDC']['@id']
                        else:
                            targetProviderVDCid = data['targetProviderVDC']['@id']
                        # iterating over the org vdc compute policies
                        for eachComputPolicy in orgVDCComputePolicesList:
                            # checking if the org vdc compute policy name is same as the source vm's applied compute policy & org vdc compute policy id is same as that of target provider vdc's id
                            if eachComputPolicy["name"] == vm["computePolicyName"] and \
                                    eachComputPolicy["pvdcId"] == targetProviderVDCid:
                                # creating the href of compute policy that should be passed in the payload data for recomposing the vapp
                                href = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                        vcdConstants.VDC_COMPUTE_POLICIES,
                                                        eachComputPolicy["id"])
                        # if vm's compute policy does not match with org vdc compute policy or org vdc compute policy's id does not match with target provider vdc's id then href will be set none
                        # resulting into raising the exception that source vm's applied placement policy is absent in target org vdc
                        if not href:
                            raise Exception(
                                'Could not find placement policy {} in target Org VDC.'.format(vm["computePolicyName"]))
                        # creating the payload dictionary
                        payloadDict = {'vmHref': vm['href'], 'vmDescription': vm['description'], 'state': state,
                                       'storageProfileHref': vm['storageProfileHref'],
                                       'vmPlacementPolicyHref': href, 'sizingPolicyHref': vm['sizingPolicyHref'],
                                       'vmNetworkConnectionDetails': networkConnectionPayloadData,
                                       'primaryNetworkConnectionIndex': vm['primaryNetworkConnectionIndex']}
                        # creating the pauload data
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.MOVE_VAPP_VM_COMPUTE_POLICY_TEMPLATE)
                xmlPayloadData += payloadData.strip("\"")
            return xmlPayloadData
        except Exception:
            raise

    @isSessionExpired
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

    @description("Checking ACL on target Org vdc")
    @remediate
    def createACL(self):
        """
        Description : Create ACL on Org VDC
        """
        try:
            logger.info('Checking ACL on target Org vdc')

            data = self.rollback.apiData
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
                userData = {"subject": {"href": subjectData['subject']['href']},
                            "accessLevel": subjectData['accessLevel']}
                accessSettingsList.append(userData)
            jsonData = json.loads(payloadData)
            # attaching the access settings to the payload data
            jsonData['accessSettings'] = {'accessSetting': accessSettingsList}
            payloadData = json.dumps(jsonData)
            # put api to create access control in target org vdc
            response = self.restClientObj.put(url, headers, data=payloadData)
            if response.status_code != requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                raise Exception(
                    'Failed to create target ACL on target Org VDC {}'.format(responseDict['Error']['@message']))
            logger.info('Successfully created ACL on target Org vdc')
        except Exception:
            raise

    @description("application of vm placement policy on target Org vdc")
    @remediate
    def applyVDCPlacementPolicy(self):
        """
        Description : Applying VM placement policy on vdc
        """
        try:
            data = self.rollback.apiData
            computePolicyHrefList = []
            # retrieving the target org vdc id, target provider vdc id & compute policy list of source from apiOutput.json
            targetOrgVDCId = data['targetOrgVDC']['@id'].split(':')[-1]
            targetProviderVDCId = data['targetProviderVDC']['@id']
            if not data.get('sourceOrgVDCComputePolicyList'):
                logger.debug('No source Org VDC compute Policy exist')
                return
            logger.info('Applying vm placement policy on target Org vdc')
            sourcePolicyList = data['sourceOrgVDCComputePolicyList']
            # getting list instance of sourcePolicyList
            sourceComputePolicyList = [sourcePolicyList] if isinstance(sourcePolicyList, dict) else sourcePolicyList
            allOrgVDCComputePolicesList = self.getOrgVDCComputePolicies()
            # getting list instance of org vdc compute policies
            orgVDCComputePolicesList = [allOrgVDCComputePolicesList] if isinstance(allOrgVDCComputePolicesList,
                                                                                   dict) else allOrgVDCComputePolicesList
            # iterating over the org vdc compute policies
            for eachComputePolicy in orgVDCComputePolicesList:
                if eachComputePolicy["pvdcId"] == targetProviderVDCId:
                    # if compute policy's id is same as target provider vdc id and compute policy is not the system default
                    if eachComputePolicy["name"] != 'System Default':
                        # iterating over the source compute policies
                        for computePolicy in sourceComputePolicyList:
                            if computePolicy['@name'] == eachComputePolicy['name'] and eachComputePolicy['name'] != \
                                    data['targetOrgVDC']['DefaultComputePolicy']['@name']:
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
                    alreadyPresentComputePoliciesList.append(
                        {'href': computePolicy['href'], 'id': computePolicy['id'], 'name': computePolicy['name']})
            payloadDict['vdcComputePolicyReference'] = alreadyPresentComputePoliciesList + computePolicyHrefList
            acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
            headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader,
                       'Content-Type': vcdConstants.GENERAL_JSON_CONTENT_TYPE}
            # creating the payload data
            payloadData = json.dumps(payloadDict)
            response = self.restClientObj.put(url, headers, data=payloadData)
            if response.status_code == requests.codes.ok:
                # there exists atleast single placement policy in source org vdc, so checking the computPolicyHrefList
                if computePolicyHrefList:
                    logger.debug('Successfully applied vm placement policy on target VDC')
            else:
                raise Exception(
                    'Failed to apply vm placement policy on target VDC {}'.format(response.json()['message']))
        except Exception:
            # setting the delete target org vdc flag
            self.DELETE_TARGET_ORG_VDC = True
            raise

    @description("Enabling Affinity Rules in Target VDC")
    @remediate
    def enableTargetAffinityRules(self, rollback=False):
        """
        Description :   Enable Affinity Rules in Target VDC
        """
        try:
            threading.current_thread().name = self.vdcName
            # Check if migrate vApp was performed as a part of migration
            if rollback and not self.rollback.metadata.get("enableTargetAffinityRules"):
                return

            data = self.rollback.apiData
            # reading the data from the apiOutput.json
            targetOrgVdcId = data['targetOrgVDC']['@id']
            targetvdcid = targetOrgVdcId.split(':')[-1]
            # checking if affinity rules present in source
            if data.get('sourceVMAffinityRules'):
                logger.info('Configuring target Org VDC affinity rules')
                sourceAffinityRules = data['sourceVMAffinityRules'] if isinstance(data['sourceVMAffinityRules'],
                                                                                  list) else [
                    data['sourceVMAffinityRules']]
                # iterating over the affinity rules
                for sourceAffinityRule in sourceAffinityRules:
                    affinityID = sourceAffinityRule['@id']
                    # url to enable/disable the affinity rules
                    # url = vcdConstants.ENABLE_DISABLE_AFFINITY_RULES.format(self.ipAddress, affinityID)
                    url = "{}{}".format(vcdConstants.AFFINITY_URL.format(self.ipAddress, targetvdcid), affinityID)
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
                    if rollback:
                        isEnabled = "false"
                    else:
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
                        # checking the status of the enabling/disabling affinity rules task
                        self._checkTaskStatus(taskUrl=task_url)
                        logger.debug('Affinity Rules got updated successfully in Target')
                    else:
                        raise Exception(
                            'Failed to update Affinity Rules in Target {}'.format(responseDict['Error']['@message']))
                logger.info('Successfully configured target Org VDC affinity rules')
        except Exception:
            logger.error(traceback.format_exc())
            raise

    @isSessionExpired
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
                taskUrl = responseData["href"]
                if taskUrl:
                    # checking the status of renaming target org vdc task
                    self._checkTaskStatus(taskUrl=taskUrl)
                    logger.debug('Renamed Org VDC to {} successfully'.format(responseDict['name']))
                return response
            raise Exception("Failed to rename the Org VDC {}".format(responseData['message']))
        except Exception:
            raise

    @isSessionExpired
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
                    sourceOrgVDCSizingPolicyList = [response for response in responseDict['values'] if
                                                    response['name'] != 'System Default']
                else:
                    # getting the source vm sizing policy for the policy named 'System Default'
                    sourceOrgVDCSizingPolicyList = [response for response in responseDict['values'] if
                                                    response['name'] == 'System Default']
                return sourceOrgVDCSizingPolicyList
            raise Exception("Failed to retrieve VM Sizing Policies of Organization VDC {} {}".format(orgVdcId,
                                                                                                     responseDict[
                                                                                                         'message']))
        except Exception:
            raise

    @description("application of vm sizing policy on target Org vdc")
    @remediate
    def applyVDCSizingPolicy(self):
        """
        Description :   Assigns the VM Sizing Policy to the specified OrgVDC
        """
        try:
            logger.info('Applying vm sizing policy on target Org vdc')

            data = self.rollback.apiData
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
                                                                                                   response.json()[
                                                                                                       'message']))
        except Exception:
            self.DELETE_TARGET_ORG_VDC = True
            raise

    @description("disconnection of target Org VDC Networks")
    @remediate
    def disconnectTargetOrgVDCNetwork(self):
        """
        Description : Disconnect target Org VDC networks
        """
        try:
            if not self.rollback.apiData['sourceEdgeGateway']:
                logger.debug('Skipping Target Org VDC Network disconnection as edge '
                             'gateway does not exist.')
                return

            logger.info('Disconnecting target Org VDC Networks.')
            targetOrgVDCId = self.rollback.apiData['targetOrgVDC']['@id']
            targetOrgVDCNetworkList = self.getOrgVDCNetworks(targetOrgVDCId, 'targetOrgVDCNetworks', saveResponse=False)
            # retrieving the target org vdc network list
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
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug(
                            'Disconnected target Org VDC network - {} successfully.'.format(vdcNetwork['name']))
                    else:
                        response = response.json()
                        raise Exception('Failed to disconnect target Org VDC network {} - {}'.format(vdcNetwork['name'],
                                                                                                     response[
                                                                                    'message']))
            logger.info('Successfully disconnected target Org VDC Networks.')
        except Exception:
            raise

    @description("Reconnection of target Org VDC Networks")
    @remediate
    def reconnectOrgVDCNetworks(self, sourceOrgVDCId, targetOrgVDCId, source=True):
        """
        Description :   Reconnects the Org VDC networks of source/ target Org VDC
        Parameters  :   source  -   Defaults to True meaning reconnect the Source Org VDC Networks (BOOL)
                                -   if False meaning reconnect the Target Org VDC Networks (BOOL)
        """
        try:
            if not self.rollback.apiData['targetEdgeGateway']:
                logger.debug('Reconnecting target Org VDC Networks as edge gateway '
                             'does not exists')
                return

            logger.info('Reconnecting target Org VDC Networks.')
            # get the listener ip configured on all target edge gateways
            listenerIp = self.rollback.apiData.get('listenerIp', {})
            # checking whether to reconnect the org vdc  networks of source or target, and getting the org vdc networks as per the source flag
            if source:
                OrgVDCNetworkList = self.retrieveNetworkListFromMetadata(sourceOrgVDCId, orgVDCType='source')
            else:
                OrgVDCNetworkList = self.retrieveNetworkListFromMetadata(targetOrgVDCId, orgVDCType='target')
            # iterating over the org vdc networks
            for vdcNetwork in OrgVDCNetworkList:
                # handling only routed networks
                if vdcNetwork['networkType'] == "NAT_ROUTED":
                    vdcNetworkID = vdcNetwork['id']
                    GatewayID = vdcNetwork['connection']['routerRef']['id']
                    listenerIpexist = GatewayID in listenerIp.keys()
                    if listenerIpexist and vdcNetwork.get('connection'):
                        #if vdcNetwork['subnets']['values'][0]['dnsServer1'] == vdcNetwork['subnets']['values'][0]['gateway']:
                        vdcNetwork['subnets']['values'][0]['dnsServer1'] = listenerIp[GatewayID]
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
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug('Reconnected {} Org VDC network - {} successfully.'.format(srcTgt, vdcNetwork['name']))
                    else:
                        response = response.json()
                        raise Exception('Failed to reconnect {} Org VDC network {} - {}'.format(srcTgt, vdcNetwork['name'],
                                                                                                response['message']))
        except Exception:
            raise

    @isSessionExpired
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
                taskUrl = task["@href"]
                if taskUrl:
                    # checking the status of disabling the edge gateway
                    self._checkTaskStatus(taskUrl=taskUrl)
                logger.debug("Disabled Distributed Routing on source edge gateway successfully")
            else:
                raise Exception("Failed to disable Distributed Routing on source edge gateway {}".format(responseDict['Error']['@message']))
        except Exception:
            raise

    @description("Update DHCP on Target Org VDC Networks")
    @remediate
    def _updateDhcpInOrgVdcNetworks(self, url, payload):
        """
            Description : Put API request to configure DHCP
            Parameters  : url - URL path (STRING)
                          payload - source dhcp configuration to be updated (DICT)
        """
        try:
            logger.debug('Updating DHCP configuration in OrgVDC network')
            self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
            response = self.restClientObj.put(url, self.headers, data=json.dumps(payload))
            if response.status_code == requests.codes.accepted:
                taskUrl = response.headers['Location']
                # checking the status of configuring the dhcp on target org vdc networks task
                self._checkTaskStatus(taskUrl=taskUrl)
                # setting the configStatus flag meaning the particular DHCP rule is configured successfully in order to skip its reconfiguration
                logger.debug('DHCP pool created successfully.')
            else:
                errorResponse = response.json()
                raise Exception('Failed to create DHCP  - {}'.format(errorResponse['message']))
        except Exception:
            raise

    @isSessionExpired
    def getEdgeClusterData(self, edgeClusterName, nsxtObj):
        """
                    Description : Get the edge clusters data from edge cluster name
                    Parameters  : edgeClusterName - Name of the edge cluster
                                  nsxtObj - nsxt Object.
        """
        try:
            edgeClusterInfoDict = {}
            # Get Backing ID of edge cluster
            edgeClusterData = nsxtObj.fetchEdgeClusterDetails(edgeClusterName)
            edgeClusterInfoDict['backingId'] = edgeClusterData['id']

            # Get name and ID of edge cluster(STRING format)
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.EDGE_CLUSTER_DATA)
            response = self.restClientObj.get(url, self.headers)

            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                resultTotal = responseDict['resultTotal']
                pageNo = 1
                pageSizeCount = 0
                resultList = []
            else:
                errorDict = response.json()
                raise Exception("Failed to get edge cluster '{}' data, error '{}' ".format(edgeClusterName, errorDict['message']))

            logger.debug('Getting edge cluster details')
            while resultTotal > 0 and pageSizeCount < resultTotal:
                url = "{}{}?page={}&pageSize={}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                                       vcdConstants.EDGE_CLUSTER_DATA, pageNo, 25)
                getSession(self)
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    resultList.extend(responseDict['values'])
                    pageSizeCount += len(responseDict['values'])
                    logger.debug('edge cluster details result pageSize = {}'.format(pageSizeCount))
                    pageNo += 1
                    resultTotal = responseDict['resultTotal']
                else:
                    errorDict = response.json()
                    raise Exception("Failed to get edge cluster '{}' data.".format(errorDict['message']))

            for edgeData in resultList:
                if edgeClusterName == edgeData['name']:
                    edgeClusterInfoDict['name'] = edgeData['name']
                    edgeClusterInfoDict['id'] = edgeData['id']
                    break
            else:
                raise Exception("Edge Gateway Cluster {} data not found in VCD.".format(edgeClusterName))
            return edgeClusterInfoDict
        except:
            raise

    @description("Configure network profile on OrgVDC if dhcp is enabled on isolated vApp network.")
    @remediate
    def updateNetworkProfileIsolatedvAppDHCP(self, sourceOrgVDCId, targetOrgVDCID, edgeGatewayDeploymentEdgeCluster, nsxtObj):
        """
            Description : Configure network profile on OrgVDC if dhcp is enabled on isolated vApp network.
            Parameters  : sourceOrgVdcID,   -   Id of the source organization VDC in URN format (STRING)
                          targetOrgVDCId    -   Id of the target organization VDC in URN format (STRING)
                          nsxtObj           -   NSX-T Object
                          edgeGatewayDeploymentEdgeCluster - edge gateway deployment edge cluster.
        """
        try:
            self.isovAppNetworkDHCPEnabled = dict()
            vAppList = self.getOrgVDCvAppsList(sourceOrgVDCId.split(":")[-1])
            if not vAppList:
                return

            # iterating over the source vapps
            for vApp in vAppList:
                # spawn thread for check vapp with own network task
                DHCPEnabledNetworkList = self._checkVappWithIsolatedNetwork(vApp, True)
                if len(DHCPEnabledNetworkList) > 0:
                    self.isovAppNetworkDHCPEnabled[vApp['@name']] = DHCPEnabledNetworkList

            if self.isovAppNetworkDHCPEnabled:
                for vApp in vAppList:
                    self.configureNetworkProfile(targetOrgVDCID, edgeGatewayDeploymentEdgeCluster, nsxtObj)
                    break
        except:
            raise

    @isSessionExpired
    def configureNetworkProfile(self, targetOrgVDCId, edgeGatewayDeploymentEdgeCluster=None, nsxtObj=None):
        """
            Description : Configure network profile on target OrgVDC
            Parameters  : targetOrgVDCId    -   Id of the target organization VDC in URN format (STRING)
                          nsxtObj           -   NSX-T Object
                          edgeGatewayDeploymentEdgeCluster - edge gateway deployment edge cluster.
        """
        try:
            logger.debug('Configuring network profile on target orgVDC')
            data = self.rollback.apiData
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.NETWORK_PROFILE.format(targetOrgVDCId))
            if edgeGatewayDeploymentEdgeCluster is not None and len(data['targetEdgeGateway']) == 0:
                edgeClusterData = self.getEdgeClusterData(edgeGatewayDeploymentEdgeCluster, nsxtObj)
                # payload to configure edge cluster details from target edge gateway
                payload = {
                    "servicesEdgeCluster": {
                        "edgeClusterRef": {
                            "name": edgeClusterData['name'],
                            "id": edgeClusterData['id']
                        },
                        "backingId": edgeClusterData['backingId']
                    }
                }
            elif len(data['targetEdgeGateway']) > 0:
                # payload to configure edge cluster details from target edge gateway
                payload = {
                    "servicesEdgeCluster": {
                        "edgeClusterRef": {
                            "name": data['targetEdgeGateway'][0]['edgeClusterConfig']['primaryEdgeCluster']['edgeClusterRef']['name'],
                            "id": data['targetEdgeGateway'][0]['edgeClusterConfig']['primaryEdgeCluster']['edgeClusterRef']['id']
                        },
                        "backingId": data['targetEdgeGateway'][0]['edgeClusterConfig']['primaryEdgeCluster']['backingId']
                    }
                }
            else:
                raise Exception("Failed to configure network profile on target OrgVDC, As there is no Target EdgeGateway"
                                " and edgeGateway DeploymentEdgeCluster.")
            self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
            response = self.restClientObj.put(url, self.headers, data=json.dumps(payload))
            if response.status_code == requests.codes.accepted:
                taskUrl = response.headers['Location']
                self._checkTaskStatus(taskUrl=taskUrl)
                logger.debug('Network profile on target OrgVDC is configured')
            else:
                errorResponce = response.json()
                raise Exception('Failed to configure network profile on target OrgVDC: {}'.format(errorResponce['message']))
        except Exception:
            raise

    @description("Configuration of DHCP on Target Org VDC Networks")
    @remediate
    def configureDHCP(self, targetOrgVDCId, edgeGatewayDeploymentEdgeCluster=None, nsxtObj=None):
        """
        Description : Configure DHCP on Target Org VDC networks
        Parameters  : targetOrgVDCId    -   Id of the target organization VDC (STRING)
        """
        try:
            logger.debug("Configuring DHCP on Target Org VDC Networks")
            data = self.rollback.apiData
            for sourceEdgeGatewayDHCP in data['sourceEdgeGatewayDHCP'].values():
                # checking if dhcp is enabled on source edge gateway
                if not sourceEdgeGatewayDHCP['enabled']:
                    logger.debug('DHCP service is not enabled or configured in Source Edge Gateway')
                else:
                    # retrieving the dhcp rules of the source edge gateway
                    dhcpRules = sourceEdgeGatewayDHCP['ipPools']['ipPools'] if isinstance(
                        sourceEdgeGatewayDHCP['ipPools']['ipPools'], list) else [
                        sourceEdgeGatewayDHCP['ipPools']['ipPools']]
                    payloaddict = {}
                    # iterating over the source edge gateway dhcp rules
                    for iprange in dhcpRules:
                        # if configStatus flag is already set means that the dhcp rule is already configured, if so then skipping the configuring of same rule and moving to the next dhcp rule
                        if iprange.get('configStatus'):
                            continue
                        start = iprange['ipRange'].split('-')[0]
                        end = iprange['ipRange'].split('-')[-1]
                        # iterating over the target org vdc networks
                        for vdcNetwork in self.retrieveNetworkListFromMetadata(targetOrgVDCId, orgVDCType='target'):
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
                                        payloaddict['enabled'] = "true" if sourceEdgeGatewayDHCP['enabled'] else "false"
                                        payloaddict['dhcpPools'] = [{
                                            "enabled": "true" if sourceEdgeGatewayDHCP['enabled'] else "false",
                                            "ipRange": {
                                                "startAddress": start,
                                                "endAddress": end
                                            },
                                            "defaultLeaseTime": 0
                                        }]
                                        payloaddict['leaseTime'] = 4294967295 if iprange['leaseTime'] == "infinite" \
                                            else iprange['leaseTime']
                                        # url to configure dhcp on target org vdc networks
                                        url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                               vcdConstants.ALL_ORG_VDC_NETWORKS,
                                                               vcdConstants.DHCP_ENABLED_FOR_ORG_VDC_NETWORK_BY_ID.format(
                                                                   vdcNetworkID))
                                        response = self.restClientObj.get(url, self.headers)
                                        if response.status_code == requests.codes.ok:
                                            responseDict = response.json()
                                            dhcpPools = responseDict['dhcpPools'] + payloaddict['dhcpPools'] if \
                                                responseDict['dhcpPools'] else payloaddict['dhcpPools']
                                            payloaddict['dhcpPools'] = dhcpPools
                                            payloaddict['leaseTime'] = payloaddict['leaseTime'] if \
                                                not responseDict['dhcpPools'] else min(int(responseDict['leaseTime']), int(payloaddict['leaseTime']))
                                            # payloadData = json.dumps(payloaddict)
                                            # put api call to configure dhcp on target org vdc networks
                                            self._updateDhcpInOrgVdcNetworks(url, payloaddict)
                                            # setting the configStatus,flag meaning the particular DHCP rule is configured successfully in order to skip its reconfiguration
                                            iprange['configStatus'] = True
                                        else:
                                            errorResponse = response.json()
                                            raise Exception(
                                                'Failed to fetch DHCP service - {}'.format(errorResponse['message']))
            if float(self.version) >= float(vcdConstants.API_VERSION_ZEUS) and data.get('OrgVDCIsolatedNetworkDHCP', []) != []:
                data = self.rollback.apiData
                targetOrgVDCNetworksList = data['targetOrgVDCNetworks'].keys()
                self.configureNetworkProfile(targetOrgVDCId, edgeGatewayDeploymentEdgeCluster, nsxtObj)
                self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                for eachDHCPConfig in data['OrgVDCIsolatedNetworkDHCP']:
                    payload = dict()
                    orgVDCNetworkName, OrgVDCIsolatedNetworkDHCPDetails = list(eachDHCPConfig.items())[0]
                    payload["enabled"] = OrgVDCIsolatedNetworkDHCPDetails['enabled']
                    payload["leaseTime"] = OrgVDCIsolatedNetworkDHCPDetails['leaseTime']
                    payload["dhcpPools"] = list()
                    firstPoolIndex = 0
                    maxLeaseTimeDhcp = []
                    if OrgVDCIsolatedNetworkDHCPDetails["dhcpPools"]:
                        for eachDhcpPool in OrgVDCIsolatedNetworkDHCPDetails["dhcpPools"]:
                            currentPoolDict = dict()
                            currentPoolDict["enabled"] = eachDhcpPool['enabled']
                            if firstPoolIndex == 0:
                                ipToBeRemoved = OrgVDCIsolatedNetworkDHCPDetails["dhcpPools"][0]['ipRange']['startAddress']
                                newStartIpAddress = ipToBeRemoved.split('.')
                                newStartIpAddress[-1] = str(int(newStartIpAddress[-1]) + 1)
                                currentPoolDict["ipRange"] = {"startAddress": '.'.join(newStartIpAddress),
                                                              "endAddress": eachDhcpPool['ipRange']['endAddress']}
                                payload['ipAddress'] = ipToBeRemoved
                                firstPoolIndex += 1
                            else:
                                currentPoolDict["ipRange"] = {"startAddress": eachDhcpPool['ipRange']['startAddress'],
                                                              "endAddress": eachDhcpPool['ipRange']['endAddress']}
                            currentPoolDict["maxLeaseTime"] = eachDhcpPool['maxLeaseTime']
                            currentPoolDict["defaultLeaseTime"] = eachDhcpPool['defaultLeaseTime']
                            maxLeaseTimeDhcp.append(eachDhcpPool['maxLeaseTime'])
                            payload["dhcpPools"].append(currentPoolDict)
                        payload['mode'] = "NETWORK"
                        payload['leaseTime'] = min(maxLeaseTimeDhcp)
                    else:
                        logger.debug('DHCP pools not present in OrgVDC Network: {}'.format(orgVDCNetworkName))
                        continue
                    if orgVDCNetworkName + '-v2t' in targetOrgVDCNetworksList:
                        url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                            vcdConstants.ORG_VDC_NETWORK_DHCP.format(
                                                data['targetOrgVDCNetworks'][orgVDCNetworkName + '-v2t']['id']))
                        self._updateDhcpInOrgVdcNetworks(url, payload)
            else:
                logger.debug('Isolated OrgVDC networks not present on source OrgVDC')

            # Configure DHCP relay on target edge gateway.
            if float(self.version) >= float(vcdConstants.API_VERSION_ANDROMEDA_10_3_1):
                self.configureDHCPRelayService()
        except:
            raise

    @description("Cleanup of IP/s from external network used by direct network")
    @remediate
    def directNetworkIpCleanup(self, source=False):
        """
        Description: Remove IP's from used by shared direct networks from external networks
        Parameters: source - Remove the IP's from source external network (BOOL)
        """
        try:
            # Return if there are no ip's to migrate
            if not self.rollback.apiData.get("directNetworkIP"):
                return
            # Locking thread as external network can be common
            self.lock.acquire(blocking=True)

            if not source:
                logger.debug("Rollback: Clearing IP's from NSX-T segment backed external network")
            # Iterating over all the networks to migrate the ip's
            for extNetName, ipData in self.rollback.apiData["directNetworkIP"].items():
                extNetName = extNetName + '-v2t' if not source else extNetName

                # Fetching source external network
                for extNet in self.fetchAllExternalNetworks():
                    if extNet['name'] == extNetName:
                        extNetData = extNet
                        break
                else:
                    raise Exception(f"External Network {extNetName} is not present in vCD")
                if ipData:
                    for ip in set(ipData):
                        # Iterating over subnets in the external network
                        for subnet in extNetData['subnets']['values']:
                            if subnet.get('totalIpCount'):
                                del subnet['totalIpCount']
                            if subnet.get('usedIpCount'):
                                del subnet['usedIpCount']
                            networkAddress = ipaddress.ip_network('{}/{}'.format(subnet['gateway'], subnet['prefixLength']),
                                                                  strict=False)
                            # If IP belongs to the network add to ipRange value
                            if ipaddress.ip_address(ip) in networkAddress:
                                ipList = list()
                                for ipRange in subnet['ipRanges']['values']:
                                    ipList.extend(self.createIpRange('{}/{}'.format(subnet['gateway'],
                                                                                    subnet['prefixLength']),
                                                                     ipRange['startAddress'],
                                                                     ipRange['endAddress']))
                                # Removing the IP from the IP list if present
                                if ip in ipList:
                                    ipList.remove(ip)
                                ipRangePayload = self.createExternalNetworkSubPoolRangePayload(ipList)
                                subnet['ipRanges']['values'] = ipRangePayload
                    # url to update external network properties
                    url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                           vcdConstants.ALL_EXTERNAL_NETWORKS, extNetData['id'])
                    # put api call to update external network
                    self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                    payloadData = json.dumps(extNetData)

                    response = self.restClientObj.put(url, self.headers, data=payloadData)
                    if response.status_code == requests.codes.accepted:
                        taskUrl = response.headers['Location']
                        # checking the status of the updating external network task
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug(
                            'External network {} updated successfully with sub allocated ip pools.'.format(
                                extNetData['name']))
                    else:
                        errorResponse = response.json()
                        raise Exception(
                            'Failed to update External network {} with sub allocated ip pools - {}'.format(
                                extNetData['name'], errorResponse['message']))
        except:
            logger.error(traceback.format_exc())
            raise
        finally:
            # Releasing thread lock
            try:
                self.lock.release()
            except RuntimeError:
                pass

    @description("Migration of IP/s to segment backed external network")
    @remediate
    def copyIPToSegmentBackedExtNet(self, rollback=False, orgVDCIDList=None):
        """
        Description: Migrate the IP assigned to vm connected to shared direct network to segment backed external network
        """
        try:
            # Acquire thread lock
            self.lock.acquire(blocking=True)

            if not rollback:
                #Fetching the IP's to be migrated to segment backed external network
                # getting the source org vdc urn
                sourceOrgVDCId = self.rollback.apiData.get('sourceOrgVDC', {}).get('@id', str())
                # getting source network list from metadata
                orgVDCNetworkList = self.retrieveNetworkListFromMetadata(sourceOrgVDCId, orgVDCType='source')
                # Iterating over source org vdc networks to find IP's used by VM's connected to direct shared network
                for sourceOrgVDCNetwork in orgVDCNetworkList:
                    if sourceOrgVDCNetwork['networkType'] == "DIRECT" and sourceOrgVDCNetwork['shared']:
                        # url to retrieve the networks with external network id
                        url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                              vcdConstants.ALL_ORG_VDC_NETWORKS,
                                              vcdConstants.QUERY_EXTERNAL_NETWORK.format(
                                                  sourceOrgVDCNetwork['parentNetworkId']['id']))
                        # get api call to retrieve the networks with external network id
                        response = self.restClientObj.get(url, self.headers)
                        responseDict = response.json()
                        if response.status_code == requests.codes.ok:
                            if int(responseDict['resultTotal']) > 1:
                                # Fetch the ips used by the VM's linked to this external network for IP migration
                                self.getIPAssociatedUsedByVM(sourceOrgVDCNetwork['name'],
                                                             sourceOrgVDCNetwork['parentNetworkId']['name'],
                                                             orgVDCIDList)
                        else:
                            raise Exception('Failed to get direct networks connected to external network {}, '
                                            'due to error -{}'.format(sourceOrgVDCNetwork['parentNetworkId']['name'],
                                                                      responseDict['message']))

            # Return if there are no ip's to migrate
            if not self.rollback.apiData.get("directNetworkIP"):
                return

            if rollback:
                logger.debug("Rollback: Copying IP's from NSX-T segment backed external network to source external network")
            else:
                logger.info("Copying IP's to NSX-T segment backed external network")
            # Iterating over all the networks to migrate the ip's
            for extNetName, ipData in self.rollback.apiData["directNetworkIP"].items():

                # if not rollback ip's will be added to target nsxt segment backed external network
                if not rollback:
                    extNetName += '-v2t'

                allExtNet = self.fetchAllExternalNetworks()

                # Fetching NSX-T segment backed external network
                for extNet in allExtNet:
                    if extNet['name'] == extNetName:
                        segmentBackedExtNetData = extNet
                        break
                else:
                    raise Exception(f"External Network {extNetName} is not present in vCD")

                for ip in set(ipData):
                    # Iterating over subnets in the external network
                    for subnet in segmentBackedExtNetData['subnets']['values']:
                        networkAddress = ipaddress.ip_network('{}/{}'.format(subnet['gateway'], subnet['prefixLength']),
                                                              strict=False)
                        # If IP belongs to the network add to ipRange value
                        if ipaddress.ip_address(ip) in networkAddress:
                            subnet['ipRanges']['values'].extend(self.createExternalNetworkSubPoolRangePayload([ip]))
                            break

                # url to update external network properties
                url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                       vcdConstants.ALL_EXTERNAL_NETWORKS, segmentBackedExtNetData['id'])
                # put api call to update external network
                self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                payloadData = json.dumps(segmentBackedExtNetData)

                response = self.restClientObj.put(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    # checking the status of the updating external network task
                    self._checkTaskStatus(taskUrl=taskUrl)
                    logger.debug(
                        'Target External network {} updated successfully with sub allocated ip pools.'.format(
                            segmentBackedExtNetData['name']))
                else:
                    errorResponse = response.json()
                    raise Exception(
                        'Failed to update External network {} with sub allocated ip pools - {}'.format(
                            segmentBackedExtNetData['name'], errorResponse['message']))
            if rollback:
                logger.debug("Successfully migrated IP's to source external network from NSX-T segment backed external network")
            else:
                logger.debug("Successfully migrated IP's to NSX-T segment backed external network")
        except:
            logger.error(traceback.format_exc())
            raise
        finally:
            # Releasing thread lock
            try:
                self.lock.release()
            except RuntimeError:
                pass

    def prepareTargetVDC(self, vcdObjList, sourceOrgVDCId, inputDict, vdcDict, nsxObj, sourceOrgVDCName, orgVDCIDList, configureBridging=False, configureServices=False):
        """
        Description :   Preparing Target VDC
        Parameters  :   vcdObjList       -   List of vcd operations class objects (LIST)
                        sourceOrgVDCId   -   ID of source Org VDC (STRING)
                        orgVDCIDList     -   List of all the org vdc's undergoing parallel migration (LIST)
                        inputDict        -   Dictionary containing data from input yaml file (DICT)
                        vdcDict          -   Dictionary holding all vdc related input data (DICT)
                        nsxObj           -   NSXTOperations class object (OBJECT)
                        sourceOrgVDCName -   Name of source org vdc (STRING)
                        orgVDCIDList     -   List of source org vdc's ID's (LIST)
                        configureBridging-   Flag that decides bridging is to be configured further or not (BOOLEAN)
                        configureServices-   Flag that decides services are to be configured further or not (BOOLEAN)
        """
        try:
            # Replacing thread name with org vdc name
            threading.current_thread().name = self.vdcName

            # Fetching org vdc network list
            orgVdcNetworkList = self.getOrgVDCNetworks(sourceOrgVDCId, 'sourceOrgVDCNetworks', saveResponse=False)

            # creating target Org VDC
            self.createOrgVDC(vdcDict)

            # applying the vm placement policy on target org vdc
            self.applyVDCPlacementPolicy()

            # applying the vm sizing policy on target org vdc
            self.applyVDCSizingPolicy()

            # checking the acl on target org vdc
            self.createACL()

            # creating target Org VDC Edge Gateway
            self.createEdgeGateway(inputDict, vdcDict, nsxObj)

            # only if source org vdc networks exist
            if orgVdcNetworkList:
                # creating target Org VDC networks
                self.createOrgVDCNetwork(orgVDCIDList, orgVdcNetworkList, inputDict, vdcDict, nsxObj)

                # disconnecting target Org VDC networks
                self.disconnectTargetOrgVDCNetwork()

            else:
                # If not source Org VDC networks are not present target Org VDC networks will also be empty
                logger.debug('Skipping Target Org VDC Network creation as no source Org VDC network exist.')
                self.rollback.apiData['targetOrgVDCNetworks'] = {}

            # Check if services are to be configured and API version is compatible or not
            if float(self.version) >= float(vcdConstants.API_VERSION_ZEUS) and configureServices:

                # Variable to set that the thread has reached here
                self.__done__ = True
                # Wait while all threads have reached this stage
                while not all([True if hasattr(obj, '__done__') else False for obj in vcdObjList]):
                    # Exit if any thread encountered any error
                    if [obj for obj in vcdObjList if hasattr(obj, '__exception__')]:
                        return
                    continue
                # Sleep time for all threads to reach this point
                time.sleep(5)
                delattr(self, '__done__')

                # creating orgVdcGroups
                self.createOrgvDCGroup(sourceOrgVDCName, vcdObjList)

                # Variable to set that the thread has reached here
                self.__done__ = True
                # Wait while all threads have reached this stage
                while not all([True if hasattr(obj, '__done__') else False for obj in vcdObjList]):
                    # Exit if any thread encountered any error
                    if [obj for obj in vcdObjList if hasattr(obj, '__exception__')]:
                        return
                    continue

                # Creating dc group for direct networks
                self.createOrgvDCGroupForImportedNetworks(sourceOrgVDCName, vcdObjList)

            # Check if bridging is to be performed
            if configureBridging:
                # writing the promiscuous mode and forged mode details to apiData dict
                self.getPromiscModeForgedTransmit(sourceOrgVDCId)

                # enable the promiscous mode and forged transmit of source org vdc networks
                self.enablePromiscModeForgedTransmit(orgVdcNetworkList)

                # get the portgroup of source org vdc networks
                self.getPortgroupInfo(orgVdcNetworkList)

            # Migrating metadata from source org vdc to target org vdc
            self.migrateMetadata()

        except:
            self.__exception__ = True
            logger.error(traceback.format_exc())
            raise
        finally:
            # Delete attribute once not required
            if hasattr(self, '__done__'):
                delattr(self, '__done__')

    def configureTargetVDC(self, vcdObjList, edgeGatewayDeploymentEdgeCluster=None, nsxtObj=None):
        """
        Description :   Configuring Target VDC
        Parameters  :   vcdObjList - List of objects of vcd operations class (LIST)
        """
        try:
            #Changing thread name to org vdc name
            threading.currentThread().name = self.vdcName

            # Fetching data from metadata
            data = self.rollback.apiData
            sourceEdgeGatewayIdList = data['sourceEdgeGatewayId']
            sourceOrgVDCId = self.rollback.apiData['sourceOrgVDC']['@id']
            targetOrgVDCId = self.rollback.apiData['targetOrgVDC']['@id']
            orgVdcNetworkList = self.retrieveNetworkListFromMetadata(sourceOrgVDCId, orgVDCType='source')
            targetOrgVDCNetworkList = self.retrieveNetworkListFromMetadata(targetOrgVDCId, orgVDCType='target')

            # edgeGatewayId = copy.deepcopy(data['targetEdgeGateway']['id'])
            if orgVdcNetworkList:
                # disconnecting source org vdc networks from edge gateway
                self.disconnectSourceOrgVDCNetwork(orgVdcNetworkList, sourceEdgeGatewayIdList)

            # connecting dummy uplink to edge gateway
            self.connectUplinkSourceEdgeGateway(sourceEdgeGatewayIdList)

            # disconnecting source org vdc edge gateway from external
            self.reconnectOrDisconnectSourceEdgeGateway(sourceEdgeGatewayIdList, connect=False)

            if targetOrgVDCNetworkList:
                # reconnecting target Org VDC networks
                self.reconnectOrgVDCNetworks(sourceOrgVDCId, targetOrgVDCId, source=False)

            # configuring firewall security groups
            self.configureFirewall(networktype=True)

            # configuring dhcp service target Org VDC networks
            self.configureDHCP(targetOrgVDCId, edgeGatewayDeploymentEdgeCluster, nsxtObj)

            if float(self.version) >= float(vcdConstants.API_VERSION_ZEUS):
                # increase in scope of Target edgegateways
                self.increaseScopeOfEdgegateways()
                # # increase in scope of Target ORG VDC networks
                self.increaseScopeforNetworks()
                # Enable DFW in the orgVDC groups
                self.enableDFWinOrgvdcGroup(vcdObjList, sourceOrgVDCId)

                # Variable to set that the thread has reached here
                self.__done__ = True
                # Wait while all threads have reached this stage
                while not all([True if hasattr(obj, '__done__') else False for obj in vcdObjList]):
                    # Exit if any thread encountered any error
                    if [obj for obj in vcdObjList if hasattr(obj, '__exception__')]:
                        return
                    continue

                # Configure DFW in org VDC groups
                self.configureSecurityTags()
                self.configureDFW(vcdObjList, sourceOrgVDCId=sourceOrgVDCId)

                # Variable to set that the thread has reached here
                self._dfw_configured = True
                # Wait while all threads have reached this stage
                while not all([True if hasattr(obj, '_dfw_configured') else False for obj in vcdObjList]):
                    # Exit if any thread encountered any error
                    if [obj for obj in vcdObjList if hasattr(obj, '__exception__')]:
                        return
                    continue

            # reconnecting target org vdc edge gateway from T0
            self.reconnectTargetEdgeGateway()
        except:
            logger.error(traceback.format_exc())
            self.__exception__ = True
            raise
        finally:
            # Delete attribute once not required
            if hasattr(self, '__done__'):
                delattr(self, '__done__')
            if hasattr(self, '_dfw_configured'):
                delattr(self, '_dfw_configured')

    def migrateCatalogItems(self, sourceOrgVDCId, targetOrgVDCId, orgUrl):
        """
        Description : Migrating Catalog Items - vApp Templates and Media & deleting catalog thereafter
        Parameters  :   sourceOrgVDCId  - source Org VDC id (STRING)
                        targetOrgVDCId  - target Org VDC id (STRING)
                        orgUrl          - Organization url (STRING)
        """
        try:
            sourceOrgVDCId = sourceOrgVDCId.split(':')[-1]
            # url to get the details of source org vdc
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(sourceOrgVDCId))
            # get api call to retrieve the source org vdc details
            sourceOrgVDCResponse = self.restClientObj.get(url, self.headers)
            sourceOrgVDCResponseDict = xmltodict.parse(sourceOrgVDCResponse.content)

            # sourceStorageProfileIDsList holds list the IDs of the source org vdc storage profiles
            sourceStorageProfileIDsList = []
            # sourceStorageProfilesList holds the list of dictionaries of details of each source org vdc storage profile
            sourceStorageProfilesList = []
            storageProfiles = sourceOrgVDCResponseDict['AdminVdc']['VdcStorageProfiles'][
                'VdcStorageProfile'] if isinstance(
                sourceOrgVDCResponseDict['AdminVdc']['VdcStorageProfiles']['VdcStorageProfile'], list) else [
                sourceOrgVDCResponseDict['AdminVdc']['VdcStorageProfiles']['VdcStorageProfile']]
            for storageProfile in storageProfiles:
                sourceStorageProfilesList.append(storageProfile)
                sourceStorageProfileIDsList.append(storageProfile['@id'])

            # get api call to retrieve the organization details
            orgResponse = self.restClientObj.get(orgUrl, headers=self.headers)
            orgResponseDict = xmltodict.parse(orgResponse.content)
            # retrieving the organization ID
            orgId = orgResponseDict['AdminOrg']['@id'].split(':')[-1]

            # if no catalogs exist
            if not orgResponseDict['AdminOrg'].get("Catalogs"):
                logger.debug("No Catalogs exist in Organization")
                return

            # orgCatalogs contains list of all catalogs in the organization
            # each org catalog in orgCatalogs is of type dict which has keys {'@href', '@name', '@type'}
            orgCatalogs = orgResponseDict['AdminOrg']["Catalogs"]["CatalogReference"] if isinstance(
                orgResponseDict['AdminOrg']["Catalogs"]["CatalogReference"], list) else [
                orgResponseDict['AdminOrg']["Catalogs"]["CatalogReference"]]

            # sourceOrgVDCCatalogDetails will hold list of only catalogs present in the source org vdc
            sourceOrgVDCCatalogDetails = []
            # iterating over all the organization catalogs
            for catalog in orgCatalogs:
                # get api call to retrieve the catalog details
                catalogResponse = self.restClientObj.get(catalog['@href'], headers=self.headers)
                catalogResponseDict = xmltodict.parse(catalogResponse.content)
                if catalogResponseDict['AdminCatalog'].get('CatalogStorageProfiles'):
                    # checking if catalogs storage profile is same from source org vdc storage profile by matching the ID of storage profile
                    if catalogResponseDict['AdminCatalog']['CatalogStorageProfiles']['VdcStorageProfile'][
                        '@id'] in sourceStorageProfileIDsList:
                        # creating the list of catalogs from source org vdc
                        sourceOrgVDCCatalogDetails.append(catalogResponseDict['AdminCatalog'])
                else:
                    # skipping the organization level catalogs(i.e catalogs that doesnot belong to any org vdc) while are handled in the for-else loop
                    logger.debug("Skipping the catalog '{}' since catalog doesnot belong to any org vdc".format(
                        catalog['@name']))

            # getting the target storage profile details
            targetOrgVDCId = targetOrgVDCId.split(':')[-1]
            # url to get target org vdc details
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(targetOrgVDCId))

            # get api call to retrieve the target org vdc details
            targetOrgVDCResponse = self.restClientObj.get(url, self.headers)
            targetOrgVDCResponseDict = xmltodict.parse(targetOrgVDCResponse.content)
            # retrieving target org vdc storage profiles list
            targetOrgVDCStorageList = targetOrgVDCResponseDict['AdminVdc']['VdcStorageProfiles'][
                'VdcStorageProfile'] if isinstance(
                targetOrgVDCResponseDict['AdminVdc']['VdcStorageProfiles']['VdcStorageProfile'], list) else [
                targetOrgVDCResponseDict['AdminVdc']['VdcStorageProfiles']['VdcStorageProfile']]

            # iterating over the source org vdc catalogs to migrate them to target org vdc
            for srcCatalog in sourceOrgVDCCatalogDetails:
                logger.debug("Migrating source Org VDC specific Catalogs")
                storageProfileHref = ''
                for storageProfile in targetOrgVDCStorageList:
                    srcOrgVDCStorageProfileDetails = self.getOrgVDCStorageProfileDetails(
                        srcCatalog['CatalogStorageProfiles']['VdcStorageProfile']['@id'])
                    # checking for the same name of target org vdc profile name matching with source catalog's storage profile
                    if srcOrgVDCStorageProfileDetails['AdminVdcStorageProfile']['@name'] == storageProfile['@name']:
                        storageProfileHref = storageProfile['@href']
                        break

                # creating target catalogs for migration
                payloadDict = {'catalogName': srcCatalog['@name'] + '-v2t',
                               'storageProfileHref': storageProfileHref,
                               'catalogDescription': srcCatalog['Description'] if srcCatalog.get('Description') else ''}
                catalogId = self.createCatalog(payloadDict, orgId)

                if catalogId:
                    # empty catalogs
                    if not srcCatalog.get('CatalogItems'):
                        logger.debug("Migrating empty catalog '{}'".format(srcCatalog['@name']))
                        # deleting the source org vdc catalog
                        self.deleteSourceCatalog(srcCatalog['@href'], srcCatalog)
                        # renaming the target org vdc catalog
                        self.renameTargetCatalog(catalogId, srcCatalog)
                        continue

                    # non-empty catalogs
                    logger.debug("Migrating non-empty catalog '{}'".format(srcCatalog['@name']))
                    # retrieving the catalog items of the catalog
                    catalogItemList = srcCatalog['CatalogItems']['CatalogItem'] if isinstance(srcCatalog['CatalogItems']['CatalogItem'], list) else [srcCatalog['CatalogItems']['CatalogItem']]

                    vAppTemplateCatalogItemList = []
                    mediaCatalogItemList = []
                    # creating seperate lists for catalog items - 1. One for media catalog items 2. One for vApp template catalog items
                    for catalogItem in catalogItemList:
                        catalogItemResponse = self.restClientObj.get(catalogItem['@href'], headers=self.headers)
                        catalogItemResponseDict = xmltodict.parse(catalogItemResponse.content)
                        if catalogItemResponseDict['CatalogItem']['Entity']['@type'] == vcdConstants.TYPE_VAPP_TEMPLATE:
                            vAppTemplateCatalogItemList.append(catalogItem)
                        elif catalogItemResponseDict['CatalogItem']['Entity']['@type'] == vcdConstants.TYPE_VAPP_MEDIA:
                            mediaCatalogItemList.append(catalogItem)
                        else:
                            raise Exception("Catalog Item '{}' of type '{}' is not supported".format(catalogItem['@name'], catalogItemResponseDict['CatalogItem']['Entity']['@type']))

                    logger.debug('Starting to move source org VDC catalog items: ')
                    # Note: First migrating the media then migrating the vapp templates to target catalog(because if migrating of media fails(it fails if the same media is used by other org vdc as well) then no need of remigrating back the vapp templates to source catalogs)
                    # moving each catalog item from the 'mediaCatalogItemList' to target catalog created above
                    for catalogItem in mediaCatalogItemList:
                        logger.debug("Migrating Media catalog item: '{}'".format(catalogItem['@name']))
                        # creating payload data to move media
                        payloadDict = {'catalogItemName': catalogItem['@name'],
                                       'catalogItemHref': catalogItem['@href']}
                        self.moveCatalogItem(payloadDict, catalogId)

                    # moving each catalog item from the 'vAppTemplateCatalogItemList' to target catalog created above
                    for catalogItem in vAppTemplateCatalogItemList:
                        logger.debug("Migrating vApp Template catalog item: '{}'".format(catalogItem['@name']))
                        # creating payload data to move vapp template
                        payloadDict = {'catalogItemName': catalogItem['@name'],
                                       'catalogItemHref': catalogItem['@href']}
                        self.moveCatalogItem(payloadDict, catalogId)

                    # deleting the source org vdc catalog
                    self.deleteSourceCatalog(srcCatalog['@href'], srcCatalog)
                    # renaming the target org vdc catalog
                    self.renameTargetCatalog(catalogId, srcCatalog)

                    # deleting the temporary lists
                    del vAppTemplateCatalogItemList
                    del mediaCatalogItemList
            else:
                # migrating non-specific org vdc  catalogs
                # in this case catalog uses any storage available in the organization; but while creating media or vapp template it uses our source org vdc's storage profile by default
                logger.debug("Migrating Non-specific Org VDC Catalogs")

                # case where no catalog items found in source org vdc to migrate non-specific org vdc catalog
                if sourceOrgVDCResponseDict['AdminVdc']['ResourceEntities'] is None:
                    # no catalog items found in the source org vdc
                    logger.debug("No catalogs items found in the source org vdc")
                    return

                # resourceEntitiesList holds the resource entities of source org vdc
                resourceEntitiesList = sourceOrgVDCResponseDict['AdminVdc']['ResourceEntities']['ResourceEntity'] if isinstance(sourceOrgVDCResponseDict['AdminVdc']['ResourceEntities']['ResourceEntity'], list) else [sourceOrgVDCResponseDict['AdminVdc']['ResourceEntities']['ResourceEntity']]

                # sourceCatalogItemsList holds the list of resource entities of type media or vapp template found in source org vdc
                # each catalog item in sourceCatalogItemsList after updating will be dictionary with keys { '@href', '@id', '@name', '@type', 'catalogName', 'catalogHref', 'catalogItemHref', 'catalogDescription'}
                sourceCatalogItemsList = [resourceEntity for resourceEntity in resourceEntitiesList if resourceEntity['@type'] == vcdConstants.TYPE_VAPP_MEDIA or resourceEntity['@type'] == vcdConstants.TYPE_VAPP_TEMPLATE]

                organizationCatalogItemList = []
                # organizationCatalogItemList holds the resource entities of type vapp template from whole organization
                organizationCatalogItemList = self.getvAppTemplates(orgId)
                # now organizationCatalogItemList will also hold resource entities of type media from whole organization
                organizationCatalogItemList.extend(self.getCatalogMedia(orgId))

                # commonCatalogItemsDetailsList holds the details of catalog common from source org vdc and organization
                # commonCatalogItemsDetailsList will have many keys, but our interest keys are 'href' - href, 'catalogName' - name of catalog, 'catalog' - catalog href, 'catalogItem' - catalog item href
                # Note: If the catalog item is of media type then all above keys are present; but if catalog item is of type vapp template then only  'href' and 'catalogName' is present.
                # So we need to find the values of 'catalog' and 'catalogItem', since those are needed further
                commonCatalogItemsDetailsList = [orgResource for orgResource in organizationCatalogItemList for srcResource in sourceCatalogItemsList if srcResource['@href'] == orgResource['href']]

                # getting the default storage profile of the target org vdc
                defaultTargetStorageProfileHref = None
                # iterating over the target org vdc storage profiles
                for eachStorageProfile in targetOrgVDCStorageList:
                    # fetching the details of the storage profile
                    orgVDCStorageProfileDetails = self.getOrgVDCStorageProfileDetails(eachStorageProfile['@id'])
                    # checking if the storage profile is the default one
                    if orgVDCStorageProfileDetails['AdminVdcStorageProfile']['Default'] == "true":
                        defaultTargetStorageProfileHref = eachStorageProfile['@href']
                        break

                # catalogItemDetailsList is a list of dictionaries; each dictionary holds the details of each catalog item found in source org vdc
                # each dictionary finally holds keys {'@href', '@id', '@name', '@type', 'catalogName', 'catalogHref', 'catalogItemHref', 'catalogDescription'}
                catalogItemDetailsList = []
                # catalogNameList is a temporary list used to get the single occurence of catalog in catalogDetailsList list
                catalogNameList = []
                # catalogDetailsList is a list of dictionaries; each dictionary holds the details of each catalog
                # each dictionary finally holds keys {'catalogName', 'catalogHref', 'catalogDescription'}
                catalogDetailsList = []
                # iterating over the source catalog items
                for eachResource in sourceCatalogItemsList:
                    # iterating over the catalogs items found in both source org vdc and organization
                    for resource in commonCatalogItemsDetailsList:
                        if eachResource['@href'] == resource['href']:
                            # catalogItem is a dict to hold the catalog item details
                            catalogItem = eachResource
                            catalogItem['catalogName'] = resource['catalogName']

                            for orgCatalog in orgCatalogs:
                                if orgCatalog['@name'] == resource['catalogName']:
                                    catalogItem['catalogHref'] = orgCatalog['@href']
                                    catalogResponseDict = self.getCatalogDetails(orgCatalog['@href'])
                                    if catalogResponseDict.get('catalogItems'):
                                        catalogItemsList = catalogResponseDict['catalogItems']['catalogItem'] if isinstance(catalogResponseDict['catalogItems']['catalogItem'], list) else [catalogResponseDict['catalogItems']['catalogItem']]
                                        for item in catalogItemsList:
                                            if item['name'] == eachResource['@name']:
                                                catalogItem['catalogItemHref'] = item['href']
                                                break

                            catalogResponseDict = self.getCatalogDetails(catalogItem['catalogHref'])
                            catalogItem['catalogDescription'] = catalogResponseDict['description'] if catalogResponseDict.get('description') else ''
                            catalogItemDetailsList.append(catalogItem)
                            if resource['catalogName'] not in catalogNameList:
                                catalogNameList.append(resource['catalogName'])
                                catalog = {'catalogName': resource['catalogName'],
                                           'catalogHref': catalogItem['catalogHref'],
                                           'catalogDescription': catalogResponseDict['description'] if catalogResponseDict.get('description') else ''}
                                catalogDetailsList.append(catalog)
                # deleting the temporary list since no more needed
                del catalogNameList

                # iterating over catalogs in catalogDetailsList
                for catalog in catalogDetailsList:
                    # creating the payload dict to create a place holder target catalog
                    payloadDict = {'catalogName': catalog['catalogName'] + '-v2t',
                                   'storageProfileHref': defaultTargetStorageProfileHref,
                                   'catalogDescription': catalog['catalogDescription']}
                    # create api call to create a new place holder catalog
                    catalogId = self.createCatalog(payloadDict, orgId)
                    if catalogId:

                        vAppTemplateCatalogItemList = []
                        mediaCatalogItemList = []
                        # creating seperate lists for catalog items - 1. One for media catalog items 2. One for vApp template catalog items
                        for catalogItem in catalogItemDetailsList:
                            if catalogItem['@type'] == vcdConstants.TYPE_VAPP_TEMPLATE:
                                vAppTemplateCatalogItemList.append(catalogItem)
                            elif catalogItem['@type'] == vcdConstants.TYPE_VAPP_MEDIA:
                                mediaCatalogItemList.append(catalogItem)
                            else:
                                raise Exception("Catalog Item '{}' of type '{}' is not supported".format(catalogItem['@name'], catalogItem['@type']))

                        logger.debug('Starting to move non-specific org VDC catalog items: ')
                        # iterating over the catalog items in mediaCatalogItemList
                        for catalogItem in mediaCatalogItemList:
                            # checking if the catalogItem belongs to the above created catalog; if so migrating that catalogItem to the newly created target catalog
                            if catalogItem['catalogName'] == catalog['catalogName']:
                                logger.debug("Migrating Media catalog item: '{}'".format(catalogItem['@name']))
                                # migrating this catalog item
                                payloadDict = {'catalogItemName': catalogItem['@name'],
                                               'catalogItemHref': catalogItem['catalogItemHref']}
                                # move api call to migrate the catalog item
                                self.moveCatalogItem(payloadDict, catalogId)

                        # iterating over the catalog items in mediaCatalogItemList
                        for catalogItem in vAppTemplateCatalogItemList:
                            # checking if the catalogItem belongs to the above created catalog; if so migrating that catalogItem to the newly created target catalog
                            if catalogItem['catalogName'] == catalog['catalogName']:
                                logger.debug("Migrating vApp Template catalog item: '{}'".format(catalogItem['@name']))
                                # migrating this catalog item
                                payloadDict = {'catalogItemName': catalogItem['@name'],
                                               'catalogItemHref': catalogItem['catalogItemHref']}
                                # move api call to migrate the catalog item
                                self.moveCatalogItem(payloadDict, catalogId)

                        catalogData = {'@name': catalog['catalogName'],
                                       '@href': catalog['catalogHref'],
                                       'Description': catalog['catalogDescription']}

                        # deleting the source org vdc catalog
                        self.deleteSourceCatalog(catalogData['@href'], catalogData)
                        # renaming the target org vdc catalog
                        self.renameTargetCatalog(catalogId, catalogData)

                        # deleting the temporary lists
                        del vAppTemplateCatalogItemList
                        del mediaCatalogItemList

        except Exception:
            raise

    @isSessionExpired
    def getSourceEdgeGatewayMacAddress(self, interfacesList):
        """
        Description :   Get source edge gateway mac address for source org vdc network portgroups
        Parameters  :   portGroupList   -   source org vdc networks corresponding portgroup details (LIST)
                        interfacesList  -   Interfaces details of source edge gateway (LIST)
        Returns     :   macAddressList  -   list of mac addresses (LIST)
        """
        try:
            data = self.rollback.apiData
            portGroupList = data.get('portGroupList')
            logger.debug("Getting Source Edge Gateway Mac Address")
            macAddressList = []
            for portGroup in portGroupList:
                for nicDetail in interfacesList:
                    # comparing source org vdc network portgroup moref and edge gateway interface details
                    if portGroup['moref'] == nicDetail['value']['backing']['network']:
                        macAddressList.append(nicDetail['value']['mac_address'])
            return macAddressList
        except Exception:
            raise

    def checkIfSourceVappsExist(self, orgVDCId, vAppListFlag=False):
        """
        Description :   Checks if there exist atleast a single vapp in source org vdc
        Returns     :   True    -   if found atleast single vapp (BOOL)
                        False   -   if not a single vapp found in source org vdc (BOOL)
                        vAppList   -    if getvAppList is set.(List)
        """
        try:
            vAppList = []
            orgvdcId = orgVDCId.split(':')[-1]
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(orgvdcId))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
            else:
                raise Exception('Error occurred while retrieving Org VDC - {} details'.format(orgVDCId))
            if not responseDict['AdminVdc'].get('ResourceEntities'):
                logger.debug('No resource entities found in source Org VDC')
                if vAppListFlag:
                    return vAppList
                return False
            # getting list instance of resources in the source org vdc
            sourceOrgVDCEntityList = responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'] if isinstance(
                responseDict['AdminVdc']['ResourceEntities']['ResourceEntity'], list) else [
                responseDict['AdminVdc']['ResourceEntities']['ResourceEntity']]
            vAppList = [vAppEntity for vAppEntity in sourceOrgVDCEntityList if vAppEntity['@type'] == vcdConstants.TYPE_VAPP]
            if vAppListFlag:
                return vAppList
            if len(vAppList) >= 1:
                return True
            return False
        except Exception:
            raise

    @description("Saving vApp count to metadata")
    @remediate
    def savevAppNoToMetadata(self):
        """
        It saves No of vApp of Sourve OrgVdc to metadata.
        """
        try:
            sourceOrgVDCId = self.rollback.apiData['sourceOrgVDC']['@id']
            vAppList = self.checkIfSourceVappsExist(sourceOrgVDCId, True)
            # save No of vApp in Source OrgVdc to metadata.
            self.rollback.apiData['sourceOrgVDC']['NoOfvApp'] = len(vAppList)
        except:
            raise

    def dumpEndStateLog(self, endStateLogger):
        """
                Description :   It dumps the Migration State Log at the end of file.
                                It creates two table which shows source and target details.
        """
        try:
            # Get metadata and target vApplist.
            targetOrgVdcId = self.rollback.apiData['targetOrgVDC']['@id']
            targetvAppList = self.checkIfSourceVappsExist(targetOrgVdcId, True)
            sourcevAppNo = self.rollback.apiData['sourceOrgVDC']['NoOfvApp']
            metadata = dict(self.rollback.apiData)

            # Add logger for state log.
            endStateTableObj = prettytable.PrettyTable()
            endStateTableObj.field_names = ['Entity Names', 'Source Org VDC Details', 'Target Org VDC Details']
            endStateTableObj.align['Entity Names'] = 'l'
            endStateTableObj.align['Source Org VDC Details'] = 'l'
            endStateTableObj.align['Target Org VDC Details'] = 'l'
            StateLog = {}

            # Get organization details
            organization = metadata[vcdConstants.ORG]
            organization_name = organization['@name']
            StateLog[vcdConstants.ORG] = {'Name': organization_name}

            # Get Source OrgVDC details.
            sourceOrgVdcData = metadata[vcdConstants.SOURCE_ORG_VDC]
            sourceOrgVdc_name = sourceOrgVdcData['@name']
            StateLog[vcdConstants.SOURCE_ORG_VDC] = {'Name': sourceOrgVdc_name}

            # Get sourceOrgVDCNetwork details.
            sourceOrgVDCNWdata = metadata[vcdConstants.SOURCE_ORG_VDC_NW]
            StateLog[vcdConstants.SOURCE_ORG_VDC_NW] = {'routed': [], 'isolated': [], 'direct': []}
            for key in sourceOrgVDCNWdata.keys():
                nw_type = sourceOrgVDCNWdata[key]['networkType']
                if nw_type == 'NAT_ROUTED':
                    StateLog[vcdConstants.SOURCE_ORG_VDC_NW]['routed'].append(key)
                elif nw_type == 'ISOLATED':
                    StateLog[vcdConstants.SOURCE_ORG_VDC_NW]['isolated'].append(key)
                elif nw_type == 'DIRECT':
                    StateLog[vcdConstants.SOURCE_ORG_VDC_NW]['direct'].append(key)

            # Get SourceEdgeGateway details.
            sourceEdgeGWList = metadata[vcdConstants.SOURCE_EDGE_GW]
            sourceEdgeGwNo = len(sourceEdgeGWList)
            StateLog[vcdConstants.SOURCE_EDGE_GW] = {'sourceEdgeGwNo': sourceEdgeGwNo, 'sourceEdgeGwData': []}
            for items in sourceEdgeGWList:
                name = items['name']
                StateLog[vcdConstants.SOURCE_EDGE_GW]['sourceEdgeGwData'].append(name)

            # Get TargetOrgVDC details.
            targetOrgVDC = metadata['targetOrgVDC']
            targetOrgVDCName = targetOrgVDC['@name']
            StateLog['targetOrgVDC'] = {'Name': targetOrgVDCName}

            # Get Target OrgVDC network data.
            targetOrgVDCNWdata = metadata[vcdConstants.TARGET_ORG_VDC_NW]
            StateLog[vcdConstants.TARGET_ORG_VDC_NW] = {'routed': [], 'isolated': [], 'direct': [], 'imported': []}
            for key in targetOrgVDCNWdata.keys():
                nw_type = targetOrgVDCNWdata[key]['networkType']
                if nw_type == 'NAT_ROUTED':
                    StateLog[vcdConstants.TARGET_ORG_VDC_NW]['routed'].append(key)
                elif nw_type == 'ISOLATED':
                    StateLog[vcdConstants.TARGET_ORG_VDC_NW]['isolated'].append(key)
                elif nw_type == 'DIRECT':
                    StateLog[vcdConstants.TARGET_ORG_VDC_NW]['direct'].append(key)
                elif nw_type == 'OPAQUE':
                    StateLog[vcdConstants.TARGET_ORG_VDC_NW]['imported'].append(key)

            # Get TargetEdgeGateway details.
            targetEdgeGWList = metadata[vcdConstants.TARGET_EDGE_GW]
            targetEdgeGwNo = len(targetEdgeGWList)
            StateLog[vcdConstants.TARGET_EDGE_GW] = {'targetEdgeGwNo': targetEdgeGwNo, 'targetEdgeGwData': []}
            for items in targetEdgeGWList:
                name = items['name']
                StateLog[vcdConstants.TARGET_EDGE_GW]['targetEdgeGwData'].append(name)

            # Get TargetvAppList details.
            targetvAppNo = len(targetvAppList)
            StateLog[vcdConstants.TARGET_VAPPS] = {'TargetvAppNo': targetvAppNo, 'TargetvAppData': []}
            for item in targetvAppList:
                data = dict(item)
                name = data['@name']
                StateLog[vcdConstants.TARGET_VAPPS]['TargetvAppData'].append(name)

            # Dump StateLog in Table.
            # Dump OrgVdc Name
            sourceOrgvdcName = StateLog[vcdConstants.SOURCE_ORG_VDC]['Name'] + '\n'
            targetOrgvdcName = StateLog[vcdConstants.TARGET_ORG_VDC]['Name'] + '\n'
            endStateTableObj.add_row(['Org VDC Name', sourceOrgvdcName, targetOrgvdcName])

            # Get source and target edge gateway.
            edgeGWList = StateLog[vcdConstants.SOURCE_EDGE_GW]['sourceEdgeGwData']
            sourceEdgeGwData = str(len(edgeGWList)) + " Edges - " + ", ".join(edgeGWList) + '\n'
            edgeGWList = StateLog[vcdConstants.TARGET_EDGE_GW]['targetEdgeGwData']
            targetEdgeGwData = str(len(edgeGWList)) + " Edges - " + ", ".join(edgeGWList) + '\n'
            endStateTableObj.add_row(['Edge Gateway details', sourceEdgeGwData, targetEdgeGwData])

            # Get source orgvdc network details.
            sourceNWData = ''
            for item in StateLog[vcdConstants.SOURCE_ORG_VDC_NW].keys():
                if item == 'routed':
                    nwList = StateLog[vcdConstants.SOURCE_ORG_VDC_NW]['routed']
                    sourceNWData += str(len(nwList)) + ' Routed - ' + ", ".join(nwList) + '\n'
                elif item == 'isolated':
                    nwList = StateLog[vcdConstants.SOURCE_ORG_VDC_NW]['isolated']
                    sourceNWData += str(len(nwList)) + ' Isolated - ' + ", ".join(nwList) + '\n'
                elif item == 'direct':
                    nwList = StateLog[vcdConstants.SOURCE_ORG_VDC_NW]['direct']
                    sourceNWData += str(len(nwList)) + ' Direct - ' + ", ".join(nwList) + '\n'

            # Get Target OrgVdc details.
            targetNWData = ''
            for item in StateLog[vcdConstants.TARGET_ORG_VDC_NW].keys():
                if item == 'routed':
                    nwList = StateLog[vcdConstants.TARGET_ORG_VDC_NW]['routed']
                    targetNWData += str(len(nwList)) + ' Routed - ' + ", ".join(nwList) + '\n'
                elif item == 'isolated':
                    nwList = StateLog[vcdConstants.TARGET_ORG_VDC_NW]['isolated']
                    targetNWData += str(len(nwList)) + ' Isolated - ' + ", ".join(nwList) + '\n'
                elif item == 'direct':
                    nwList = StateLog[vcdConstants.TARGET_ORG_VDC_NW]['direct']
                    targetNWData += str(len(nwList)) + ' Direct - ' + ", ".join(nwList) + '\n'
                elif item == 'imported':
                    nwList = StateLog[vcdConstants.TARGET_ORG_VDC_NW]['imported']
                    targetNWData += str(len(nwList)) + ' Imported - ' + ", ".join(nwList) + '\n'
            endStateTableObj.add_row(['Org VDC Networks', sourceNWData, targetNWData])

            # Get source and target vApp data.
            vAppList = StateLog[vcdConstants.TARGET_VAPPS]['TargetvAppData']
            # endStateTableObj.add_row(['vApp Details', sourcevAppData, targetvAppData])
            endStateTableObj.add_row(["No of vApps (Including Standalone VMs)", sourcevAppNo, len(targetvAppList)])

            threading.currentThread().name = "MainThread"

            # End state table details
            endStateTable = endStateTableObj.get_string()
            endStateLogger.info('\nOrganization Name : {}\nOrgVdc Details\n{}'.format(
                StateLog[vcdConstants.ORG]['Name'], endStateTable))
        except Exception:
            raise Exception('Failed to create migration end state log table.')
        finally:
            threading.currentThread().name = "MainThread"

    def fetchTargetStorageProfiles(self, targetVdc):
        """
        Description :   Collects target storage profiles and saves name to href map.
        Parameters  :   targetVdc - target Org VDC details (DICT)
        """
        targetStorageProfileList = (
            targetVdc['VdcStorageProfiles']['VdcStorageProfile']
            if isinstance(targetVdc['VdcStorageProfiles']['VdcStorageProfile'], list)
            else [targetVdc['VdcStorageProfiles']['VdcStorageProfile']])

        self.targetStorageProfileMap = {
            storageProfile['@name']: storageProfile['@href']
            for storageProfile in targetStorageProfileList
        }

    @isSessionExpired
    def detachVmDisk(self, disks, vmHref, vmName, timeout=None):
        """
        Description : Detach a disk from VM
        Parameters  : disks -  List of disks attached to a VM (LIST)
                      vmHref  -  VM href (STR)
                      vmName  -  VM name (STR)
                      timeout  -  Timeout to be used for detach VM process(INT)
        """
        # Get attached VMs using API and perform following operation
        # 1. If VM is not attached, skip further processing
        # 2. If VM is attached and VM href do not match with metadata, raise
        for disk in disks:
            attached_vms = self.getAttachedVms(disk)
            if not attached_vms:
                logger.debug(f'Disk {disk["name"]} is already detached')
                return
            if vmHref != attached_vms["href"]:
                raise Exception('VM attached to disk is changed after starting migration')

            # Start Detachment process
            logger.info(f'Detaching disk {disk["name"]} from VM {vmName}')
            url = f'{vmHref}/{vcdConstants.VM_DETACH_DISK}'
            payload = json.dumps({
                'disk': {'href': disk["href"]}
            })
            headers = {
                'Authorization': self.headers['Authorization'],
                'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE.format(self.version),
                'Content-Type': vcdConstants.GENERAL_JSON_ONLY_CONTENT_TYPE,
            }
            response = self.restClientObj.post(url, headers, data=payload)
            if response.status_code == requests.codes.accepted:
                for link in response.json()['link']:
                    if link['type'] == vcdConstants.JSON_TASK_TYPE:
                        self._checkTaskStatus(link['href'], timeoutForTask=timeout)
                logger.info(f'Successfully detached disk {disk["name"]} from VM {vmName}')

            else:
                raise Exception(f'Error occurred while detaching disk {disk["name"]} from VM {vmName}: '
                                f'{response.json()["message"]}')

    @isSessionExpired
    def attachVmDisk(self, disks, vmHref, vmName, timeout=None):
        """
        Description : Attach a disk from VM
        Parameters  : disks -  List of disks attached to a VM (LIST)
                      vmHref  -  VM href (STR)
                      vmName  -  VM name (STR)
                      timeout  -  Timeout to be used for attach VM process(INT)
        """
        # Get attached VMs using API and perform following operation
        # 1. If VM is attached, check if attached VM is same as requested
        # 2. If Attached VM is different, raise
        for disk in disks:
            present_attached_vm = self.getAttachedVms(disk)
            if present_attached_vm:
                if vmHref == present_attached_vm["href"]:
                    logger.debug(f'Disk {disk["name"]} is already attached to {vmName}')
                    return
                else:
                    raise Exception('VM attached to disk is changed after starting migration')

            logger.info(f'Attaching disk {disk["name"]} to VM {vmName}')
            url = f'{vmHref}/{vcdConstants.VM_ATTACH_DISK}'
            payload = json.dumps({
                'disk': {'href': disk["href"]}
            })
            headers = {
                'Authorization': self.headers['Authorization'],
                'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE.format(self.version),
                'Content-Type': vcdConstants.GENERAL_JSON_ONLY_CONTENT_TYPE,
            }
            response = self.restClientObj.post(url, headers, data=payload)
            if response.status_code == requests.codes.accepted:
                for link in response.json()['link']:
                    if link['type'] == vcdConstants.JSON_TASK_TYPE:
                        self._checkTaskStatus(link['href'], timeoutForTask=timeout)
                logger.info(f'Successfully attached disk {disk["name"]} to VM {vmName}')
            else:
                raise Exception(f'Error occurred while attaching disk {disk["name"]} to VM {vmName}: '
                                f'{response.json()["message"]}')

    @isSessionExpired
    def moveDisk(self, disk, target_vdc_href, timeout=None):
        """
        Description : Move disk from its current VDC to target VDC
        Parameters  : disk -  Disk details fetched using get disk api (DICT)
                      target_vdc_href  -  HREF/URL for Org VDC to which disk is to be
                       migrated (STRING)
                      timeout  -  Timeout to be used for disk move process(INT)
        """
        logger.info(f'Moving disk {disk["name"]}')
        url = f'{disk["href"]}/{vcdConstants.DISK_MOVE}'
        payload = json.dumps({
            'vdc': {'href': target_vdc_href},
            'storagePolicy': {'href': self.targetStorageProfileMap.get(disk['storageProfileName'])},
            'iops': disk['iops'],
        })
        headers = {
            'Authorization': self.headers['Authorization'],
            'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE.format(self.version),
            'Content-Type': vcdConstants.GENERAL_JSON_ONLY_CONTENT_TYPE,
            'X-VMWARE-VCLOUD-TENANT-CONTEXT': self.rollback.apiData['Organization']['@id'],
        }
        response = self.restClientObj.post(url, headers, data=payload)
        same_vdc_error = 'The destination VDC must be different from the VDC the disk is already in.'
        if response.status_code == requests.codes.accepted:
            for link in response.json()['link']:
                if link['type'] == vcdConstants.JSON_TASK_TYPE:
                    self._checkTaskStatus(link['href'], timeoutForTask=timeout)
            logger.info(f'Successfully moved disk {disk["name"]}')

        elif response.status_code == requests.codes.bad_request and same_vdc_error in response.json()['message']:
            logger.debug(f'Disk {disk["name"]} is already present in VDC')

        else:
            raise Exception(f'Move disk {disk["name"]} failed with error: {response.json()["message"]}')

    @isSessionExpired
    def getVmVdc(self, vm, pageSize=vcdConstants.DEFAULT_QUERY_PAGE_SIZE):
        """
        Description : Executes a query API and iterate over all pages to generate result
        Parameters  : base_url - url with query filter and without paging info (STRING)
                      entity - Type of entity queried (STRING)
                      pageSize - no of query results to be included in single page (INT)
        Returns     : List of all query results (LIST)
        """
        base_url = f"{vcdConstants.XML_API_URL.format(self.ipAddress)}query?type=vm&filter=(((href=={vm['href']})))"
        logger.debug(f'Getting VM details')
        # Get first page of query
        url = f"{base_url}&page=1&pageSize={pageSize}&format=records"
        headers = {
            'Authorization': self.headers['Authorization'],
            'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE,
            'X-VMWARE-VCLOUD-TENANT-CONTEXT':
                self.rollback.apiData['Organization']['@id'],
        }
        response = self.restClientObj.get(url, headers)
        if not response.status_code == requests.codes.ok:
            logger.error(f'Error occurred while retrieving VM details: {response.json()["message"]}')
            raise Exception(f'Error occurred while retrieving VM details: {response.json()["message"]}')

        resultFetched = response.json()['record']
        if len(resultFetched) == 1:
            return resultFetched[0].get('vdc').split('/')[-1]
        else:
            logger.debug('Cannot find VDC for VM')

    def _getSourceDisksData(self, vcdObjList):
        """Description : Get disk details from all source org VDCs"""
        return self.sourceDisksData or [
            (vcdObj, disk)
            for vcdObj in vcdObjList
            for disk in vcdObj.namedDisks.get(vcdObj.rollback.apiData['sourceOrgVDC']['@id'], [])
        ]

    def _getTargetDisksData(self, vcdObjList):
        """Description : Get disk details from all target org VDCs"""
        return self.targetDisksData or [
            (vcdObj, disk)
            for vcdObj in vcdObjList
            for disk in vcdObj.namedDisks.get(vcdObj.rollback.apiData['targetOrgVDC']['@id'], [])
        ]

    @staticmethod
    def _getVmToDisks(disksData, rollback=False):
        """
        Description :   Filter disks that are attached to VM as per VM
        Parameters  :   disksData -  List of disks with vcdObj (LIST)
                        rollback  - Timeout to be used for attach VM process(INT)
        Returns     :   Mapping of VM to its attached disks
        """
        vmToDisks = defaultdict(list)
        for vcdObj, disk in disksData:
            vm = disk['metadata'].get('attached_vm')
            if vm:
                vmToDisks[(vcdObj, vm['href'], vm['name'])].append(disk)
            else:
                if rollback:
                    logger.debug(f'Disk {disk["name"]} was not attached to any VM')
                else:
                    logger.debug(f'Disk {disk["name"]} is not attached to any VM')

        return vmToDisks

    @description("Detaching disks from VM")
    @remediate_threaded
    def detachNamedDisks(self, vcdObjList, timeout=None, threadCount=75):
        """
        Description :   Detach all named disks from their respective VM. Attach back if any error occurred
                        while detaching
        Parameters  :   vcdObjList - List of objects of vcd operations class (LIST)
                        timeout    - timeout for disk operation (INT)
                        threadCount- Thread count for disk operation (INT)
        """
        # 1. Check if disk is attached to any VM(using metadata)
        # 2. Detach disk from VM
        # 3. If any detach fails, attach back all disk to VM as mentioned in metadata
        if float(self.version) < float(vcdConstants.API_VERSION_ANDROMEDA):
            return

        try:
            self.sourceDisksData = self._getSourceDisksData(vcdObjList)
            if not self.sourceDisksData:
                return

            threading.current_thread().name = "MainThread"
            logger.info('Detaching disks from VMs')

            for (vcdObj, vmHref, vmName), disks in self._getVmToDisks(self.sourceDisksData).items():
                self.thread.spawnThread(vcdObj.detachVmDisk, disks, vmHref, vmName, timeout)

            # Blocking the main thread until all the threads complete execution
            self.thread.joinThreads()
            threading.current_thread().name = "MainThread"
            if self.thread.stop():
                raise Exception('Failed to detach independent disks')

            logger.info('Successfully detached independent disks')

        except Exception as e:
            logger.error(f'Exception occurred while detaching disk: {e}')
            self.attachNamedDisks(self.sourceDisksData, timeout=timeout, threadCount=threadCount)
            raise

    @remediate_threaded
    def detachNamedDisksRollback(self, vcdObjList, timeout=None, threadCount=75):
        """
        Description :   Rollback method to Detach all named disks from their respective VM. Attach back if any error
                        occurred while detaching
        Parameters  :   vcdObjList - List of objects of vcd operations class (LIST)
                        timeout    - timeout for disk operation (INT)
                        threadCount- Thread count for simultaneous disk operation (INT)
        """
        # 1. Check if disk is attached to any VM(using metadata)
        # 2. Detach disk from VM
        # 3. If any detach fails, attach back all disk to VM as mentioned in metadata
        if float(self.version) < float(vcdConstants.API_VERSION_ANDROMEDA):
            return

        # Check if disk operations was performed or not
        if not isinstance(self.rollback.metadata.get('moveAndAttachNamedDisks'), bool):
            return

        # If rollback of one of the org vdc is complete then return
        try:
            [vcdObj.rollback.apiData['targetOrgVDC']['@id'] for vcdObj in vcdObjList]
        except:
            return

        try:
            self.targetDisksData = self._getTargetDisksData(vcdObjList)
            if not self.targetDisksData:
                return

            self.rollback.executionResult['moveAndAttachNamedDisks'] = False
            self.saveMetadataInOrgVdc()

            threading.current_thread().name = "MainThread"
            logger.info('Rollback: Detaching disks from VMs')

            for (vcdObj, vmHref, vmName), disks in self._getVmToDisks(self.targetDisksData).items():
                self.thread.spawnThread(vcdObj.detachVmDisk, disks, vmHref, vmName, timeout)

            # Blocking the main thread until all the threads complete execution
            self.thread.joinThreads()
            threading.current_thread().name = "MainThread"
            if self.thread.stop():
                raise Exception('Failed to detach independent disks')

            logger.info('Rollback: Successfully detached independent disks')

        except Exception as e:
            logger.error(f'Exception occurred while detaching disk: {e}')
            self.attachNamedDisks(self.targetDisksData, timeout=timeout, threadCount=threadCount)
            raise
        finally:
            # Restoring thread name
            threading.current_thread().name = "MainThread"

    def attachNamedDisks(self, disksData, timeout=None, threadCount=75, rollback=True):
        """
        Description : attach all named disks from their respective VM. VM details are
         fetched from disk metadata
        Parameters  : disksData -  List of disk to be attached (LIST)
                      timeout  - Timeout to be used for attach VM process(INT)
                      threadCount- Thread count for simultaneous disk operation (INT)
                      rollback - Set to True for logging purpose
        """
        # 1. Get attached attached VM from metadata
        # 2. Attach disk to VM
        # 2.1. If disk is attached to same VM as the one mentioned in metadata, skip
        # 2.2. If disk is attached to different VM as the one mentioned in metadata,
        #      raise
        if float(self.version) < float(vcdConstants.API_VERSION_ANDROMEDA):
            return

        if not disksData:
            return

        # Saving current number of threads
        currentThreadCount = self.thread.numOfThread
        try:
            # Setting new thread count
            self.thread.numOfThread = threadCount
            threading.current_thread().name = "MainThread"

            if rollback:
                logger.info('Rollback: Attaching VMs to disks')
            else:
                logger.info('Attaching VMs to disks')

            for (vcdObj, vmHref, vmName), disks in self._getVmToDisks(disksData, rollback=True).items():
                self.thread.spawnThread(vcdObj.attachVmDisk, disks, vmHref, vmName, timeout)

            # Blocking the main thread until all the threads complete execution
            self.thread.joinThreads()
            threading.current_thread().name = "MainThread"
            if self.thread.stop():
                raise Exception('Rollback: Failed to attach independent disks')

        except:
            raise

        finally:
            # Restoring thread count
            self.thread.numOfThread = currentThreadCount

    def moveNamedDisk(self, disk, timeout, rollback, partialMove):
        """
        Description :   Move disk to target VDC
        Parameters  :   disk        - disk to be moved (DICT)
                        timeout     - timeout for disk operation (INT)
                        rollback    - whether to rollback from T2V (BOOL)
                        partialMove - It set True, move operation of VM to be attached to disk will be verified.
                                      If VM has not been moved, disk will not be moved.

        """
        if rollback:
            targetVdc = self.rollback.apiData['sourceOrgVDC']
        else:
            targetVdc = self.rollback.apiData['targetOrgVDC']
        targetVdcId = targetVdc['@id'].split(':')[-1]

        # When disk is not attached to VM, only move disk
        if not disk['metadata'].get('attached_vm'):
            self.moveDisk(disk, targetVdc['@href'], timeout=timeout)
            return

        if partialMove:
            # When disk is attacked to VM, check current VDC of of VM. If it
            # matches with target VDC for disk(i.e. VM is moved), move disk.
            # If VM is not moved, do not move disk. It will be attached back to
            # source VM.
            if targetVdcId == self.getVmVdc(disk['metadata']["attached_vm"]):
                self.moveDisk(disk, targetVdc['@href'], timeout=timeout)
            else:
                logger.info(f'Skipping disk {disk["name"]} movement as attached VM is not moved')
        else:
            self.moveDisk(disk, targetVdc['@href'], timeout=timeout)

    @description("Moving disks to Target VDC and re-attaching to VM")
    @remediate_threaded
    def moveAndAttachNamedDisks(self, vcdObjList, timeout=None, threadCount=75, partialMove=False):
        """
        Description :   Move all named disks. attach all named disks from their
                        respective VM. VM details are fetched from disk metadata
        Parameters  :   vcdObjList  - List of objects of vcd operations class (LIST)
                        timeout     - timeout for disk operation (INT)
                        rollback    - whether to rollback from T2V (BOOL)
                        threadCount - Thread count for simultaneous disk operation
                                      (used in remediate_threaded decorator)(INT)
                        partialMove - It set True, move operation of VM to be attached to disk will be verified.
                                      If VM has not been moved, disk will not be moved and metadata will not be updated

        """
        if float(self.version) < float(vcdConstants.API_VERSION_ANDROMEDA):
            return

        try:
            self.sourceDisksData = self._getSourceDisksData(vcdObjList)
            self.targetDisksData = self._getTargetDisksData(vcdObjList)
            if not self.sourceDisksData and not self.targetDisksData:
                logger.debug('No independent disks found')
                return

            # If any disk and its attached VM are not moved during migration, attach disk back to its VM during rollback
            if self.targetDisksData:
                threading.current_thread().name = "MainThread"
                logger.info("Verifying disks already present in Target Org VDC are attached to respective VMs")
                for (vcdObj, vmHref, vmName), disks in self._getVmToDisks(self.targetDisksData, rollback=True).items():
                    self.thread.spawnThread(vcdObj.attachVmDisk, disks, vmHref, vmName, timeout)

            if self.sourceDisksData:
                threading.current_thread().name = "MainThread"
                logger.info("Moving disks and re-attaching to VM")

                for vcdObj in vcdObjList:
                    vcdObj.fetchTargetStorageProfiles(vcdObj.rollback.apiData['targetOrgVDC'])

                # Start disk movement
                for vcdObj, disk in self.sourceDisksData:
                    self.thread.spawnThread(vcdObj.moveNamedDisk, disk, timeout, False, partialMove)

            # Blocking the main thread until all the threads complete execution
            self.thread.joinThreads()
            if self.thread.stop():
                raise Exception('Failed to move independent disks')

            # Attach disk to VM
            if self.sourceDisksData:
                for (vcdObj, vmHref, vmName), disks in self._getVmToDisks(self.sourceDisksData, rollback=True).items():
                    self.thread.spawnThread(vcdObj.attachVmDisk, disks, vmHref, vmName, timeout)

            # Blocking the main thread until all the threads complete execution
            self.thread.joinThreads()
            if self.thread.stop():
                raise Exception('Failed to attach independent disks')

            threading.current_thread().name = "MainThread"
            if partialMove:
                logger.info('Moved non-attached disks and disks attached to VMs that are moved')
                return METADATA_SAVE_FALSE

            if self.sourceDisksData:
                logger.info('Successfully moved and attached independent disks')

        except Exception as e:
            logger.error(f'Exception occurred while moving or attaching disk: {e}')
            raise

    @remediate_threaded
    def moveAndAttachNamedDisksRollback(self, vcdObjList, timeout=None, threadCount=75, partialMove=False):
        """
        Description :   Rollback operation to move all named disks. attach all named disks from their
                        respective VM. VM details are fetched from disk metadata
        Parameters  :   vcdObjList  - List of objects of vcd operations class (LIST)
                        timeout     - timeout for disk operation (INT)
                        rollback    - whether to rollback from T2V (BOOL)
                        threadCount - Thread count for simultaneous disk operation
                                      (used in remediate_threaded decorator)(INT)
                        partialMove - It set True, move operation of VM to be attached to disk will be verified.
                                      If VM has not been moved, disk will not be moved and metadata will not be updated

        """
        if float(self.version) < float(vcdConstants.API_VERSION_ANDROMEDA):
            return

        # Check if disk operations was performed or not
        if not isinstance(self.rollback.metadata.get('detachNamedDisks'), bool):
            return

        # If rollback of one of the org vdc is complete then return
        try:
            [vcdObj.rollback.apiData['targetOrgVDC']['@id'] for vcdObj in vcdObjList]
        except:
            return

        try:
            self.sourceDisksData = self._getSourceDisksData(vcdObjList)
            self.targetDisksData = self._getTargetDisksData(vcdObjList)
            if not self.sourceDisksData and not self.targetDisksData:
                logger.debug('Rollback: No independent disks found')
                return

            self.rollback.executionResult['detachNamedDisks'] = False
            self.saveMetadataInOrgVdc()

            # If any disk and its attached VM are not moved during migration, attach disk back to its VM during rollback
            if self.sourceDisksData:
                threading.current_thread().name = "MainThread"
                logger.info(
                    "Rollback: Verifying disks already present in Source Org VDC are attached to respective VMs")
                for (vcdObj, vmHref, vmName), disks in self._getVmToDisks(self.sourceDisksData, rollback=True).items():
                    self.thread.spawnThread(vcdObj.attachVmDisk, disks, vmHref, vmName, timeout)

            # Start disk movement
            if self.targetDisksData:
                for vcdObj in vcdObjList:
                    vcdObj.fetchTargetStorageProfiles(vcdObj.rollback.apiData['sourceOrgVDC'])

                threading.current_thread().name = "MainThread"
                logger.info("Rollback: Moving disks and re-attaching to VM")
                for vcdObj, disk in self.targetDisksData:
                    self.thread.spawnThread(vcdObj.moveNamedDisk, disk, timeout, True, partialMove)

            # Blocking the main thread until all the threads complete execution
            self.thread.joinThreads()
            if self.thread.stop():
                raise Exception('Failed to move independent disks')

            # Attach disk to VM
            if self.targetDisksData:
                for (vcdObj, vmHref, vmName), disks in self._getVmToDisks(self.targetDisksData, rollback=True).items():
                    self.thread.spawnThread(vcdObj.attachVmDisk, disks, vmHref, vmName, timeout)

            # Blocking the main thread until all the threads complete execution
            self.thread.joinThreads()
            if self.thread.stop():
                raise Exception('Failed to attach independent disks')

            threading.current_thread().name = "MainThread"
            if partialMove:
                logger.info('Rollback: Moved non-attached disks and disks attached to VMs that are moved')
                return

            if self.targetDisksData:
                logger.info('Rollback: Successfully moved and attached independent disks')

        except Exception as e:
            logger.error(f'Rollback: Exception occurred while moving or attaching disk: {e}')
            raise

        else:
            threading.current_thread().name = "MainThread"
            if not partialMove:
                # If disks rollback is successful, remove the metadata keys from metadata
                if isinstance(self.rollback.metadata.get('moveAndAttachNamedDisks'), bool):
                    self.deleteMetadataApiCall(
                        key='moveAndAttachNamedDisks-system-v2t',
                        orgVDCId=self.rollback.apiData.get('sourceOrgVDC', {}).get('@id'))
                if isinstance(self.rollback.metadata.get('detachNamedDisks'), bool):
                    self.deleteMetadataApiCall(
                        key='detachNamedDisks-system-v2t',
                        orgVDCId=self.rollback.apiData.get('sourceOrgVDC', {}).get('@id'))

    def migrateVapps(self, vcdObjList, inputDict, timeout=None, threadCount=75):
        """
        Description : Migrating vApps i.e composing target placeholder vapps and recomposing target vapps
        Parameters  : vcdObjList - List of objects of vcd operations class (LIST)
                      inputDict  - input file data in form of dictionary (DICT)
                      timeout    - timeout for vApp migration (INT)
                      threadCount- Thread count for vApp migration (INT)
        """
        # Saving current number of threads
        currentThreadCount = self.thread.numOfThread
        try:
            # Setting new thread count
            self.thread.numOfThread = threadCount
            # Saving status of moveVapp function
            self.rollback.executionResult['moveVapp'] = False
            # Iterating over vcd operations objects to fetch the corresponding details
            sourceOrgVDCNameList, sourceOrgVDCIdList, targetOrgVDCIdList, orgVDCNetworkList = list(), list(), list(), list()
            for vcdObj, orgVdcDict in zip(vcdObjList, inputDict["VCloudDirector"]["SourceOrgVDC"]):
                sourceOrgVDCNameList.append(orgVdcDict["OrgVDCName"])
                sourceOrgVDCIdList.append(vcdObj.rollback.apiData['sourceOrgVDC']['@id'])
                targetOrgVDCIdList.append(vcdObj.rollback.apiData['targetOrgVDC']['@id'])
                dfwStatus = True if vcdObj.rollback.apiData.get('OrgVDCGroupID') else False
                orgVDCNetworkList.append(vcdObj.getOrgVDCNetworks(vcdObj.rollback.apiData['targetOrgVDC']['@id'],
                                                             'targetOrgVDCNetworks', dfwStatus=dfwStatus,
                                                             saveResponse=False, sharedNetwork=True))

            threading.current_thread().name = "MainThread"
            # handling the case if there exist no vapps in source org vdc
            # if no source vapps are present then skipping all the below steps as those are not required
            if not any([self.checkIfSourceVappsExist(sourceOrgVDCId) for sourceOrgVDCId in sourceOrgVDCIdList]):
                logger.debug("No Vapps in Source Org VDC, hence skipping migrateVapps task.")
                self.rollback.executionResult['moveVapp'] = True
            else:
                # Logging continuation message
                if self.rollback.metadata and not hasattr(self.rollback, 'retry'):
                    logger.info(
                        'Continuing migration of NSX-V backed Org VDC to NSX-T backed from {}.'.format(
                            "Migration of vApps"))
                    for vcdObj in vcdObjList:
                        vcdObj.rollback.retry = True

                if not self.rollback.metadata.get('moveVapp'):
                    # recompose target vApp by adding source vm
                    logger.info('Migrating source vApps.')
                    self.moveVapp(sourceOrgVDCIdList, targetOrgVDCIdList, orgVDCNetworkList, timeout, vcdObjList, sourceOrgVDCNameList)
                    logger.info('Successfully migrated source vApps.')
                    self.rollback.executionResult['moveVapp'] = True
        except Exception:
            self.rollback.executionResult['detachNamedDisks'] = False
            self.moveAndAttachNamedDisks(vcdObjList, timeout, threadCount, partialMove=True)
            raise
        finally:
            # Restoring thread count
            self.thread.numOfThread = currentThreadCount
            # Saving metadata
            self.saveMetadataInOrgVdc()
            threading.current_thread().name = "MainThread"

    def vappRollback(self, vcdObjList, inputDict, timeout, threadCount=75):
        """
        Description: Rollback of vapps from target to source org vdc
        Parameters : vcdObjList - List of objects of vcd operations class (LIST)
                     inputDict  - input file data in form of dictionary (DICT)
                     timeout    - timeout for vApp migration (INT)
                     threadCount- Thread count for vApp migration (INT)
        """
        # Saving current number of threads
        currentThreadCount = self.thread.numOfThread
        try:
            # Check if vApp migration was performed or not
            if not isinstance(self.rollback.metadata.get('moveVapp'), bool):
                return
            # Setting new thread count
            self.thread.numOfThread = threadCount

            # Iterating over vcd operations objects to fetch the corresponding details
            sourceOrgVDCNameList, sourceOrgVDCIdList, targetOrgVDCIdList, orgVDCNetworkList, = list(), list(), list(), list()
            for vcdObj, orgVdcDict in zip(vcdObjList, inputDict["VCloudDirector"]["SourceOrgVDC"]):

                try:
                    sourceOrgVDCNameList.append(orgVdcDict["OrgVDCName"])
                    sourceOrgVDCIdList.append(vcdObj.rollback.apiData['sourceOrgVDC']['@id'])
                    targetOrgVDCIdList.append(vcdObj.rollback.apiData['targetOrgVDC']['@id'])
                    dfwStatus = True if vcdObj.rollback.apiData.get('OrgVDCGroupID') else False
                except:
                    # If rollback of one of the org vdc is complete then return
                    return

                # get source org vdc networks
                orgVDCNetworkList.append(vcdObj.getOrgVDCNetworks(vcdObj.rollback.apiData['sourceOrgVDC']['@id'],
                                                                  'sourceOrgVDCNetworks', dfwStatus=dfwStatus,
                                                                  saveResponse=False, sharedNetwork=True))

                # Rolling back affinity rules
                vcdObj.enableTargetAffinityRules(rollback=True)

            self.rollback.executionResult['moveVapp'] = False
            self.saveMetadataInOrgVdc()

            # move vapp from target to source org vdc
            self.moveVapp(targetOrgVDCIdList, sourceOrgVDCIdList, orgVDCNetworkList, timeout, vcdObjList, sourceOrgVDCNameList, rollback=True)
        except Exception:
            self.moveAndAttachNamedDisksRollback(vcdObjList, timeout, threadCount, partialMove=True)
            raise
        else:
            if isinstance(self.rollback.metadata.get('moveVapp'), bool):
                # If bridging rollback is successful, remove the bridging key from metadata
                self.deleteMetadataApiCall(key='moveVapp-system-v2t',
                                                    orgVDCId=self.rollback.apiData.get('sourceOrgVDC', {}).get(
                                                        '@id'))
        finally:
            # Restoring thread count
            self.thread.numOfThread = currentThreadCount
            # Restoring thread name
            threading.current_thread().name = "MainThread"

    @isSessionExpired
    def getEdgeVmId(self):
        """
        Description : Method to get edge VM ID
        Parameters : edgeGatewayId - Edge gateway ID (STRING)
        Returns : edgeVmId - Edge Gateway VM ID (STRING)
        """
        try:
            logger.debug("Getting Edge VM ID")
            edgeVmIdList = []
            edgeGatewayIdList = self.rollback.apiData['sourceEdgeGatewayId']
            for edgeGatewayId in edgeGatewayIdList:
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
                    if isinstance(edgeNetworkDict[vcdConstants.EDGE_GATEWAY_STATUS_KEY][
                                      vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY][vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY],
                                  list):
                        edgeVmId = [edgeNetworkData for edgeNetworkData in
                                    edgeNetworkDict[vcdConstants.EDGE_GATEWAY_STATUS_KEY][
                                        vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY][
                                        vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY] if
                                    edgeNetworkData['haState'] == 'active']
                        if edgeVmId:
                            edgeVmId = edgeVmId[0]["id"]
                        else:
                            raise Exception(
                                'Could not find the edge vm id for source edge gateway {}'.format(edgeGatewayId))
                    else:
                        edgeVmId = \
                        edgeNetworkDict[vcdConstants.EDGE_GATEWAY_STATUS_KEY][vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY][
                            vcdConstants.EDGE_GATEWAY_VM_STATUS_KEY]["id"]
                    edgeVmIdList.append(edgeVmId)
                else:
                    errorDict = xmltodict.parse(response.content)
                    raise Exception(
                        "Failed to get edge gateway status. Error - {}".format(errorDict['error']['details']))
            return edgeVmIdList
        except Exception:
            raise

    @description("connection of dummy uplink to source Edge gateway")
    @remediate
    def connectUplinkSourceEdgeGateway(self, sourceEdgeGatewayIdList, rollback=False):
        """
        Description :  Connect another uplink to source Edge Gateways from the specified OrgVDC
        Parameters  :   sourceEdgeGatewayId -   Id of the Organization VDC Edge gateway (STRING)
                        rollback - key that decides whether to perform rollback or not (BOOLEAN)
        """
        try:
            # Check if services configuration or network switchover was performed or not
            if rollback and not isinstance(self.rollback.metadata.get("configureTargetVDC", {}).get("connectUplinkSourceEdgeGateway"), bool):
                return

            if not sourceEdgeGatewayIdList:
                logger.debug('Skipping connecting/disconnecting dummy uplink as edge'
                             ' gateway does not exists')
                return

            if rollback:
                logger.info('Rollback: Disconnecting dummy-uplink from source Edge Gateway')
            else:
                logger.info('Connecting dummy uplink to source Edge gateway.')
            logger.debug("Connecting another uplink to source Edge Gateway")

            data = self.rollback.apiData
            dummyExternalNetwork = self.getExternalNetwork(data['dummyExternalNetwork']['name'], isDummyNetwork=True)
            if not rollback:
                # Validating if sufficient free IP's are present in dummy external network
                freeIpCount = dummyExternalNetwork['totalIpCount'] - dummyExternalNetwork['usedIpCount']
                if freeIpCount < len(sourceEdgeGatewayIdList):
                    raise Exception(
                        f"{len(sourceEdgeGatewayIdList)} free IP's are required in dummy external network "
                        f"but only {freeIpCount} free IP's are present.")

            for sourceEdgeGatewayId in sourceEdgeGatewayIdList:
                orgVDCEdgeGatewayId = sourceEdgeGatewayId.split(':')[-1]
                # url to connect uplink the source edge gateway
                url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                    vcdConstants.UPDATE_EDGE_GATEWAY_BY_ID.format(orgVDCEdgeGatewayId))
                acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
                headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
                # retrieving the details of the edge gateway
                response = self.restClientObj.get(url, headers)
                responseDict = response.json()
                if response.status_code == requests.codes.ok:
                    gatewayInterfaces = responseDict['configuration']['gatewayInterfaces']['gatewayInterface']
                    if len(gatewayInterfaces) >= 9:
                        raise Exception(
                            'No more uplinks present on source Edge Gateway to connect dummy External Uplink.')
                    if not rollback:
                        dummyUplinkAlreadyConnected = True if [interface for interface in gatewayInterfaces
                                                               if interface['name'] == dummyExternalNetwork['name']] \
                                                                else False
                        if dummyUplinkAlreadyConnected:
                            logger.debug("Dummy Uplink is already connected to edge gateway - {}".format(responseDict['name']))
                            continue
                        filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
                        # creating the dummy external network link
                        networkId = dummyExternalNetwork['id'].split(':')[-1]
                        networkHref = "{}network/{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                                            networkId)
                        # creating the payload data for adding dummy external network
                        payloadDict = {'edgeGatewayUplinkName': dummyExternalNetwork['name'],
                                       'networkHref': networkHref,
                                       'uplinkGateway': dummyExternalNetwork['subnets']['values'][0]['gateway'],
                                       'prefixLength': dummyExternalNetwork['subnets']['values'][0]['prefixLength'],
                                       'uplinkIpAddress': ""}
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.CONNECT_ADDITIONAL_UPLINK_EDGE_GATEWAY_TEMPLATE)
                        payloadData = json.loads(payloadData)
                        gatewayInterfaces.append(payloadData)
                    else:

                        # Computation to remove dummy external network key from API payload
                        extNameList = [externalNetwork['name'] for externalNetwork in data['sourceExternalNetwork']]
                        extRemoveList = list()
                        for index, value in enumerate(gatewayInterfaces):
                            if value['name'] not in extNameList:
                                extRemoveList.append(value)
                        for value in extRemoveList:
                            gatewayInterfaces.remove(value)
                            # if value['name'] == dummyExternalNetwork['name']:
                            #     gatewayInterfaces.pop(index)
                    responseDict['configuration']['gatewayInterfaces']['gatewayInterface'] = gatewayInterfaces
                    responseDict['edgeGatewayServiceConfiguration'] = None
                    del responseDict['tasks']
                    payloadData = json.dumps(responseDict)
                    acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE
                    self.headers["Content-Type"] = vcdConstants.XML_UPDATE_EDGE_GATEWAY
                    headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader,
                               'Content-Type': vcdConstants.JSON_UPDATE_EDGE_GATEWAY}
                    # updating the details of the edge gateway
                    response = self.restClientObj.put(url + '/action/updateProperties', headers, data=payloadData)
                    responseData = response.json()
                    if response.status_code == requests.codes.accepted:
                        taskUrl = responseData["href"]
                        if taskUrl:
                            # checking the status of renaming target org vdc task
                            self._checkTaskStatus(taskUrl=taskUrl)
                            if rollback:
                                logger.debug(
                                    'Disconnected dummy uplink from source Edge gateway {} successfully'.format(
                                        responseDict['name']))
                            else:
                                logger.debug('Connected dummy uplink to source Edge gateway {} successfully'.format(
                                    responseDict['name']))

                                # Saving rollback key after successful dummy uplink connection to one edge gateway
                                self.rollback.executionResult["configureTargetVDC"]["connectUplinkSourceEdgeGateway"] = False
                            continue
                    else:
                        if rollback:
                            raise Exception(
                                "Failed to disconnect dummy uplink from source Edge gateway {} with error {}".format(
                                    responseDict['name'], responseData['message']))
                        else:
                            raise Exception(
                                "Failed to connect dummy uplink to source Edge gateway {} with error {}".format(
                                    responseDict['name'], responseData['message']))
                else:
                    raise Exception("Failed to get edge gateway '{}' details due to error - {}".format(
                        responseDict['name'], responseDict['message']))
            if not rollback:
                logger.info('Successfully connected dummy uplink to source Edge gateway.')
        except Exception:
            self.saveMetadataInOrgVdc()
            raise

    @isSessionExpired
    def updateSourceExternalNetwork(self, networkName, edgeGatewaySubnetDict):
        """
        Description : Update Source External Network sub allocated ip pools
        Parameters : networkName: source external network name (STRING)
                     edgeGatewaySubnetDict: source edge gateway sub allocated ip pools (DICT)
        """
        try:
            # iterating over all the external networks
            for response in self.fetchAllExternalNetworks():
                # checking if networkName is present in the list,
                if response['name'] == networkName:
                    # getting the external network sub allocated pools
                    for index, subnet in enumerate(response['subnets']['values']):
                        externalRanges = subnet['ipRanges']['values']
                        externalRangeList = []
                        externalNetworkSubnet = ipaddress.ip_network(
                            '{}/{}'.format(subnet['gateway'], subnet['prefixLength']),
                            strict=False)
                        # creating range of source external network pool range
                        for externalRange in externalRanges:
                            externalRangeList.extend(
                                self.createIpRange(externalNetworkSubnet, externalRange['startAddress'], externalRange['endAddress']))
                        subIpPools = edgeGatewaySubnetDict.get(externalNetworkSubnet)
                        # If no ipPools are used from corresponding network then skip the iteration
                        if not subIpPools:
                            continue
                        # creating range of source edge gateway sub allocated pool range
                        subIpRangeList = []
                        for ipRange in subIpPools:
                            subIpRangeList.extend(
                                self.createIpRange(externalNetworkSubnet, ipRange['startAddress'], ipRange['endAddress']))
                        # removing the sub allocated ip pools of source edge gateway from source external network
                        for ip in subIpRangeList:
                            if ip in externalRangeList:
                                externalRangeList.remove(ip)
                        # getting the source edge gateway sub allocated ip pool after removing used ips i.e source edge gateway
                        result = self.createExternalNetworkSubPoolRangePayload(externalRangeList)
                        response['subnets']['values'][index]['ipRanges']['values'] = result

                    # API call to update external network details
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
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug('Updating external network sub allocated ip pool {}'.format(networkName))
                    else:
                        errorDict = apiResponse.json()
                        raise Exception(
                            "Failed to reset the target external network '{}' to its initial state: {}".format(
                                networkName,
                                errorDict['message']))
        except Exception:
            raise

    @staticmethod
    def createExternalNetworkSubPoolRangePayload(externalNetworkPoolRangeList):
        """
        Description : Create external network sub ip pool range payload
        Parameters : externalNetworkPoolRangeList - external network pool range (LIST)
        """
        resultData = []
        for ipAddress in externalNetworkPoolRangeList:
            resultData.append({'startAddress': ipAddress, 'endAddress': ipAddress})
        return resultData

    @isSessionExpired
    def deleteSourceCatalog(self, catalogUrl, srcCatalog):
        """
        Description :   Deletes the source org vdc catalog of the specified catalog url
        Parameters  :   catalogUrl  -   url of the source catalog (STRING)
                        srcCatalog  -   Details of the source catalog (DICT)
        """
        try:
            # deleting catalog
            logger.debug("Deleting catalog '{}'".format(srcCatalog['@name']))
            # url to delete the catalog
            deleteCatalogUrl = '{}?recursive=true&force=true'.format(catalogUrl)
            # delete api call to delete the catalog
            deleteCatalogResponse = self.restClientObj.delete(deleteCatalogUrl, self.headers)
            deleteCatalogResponseDict = xmltodict.parse(deleteCatalogResponse.content)
            if deleteCatalogResponse.status_code == requests.codes.accepted:
                task = deleteCatalogResponseDict["Task"]
                taskUrl = task["@href"]
                if taskUrl:
                    # checking the status of deleting the catalog task
                    self._checkTaskStatus(taskUrl=taskUrl)
                logger.debug("Catalog '{}' deleted successfully".format(srcCatalog['@name']))
            else:
                raise Exception("Failed to delete catalog '{}' - {}".format(srcCatalog['@name'],
                                                                            deleteCatalogResponseDict['Error'][
                                                                                '@message']))

        except Exception:
            raise

    @isSessionExpired
    def renameTargetCatalog(self, catalogId, srcCatalog):
        """
        Description :   Renames the target org vdc catalog of the specified catalog url
        Parameters  :   catalogId   -   ID of the source catalog (STRING)
                        srcCatalog  -   Details of the source catalog (DICT)
        """
        try:
            # renaming catalog
            logger.debug("Renaming the catalog '{}' to '{}'".format(srcCatalog['@name'] + '-v2t',
                                                                    srcCatalog['@name']))
            # url to rename the catalog
            renameCatalogUrl = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                             vcdConstants.RENAME_CATALOG.format(catalogId))
            # creating the payload
            payloadDict = {'catalogName': srcCatalog['@name'],
                           'catalogDescription': srcCatalog['Description'] if srcCatalog.get('Description') else ''}

            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
            payloadData = self.vcdUtils.createPayload(filePath,
                                                      payloadDict,
                                                      fileType='yaml',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.RENAME_CATALOG_TEMPLATE)
            payloadData = json.loads(payloadData)
            # setting the content-type to rename the catalog
            headers = {'Authorization': self.headers['Authorization'],
                       'Accept': vcdConstants.VCD_API_HEADER,
                       'Content-Type': vcdConstants.RENAME_CATALOG_CONTENT_TYPE}
            # put api call to rename the catalog back to its original name
            renameCatalogResponse = self.restClientObj.put(renameCatalogUrl, headers, data=payloadData)
            if renameCatalogResponse.status_code == requests.codes.ok:
                logger.debug("Catalog '{}' renamed to '{}' successfully".format(srcCatalog['@name'] + '-v2t',
                                                                                srcCatalog['@name']))
            else:
                raise Exception("Failed to rename catalog '{}' to '{}'".format(srcCatalog['@name'] + '-v2t',
                                                                               srcCatalog['@name']))
        except Exception:
            raise

    @isSessionExpired
    def moveVappApiCall(self, vApp, targetOrgVDCNetworkList, targetOrgVDCId, filePath, timeout, sourceOrgVDCName=None, rollback=False):
        """
            Description :   Prepares the payload for moving the vApp and sends post api call for it
            Parameters  :   vApp  -   Information related to a specific vApp (DICT)
                            targetOrgVDCNetworkList - All the target org vdc networks (LIST)
                            targetOrgVDCId - ID of target org vdc (STRING)
                            filePath - file path of template.yml which holds all the templates (STRING)
                            timeout  -  timeout to be used for vapp migration task (INT)
                            rollback - whether to rollback from T2V (BOOLEAN)
        """
        # Saving thread name as per vdc name
        threading.currentThread().name = sourceOrgVDCName

        otherNetworkList = list()
        if rollback:
            logger.info('Moving vApp - {} to source Org VDC - {}'.format(vApp['@name'], sourceOrgVDCName))
        else:
            logger.info('Moving vApp - {} to target Org VDC - {}'.format(vApp['@name'], sourceOrgVDCName + '-v2t'))
        networkList = []
        response = self.restClientObj.get(vApp['@href'], self.headers)
        responseDict = xmltodict.parse(response.content)
        vAppData = responseDict['VApp']
        # checking for the 'NetworkConfig' in 'NetworkConfigSection' of vapp
        if vAppData['NetworkConfigSection'].get('NetworkConfig'):
            vAppNetworkList = vAppData['NetworkConfigSection']['NetworkConfig'] \
                if isinstance(vAppData['NetworkConfigSection']['NetworkConfig'], list) else [
                vAppData['NetworkConfigSection']['NetworkConfig']]
            if rollback:
                # retrieving the network details list of same name networks from source & target, target networks will have -v2t appended
                networkList = [(network, vAppNetwork) for network in targetOrgVDCNetworkList for vAppNetwork in
                               vAppNetworkList if vAppNetwork['@networkName'] == network['name'] + '-v2t']
            else:
                # retrieving the network details list of same name networks from source & target
                networkList = [(network, vAppNetwork) for network in targetOrgVDCNetworkList for vAppNetwork in
                               vAppNetworkList if vAppNetwork['@networkName'] + '-v2t' == network['name']]
            # retrieving the network details of other networks other than org vdc networks
            otherNetworkList = [vAppNetwork for vAppNetwork in vAppNetworkList]
        # if networks present
        networkPayloadData = ''
        if networkList:
            # iterating over the network list
            for network, vAppNetwork in networkList:
                # creating payload dictionary with network details
                networkName = "{}network/{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                                    network["id"].split(':')[-1])
                payloadDict = {'networkName': network['name'],
                               'networkDescription': vAppNetwork['Description'] if vAppNetwork.get(
                                   'Description') else '',
                               'parentNetwork': networkName,
                               'fenceMode': vAppNetwork['Configuration']['FenceMode']}
                payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                          componentName=vcdConstants.COMPONENT_NAME,
                                                          templateName=vcdConstants.MOVE_VAPP_NETWORK_CONFIG_TEMPLATE)
                networkPayloadData += payloadData.strip("\"")
        # creating payload for no network and vapp network
        if otherNetworkList:
            for network in otherNetworkList:
                if not network['Configuration'].get('ParentNetwork'):
                    if network['@networkName'] == 'none':
                        networkName = network['@networkName']
                    else:
                        if rollback:
                            networkName = network['@networkName'].replace('-v2t', '')
                        else:
                            networkName = network['@networkName'] + '-v2t'
                    featuresConfig = ''
                    # Check DHCP service and Enable DHCP service.
                    sourceDhcpConfig = network['Configuration'].get('Features', {}).get('DhcpService', {})
                    if sourceDhcpConfig.get('IsEnabled') == 'true':
                        payloadDict = {
                            'isEnabled': sourceDhcpConfig['IsEnabled'],
                            'defaultLeaseTime': sourceDhcpConfig.get('DefaultLeaseTime'),
                            'maxLeaseTime': sourceDhcpConfig['MaxLeaseTime'],
                            'ipRangeStartAddress': sourceDhcpConfig['IpRange']['StartAddress'],
                            'ipRangeEndAddress': sourceDhcpConfig['IpRange']['EndAddress'],
                        }
                        dhcpConfig = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                 componentName=vcdConstants.COMPONENT_NAME,
                                                                 templateName='moveVappNetworkConfigFeaturesDhcp',).strip('"')

                        payloadDict = {'dhcpConfig': dhcpConfig, }
                        featuresConfig = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                     componentName=vcdConstants.COMPONENT_NAME,
                                                                     templateName='moveVappNetworkConfigFeatures', ).strip('"')

                    # if static ip pools exist in vapp network
                    if network['Configuration']['IpScopes']['IpScope'].get('IpRanges'):
                        payloadDict = {'networkName': networkName,
                                       'networkDescription': network['Description'] if network.get(
                                           'Description') else '',
                                       'fenceMode': network['Configuration']['FenceMode'],
                                       'isInherited': network['Configuration']['IpScopes']['IpScope']['IsInherited'],
                                       'gateway': network['Configuration']['IpScopes']['IpScope']['Gateway'],
                                       'netmask': network['Configuration']['IpScopes']['IpScope']['Netmask'],
                                       'subnet': network['Configuration']['IpScopes']['IpScope'][
                                           'SubnetPrefixLength'] if
                                       network['Configuration']['IpScopes']['IpScope'].get('SubnetPrefixLength') else 1,
                                       'dns1': network['Configuration']['IpScopes']['IpScope']['Dns1'] if
                                       network['Configuration']['IpScopes']['IpScope'].get('Dns1') else '',
                                       'startAddress':
                                           network['Configuration']['IpScopes']['IpScope']['IpRanges']['IpRange'][
                                               'StartAddress'],
                                       'endAddress':
                                           network['Configuration']['IpScopes']['IpScope']['IpRanges']['IpRange'][
                                               'EndAddress'],
                                       'isDeployed': network['IsDeployed'],
                                       'featuresConfig': featuresConfig,
                                       }
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.MOVE_VAPP_NO_NETWORK_IP_POOL_CONFIG_TEMPLATE)
                    else:
                        payloadDict = {'networkName': networkName,
                                       'networkDescription': network['Description'] if network.get(
                                           'Description') else '',
                                       'fenceMode': network['Configuration']['FenceMode'],
                                       'isInherited': network['Configuration']['IpScopes']['IpScope']['IsInherited'],
                                       'gateway': network['Configuration']['IpScopes']['IpScope']['Gateway'],
                                       'netmask': network['Configuration']['IpScopes']['IpScope']['Netmask'],
                                       'subnet': network['Configuration']['IpScopes']['IpScope'][
                                           'SubnetPrefixLength'] if
                                       network['Configuration']['IpScopes']['IpScope'].get('SubnetPrefixLength') else 1,
                                       'dns1': network['Configuration']['IpScopes']['IpScope']['Dns1'] if
                                       network['Configuration']['IpScopes']['IpScope'].get('Dns1') else '',
                                       'isDeployed': network['IsDeployed'],
                                       'featuresConfig': featuresConfig
                                       }
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.MOVE_VAPP_NO_NETWORK_CONFIG_TEMPLATE)
                    networkPayloadData += payloadData.strip("\"")
        # create vApp children vm's payload
        vmPayloadData = self.createMoveVappVmPayload(vApp, targetOrgVDCId, rollback=rollback)
        if vmPayloadData and networkPayloadData:
            payloadDict = {'vAppHref': vApp['@href'],
                           'networkConfig': networkPayloadData,
                           'vmDetails': vmPayloadData}
            # creating payload data
            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.MOVE_VAPP_TEMPLATE)
        elif vmPayloadData and not networkPayloadData:
            payloadDict = {'vAppHref': vApp['@href'],
                           'vmDetails': vmPayloadData}
            # creating payload data
            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='yaml',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.MOVE_VAPP_NO_NETWORK_VM_TEMPLATE)
        payloadData = json.loads(payloadData)
        # url to compose vapp in target org vdc
        url = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                            vcdConstants.MOVE_VAPP_IN_ORG_VDC.format(targetOrgVDCId))
        self.headers["Content-Type"] = vcdConstants.XML_MOVE_VAPP
        # post api call to compose vapps in target org vdc
        response = self.restClientObj.post(url, self.headers, data=payloadData)
        if response.status_code == requests.codes.accepted:
            responseDict = xmltodict.parse(response.content)
            task = responseDict["Task"]
            taskUrl = task["@href"]
            if taskUrl:
                # checking for the status of the composing vapp task
                self._checkTaskStatus(taskUrl, timeoutForTask=timeout)
        else:
            responseDict = xmltodict.parse(response.content)
            raise Exception(
                'Failed to move vApp - {} with errors {}'.format(vApp['@name'], responseDict['Error']['@message']))
        if rollback:
            logger.info(
                'Moved vApp - {} successfully to source Org VDC - {}'.format(vApp['@name'], sourceOrgVDCName))
        else:
            logger.info(
                'Moved vApp - {} successfully to target Org VDC - {}'.format(vApp['@name'],
                                                                             sourceOrgVDCName + '-v2t'))

    @isSessionExpired
    def moveVapp(self, sourceOrgVDCIdList, targetOrgVDCIdList, targetOrgVDCNetworkList, timeout, vcdObjList, sourceOrgVDCNameList=None, rollback=False):
        """
        Description : Move vApp from source Org VDC to Target Org vdc
        Parameters  : sourceOrgVDCId    -   Id of the source organization VDC (STRING)
                      targetOrgVDCId    -   Id of the target organization VDC (STRING)
                      targetOrgVDCNetworkList - List of target Org VDC networks (LIST)
                      timeout  -  timeout to be used for vapp migration task (INT)
                      rollback - whether to rollback from T2V (BOOLEAN)
        """
        try:
            vAppData = list()
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
            # Fetching vApps from org vdc
            for sourceOrgVDCId, targetOrgVDCId, targetOrgVDCNetworks, sourceOrgVDCName in zip_longest(sourceOrgVDCIdList,
                                                                                                     targetOrgVDCIdList,
                                                                                                     targetOrgVDCNetworkList,
                                                                                                     sourceOrgVDCNameList):
                sourceOrgVDCId = sourceOrgVDCId.split(':')[-1]
                vAppData.append(self.getOrgVDCvAppsList(sourceOrgVDCId))

            threading.current_thread().name = "MainThread"
            if rollback and reduce(lambda x, y: x+y, vAppData):
                logger.info("RollBack: Migrating Target vApps")
            elif rollback and not reduce(lambda x, y: x+y, vAppData):
                return

            for vcdObj, sourceOrgVDCId, targetOrgVDCId, targetOrgVDCNetworks, sourceOrgVDCName, vAppList in zip_longest(
                    vcdObjList,
                    sourceOrgVDCIdList,
                    targetOrgVDCIdList,
                    targetOrgVDCNetworkList,
                    sourceOrgVDCNameList,
                    vAppData):
                # retrieving target org vdc id
                targetOrgVDCId = targetOrgVDCId.split(':')[-1]

                # iterating over the source vapps
                for vApp in vAppList:
                    # Spawning threads for move vApp call
                    self.thread.spawnThread(vcdObj.moveVappApiCall, vApp, targetOrgVDCNetworks, targetOrgVDCId, filePath,
                                            timeout, sourceOrgVDCName=sourceOrgVDCName, rollback=rollback, block=True)
            # Blocking the main thread until all the threads complete execution
            self.thread.joinThreads()

            # Checking if any thread's execution failed
            if self.thread.stop():
                raise Exception('Failed to move vApp/s')
        except Exception:
            raise
        else:
            self.rollback.executionResult['moveVapp'] = True

    @isSessionExpired
    def renameTargetNetworks(self, targetVDCId):
        """
        Description :   Renames all the target org vdc networks in the specified target Org VDC as those in source Org VDC
        Parameters  :   targetVDCId -   id of the target org vdc (STRING)
        """
        try:
            # splitting thr target org vdc id as per the xml api requirements
            targetVDCId = targetVDCId.split(':')[-1]
            headers = {'Authorization': self.headers['Authorization'],
                       'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE}
            # url to get the target org vdc details
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.ORG_VDC_BY_ID.format(targetVDCId))
            # get api call to retrieve the target org vdc details
            response = self.restClientObj.get(url, headers=headers)
            getResponseDict = response.json()

            # Case 1: Handling the case of renaming target org vdc networks
            # getting the list instance of all the target org vdc networks
            targetOrgVDCNetworks = getResponseDict['availableNetworks']['network'] if isinstance(getResponseDict['availableNetworks']['network'], list) else [getResponseDict['availableNetworks']['network']]
            # iterating over the target org vdc networks
            for network in targetOrgVDCNetworks:
                self.renameTargetOrgVDCNetworks(network)

            # Case 2: Handling the case renaming target vapp isolated networks
            # to get the target vapp networks, getting the target vapps
            if getResponseDict.get('resourceEntities'):
                targetOrgVDCEntityList = getResponseDict['resourceEntities']['resourceEntity'] if isinstance(getResponseDict['resourceEntities']['resourceEntity'], list) else [getResponseDict['resourceEntities']['resourceEntity']]
                vAppList = [vAppEntity for vAppEntity in targetOrgVDCEntityList if vAppEntity['type'] == vcdConstants.TYPE_VAPP]
                if vAppList:
                    self.renameTargetVappIsolatedNetworks(vAppList)
        except Exception:
            raise

    @description("Fetching Promiscous Mode and Forged transmit information")
    @remediate
    def getPromiscModeForgedTransmit(self, sourceOrgVDCId):
        """
        Description : Get the Promiscous Mode and Forged transmit information of source org vdc network
        """
        try:
            logger.info("Fetching Promiscous Mode and Forged transmit information of source org vdc network")
            orgVDCNetworkList = self.getOrgVDCNetworks(sourceOrgVDCId, 'sourceOrgVDCNetworks', saveResponse=False)
            data = self.rollback.apiData
            # list of the org vdc networks with its promiscuous mode and forged transmit details
            promiscForgedList = []
            # iterating over the org vdc network list
            for orgVdcNetwork in orgVDCNetworkList:
                # url to get the dvportgroup details of org vdc network
                url = "{}{}/{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                          vcdConstants.ALL_ORG_VDC_NETWORKS, orgVdcNetwork['id'], vcdConstants.ORG_VDC_NETWORK_PORTGROUP_PROPERTIES_URI)
                # get api call to retrieve the dvportgroup details of org vdc network
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    # creating the dictionary of details of the promiscuous mode and forge transmit details
                    detailsDict = {}
                    detailsDict["id"] = orgVdcNetwork['id']
                    detailsDict["name"] = orgVdcNetwork['name']
                    detailsDict["promiscForge"] = responseDict
                    # appending the dictionary to the above list
                    promiscForgedList.append(detailsDict)
                else:
                    raise Exception('Failed to get dvportgroup properties of source Org VDC network {}'.format(orgVdcNetwork['name']))
            # writing promiscForgedList to the apiOutput.json for further use(for disabling the promiscuous mode and forged transmit in case of rollback)
            data["orgVDCNetworkPromiscModeList"] = promiscForgedList
        except Exception:
            raise

    @isSessionExpired
    def resetTargetExternalNetwork(self, networkName):
        """
        Description :   Resets the target external network(i.e updating the target external network to its initial state)
        Parameters  :   uplinkName  -   name of the source external network
        """
        try:
            # Check if org vdc edge gateways were created or not
            if not self.rollback.metadata.get("prepareTargetVDC", {}).get("createEdgeGateway"):
                return

            # Locking as this operation can only be performed by one thread at a time
            self.lock.acquire(blocking=True)
            logger.debug("Lock acquired by thread - '{}'".format(threading.currentThread().getName()))

            logger.info('Rollback: Reset the target external network')
            data = self.rollback.apiData

            targetExternalNetworkData = self.getExternalNetwork(networkName)

            # reading the data of target external network from apiOutput.json to create payload
            payloadDict = copy.deepcopy(targetExternalNetworkData)

            # retrieving the source edge gateway uplinks before migration tool run
            edgeGatewayLinks = []
            for edgeGateway in data['sourceEdgeGateway']:
                edgeGatewayLinks += edgeGateway['edgeGatewayUplinks'] \
                    if isinstance(edgeGateway['edgeGatewayUplinks'], list) \
                    else [edgeGateway['edgeGatewayUplinks']]

            for sourceExtNet in data['sourceExternalNetwork']:
                indexToUpdate = None
                uplinkName = sourceExtNet['name']
                for sourceExtNetSubnet in sourceExtNet['subnets']['values']:
                    sourceExtNetGateway = sourceExtNetSubnet['gateway']
                    sourceExtNetPrefix = sourceExtNetSubnet['prefixLength']
                    sourceExtNetNetworkAddress = ipaddress.ip_network(
                        '{}/{}'.format(sourceExtNetGateway, sourceExtNetPrefix), strict=False)
                    for index, value in enumerate(targetExternalNetworkData['subnets']['values']):
                        targetExtNetNetworkAddress = ipaddress.ip_network(
                            '{}/{}'.format(value['gateway'], value['prefixLength']), strict=False)
                        if sourceExtNetNetworkAddress == targetExtNetNetworkAddress:
                            indexToUpdate = index
                            break
                    else:
                        continue
                    # getting the target external network's subnet ip range from apiOutput.json
                    targetExternalRange = targetExternalNetworkData['subnets']['values'][indexToUpdate]['ipRanges'][
                        'values']

                    targetExternalRangeList = []
                    # creating range of source external network pool range
                    for externalRange in targetExternalRange:
                        # breaking the iprange into list of ips covering all the ip address lying in the range
                        targetExternalRangeList.extend(
                            self.createIpRange('{}/{}'.format(sourceExtNetGateway, sourceExtNetPrefix),
                                               externalRange['startAddress'], externalRange['endAddress']))

                    targetExternalRangeList = list(set(targetExternalRangeList))

                    sourceEdgeGatewaySubIpPools = []

                    # iterating over the edge gateway links to find the matching uplink with source external network
                    for edgeGatewayLink in edgeGatewayLinks:
                        if edgeGatewayLink['uplinkName'] == uplinkName:
                            for edgeGatewayLinkSubnet in edgeGatewayLink['subnets']['values']:
                                # Getting value of primary ip
                                primaryIp = edgeGatewayLinkSubnet.get('primaryIp')
                                # Creating ip range for primary ip
                                subIpRange = [{'startAddress': primaryIp, 'endAddress': primaryIp}]
                                # adding primary ip to sub alloacated ip pool
                                if primaryIp and ipaddress.ip_address(primaryIp) in sourceExtNetNetworkAddress:
                                    edgeGatewayLinkSubnet['ipRanges']['values'].extend(subIpRange)
                                # getting the source edge gateway's static subnet ip pool
                                if ipaddress.ip_network('{}/{}'.format(edgeGatewayLinkSubnet['gateway'],
                                                                       edgeGatewayLinkSubnet['prefixLength']),
                                                        strict=False) == sourceExtNetNetworkAddress:
                                    sourceEdgeGatewaySubIpPools += edgeGatewayLinkSubnet['ipRanges']['values']

                    sourceEdgeGatewaySubIpRangeList = []
                    for ipRange in sourceEdgeGatewaySubIpPools:
                        # breaking the iprange into list of ips covering all the ip address lying in the range
                        sourceEdgeGatewaySubIpRangeList.extend(
                            self.createIpRange('{}/{}'.format(sourceExtNetGateway, sourceExtNetPrefix),
                                               ipRange['startAddress'], ipRange['endAddress']))

                    # removing the source edge gateway's static ips from target external ip list
                    for subIp in sourceEdgeGatewaySubIpRangeList:
                        if subIp in targetExternalRangeList:
                            targetExternalRangeList.remove(subIp)

                    # creating the range of each single ip in target external network's ips
                    targetExternalNetworkStaticIpPoolList = self.createExternalNetworkSubPoolRangePayload(
                        targetExternalRangeList)

                    # assigning the targetExternalNetworkStaticIpPoolList to the ipRanges of target external network to reset it to its initial state
                    payloadDict['subnets']['values'][indexToUpdate]['ipRanges'][
                        'values'] = targetExternalNetworkStaticIpPoolList

            payloadData = json.dumps(payloadDict)
            # url to update the target external networks
            url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                   vcdConstants.ALL_EXTERNAL_NETWORKS,
                                   targetExternalNetworkData['id'])

            # setting the content type to json
            self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE

            # put api call to update the target external networks
            apiResponse = self.restClientObj.put(url, self.headers, data=payloadData)
            if apiResponse.status_code == requests.codes.accepted:
                taskUrl = apiResponse.headers['Location']
                self._checkTaskStatus(taskUrl=taskUrl)
                logger.debug("Successfully reset the target external network '{}' to its initial state".format(
                    targetExternalNetworkData['name']))
            else:
                errorDict = apiResponse.json()
                raise Exception("Failed to reset the target external network '{}' to its initial state: {}".format(
                    targetExternalNetworkData['name'],
                    errorDict['message']))
        except Exception:
            raise
        finally:
            try:
                # Releasing the lock
                self.lock.release()
                logger.debug("Lock released by thread - '{}'".format(threading.currentThread().getName()))
            except RuntimeError:
                pass

    @isSessionExpired
    def getCatalogDetails(self, catalogHref):
        """
        Description :   Returns the details of the catalog
        Parameters: catalogHref - href of catalog for which details required (STRING)
        """
        try:
            headers = {'Authorization': self.headers['Authorization'],
                       'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE}
            catalogResponse = self.restClientObj.get(catalogHref, headers)
            if catalogResponse.status_code == requests.codes.ok:
                catalogResponseDict = catalogResponse.json()
                return catalogResponseDict
            else:
                errorDict = catalogResponse.json()
                raise Exception("Failed to retrieve the catalog details: {}".format(errorDict['message']))
        except Exception:
            raise

    @isSessionExpired
    def createCatalog(self, catalog, orgId):
        """
        Description :   Creates an empty placeholder catalog
        Parameters: catalog - payload dict for creating catalog (DICT)
                    orgId - Organization Id where catalog is to be created (STRING)
        """
        try:
            # create catalog url
            catalogUrl = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                       vcdConstants.CREATE_CATALOG.format(orgId))
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
            # creating the payload data
            payloadData = self.vcdUtils.createPayload(filePath,
                                                      catalog,
                                                      fileType='yaml',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.CREATE_CATALOG_TEMPLATE)
            payloadData = json.loads(payloadData)
            # setting the content-type to create a catalog
            headers = {'Authorization': self.headers['Authorization'],
                       'Accept': vcdConstants.VCD_API_HEADER,
                       'Content-Type': vcdConstants.XML_CREATE_CATALOG}
            # post api call to create target catalogs
            createCatalogResponse = self.restClientObj.post(catalogUrl, headers, data=payloadData)
            if createCatalogResponse.status_code == requests.codes.created:
                logger.debug("Catalog '{}' created successfully".format(catalog['catalogName']))
                createCatalogResponseDict = xmltodict.parse(createCatalogResponse.content)
                # getting the newly created target catalog id
                catalogId = createCatalogResponseDict["AdminCatalog"]["@id"].split(':')[-1]
                return catalogId
            else:
                errorDict = xmltodict.parse(createCatalogResponse.content)
                raise Exception("Failed to create Catalog '{}' : {}".format(catalog['catalogName'],
                                                                            errorDict['Error']['@message']))

        except Exception:
            raise

    @isSessionExpired
    def moveCatalogItem(self, catalogItem, catalogId):
        """
        Description :   Moves the catalog Item
        Parameters : catalogItem - catalog item payload (DICT)
                     catalogId - catalog Id where this catalogitem to be moved (STRING)
        """
        try:
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
            # move catalog item url
            moveCatalogItemUrl = "{}{}".format(vcdConstants.XML_API_URL.format(self.ipAddress),
                                               vcdConstants.MOVE_CATALOG.format(catalogId))
            # creating the payload data to move the catalog item
            payloadData = self.vcdUtils.createPayload(filePath,
                                                      catalogItem,
                                                      fileType='yaml',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.MOVE_CATALOG_TEMPLATE)
            payloadData = json.loads(payloadData)
            # post api call to move catalog items
            response = self.restClientObj.post(moveCatalogItemUrl, self.headers, data=payloadData)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.accepted:
                task = responseDict["Task"]
                taskUrl = task["@href"]
                if taskUrl:
                    # checking the status of moving catalog item task
                    self._checkTaskStatus(taskUrl=taskUrl)
                logger.debug("Catalog Item '{}' moved successfully".format(catalogItem['catalogItemName']))
            else:
                raise Exception('Failed to move catalog item - {}'.format(responseDict['Error']['@message']))

        except Exception:
            raise

    @description("creation of target Org VDC")
    @remediate
    def createOrgVDC(self, vdcDict):
        """
        Description :   Creates an Organization VDC
        """
        try:
            logger.info('Preparing Target VDC.')
            logger.info('Creating target Org VDC')
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.yml')
            data = self.rollback.apiData
            targetOrgVDCId = ''
            # organization id
            orgCompleteId = data['Organization']['@id']
            orgId = orgCompleteId.split(':')[-1]
            # retrieving organization url
            orgUrl = data['Organization']['@href']
            # retrieving source org vdc and target provider vdc data
            sourceOrgVDCPayloadDict = data["sourceOrgVDC"]
            targetPVDCPayloadDict = data['targetProviderVDC']
            targetPVDCPayloadList = [
                targetPVDCPayloadDict['StorageProfiles']['ProviderVdcStorageProfile']] if isinstance(
                targetPVDCPayloadDict['StorageProfiles']['ProviderVdcStorageProfile'], dict) else \
                targetPVDCPayloadDict['StorageProfiles']['ProviderVdcStorageProfile']
            sourceOrgVDCPayloadList = [
                sourceOrgVDCPayloadDict['VdcStorageProfiles']['VdcStorageProfile']] if isinstance(
                sourceOrgVDCPayloadDict['VdcStorageProfiles']['VdcStorageProfile'], dict) else \
                sourceOrgVDCPayloadDict['VdcStorageProfiles']['VdcStorageProfile']

            vdcStorageProfilePayloadData = ''
            # iterating over the source org vdc storage profiles
            for eachStorageProfile in sourceOrgVDCPayloadList:
                orgVDCStorageProfileDetails = self.getOrgVDCStorageProfileDetails(eachStorageProfile['@id'])
                vdcStorageProfileDict = {'vspEnabled': "true" if orgVDCStorageProfileDetails['AdminVdcStorageProfile'][
                                                                     'Enabled'] == "true" else "false",
                                         'vspUnits': 'MB',
                                         'vspLimit': str(
                                             orgVDCStorageProfileDetails['AdminVdcStorageProfile']['Limit']),
                                         'vspDefault': "true" if orgVDCStorageProfileDetails['AdminVdcStorageProfile'][
                                                                     'Default'] == "true" else "false"}
                for eachSP in targetPVDCPayloadList:
                    if eachStorageProfile['@name'] == eachSP['@name']:
                        vdcStorageProfileDict['vspHref'] = eachSP['@href']
                        vdcStorageProfileDict['vspName'] = eachSP['@name']
                        break
                eachStorageProfilePayloadData = self.vcdUtils.createPayload(filePath,
                                                                            vdcStorageProfileDict,
                                                                            fileType='yaml',
                                                                            componentName=vcdConstants.COMPONENT_NAME,
                                                                            templateName=vcdConstants.STORAGE_PROFILE_TEMPLATE_NAME)
                vdcStorageProfilePayloadData += eachStorageProfilePayloadData.strip("\"")

            # Shared network and DFW need target org VDC to be part of DC group. If org VDC is created without network
            # pool, it cannot be part of DC group. Hence if shared network or DFW is present, assign default or user
            # provided network pool of target PVDC to target Org VDC.
            if (data['sourceOrgVDC'].get('NetworkPoolReference')
                    or self.isSharedNetworkPresent()
                    or self.getDistributedFirewallConfig()):
                networkPoolReferences = targetPVDCPayloadDict['NetworkPoolReferences']

                # if multiple network pools exist, take the network pool references passed in user spec
                if isinstance(networkPoolReferences['NetworkPoolReference'], list):
                    tpvdcNetworkPool = [
                        pool
                        for pool in networkPoolReferences['NetworkPoolReference']
                        if pool['@name'] == vdcDict.get('NSXTNetworkPoolName')
                    ]
                    if tpvdcNetworkPool:
                        networkPoolHref = tpvdcNetworkPool[0]['@href']
                        networkPoolId = tpvdcNetworkPool[0]['@id']
                        networkPoolName = tpvdcNetworkPool[0]['@name']
                        networkPoolType = tpvdcNetworkPool[0]['@type']
                    else:
                        raise Exception(
                            f"Network Pool {vdcDict.get('NSXTNetworkPoolName')} doesn't exist in Target PVDC")

                # if PVDC has a single network pool, take it
                else:
                    networkPoolHref = targetPVDCPayloadDict['NetworkPoolReferences']['NetworkPoolReference']['@href']
                    networkPoolId = targetPVDCPayloadDict['NetworkPoolReferences']['NetworkPoolReference']['@id']
                    networkPoolName = targetPVDCPayloadDict['NetworkPoolReferences']['NetworkPoolReference']['@name']
                    networkPoolType = targetPVDCPayloadDict['NetworkPoolReferences']['NetworkPoolReference']['@type']

            else:
                logger.debug(
                    'Network pool not present and Org VDC is not using shared network or distributed firewall')
                networkPoolHref = None
                networkPoolId = None
                networkPoolName = None
                networkPoolType = None

            # creating the payload dict
            orgVdcPayloadDict = {'orgVDCName': data["sourceOrgVDC"]["@name"] + '-v2t',
                                 'vdcDescription': data['sourceOrgVDC']['Description'] if data['sourceOrgVDC'].get(
                                     'Description') else '',
                                 'allocationModel': data['sourceOrgVDC']['AllocationModel'],
                                 'cpuUnits': data['sourceOrgVDC']['ComputeCapacity']['Cpu']['Units'],
                                 'cpuAllocated': data['sourceOrgVDC']['ComputeCapacity']['Cpu']['Allocated'],
                                 'cpuLimit': data['sourceOrgVDC']['ComputeCapacity']['Cpu']['Limit'],
                                 'cpuReserved': data['sourceOrgVDC']['ComputeCapacity']['Cpu']['Reserved'],
                                 'cpuUsed': data['sourceOrgVDC']['ComputeCapacity']['Cpu']['Used'],
                                 'memoryUnits': data['sourceOrgVDC']['ComputeCapacity']['Memory']['Units'],
                                 'memoryAllocated': data['sourceOrgVDC']['ComputeCapacity']['Memory']['Allocated'],
                                 'memoryLimit': data['sourceOrgVDC']['ComputeCapacity']['Memory']['Limit'],
                                 'memoryReserved': data['sourceOrgVDC']['ComputeCapacity']['Memory']['Reserved'],
                                 'memoryUsed': data['sourceOrgVDC']['ComputeCapacity']['Memory']['Used'],
                                 'nicQuota': data['sourceOrgVDC']['NicQuota'],
                                 'networkQuota': data['sourceOrgVDC']['NetworkQuota'],
                                 'vmQuota': data['sourceOrgVDC']['VmQuota'],
                                 'isEnabled': "true",
                                 'vdcStorageProfile': vdcStorageProfilePayloadData,
                                 'resourceGuaranteedMemory': data['sourceOrgVDC']['ResourceGuaranteedMemory'],
                                 'resourceGuaranteedCpu': data['sourceOrgVDC']['ResourceGuaranteedCpu'],
                                 'vCpuInMhz': data['sourceOrgVDC']['VCpuInMhz'],
                                 'isThinProvision': data['sourceOrgVDC']['IsThinProvision'],
                                 'networkPoolHref': networkPoolHref,
                                 'networkPoolId': networkPoolId,
                                 'networkPoolName': networkPoolName,
                                 'networkPoolType': networkPoolType,
                                 'providerVdcHref': targetPVDCPayloadDict['@href'],
                                 'providerVdcId': targetPVDCPayloadDict['@id'],
                                 'providerVdcName': targetPVDCPayloadDict['@name'],
                                 'providerVdcType': targetPVDCPayloadDict['@type'],
                                 'usesFastProvisioning': data['sourceOrgVDC']['UsesFastProvisioning'],
                                 'defaultComputePolicy': '',
                                 'isElastic': data['sourceOrgVDC']['IsElastic'],
                                 'includeMemoryOverhead': data['sourceOrgVDC']['IncludeMemoryOverhead']}

            # retrieving org vdc compute policies
            allOrgVDCComputePolicesList = self.getOrgVDCComputePolicies()
            isSizingPolicy = False
            # getting the vm sizing policy of source org vdc
            sourceSizingPoliciesList = self.getVmSizingPoliciesOfOrgVDC(data['sourceOrgVDC']['@id'])
            if isinstance(sourceSizingPoliciesList, dict):
                sourceSizingPoliciesList = [sourceSizingPoliciesList]
            # iterating over the source org vdc vm sizing policies and check the default compute policy is sizing policy
            for eachPolicy in sourceSizingPoliciesList:
                if eachPolicy['id'] == data['sourceOrgVDC']['DefaultComputePolicy']['@id'] and eachPolicy[
                    'name'] != 'System Default':
                    # set sizing policy to true if default compute policy is sizing
                    isSizingPolicy = True
            if data['sourceOrgVDC']['DefaultComputePolicy']['@name'] != 'System Default' and not isSizingPolicy:
                # Getting the href of the compute policy if not 'System Default' as default compute policy
                orgVDCComputePolicesList = [allOrgVDCComputePolicesList] if isinstance(allOrgVDCComputePolicesList,
                                                                                       dict) else allOrgVDCComputePolicesList
                # iterating over the org vdc compute policies
                for eachComputPolicy in orgVDCComputePolicesList:
                    if eachComputPolicy["name"] == data['sourceOrgVDC']['DefaultComputePolicy']['@name'] and \
                            eachComputPolicy["pvdcId"] == data['targetProviderVDC']['@id']:
                        href = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                vcdConstants.VDC_COMPUTE_POLICIES,
                                                eachComputPolicy["id"])
                        computePolicyDict = {'defaultComputePolicyHref': href,
                                             'defaultComputePolicyId': eachComputPolicy["id"],
                                             'defaultComputePolicyName': data['sourceOrgVDC']['DefaultComputePolicy'][
                                                 '@name']}
                        computePolicyPayloadData = self.vcdUtils.createPayload(filePath,
                                                                               computePolicyDict,
                                                                               fileType='yaml',
                                                                               componentName=vcdConstants.COMPONENT_NAME,
                                                                               templateName=vcdConstants.COMPUTE_POLICY_TEMPLATE_NAME)
                        orgVdcPayloadDict['defaultComputePolicy'] = computePolicyPayloadData.strip("\"")
                        break
                else:  # for else (loop else)
                    raise Exception(
                        "No Target Compute Policy found with same name as Source Org VDC default Compute Policy and belonging to the target Provider VDC.")
            # if sizing policy is set, default compute policy is vm sizing polciy
            if isSizingPolicy:
                computePolicyDict = {'defaultComputePolicyHref': data['sourceOrgVDC']['DefaultComputePolicy']['@href'],
                                     'defaultComputePolicyId': data['sourceOrgVDC']['DefaultComputePolicy']['@id'],
                                     'defaultComputePolicyName': data['sourceOrgVDC']['DefaultComputePolicy']['@name']}
                computePolicyPayloadData = self.vcdUtils.createPayload(filePath,
                                                                       computePolicyDict,
                                                                       fileType='yaml',
                                                                       componentName=vcdConstants.COMPONENT_NAME,
                                                                       templateName=vcdConstants.COMPUTE_POLICY_TEMPLATE_NAME)
                orgVdcPayloadDict['defaultComputePolicy'] = computePolicyPayloadData.strip("\"")
            orgVdcPayloadData = self.vcdUtils.createPayload(filePath,
                                                            orgVdcPayloadDict,
                                                            fileType='yaml',
                                                            componentName=vcdConstants.COMPONENT_NAME,
                                                            templateName=vcdConstants.CREATE_ORG_VDC_TEMPLATE_NAME)

            payloadData = json.loads(orgVdcPayloadData)

            # url to create org vdc
            url = "{}{}".format(vcdConstants.XML_ADMIN_API_URL.format(self.ipAddress),
                                vcdConstants.CREATE_ORG_VDC.format(orgId))
            self.headers["Content-Type"] = vcdConstants.XML_CREATE_VDC_CONTENT_TYPE
            # post api to create org vdc

            response = self.restClientObj.post(url, self.headers, data=payloadData)
            responseDict = xmltodict.parse(response.content)
            if response.status_code == requests.codes.created:
                taskId = responseDict["AdminVdc"]["Tasks"]["Task"]
                if isinstance(taskId, dict):
                    taskId = [taskId]
                for task in taskId:
                    if task["@operationName"] == vcdConstants.CREATE_VDC_TASK_NAME:
                        taskUrl = task["@href"]
                        # Fetching target org vdc id for deleting target vdc in case of failure
                        targetOrgVDCId = re.search(r'\((.*)\)', task['@operation']).group(1)
                if taskUrl:
                    # checking the status of the task of creating the org vdc
                    self._checkTaskStatus(taskUrl=taskUrl)
                logger.info('Target Org VDC {} created successfully'.format(data["sourceOrgVDC"]["@name"] + '-v2t'))
                # returning the id of the created org vdc
                return self.getOrgVDCDetails(orgUrl, responseDict['AdminVdc']['@name'], 'targetOrgVDC')
            raise Exception('Failed to create target Org VDC. Errors {}.'.format(responseDict['Error']['@message']))
        except Exception as exception:
            if targetOrgVDCId:
                logger.debug("Creation of target vdc failed, so removing that entity from vCD")
                try:
                    self.deleteOrgVDC(targetOrgVDCId)
                except Exception as e:
                    errorMessage = f'No access to entity "com.vmware.vcloud.entity.vdc:{targetOrgVDCId}'
                    if errorMessage in str(e):
                        pass
                    else:
                        raise Exception('Failed to delete target org vdc during rollback')
            raise exception

    @description(desc="enabling the promiscuous mode and forged transmit on source Org VDC networks")
    @remediate
    def enablePromiscModeForgedTransmit(self, orgVDCNetworkList):
        """
        Description : Enabling Promiscuous Mode and Forged transmit of source org vdc network
        Parameters  : orgVDCNetworkList - List containing source org vdc networks (LIST)
        """
        try:
            logger.info('Enabling the promiscuous mode and forged transmit on source Org VDC networks.')
            # if call to disable to promiscuous mode then orgVDCNetworkList will be retrieved from apiOutput.json
            # iterating over the orgVDCNetworkList
            for orgVdcNetwork in orgVDCNetworkList:
                # url to get the dvportgroup details of org vdc network
                url = "{}{}/{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                          vcdConstants.ALL_ORG_VDC_NETWORKS,
                                          orgVdcNetwork['id'],
                                          vcdConstants.ORG_VDC_NETWORK_PORTGROUP_PROPERTIES_URI)
                # get api call to retrieve the dvportgroup details of org vdc network
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    # if enable call then setting the mode True
                    for portGroupData in responseDict['dvpgProperties']:
                        portGroupData['promiscuousMode'] = True
                        portGroupData['forgedTransmit'] = True

                    payloadData = json.dumps(responseDict)
                    # updating the org vdc network dvportgroup properties
                    self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                    # put api call to update the promiscuous mode and forged mode
                    apiResponse = self.restClientObj.put(url, self.headers, data=payloadData)
                    if apiResponse.status_code == requests.codes.accepted:
                        taskUrl = apiResponse.headers['Location']
                        # checking the status of the updating dvpgportgroup properties of org vdc network task
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug('Successfully enabled source Org VDC Network {} dvportgroup properties.'.format(
                            orgVdcNetwork['name']))
                    else:
                        errorResponse = apiResponse.json()
                        raise Exception(
                            'Failed to enable dvportgroup properties of source Org VDC network {} - {}'.format(
                                orgVdcNetwork['name'], errorResponse['message']))
                else:
                    raise Exception('Failed to get dvportgroup properties of source Org VDC network {}'.format(
                        orgVdcNetwork['name']))
        except Exception:
            raise

    @isSessionExpired
    def disablePromiscModeForgedTransmit(self):
        """
        Description : Disabling Promiscuous Mode and Forged transmit of source org vdc network
        """
        try:
            if not self.rollback.metadata.get("prepareTargetVDC", {}).get("enablePromiscModeForgedTransmit"):
                return
            logger.info("RollBack: Restoring the Promiscuous Mode and Forged Mode")
            data = self.rollback.apiData
            orgVDCNetworkList = data["orgVDCNetworkPromiscModeList"]
            # iterating over the orgVDCNetworkList
            for orgVdcNetwork in orgVDCNetworkList:
                # url to get the dvportgroup details of org vdc network
                url = "{}{}/{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                          vcdConstants.ALL_ORG_VDC_NETWORKS,
                                          orgVdcNetwork['id'],
                                          vcdConstants.ORG_VDC_NETWORK_PORTGROUP_PROPERTIES_URI)
                # get api call to retrieve the dvportgroup details of org vdc network
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()

                    # Iterating over all the portgroups to reset the promiscous and forged-transmit value
                    for index, portGroupData in enumerate(orgVdcNetwork['promiscForge']['dvpgProperties']):
                        # disable call then setting the mode to its initial state by retrieving from metadata
                        responseDict['dvpgProperties'][index]['promiscuousMode'] = portGroupData['promiscuousMode']
                        responseDict['dvpgProperties'][index]['forgedTransmit'] = portGroupData['forgedTransmit']

                    payloadData = json.dumps(responseDict)

                    # updating the org vdc network dvportgroup properties
                    self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                    # put api call to update the promiscuous mode and forged mode
                    apiResponse = self.restClientObj.put(url, self.headers, data=payloadData)
                    if apiResponse.status_code == requests.codes.accepted:
                        taskUrl = apiResponse.headers['Location']
                        # checking the status of the updating dvpgportgroup properties of org vdc network task
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug('Successfully disabled source Org VDC Network {} dvportgroup properties.'.format(
                            orgVdcNetwork['name']))
                    else:
                        errorResponse = apiResponse.json()
                        raise Exception(
                            'Failed to disabled dvportgroup properties of source Org VDC network {} - {}'.format(
                                orgVdcNetwork['name'], errorResponse['message']))
                else:
                    raise Exception('Failed to get dvportgroup properties of source Org VDC network {}'.format(
                        orgVdcNetwork['name']))
        except Exception:
            raise

    @isSessionExpired
    def renameVappNetworks(self, vAppNetworkHref):
        """
        Description :   Renames the vApp isolated network back to its original name
                        (i.e removes the trailing -v2t string of the vapp network name)
        Parameters  :   vAppNetworkHref -   href of the vapp network (STRING)
        """
        try:
            # setting the headers required for the api
            headers = {'Authorization': self.headers['Authorization'],
                       'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE}
            # get api call to retrieve the vapp isolated networks' details
            vAppNetworkResponse = self.restClientObj.get(vAppNetworkHref, headers)
            vAppNetworkResponseDict = vAppNetworkResponse.json()
            # changing the name of the vapp isolated network
            vAppNetworkResponseDict['name'] = vAppNetworkResponseDict['name'][
                                              0: len(vAppNetworkResponseDict['name']) - 4]
            # creating the payload data
            payloadData = json.dumps(vAppNetworkResponseDict)
            # setting the content-type required for the api
            headers['Content-Type'] = vcdConstants.VAPP_NETWORK_CONTENT_TYPE
            # put api call to update rename the target vapp isolated network
            putResponse = self.restClientObj.put(vAppNetworkHref, headers=headers, data=payloadData)
            if putResponse.status_code == requests.codes.ok:
                logger.debug(
                    "Target vApp Isolated Network successfully renamed to '{}'".format(vAppNetworkResponseDict['name']))
            else:
                putResponseDict = putResponse.json()
                raise Exception("Failed to rename the target vApp Isolated Network '{}' : {}".format(
                    vAppNetworkResponseDict['name'] + '-v2t',
                    putResponseDict['message']))
            # sleep for 5 seconds before deleting next network
            time.sleep(5)
        except Exception:
            raise

    @isSessionExpired
    def renameTargetVappIsolatedNetworks(self, vAppList):
        """
        Description :   Renames all the vApp isolated networks for each vApp in the specified vApps list
        Parameters  :   vAppList    -   list of details of target vApps (LIST)
        """
        try:
            # iterating over the target vapps
            for vApp in vAppList:
                # get api call to retrieve the details of target vapp
                vAppResponse = self.restClientObj.get(vApp['href'], self.headers)
                vAppResponseDict = xmltodict.parse(vAppResponse.content)
                vAppData = vAppResponseDict['VApp']
                # checking for the networks in the vapp
                if vAppData['NetworkConfigSection'].get('NetworkConfig'):
                    vAppNetworkList = vAppData['NetworkConfigSection']['NetworkConfig'] if isinstance(vAppData['NetworkConfigSection']['NetworkConfig'], list) else [vAppData['NetworkConfigSection']['NetworkConfig']]
                    if vAppNetworkList:
                        # iterating over the networks in vapp
                        for vAppNetwork in vAppNetworkList:
                            # handling only vapp isolated networks whose name ends with -v2t
                            if vAppNetwork['@networkName'].endswith('-v2t'):
                                vAppLinksList = vAppData['Link'] if isinstance(vAppData['Link'], list) else [vAppData['Link']]
                                # iterating over the vAppLinksList to get the vapp isolated networks' href
                                for link in vAppLinksList:
                                    if link.get('@name'):
                                        if link['@name'] == vAppNetwork['@networkName'] and 'admin' not in link['@href']:
                                            vAppNetworkHref = link['@href']
                                            break
                                else:
                                    logger.debug("Failed to rename the target isolated network '{}', since failed to get href".format(vAppNetwork['@networkName']))
                                    continue
                                self.renameVappNetworks(vAppNetworkHref)
        except Exception:
            raise

    @isSessionExpired
    def renameTargetOrgVDCNetworks(self, network):
        """
        Description :   Renames the target org VDC networks back to its original name
                        (i.e removes the trailing -v2t from the target org VDC network name)
        Parameters  :   network -   details of the network that is to be renamed (DICT)
        """
        try:
            headers = {'Authorization': self.headers['Authorization'],
                       'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE}
            # open api get url to retrieve the details of target org vdc network
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.GET_ORG_VDC_NETWORK_BY_ID.format(network['id']))
            # get api call to retrieve the details of target org vdc network
            networkResponse = self.restClientObj.get(url, headers=self.headers)
            networkResponseDict = networkResponse.json()

            # checking if the target org vdc network name endwith '-v2t', if so removing the '-v2t' from the name
            if networkResponseDict['name'].endswith('-v2t'):
                # getting the original name of the
                networkResponseDict['name'] = networkResponseDict['name'][0: len(networkResponseDict['name']) - 4]
                # creating the payload data of the retrieved details of the org vdc network
                payloadData = json.dumps(networkResponseDict)
                # setting the content-type as per the api requirement
                headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                # put api call to rename the target org vdc network
                putResponse = self.restClientObj.put(url, headers=headers, data=payloadData)
                if putResponse.status_code == requests.codes.accepted:
                    taskUrl = putResponse.headers['Location']
                    self._checkTaskStatus(taskUrl=taskUrl)
                    logger.debug("Target Org VDC Network '{}' renamed successfully".format(networkResponseDict['name']))
                else:
                    errorDict = putResponse.json()
                    raise Exception("Failed to rename the target org VDC to '{}' : {}".format(networkResponseDict['name'],
                                                                                              errorDict['message']))

        except Exception:
            raise

    @isSessionExpired
    def createDCgroup(self, dcGroupName, sharedGroup=False, orgVdcIdList=None):
        """
        Description: Create datacenter group
        Parameter: dcGroupName - Name of datacenter group to be created (STRING)
                   sharedGroup - Flag that decides to share org vdc group with multiple org vdc (BOOLEAN)
                   orgVDCIDList-   List of all the org vdc's undergoing parallel migration (LIST)
        """
        # open api to create Org vDC group
        url = '{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.VDC_GROUPS)
        targetOrgVDCId = self.rollback.apiData['targetOrgVDC']['@id']
        organizationId = self.rollback.apiData['Organization']['@id']

        if sharedGroup:
            payloadDict = {'orgId': organizationId,
                           'name': dcGroupName,
                           'participatingOrgVdcs': [{
                               'vdcRef': {'id': orgVDCId}, 'orgRef': {'id': organizationId},
                           } for orgVDCId in orgVdcIdList],
                           'type': 'LOCAL',
                           'networkProviderType': 'NSX_T'
                           }
        else:
            payloadDict = {'orgId': organizationId,
                           'name': dcGroupName,
                           'participatingOrgVdcs': [{
                               'vdcRef': {'id': targetOrgVDCId}, 'orgRef': {'id': organizationId}}],
                           'type': 'LOCAL',
                           'networkProviderType': 'NSX_T'
                           }
        payloadData = json.dumps(payloadDict)
        # setting the content-type as per the api requirement
        self.headers['Content-Type'] = 'application/json'
        response = self.restClientObj.post(url, self.headers, data=payloadData)
        if response.status_code == requests.codes.accepted:
            taskUrl = response.headers['Location']
            header = {'Authorization': self.headers['Authorization'],
                      'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE}
            taskResponse = self.restClientObj.get(url=taskUrl, headers=header)
            responseDict = taskResponse.json()
            self._checkTaskStatus(taskUrl=taskUrl)
            logger.debug(
                "Target Org VDC Group '{}' created successfully".format(dcGroupName))
            return responseDict['owner']['id']
        else:
            errorDict = response.json()
            raise Exception("Failed to create target org VDC Group '{}' ".format(errorDict['message']))

    @description('Creating Org vDC groups for Imported Networks in Target Org VDC')
    @remediate
    def createOrgvDCGroupForImportedNetworks(self, sourceOrgVDCName, vcdObjList):
        """
        Description: Creating Shared Org vDC group with multiple Org vDC for imported networks
        Parameter:   sourceOrgVDCName -  Name of the source orgVDC (STRING)
                     vcdObjList       -   List of vcd operations class objects (LIST)
        """
        try:
            logger.debug("Org VDC group is getting created for direct/imported networks")
            # Taking lock as one org vdc will be creating groups first
            self.lock.acquire(blocking=True)
            # Source org vdc id list
            sourceOrgVDCId = self.rollback.apiData['sourceOrgVDC']['@id']
            # Fetching target org vdc id list
            orgVDCIDList = [vcdObj.rollback.apiData['targetOrgVDC']['@id'] for vcdObj in vcdObjList]
            # Fetch data center group id from metadata
            ownerIds = self.rollback.apiData.get('OrgVDCGroupID', {})
            orgVdcNetworks = self.getOrgVDCNetworks(sourceOrgVDCId, 'sourceOrgVDCNetworks', saveResponse=False)
            # Fetch target org vdc id list
            targetOrgVDCNetworks = self.retrieveNetworkListFromMetadata(self.rollback.apiData['targetOrgVDC']['@id'],
                                                                        dfwStatus=False, orgVDCType='target')
            # Fetching all target org vdc networks from all the org vdc's
            allTargetOrgVDCNetworks = list()
            for vcdObj in vcdObjList:
                allTargetOrgVDCNetworks += vcdObj.retrieveNetworkListFromMetadata(
                    self.rollback.apiData['targetOrgVDC']['@id'], dfwStatus=False, orgVDCType='target')

            # Handling corner case for shared isolated networks with no conflicts
            if [network for network in orgVdcNetworks if network['shared']]:
                orgId = self.rollback.apiData['Organization']['@id']
                targetOrgVDCNameList = [vcdObj.vdcName + "-v2t" for vcdObj in vcdObjList]

                for targetNetwork in targetOrgVDCNetworks:
                    # Finding all vdc groups linked to the org vdc's to be parallely migrated
                    vdcGroups = [dcGroup for dcGroup in self.getOrgVDCGroup() if
                                 dcGroup['orgId'] == orgId and [vdc for vdc in dcGroup['participatingOrgVdcs'] if
                                                                vdc['vdcRef']['name'] in targetOrgVDCNameList]]

                    # Finding shared dc group
                    sharedDCGroup = [dcGroup for dcGroup in vdcGroups if
                                     len(dcGroup['participatingOrgVdcs']) == len(vcdObjList)]

                    for network in orgVdcNetworks:
                        if targetNetwork['name'] == network['name'] + '-v2t':
                            # Handle datacenter group scenario for imported shared network use case
                            if network["networkType"] == "DIRECT" and network["shared"] and \
                                    targetNetwork["networkType"] == "OPAQUE" and \
                                    network[
                                        "backingNetworkType"] == vcdConstants.DIRECT_NETWORK_CONNECTED_TO_PG_BACKED_EXT_NET and \
                                    targetNetwork['id'] not in self.rollback.apiData.get('OrgVDCGroupID', {}):

                                # Searching for shared dc group having no conflicts with the imported network
                                edgeGatewayNetworkMapping = dict()
                                isolatedNetworksList = []
                                for ntw in allTargetOrgVDCNetworks:
                                    if ntw["networkType"] == "NAT_ROUTED":
                                        if ntw["connection"]["routerRef"]["id"] in self.rollback.apiData.get(
                                                'OrgVDCGroupID', {}) and self.rollback.apiData['OrgVDCGroupID'][
                                            ntw["connection"]["routerRef"]["id"]] in [group['id'] for group in
                                                                                      sharedDCGroup]:
                                            if ntw["connection"]["routerRef"]["id"] not in edgeGatewayNetworkMapping:
                                                edgeGatewayNetworkMapping[ntw["connection"]["routerRef"]["id"]] = [
                                                    ntw]
                                            else:
                                                edgeGatewayNetworkMapping[ntw["connection"]["routerRef"]["id"]].append(
                                                    ntw)
                                    if ntw["networkType"] == "ISOLATED":
                                        if ntw["id"] in self.rollback.apiData.get(
                                                'OrgVDCGroupID', {}) and self.rollback.apiData['OrgVDCGroupID'][
                                           ntw["id"]] in [group['id'] for group in sharedDCGroup]:
                                            isolatedNetworksList.append(ntw)

                                dcGroupName = sourceOrgVDCName + '-Group-' + network['name']

                                dcGroupId = None
                                # Finding if the routed networks conflict with the imported network
                                for gatewayId, networkList in edgeGatewayNetworkMapping.items():
                                    for ntw in networkList:
                                        for subnet in ntw['subnets']['values']:
                                            networkAddress = ipaddress.ip_network(f"{subnet['gateway']}/"
                                                                                  f"{subnet['prefixLength']}",
                                                                                  strict=False)
                                            networkToCheckAddress = ipaddress.ip_network(
                                                f"{targetNetwork['subnets']['values'][0]['gateway']}/"
                                                f"{targetNetwork['subnets']['values'][0]['prefixLength']}",
                                                strict=False)
                                            if networkAddress.overlaps(networkToCheckAddress):
                                                break
                                        else:
                                            continue
                                        break
                                    else:
                                        dcGroupId = self.rollback.apiData['OrgVDCGroupID'][gatewayId]
                                        break

                                # Finding if isolated shared networks conflicts with the imported network
                                if not dcGroupId:
                                    for ntw in isolatedNetworksList:
                                        for subnet in ntw['subnets']['values']:
                                            networkAddress = ipaddress.ip_network(f"{subnet['gateway']}/"
                                                                                  f"{subnet['prefixLength']}",
                                                                                  strict=False)
                                            networkToCheckAddress = ipaddress.ip_network(
                                                f"{targetNetwork['subnets']['values'][0]['gateway']}/"
                                                f"{targetNetwork['subnets']['values'][0]['prefixLength']}",
                                                strict=False)
                                            if networkAddress.overlaps(networkToCheckAddress):
                                                break
                                        else:
                                            dcGroupId = self.rollback.apiData['OrgVDCGroupID'][ntw['id']]

                                # If shared dc group id without any conflicts is present use that
                                # Else create a new shared dc group for this network
                                if not dcGroupId:
                                    dcGroupId = self.createDCgroup(dcGroupName, sharedGroup=True,
                                                                   orgVdcIdList=orgVDCIDList)
                                ownerIds.update({targetNetwork['id']: dcGroupId})
                                self.rollback.apiData['OrgVDCGroupID'] = ownerIds
                            break
        except:
            raise
        finally:
            try:
                # Releasing the lock
                self.lock.release()
                logger.debug("Lock released by thread - '{}'".format(threading.currentThread().getName()))
            except RuntimeError:
                pass

    @description('Creating Org vDC groups in Target Org VDC')
    @remediate
    def createOrgvDCGroup(self, sourceOrgVDCName, vcdObjList):
        """
        Description: Creating Org vDC group with single Org vDC
        Parameter:   sourceOrgVDCName -  Name of the source orgVDC (STRING)
                     vcdObjList       -   List of vcd operations class objects (LIST)
        """
        try:
            # Taking lock as one org vdc will be creating groups first
            self.lock.acquire(blocking=True)
            # Fetching target org vdc id list
            orgVDCIDList = [vcdObj.rollback.apiData['targetOrgVDC']['@id'] for vcdObj in vcdObjList]
            # Source org vdc id list
            sourceOrgVDCId = self.rollback.apiData['sourceOrgVDC']['@id']
            # Fetch all DFW rules from source org vdc id
            allLayer3Rules = self.getDistributedFirewallConfig(sourceOrgVDCId)
            # Name of conflicting isolated networks
            conflictingNetworksName = list()

            targetEdgegateways = self.rollback.apiData['targetEdgeGateway']
            conflictNetworks = self.rollback.apiData.get('ConflictNetworks')
            orgVdcNetworks = self.getOrgVDCNetworks(sourceOrgVDCId, 'sourceOrgVDCNetworks', saveResponse=False)
            # Fetch target org vdc id list
            targetOrgVDCNetworks = self.retrieveNetworkListFromMetadata(self.rollback.apiData['targetOrgVDC']['@id'],
                                                                        dfwStatus=False, orgVDCType='target')
            if not conflictNetworks:
                conflictNetworks = []

            # Fetch data center group id from metadata
            ownerIds = self.rollback.apiData.get('OrgVDCGroupID', {})
            # Check if DFW is configured on source org vdc id
            if allLayer3Rules:
                logger.info('Org VDC group is getting created')
                # Iterate over target edge gateways
                for targetEdgegateway in targetEdgegateways:
                    # Check if dc group for this edge gateway is already created or not
                    if targetEdgegateway['id'] not in self.rollback.apiData.get('OrgVDCGroupID', {}):
                        dcGroupName = sourceOrgVDCName + '-Group-' + targetEdgegateway['name']
                        # Finding list of target networks connected to this edge gateway
                        targetNetworkConnectedToEdge = list(filter(
                            lambda network: network["networkType"] == "NAT_ROUTED" and
                                            network['connection']['routerRef']['id'] == targetEdgegateway['id'],
                            targetOrgVDCNetworks))

                        # Finding list of shared networks from source org vdc linked to these target networks
                        if ([targetNetwork
                             for targetNetwork in targetNetworkConnectedToEdge
                             for sourceNetwork in orgVdcNetworks
                             if sourceNetwork['name'] + '-v2t' == targetNetwork['name'] and sourceNetwork['shared']]):
                            # Creating a shared dc groups
                            dcGroupId = self.createDCgroup(dcGroupName, sharedGroup=True,
                                                           orgVdcIdList=orgVDCIDList)
                            ownerIds.update({targetEdgegateway['id']: dcGroupId})
                            self.rollback.apiData['OrgVDCGroupID'] = ownerIds
                            # As this dc group is shared adding this to all object id's
                            for vcdObj in vcdObjList:
                                dcGroupMapping = vcdObj.rollback.apiData.get('OrgVDCGroupID', {})
                                dcGroupMapping.update({targetEdgegateway['id']: dcGroupId})
                                vcdObj.rollback.apiData['OrgVDCGroupID'] = dcGroupMapping
                        # If no shared network is connected to this edge gateway, create a normal dc group
                        else:
                            dcGroupId = self.createDCgroup(dcGroupName)
                            ownerIds.update({targetEdgegateway['id']: dcGroupId})
                            self.rollback.apiData['OrgVDCGroupID'] = ownerIds
                # Creating dc group for all the conflicting isolated networks
                for network in conflictNetworks:
                    if network['id'] not in self.rollback.apiData.get('OrgVDCGroupID', {}):
                        dcGroupName = sourceOrgVDCName + '-Group-' + network['name']
                        # If network is shared, create a shared dc group
                        if network['shared']:
                            dcGroupId = self.createDCgroup(dcGroupName, sharedGroup=True,
                                                           orgVdcIdList=orgVDCIDList)
                            ownerIds.update({network['id']: dcGroupId})
                            self.rollback.apiData['OrgVDCGroupID'] = ownerIds
                            # As this dc group is shared adding this to all object id's
                            for vcdObj in vcdObjList:
                                dcGroupMapping = vcdObj.rollback.apiData.get('OrgVDCGroupID', {})
                                dcGroupMapping.update({network['id']: dcGroupId})
                                vcdObj.rollback.apiData['OrgVDCGroupID'] = dcGroupMapping
                        else:
                            dcGroupId = self.createDCgroup(dcGroupName)
                            ownerIds.update({network['id']: dcGroupId})
                            self.rollback.apiData['OrgVDCGroupID'] = ownerIds

                # Creating/Checking dc group for non-conflicting non-shared isolated networks
                for targetNetwork in targetOrgVDCNetworks:
                    for network in orgVdcNetworks:
                        if targetNetwork['name'] == network['name'] + '-v2t':
                            if network["networkType"] == "ISOLATED" and \
                                    not network['shared'] and \
                                    targetNetwork['id'] not in self.rollback.apiData.get('OrgVDCGroupID', {}):
                                orgId = self.rollback.apiData['Organization']['@id']
                                # Finding non-shared dc groups for non-shared non-conflicting isolated networks
                                vdcGroups = [dcGroup for dcGroup in self.getOrgVDCGroup() if
                                             dcGroup['orgId'] == orgId and len(dcGroup['participatingOrgVdcs']) == 1 and
                                             dcGroup['participatingOrgVdcs'][0][
                                                 'vdcRef']['name'] == sourceOrgVDCName + '-v2t']
                                # Removing dc groups created for isolated conflicting networks
                                filteredVDCGroups = list(filter(lambda group: not any([
                                    True if networkName in group['name'] else False for networkName in
                                    [ntw['name'] for ntw in conflictNetworks]]),
                                                                vdcGroups))
                                # If non-shared dc-group is present use that else create a new dc group
                                if filteredVDCGroups:
                                    dcGroupId = filteredVDCGroups[0]['id']
                                else:
                                    dcGroupName = sourceOrgVDCName + '-Group-' + network['name']
                                    dcGroupId = self.createDCgroup(dcGroupName)
                                ownerIds.update({targetNetwork['id']: dcGroupId})
                                self.rollback.apiData['OrgVDCGroupID'] = ownerIds

            # Create datacenter groups if DFW is not configured but shared nws are present
            elif [network for network in orgVdcNetworks if network['shared']]:
                logger.info('Org VDC group is getting created for shared networks')

                # Fetching name of all the conflicting networks
                if conflictNetworks:
                    conflictingNetworksName = [network['name'] for network in conflictNetworks]

                # Creating DC Group for routed shared networks
                for targetNetwork in targetOrgVDCNetworks:
                    for network in orgVdcNetworks:
                        if targetNetwork['name'] == network['name'] + '-v2t':
                            if network["networkType"] == "NAT_ROUTED" and \
                                    network['shared'] and \
                                    targetNetwork['connection']['routerRef']['id'] not in \
                                    self.rollback.apiData.get('OrgVDCGroupID', {}):
                                dcGroupName = sourceOrgVDCName + '-Group-' + network['connection']['routerRef']['name']
                                dcGroupId = self.createDCgroup(dcGroupName,
                                                               sharedGroup=True,
                                                               orgVdcIdList=orgVDCIDList)
                                ownerIds.update({
                                    targetNetwork['connection']['routerRef']['id']: dcGroupId
                                })
                                self.rollback.apiData['OrgVDCGroupID'] = ownerIds
                                # As this dc group is shared adding this to all object id's
                                for vcdObj in vcdObjList:
                                    dcGroupMapping = vcdObj.rollback.apiData.get('OrgVDCGroupID', {})
                                    dcGroupMapping.update({targetNetwork['connection']['routerRef']['id']: dcGroupId})
                                    vcdObj.rollback.apiData['OrgVDCGroupID'] = dcGroupMapping
                            break

                # Creating dc group for isolated shared conflicting networks
                if conflictNetworks:
                    for targetNetwork in targetOrgVDCNetworks:
                        for network in conflictNetworks:
                            if targetNetwork['name'] == network['name'] + '-v2t':
                                if targetNetwork['id'] not in self.rollback.apiData.get('OrgVDCGroupID', {}) and \
                                        network['shared']:
                                    dcGroupName = sourceOrgVDCName + '-Group-' + network['name']
                                    dcGroupId = self.createDCgroup(dcGroupName, sharedGroup=True,
                                                                   orgVdcIdList=orgVDCIDList)
                                    ownerIds.update({targetNetwork['id']: dcGroupId})
                                    self.rollback.apiData['OrgVDCGroupID'] = ownerIds
                                    # As this dc group is shared adding this to all object id's
                                    for vcdObj in vcdObjList:
                                        dcGroupMapping = vcdObj.rollback.apiData.get('OrgVDCGroupID', {})
                                        dcGroupMapping.update(
                                            {targetNetwork['id']: self.rollback.apiData['OrgVDCGroupID'][
                                                targetNetwork['id']]})
                                        vcdObj.rollback.apiData['OrgVDCGroupID'] = dcGroupMapping
                                break

            # Handling corner case for shared isolated networks with no conflicts
            if [network for network in orgVdcNetworks if network['shared']]:
                orgId = self.rollback.apiData['Organization']['@id']
                targetOrgVDCNameList = [vcdObj.vdcName + "-v2t" for vcdObj in vcdObjList]

                for targetNetwork in targetOrgVDCNetworks:
                    # Finding all vdc groups linked to the org vdc's to be parallely migrated
                    vdcGroups = [dcGroup for dcGroup in self.getOrgVDCGroup() if
                                 dcGroup['orgId'] == orgId and [vdc for vdc in dcGroup['participatingOrgVdcs'] if
                                                                vdc['vdcRef']['name'] in targetOrgVDCNameList]]

                    # Removing dc groups created for isolated networks
                    filteredVDCGroups = list(filter(lambda group: not any([
                        True if networkName in group['name'] else False for networkName in conflictingNetworksName]),
                                                    vdcGroups))

                    # Finding filtered shared dc groups
                    filteredSharedVDCGroups = [dcGroup for dcGroup in filteredVDCGroups if
                                               len(dcGroup['participatingOrgVdcs']) == len(vcdObjList)]

                    for network in orgVdcNetworks:
                        if targetNetwork['name'] == network['name'] + '-v2t':
                            if network["networkType"] == "ISOLATED" and network["shared"] and \
                                    targetNetwork['id'] not in self.rollback.apiData.get('OrgVDCGroupID', {}):
                                dcGroupName = sourceOrgVDCName + '-Group-' + network['name']
                                # If shared dc group id is present use that
                                if filteredSharedVDCGroups:
                                    dcGroupId = filteredSharedVDCGroups[0]['id']
                                # Else create a new shared dc group for this network
                                else:
                                    dcGroupId = self.createDCgroup(dcGroupName, sharedGroup=True,
                                                                   orgVdcIdList=orgVDCIDList)
                                ownerIds.update({targetNetwork['id']: dcGroupId})
                                self.rollback.apiData['OrgVDCGroupID'] = ownerIds
                                # As this dc group is shared adding this to all object id's
                                for vcdObj in vcdObjList:
                                    dcGroupMapping = vcdObj.rollback.apiData.get('OrgVDCGroupID', {})
                                    dcGroupMapping.update(
                                        {targetNetwork['id']: self.rollback.apiData['OrgVDCGroupID'][
                                            targetNetwork['id']]})
                                    vcdObj.rollback.apiData['OrgVDCGroupID'] = dcGroupMapping
                            break
        except Exception:
            raise
        finally:
            try:
                # Saving metadata for all org vdc's
                for vcdObj in vcdObjList:
                    # Check for current class object
                    if self is not vcdObj:
                        vcdObj.saveMetadataInOrgVdc()
            finally:
                try:
                    # Releasing the lock
                    self.lock.release()
                    logger.debug("Lock released by thread - '{}'".format(threading.currentThread().getName()))
                except RuntimeError:
                    pass

    @description('Enable DFW in Orgvdc group')
    @remediate
    def enableDFWinOrgvdcGroup(self, vcdObjList, sourceOrgVDCId, rollback=False):
        """
        Description :   Enable DFW in Orgvdc group
        Parameters  :   rollback- True to disable DFW in ORG VDC group
        """
        try:
            # Acquire lock as dc groups can be common in different org vdc's
            self.lock.acquire(blocking=True)

            # Check if services configuration or network switchover was performed or not
            if rollback and not self.rollback.metadata.get("configureTargetVDC", {}).get("enableDFWinOrgvdcGroup"):
                return
            sourceOrgVDCId = self.rollback.apiData['sourceOrgVDC']['@id']
            # Fetch DFW rules from source org vdc
            allLayer3Rules = self.getDistributedFirewallConfig(sourceOrgVDCId)
            orgvDCgroupIds = self.rollback.apiData['OrgVDCGroupID'].values() if self.rollback.apiData.get('OrgVDCGroupID') else []
            # Enable DFW only if DFW was enabled and configured on source org vdc
            if allLayer3Rules:
                for orgvDCgroupId in orgvDCgroupIds:
                    if rollback:
                        url = '{}{}{}/default'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                              vcdConstants.GET_VDC_GROUP_BY_ID.format(orgvDCgroupId),
                                              vcdConstants.ENABLE_DFW_POLICY)
                        logger.debug('DFW is getting disabled in Org VDC group id: {}'.format(orgvDCgroupId))
                        payloadDict = {"id": "default", "name": "Default", "enabled": False}
                    else:
                        url = '{}{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                              vcdConstants.GET_VDC_GROUP_BY_ID.format(orgvDCgroupId),
                                              vcdConstants.ENABLE_DFW_POLICY)
                        logger.debug('DFW is getting enabled in Org VDC group id: {}'.format(orgvDCgroupId))
                        payloadDict = {"enabled": True, "defaultPolicy": {"name": "defaultPolicy Allow", "enabled": True}}
                    payloadData = json.dumps(payloadDict)
                    # setting the content-type as per the api requirement
                    self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                    response = self.restClientObj.put(url, self.headers, data=payloadData)
                    if response.status_code == requests.codes.accepted:
                        taskUrl = response.headers['Location']
                        header = {'Authorization': self.headers['Authorization'],
                                  'Accept': vcdConstants.GENERAL_JSON_CONTENT_TYPE}
                        taskResponse = self.restClientObj.get(url=taskUrl, headers=header)
                        responseDict = taskResponse.json()
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug("DFW is enabled successfully on VDC group id: {}".format(orgvDCgroupId))
                    else:
                        errorDict = response.json()
                        raise Exception("Failed to enable DFW '{}' ".format(errorDict['message']))
                if not rollback:
                    self.configureDfwDefaultRule(vcdObjList, sourceOrgVDCId)

        except Exception:
            raise
        finally:
            try:
                # Releasing the lock
                self.lock.release()
                logger.debug("Lock released by thread - '{}'".format(threading.currentThread().getName()))
            except RuntimeError:
                pass

    @description('Increasing/Decreasing the scope of Edge gateways')
    @remediate
    def increaseScopeOfEdgegateways(self, rollback=False):
        """
        Description: Increasing the scope of Edge gateways to VDC group
        parameter: rollback- True to decrease the scope of edgegateway from NSX-T ORG VDC
        """
        try:
            # Check if scope of edge gateways was changed or not
            if rollback and not self.rollback.metadata.get("configureTargetVDC", {}).get("increaseScopeOfEdgegateways"):
                return

            edgeGatewayList = self.rollback.apiData['targetEdgeGateway']
            if not edgeGatewayList:
                return

            sourceOrgVDCId = self.rollback.apiData['sourceOrgVDC']['@id']
            allLayer3Rules = self.getDistributedFirewallConfig(sourceOrgVDCId)
            if allLayer3Rules or [network for network in self.retrieveNetworkListFromMetadata(
                    sourceOrgVDCId, orgVDCType='source') if network['shared']]:
                if rollback:
                    logger.info("Rollback: Decreasing scope of edge gateways")
                else:
                    logger.info('Increasing scope of edge gateways')
                ownerRefIDs = self.rollback.apiData.get('OrgVDCGroupID', {})
                targetOrgVdcId = self.rollback.apiData['targetOrgVDC']['@id']
                for edgeGateway in edgeGatewayList:
                    if rollback:
                        logger.debug('Decreasing the scope of Edge gateway - {}'.format(edgeGateway['name']))
                    else:
                        logger.debug('Increasing the scope of Edge gateway - {}'.format(edgeGateway['name']))
                    # url to update external network properties
                    url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                           vcdConstants.ALL_EDGE_GATEWAYS, edgeGateway['id'])
                    header = {'Authorization': self.headers['Authorization'],
                              'Accept': vcdConstants.OPEN_API_CONTENT_TYPE+';version='+self.version}
                    response = self.restClientObj.get(url, header)
                    if response.status_code == requests.codes.ok:
                        responseDict = response.json()
                        if rollback:
                            # changing the owner reference from org VDC to org VDC group
                            responseDict['ownerRef'] = {'id': targetOrgVdcId}
                        else:
                            ownerRefID = ownerRefIDs[edgeGateway['id']] if ownerRefIDs.get(edgeGateway['id']) else targetOrgVdcId
                            # changing the owner reference from org VDC to org VDC group
                            responseDict['ownerRef'] = {'id': ownerRefID}
                        payloadData = json.dumps(responseDict)
                        self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                        # put call to increase the scope of the edgegateway
                        response = self.restClientObj.put(url, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            # successful creation of firewall group
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl, returnOutput=False)
                            logger.debug('Successfully changed the scope of Edge gateway - {}'.format(edgeGateway['name']))
                        else:
                            errorResponse = response.json()
                            # failure in increase scope of the network
                            raise Exception('Failed to increase scope of the EdgeGateway {} - {}'.format(responseDict['name'], errorResponse['message']))
                    else:
                        responseDict = response.json()
                        raise Exception('Failed to retrieve Edgewateway- {}'.format(responseDict['message']))

        except Exception:
            raise

    @isSessionExpired
    def deleteOrgVDCGroup(self):
        """
        Description: Deleting the ORG VDC group as part of rollback
        """
        try:
            # Taking thread lock as one org vdc will delete groups first
            self.lock.acquire(blocking=True)
            # Check if org vdc groups were created or not
            if not self.rollback.metadata.get("prepareTargetVDC", {}).get("createOrgvDCGroup"):
                return

            ownerRefIDs = self.rollback.apiData.get('OrgVDCGroupID')
            if ownerRefIDs:
                logger.info("Rollback: Deleting Data Center Groups")
                vdcGroupsIds = [group['id'] for group in self.getOrgVDCGroup()]

                for ownerRefID in set(ownerRefIDs.values()):
                    if ownerRefID in vdcGroupsIds:
                        # open api to create Org vDC group
                        url = '{}{}/{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.VDC_GROUPS, ownerRefID)
                        response = self.restClientObj.delete(url, self.headers)
                        if response.status_code == requests.codes.accepted:
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl=taskUrl)
                        else:
                            response = response.json()
                            raise Exception("Failed to delete ORG VDC group from target - {}".format(response['message']))
        except Exception:
            raise
        finally:
            try:
                # Releasing the lock
                self.lock.release()
                logger.debug("Lock released by thread - '{}'".format(threading.currentThread().getName()))
            except RuntimeError:
                pass

    @isSessionExpired
    def getIPAssociatedUsedByVM(self, networkName, externalNetworkName, vdcIDList):
        """
        Description: Method to find all the IPS to be migrated used by vm connected to shared direct networks and save that to metadata
        Parameters:  networkName - Name of shared service direct network
                     vdcIDList - list of id of source org vdc (LIST)
        """
        try:
            ipList = list()

            vAppList = list()
            # Fetching vapps from all the org vdc's partaking in the migration
            for vdcId in vdcIDList:
                vAppList += self.getOrgVDCvAppsList(orgVDCId=vdcId)
            for vApp in vAppList:
                # Check vCD session
                getSession(self)
                # get api call to retrieve the vapp details
                response = self.restClientObj.get(vApp['@href'], self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = xmltodict.parse(response.content, process_namespaces=False, attr_prefix='')
                    vAppData = responseDict.get('VApp', {})
                    # checking if the vapp has vms
                    if vAppData and vAppData.get('Children'):
                        vmList = vAppData['Children']['Vm'] if isinstance(
                            vAppData['Children']['Vm'],
                            list) else [
                            vAppData['Children']['Vm']]
                        # iterating over vms in the vapp
                        for vm in vmList:
                            if vm.get('NetworkConnectionSection') and \
                                    vm['NetworkConnectionSection'].get('NetworkConnection'):
                                vmNetworkSpec = vm['NetworkConnectionSection']['NetworkConnection'] \
                                    if isinstance(vm['NetworkConnectionSection']['NetworkConnection'], list) \
                                    else [vm['NetworkConnectionSection']['NetworkConnection']]
                                for network in vmNetworkSpec:
                                    if network['network'] == networkName and network['IpAddressAllocationMode'] == 'POOL':
                                        ipList.append(network['IpAddress'])
                else:
                    raise Exception("Failed to fetch vApp details")
                # Saving these IP's in metadata
                directNetworkIPS = self.rollback.apiData.get("directNetworkIP", {})
                if externalNetworkName in directNetworkIPS:
                    directNetworkIPS[externalNetworkName] = list(set(directNetworkIPS[externalNetworkName] + ipList))
                else:
                    directNetworkIPS[externalNetworkName] = list(set(ipList))
                self.rollback.apiData["directNetworkIP"] = directNetworkIPS
            return ipList
        except:
            raise
        finally:
            self.saveMetadataInOrgVdc()

    @isSessionExpired
    def createDirectNetworkPayload(self, orgVDCIDList, inputDict, vdcDict, nsxObj, orgvdcNetowork, parentNetworkId):
        """
        Description: THis method is used to create payload for direct network and imported network
        return: payload data - payload data for creating a network
        """
        try:
            segmentName = None
            payloadDict = dict()
            # url to retrieve the networks with external network id
            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_ORG_VDC_NETWORKS,
                                  vcdConstants.QUERY_EXTERNAL_NETWORK.format(parentNetworkId['id']))
            # get api call to retrieve the networks with external network id
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                if int(responseDict['resultTotal']) > 1:
                    if not orgvdcNetowork['shared']:
                        payloadDict = {
                            'name': orgvdcNetowork['name'] + '-v2t',
                            'description': orgvdcNetowork['description'] if orgvdcNetowork.get('description') else '',
                            'networkType': orgvdcNetowork['networkType'],
                            'parentNetworkId': orgvdcNetowork['parentNetworkId']
                        }
                    else:
                        # Payload for shared direct network / service network use case
                        externalNetworks = self.fetchAllExternalNetworks()
                        for extNet in externalNetworks:
                            # Finding segment backed ext net for shared direct network
                            if parentNetworkId['name'] + '-v2t' == extNet['name']:
                                if [backing for backing in extNet['networkBackings']['values'] if
                                     backing['backingTypeValue'] == 'IMPORTED_T_LOGICAL_SWITCH']:
                                    payloadDict = {
                                        'name': orgvdcNetowork['name'] + '-v2t',
                                        'description': orgvdcNetowork['description'] if orgvdcNetowork.get(
                                            'description') else '',
                                        'networkType': orgvdcNetowork['networkType'],
                                        'parentNetworkId': {'name': extNet['name'],
                                                            'id': extNet['id']},
                                        'shared': True
                                    }
                                    break
                        else:
                            raise(f"NSXT segment backed external network {parentNetworkId['name'] + '-v2t'} is not present, and it is required for this direct shared network - {orgvdcNetowork['name']}")
                else:
                    # Getting source external network details
                    sourceExternalNetwork = self.fetchAllExternalNetworks()
                    externalList = [externalNetwork['networkBackings'] for externalNetwork in sourceExternalNetwork if externalNetwork['id'] == parentNetworkId['id']]
                    if isinstance(sourceExternalNetwork, Exception):
                        raise sourceExternalNetwork
                    for value in externalList:
                        externalDict = value
                    backingid = [values['backingId'] for values in externalDict['values']]
                    url = '{}{}'.format(vcdConstants.XML_API_URL.format(self.ipAddress), vcdConstants.GET_PORTGROUP_VLAN_ID.format(backingid[0]))
                    acceptHeader = vcdConstants.GENERAL_JSON_CONTENT_TYPE.format(self.version)
                    headers = {'Authorization': self.headers['Authorization'], 'Accept': acceptHeader}
                    # get api call to retrieve the networks with external network id
                    response = self.restClientObj.get(url, headers)
                    if response.status_code == requests.codes.ok:
                        responseDict = response.json()
                        if responseDict['record']:
                            for record in responseDict['record']:
                                vlanId =record['vlanId']
                            segmetId, segmentName = nsxObj.createLogicalSegments(orgvdcNetowork, inputDict["VCloudDirector"]["ImportedNeworkTransportZone"], vlanId)
                        ipRanges = [
                            {
                                'startAddress': ipRange['startAddress'],
                                'endAddress': ipRange['endAddress'],
                            }
                            for ipRange in orgvdcNetowork['subnets']['values'][0]['ipRanges']['values']
                        ]
                        payloadDict = {
                            'name': orgvdcNetowork['name'] + '-v2t',
                            'description': orgvdcNetowork['description'] if orgvdcNetowork.get('description') else '',
                            'networkType': 'OPAQUE',
                            "subnets": {
                               "values": [{
                                    "gateway": orgvdcNetowork['subnets']['values'][0]['gateway'],
                                    "prefixLength":  orgvdcNetowork['subnets']['values'][0]['prefixLength'],
                                    "dnsSuffix": orgvdcNetowork['subnets']['values'][0]['dnsSuffix'],
                                    "dnsServer1": orgvdcNetowork['subnets']['values'][0]['dnsServer1'],
                                    "dnsServer2": orgvdcNetowork['subnets']['values'][0]['dnsServer2'],
                                    "ipRanges": {
                                        "values": ipRanges
                                    },
                                }]
                            },
                            'backingNetworkId': segmetId
                        }
                    else:
                        raise Exception('Failed to get external network {} vlan ID'.format(parentNetworkId['name']))
            else:
                raise Exception('Failed to get external network {}'.format(parentNetworkId['name']))
            payloadData = json.dumps(payloadDict)
            return segmentName, payloadData
        except Exception:
            raise

