# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description : Configuring Edge Gateway Services
"""

import logging
import json
import os
import random
import time
import ipaddress
import copy

from collections import OrderedDict

import requests
import xmltodict

import src.core.vcd.vcdConstants as vcdConstants

from src.core.vcd.vcdValidations import VCDMigrationValidation, isSessionExpired, remediate, description

logger = logging.getLogger('mainLogger')


class ConfigureEdgeGatewayServices(VCDMigrationValidation):
    """
    Description : Class having edge gateway services configuration operations
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        vcdConstants.VCD_API_HEADER = vcdConstants.VCD_API_HEADER.format(self.version)
        vcdConstants.GENERAL_JSON_CONTENT_TYPE = vcdConstants.GENERAL_JSON_CONTENT_TYPE.format(self.version)

    def configureServices(self, metadata, noSnatDestSubnet, loadBalancerVIPSubnet, nsxvObj, ServiceEngineGroupName):
        """
        Description :   Configure the  service to the Target Gateway
        Parameters  :   metadata - Status of service configuration (DICT)
                        noSnatDestSubnet - Destination subnet address
                        loadBalancerVIPSubnet - Subnet for loadbalancer virtual service VIP configuration
                        nsxvObj - NSXVOperations class object
                        ServiceEngineGroupName - Name of service engine group for load balancer configuration (STRING)
        """
        try:
            if not self.rollback.apiData['targetEdgeGateway']:
                logger.debug('Skipping services configuration as edge gateway does '
                             'not exists')
                return

            targetEdgeGatewayIdList = [edgeGateway['id'] for edgeGateway in self.rollback.apiData['targetEdgeGateway']]
            ipsecConfigDict = self.rollback.apiData['ipsecConfigDict']

            # reading data from metadata
            data = self.rollback.apiData
            # taking target edge gateway id from apioutput json file
            targetOrgVdcId = data['targetOrgVDC']['@id']

            # Configuring target IPSEC
            self.configTargetIPSEC(ipsecConfigDict)
            # Configuring target NAT
            self.configureTargetNAT(noSnatDestSubnet)
            # Configuring firewall
            self.configureFirewall(networktype=False, configureIPSET=True)
            # Configuring BGP
            self.configBGP()
            # Configuring DNS
            self.configureDNS()
            # configuring loadbalancer
            self.configureLoadBalancer(nsxvObj, ServiceEngineGroupName, loadBalancerVIPSubnet)
            logger.debug("Edge Gateway services configured successfully")
        except Exception:
            raise

    @isSessionExpired
    def cidrCalculator(self, rangeofips):
        """
        Description : Convert the range od ips to CIDR format
        Parameters  : Range of ips (STRING)
        """
        try:
            # from parameter splitting the range of ip's with '-'
            start = rangeofips.split('-')[0].strip()
            end = rangeofips.split('-')[-1].strip()

            listOfIpsInIpRange = [str(ipaddress.IPv4Address(ip)) for ip in range(int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end) + 1))]

            iplist = end.split('.')
            iplist.pop()
            iplist.append(str(0))
            ip = '.'.join(iplist)

            for CIDRPrefix in range(32, 0, -1):
                result = str(ip) + '/' + str(CIDRPrefix)
                ipsInNetworkFormed = [str(ip) for ip in ipaddress.ip_network(result, strict=False)]
                if all([True if ip in ipsInNetworkFormed else False for ip in
                        listOfIpsInIpRange]):
                    return str(result)

                if CIDRPrefix == 1:
                    return str(result)

        except Exception:
            raise

    @description("configuration of Firewall")
    @remediate
    def configureFirewall(self, networktype=False, configureIPSET=False):
        """
        Description :   Configure Firewall rules on target edge gateway
        Parameters  :   edgeGatewayId   -   id of the edge gateway (STRING)
                        targetOrgVDCId - ID of target org vdc (STRING)
                        networktype- False/true whether to configure security group or not
                                    default value will be false
        """
        try:
            firewallIdDict = list()
            for sourceEdgeGateway in self.rollback.apiData['sourceEdgeGateway']:
                logger.debug("Configuring Firewall Services in Target Edge Gateway - {}".format(sourceEdgeGateway['name']))
                sourceEdgeGatewayId = sourceEdgeGateway['id'].split(':')[-1]
                edgeGatewayId = list(filter(lambda edgeGatewayData: edgeGatewayData['name'] == sourceEdgeGateway['name'],
                                     self.rollback.apiData['targetEdgeGateway']))[0]['id']

                data = self.getEdgeGatewayFirewallConfig(sourceEdgeGatewayId, validation=False)
                # retrieving list instance of firewall rules from source edge gateway
                sourceFirewallRules = data if isinstance(data, list) else [data]
                # getting vcd id
                vcdid = self.rollback.apiData['sourceOrgVDC']['@id']
                vcdid = vcdid.split(':')[-1]
                # url to configure firewall rules on target edge gateway
                firewallUrl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                              vcdConstants.ALL_EDGE_GATEWAYS,
                                              vcdConstants.T1_ROUTER_FIREWALL_CONFIG.format(edgeGatewayId))
                if not networktype:
                    # retrieving the application port profiles
                    applicationPortProfilesList = self.getApplicationPortProfiles()
                    url = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                        vcdConstants.GET_IPSET_GROUP_BY_ID.format(
                                            vcdConstants.IPSET_SCOPE_URL.format(vcdid)))
                    response = self.restClientObj.get(url, self.headers)
                    if response.status_code == requests.codes.ok:
                        responseDict = xmltodict.parse(response.content)
                        if responseDict.get('list'):
                            ipsetgroups = responseDict['list']['ipset'] if isinstance(responseDict['list']['ipset'],
                                                                                      list) else [
                                responseDict['list']['ipset']]
                        else:
                            ipsetgroups = []
                        if ipsetgroups:
                            if configureIPSET:
                                firewallIdDict = self.createIPSET(ipsetgroups, edgeGatewayId)
                                # creating a dict with firewallName as key and firewallIDs as value
                                # firewallIdDict = dict(zip(firewallName, firewallIDs))
                        firewallIdDict = self.rollback.apiData.get('firewallIdDict')
                # if firewall rules are configured on source edge gateway
                if sourceFirewallRules:
                    # firstTime variable is to check whether security groups are getting configured for the first time
                    firstTime = True
                    # iterating over the source edge gateway firewall rules
                    for firewallRule in sourceFirewallRules:
                        # if configStatus flag is already set means that the firewall rule is already configured, if so then skipping the configuring of same rule and moving to the next firewall rule
                        if self.rollback.apiData.get(firewallRule['id']) and not networktype:
                            if self.rollback.apiData[firewallRule['id']] == sourceEdgeGatewayId:
                                continue
                        data = dict()
                        ipAddressList = list()
                        applicationServicesList = list()
                        payloadDict = dict()
                        sourcefirewallGroupId = list()
                        destinationfirewallGroupId = list()
                        # checking for the source key in firewallRule dictionary
                        if firewallRule.get('source', None):
                            # retrieving ip address list source edge gateway firewall rule
                            if firewallRule['source'].get("ipAddress", None):
                                ipAddressList = firewallRule['source']['ipAddress'] if isinstance(
                                    firewallRule['source']['ipAddress'], list) else [
                                    firewallRule['source']['ipAddress']]
                            ipsetgroups = list()
                            networkgroups = list()
                            # retrieving ipset list source edge gateway firewall rule
                            if firewallRule['source'].get("groupingObjectId", None):
                                groups = firewallRule['source']['groupingObjectId'] if isinstance(
                                    firewallRule['source']['groupingObjectId'], list) else [
                                    firewallRule['source']['groupingObjectId']]
                                ipsetgroups = [group for group in groups if "ipset" in group]
                                networkgroups = [group for group in groups if "network" in group]
                            # checking if the networktype is false
                            if not networktype:
                                if ipAddressList:
                                    # creating payload data to create firewall group
                                    firewallGroupDict = {
                                        'name': firewallRule['name'] + '-' + 'Source-' + str(random.randint(1, 1000)),
                                        'edgeGatewayRef': {'id': edgeGatewayId},
                                        'ipAddresses': ipAddressList}
                                    firewallGroupDict = json.dumps(firewallGroupDict)
                                    # url to create firewall group
                                    firewallGroupUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                                     vcdConstants.CREATE_FIREWALL_GROUP)
                                    self.headers['Content-Type'] = 'application/json'
                                    # post api call to create firewall group
                                    response = self.restClientObj.post(firewallGroupUrl, self.headers,
                                                                       data=firewallGroupDict)
                                    if response.status_code == requests.codes.accepted:
                                        # successful creation of firewall group
                                        taskUrl = response.headers['Location']
                                        firewallGroupId = self._checkTaskStatus(taskUrl=taskUrl, returnOutput=True)
                                        sourcefirewallGroupId.append(
                                            {'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
                                    else:
                                        errorResponse = response.json()
                                        raise Exception(
                                            'Failed to create Firewall group - {}'.format(errorResponse['message']))
                                if ipsetgroups:
                                    # iterating all the IPSET in a firewall rule one by one
                                    for ipsetgroup in ipsetgroups:
                                        # url to retrieve the info of ipset group by id
                                        ipseturl = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                                                 vcdConstants.GET_IPSET_GROUP_BY_ID.format(ipsetgroup))
                                        # get api call to retrieve the ipset group info
                                        ipsetresponse = self.restClientObj.get(ipseturl, self.headers)
                                        if ipsetresponse.status_code == requests.codes.ok:
                                            # successful retrieval of ipset group info
                                            ipsetresponseDict = xmltodict.parse(ipsetresponse.content)
                                            # checking whether the key present in the IPSET firewallIdDict
                                            if firewallIdDict.get(edgeGatewayId):
                                                # checking wheather IPset name present in the dict
                                                if firewallIdDict[edgeGatewayId].get(ipsetresponseDict['ipset']['name']):
                                                    ipsetDict = firewallIdDict[edgeGatewayId][ipsetresponseDict['ipset']['name']]
                                                    sourcefirewallGroupId.append(ipsetDict)
                            # checking if any routed org vdc networks added in the firewall rule and networktype should be true
                            if networkgroups and networktype:
                                # checking if there are any network present in the fire wall rule
                                if len(networkgroups) != 0 and firstTime:
                                    logger.debug('Configuring security groups in the firewall in Target Edge Gateway - {}'.format(sourceEdgeGateway['name']))
                                    # Changing it into False because only want to log first time
                                    firstTime = False
                                # get api call to retrieve firewall info of target edge gateway
                                response = self.restClientObj.get(firewallUrl, self.headers)
                                if response.status_code == requests.codes.ok:
                                    userDefinedRulesList = list()
                                    # successful retrieval of firewall info
                                    responseDict = response.json()
                                    userDefinedRulesList = responseDict['userDefinedRules']
                                    for rule in userDefinedRulesList:
                                        name = rule['name'].split('-')[-1]
                                        if firewallRule['id'] == name:
                                            index = userDefinedRulesList.index(rule)
                                            userDefinedRulesList.pop(index)
                                            firewallGroupId = self.createSecurityGroup(networkgroups, firewallRule,
                                                                                       edgeGatewayId)
                                            if rule.get('sourceFirewallGroups'):
                                                for id in firewallGroupId:
                                                    rule['sourceFirewallGroups'].append({'id': '{}'.format(id)})
                                                data['userDefinedRules'] = userDefinedRulesList + [rule]
                                            else:
                                                for id in firewallGroupId:
                                                    sourcefirewallGroupId.append({'id': '{}'.format(id)})
                                                rule['sourceFirewallGroups'] = sourcefirewallGroupId
                                                data['userDefinedRules'] = userDefinedRulesList + [rule]
                                            payloadData = json.dumps(data)
                                            self.headers['Content-Type'] = 'application/json'
                                            # put api call to configure firewall rules on target edge gateway
                                            response = self.restClientObj.put(firewallUrl, self.headers,
                                                                              data=payloadData)
                                            if response.status_code == requests.codes.accepted:
                                                # successful configuration of firewall rules on target edge gateway
                                                taskUrl = response.headers['Location']
                                                self._checkTaskStatus(taskUrl=taskUrl)
                                                logger.debug(
                                                    'Firewall rule {} updated successfully with security group.'.format(
                                                        firewallRule['name']))
                                            else:
                                                # failure in configuration of firewall rules on target edge gateway
                                                response = response.json()
                                                raise Exception(
                                                    'Failed to update Firewall rule - {}'.format(response['message']))
                        ipAddressList = list()
                        # checking for the destination key in firewallRule dictionary
                        if firewallRule.get('destination', None):
                            # retrieving ip address list source edge gateway firewall rule
                            if firewallRule['destination'].get("ipAddress", None):
                                ipAddressList = firewallRule['destination']['ipAddress'] if isinstance(
                                    firewallRule['destination']['ipAddress'], list) else [
                                    firewallRule['destination']['ipAddress']]
                            ipsetgroups = list()
                            networkgroups = list()
                            # retrieving ipset group list source edge gateway firewall rule
                            if firewallRule['destination'].get("groupingObjectId", None):
                                groups = firewallRule['destination']['groupingObjectId'] if isinstance(
                                    firewallRule['destination']['groupingObjectId'], list) else [
                                    firewallRule['destination']['groupingObjectId']]
                                ipsetgroups = [group for group in groups if "ipset" in group]
                                networkgroups = [group for group in groups if "network" in group]
                            # checking if networktype is false
                            if not networktype:
                                if ipAddressList:
                                    # creating payload data to create firewall group
                                    firewallGroupDict = {'name': firewallRule['name'] + '-' + 'destination-' + str(
                                        random.randint(1, 1000)), 'edgeGatewayRef': {'id': edgeGatewayId},
                                                         'ipAddresses': ipAddressList}
                                    firewallGroupDict = json.dumps(firewallGroupDict)
                                    # url to create firewall group
                                    firewallGroupUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                                     vcdConstants.CREATE_FIREWALL_GROUP)
                                    self.headers['Content-Type'] = 'application/json'
                                    # post api call to create firewall group
                                    response = self.restClientObj.post(firewallGroupUrl, self.headers,
                                                                       data=firewallGroupDict)
                                    if response.status_code == requests.codes.accepted:
                                        # successful creation of firewall group
                                        taskUrl = response.headers['Location']
                                        firewallGroupId = self._checkTaskStatus(taskUrl=taskUrl, returnOutput=True)
                                        destinationfirewallGroupId.append(
                                            {'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
                                    else:
                                        errorResponse = response.json()
                                        raise Exception(
                                            'Failed to create Firewall group - {}'.format(errorResponse['message']))
                                if ipsetgroups:
                                    # iterating all the IPSET in a firewall rule one by one
                                    for ipsetgroup in ipsetgroups:
                                        # url to retrieve the info of ipset group by id
                                        ipseturl = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                                                 vcdConstants.GET_IPSET_GROUP_BY_ID.format(ipsetgroup))
                                        # get api call to retrieve the ipset group info
                                        ipsetresponse = self.restClientObj.get(ipseturl, self.headers)
                                        if ipsetresponse.status_code == requests.codes.ok:
                                            # successful retrieval of ipset group info
                                            ipsetresponseDict = xmltodict.parse(ipsetresponse.content)
                                            # checking whether the key present in the IPSET firewallIdDict
                                            if firewallIdDict.get(edgeGatewayId):
                                                # checking wheather IPset name present in the dict
                                                if firewallIdDict[edgeGatewayId].get(ipsetresponseDict['ipset']['name']):
                                                    ipsetDict = firewallIdDict[edgeGatewayId][ipsetresponseDict['ipset']['name']]
                                                    destinationfirewallGroupId.append(ipsetDict)
                            # checking if any routed org vdc networks added in the firewall rule and networktype should be true
                            if networkgroups and networktype:
                                # checking if there are any network present in the fire wall rule
                                if len(networkgroups) != 0 and firstTime:
                                    logger.info('Configuring security groups in the firewall')
                                    # Changing it into False because only want to log first time
                                    firstTime = False
                                # get api call to retrieve firewall info of target edge gateway
                                response = self.restClientObj.get(firewallUrl, self.headers)
                                if response.status_code == requests.codes.ok:
                                    userDefinedRulesList = list()
                                    # successful retrieval of firewall info
                                    responseDict = response.json()
                                    userDefinedRulesList = responseDict['userDefinedRules']
                                    for rule in userDefinedRulesList:
                                        name = rule['name'].split('-')[-1]
                                        if firewallRule['id'] == name:
                                            index = userDefinedRulesList.index(rule)
                                            userDefinedRulesList.pop(index)
                                            firewallGroupId = self.createSecurityGroup(networkgroups, firewallRule,
                                                                                       edgeGatewayId)
                                            if rule.get('destinationFirewallGroups'):
                                                for id in firewallGroupId:
                                                    rule['destinationFirewallGroups'].append({'id': '{}'.format(id)})
                                                data['userDefinedRules'] = userDefinedRulesList + [rule]
                                            else:
                                                for id in firewallGroupId:
                                                    destinationfirewallGroupId.append({'id': '{}'.format(id)})
                                                rule['destinationFirewallGroups'] = destinationfirewallGroupId
                                                data['userDefinedRules'] = userDefinedRulesList + [rule]
                                            payloadData = json.dumps(data)
                                            self.headers['Content-Type'] = 'application/json'
                                            # put api call to configure firewall rules on target edge gateway
                                            response = self.restClientObj.put(firewallUrl, self.headers,
                                                                              data=payloadData)
                                            if response.status_code == requests.codes.accepted:
                                                # successful configuration of firewall rules on target edge gateway
                                                taskUrl = response.headers['Location']
                                                self._checkTaskStatus(taskUrl=taskUrl)
                                                logger.debug(
                                                    'Firewall rule {} updated successfully with security group.'.format(
                                                        firewallRule['name']))
                                            else:
                                                # failure in configuration of firewall rules on target edge gateway
                                                response = response.json()
                                                raise Exception(
                                                    'Failed to update Firewall rule - {}'.format(response['message']))
                        if not networktype:
                            userDefinedRulesList = list()
                            # get api call to retrieve firewall info of target edge gateway
                            response = self.restClientObj.get(firewallUrl, self.headers)
                            if response.status_code == requests.codes.ok:
                                # successful retrieval of firewall info
                                responseDict = response.json()
                                userDefinedRulesList = responseDict['userDefinedRules']
                            # updating the payload with source firewall groups, destination firewall groups, user defined firewall rules, application port profiles
                            action = 'ALLOW' if firewallRule['action'] == 'accept' else 'DROP'
                            payloadDict.update({'name': firewallRule['name'] + "-" + firewallRule['id'],
                                                'enabled': firewallRule['enabled'], 'action': action})
                            payloadDict['sourceFirewallGroups'] = sourcefirewallGroupId if firewallRule.get('source',
                                                                                                            None) else []
                            payloadDict['destinationFirewallGroups'] = destinationfirewallGroupId if firewallRule.get(
                                'destination', None) else []
                            payloadDict['logging'] = "true" if firewallRule['loggingEnabled'] == "true" else "false"
                            # checking for the application key in firewallRule
                            if firewallRule.get('application'):
                                if firewallRule['application'].get('service'):
                                    # list instance of application services
                                    firewallRules = firewallRule['application']['service'] if isinstance(
                                        firewallRule['application']['service'], list) else [
                                        firewallRule['application']['service']]
                                    # iterating over the application services
                                    for applicationService in firewallRules:
                                        # if protocol is not icmp
                                        if applicationService['protocol'] != "icmp":
                                            protocol_name, port_id = self._searchApplicationPortProfile(
                                                applicationPortProfilesList,
                                                applicationService['protocol'],
                                                applicationService['port'])
                                            applicationServicesList.append({'name': protocol_name, 'id': port_id})
                                            payloadDict['applicationPortProfiles'] = applicationServicesList
                                        else:
                                            # if protocol is icmp
                                            # iterating over the application port profiles
                                            for value in applicationPortProfilesList:
                                                if value['name'] == vcdConstants.ICMP_ALL:
                                                    protocol_name, port_id = value['name'], value['id']
                                                    applicationServicesList.append(
                                                        {'name': protocol_name, 'id': port_id})
                                                    payloadDict["applicationPortProfiles"] = applicationServicesList
                            else:
                                payloadDict['applicationPortProfiles'] = applicationServicesList
                            data['userDefinedRules'] = userDefinedRulesList + [
                                payloadDict] if userDefinedRulesList else [payloadDict]
                            payloadData = json.dumps(data)
                            self.headers['Content-Type'] = 'application/json'
                            # put api call to configure firewall rules on target edge gateway
                            response = self.restClientObj.put(firewallUrl, self.headers, data=payloadData)
                            if response.status_code == requests.codes.accepted:
                                # successful configuration of firewall rules on target edge gateway
                                taskUrl = response.headers['Location']
                                self._checkTaskStatus(taskUrl=taskUrl)
                                # setting the configStatus flag meaning the particular firewall rule is configured successfully in order to skip its reconfiguration
                                self.rollback.apiData[firewallRule['id']] = sourceEdgeGatewayId
                                logger.debug('Firewall rule {} created successfully.'.format(firewallRule['name']))
                            else:
                                # failure in configuration of firewall rules on target edge gateway
                                response = response.json()
                                raise Exception('Failed to create Firewall rule on target Edge gateway {} - {}'.format(sourceEdgeGateway['name'], response['message']))
                    if not networktype:
                        logger.debug(f"Firewall rules configured successfully on target Edge gateway {sourceEdgeGateway['name']}")
                    if not firstTime:
                        logger.debug(f"Successfully configured security groups for Edge gateway {sourceEdgeGateway['name']}")
        except Exception:
            # Saving metadata in org VDC
            self.saveMetadataInOrgVdc()
            raise

    @description("configuration of Target IPSEC")
    @remediate
    def configTargetIPSEC(self, ipsecConfig):
        """
        Description :   Configure the IPSEC service to the Target Gateway
        Parameters  :   ipsecConfig   -   Details of IPSEC configuration  (DICT)
        """
        try:
            logger.info('Configuring Target Edge gateway services.')
            logger.debug('IPSEC is getting configured')
            targetEdgeGateway = copy.deepcopy(self.rollback.apiData['targetEdgeGateway'])
            targetEdgegatewayIdList = [(edgeGateway['id'], edgeGateway['name']) for edgeGateway in targetEdgeGateway]
            data = self.rollback.apiData
            IPsecStatus = data.get('IPsecStatus', {})
            for t1gatewayId, targetEdgeGatewayName in targetEdgegatewayIdList:
                # Status dict for ipsec config
                ipsecConfigured = IPsecStatus.get(t1gatewayId, [])
                ipsecConfigDict = ipsecConfig.get(targetEdgeGatewayName)
                # checking if ipsec is enabled on source org vdc edge gateway, if not then returning
                if not ipsecConfigDict or not ipsecConfigDict['enabled']:
                    logger.debug('IPSec is not enabled or configured in source Org VDC for edge gateway - {}.'.format(
                        targetEdgeGatewayName
                    ))
                    continue
                logger.debug("Configuring IPSEC Services in Target Edge Gateway - {}".format(targetEdgeGatewayName))
                # if enabled then retrieving the list instance of source  ipsec
                sourceIPsecSite = ipsecConfigDict['sites']['sites'] if isinstance(ipsecConfigDict['sites']['sites'], list) else [ipsecConfigDict['sites']['sites']]
                # url to configure the ipsec rules on target edge gateway
                url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                      vcdConstants.T1_ROUTER_IPSEC_CONFIG.format(t1gatewayId))
                # if configured ipsec rules on source org vdc edge gateway, then configuring the same on target edge gateway
                if ipsecConfigDict['enabled']:
                    for sourceIPsecSite in sourceIPsecSite:
                        # if configStatus flag is already set means that the sourceIPsecSite rule is already configured, if so then skipping the configuring of same rule and moving to the next sourceIPsecSite rule
                        if sourceIPsecSite['name'] in ipsecConfigured:
                            continue
                        # if the subnet is not a list converting it in the list
                        externalIpCIDR = sourceIPsecSite['localSubnets']['subnets'] if isinstance(sourceIPsecSite['localSubnets']['subnets'], list) else [sourceIPsecSite['localSubnets']['subnets']]
                        RemoteIpCIDR = sourceIPsecSite['peerSubnets']['subnets'] if isinstance(sourceIPsecSite['peerSubnets']['subnets'], list) else [sourceIPsecSite['peerSubnets']['subnets']]
                        # creating payload dictionary
                        payloadDict = {"name": sourceIPsecSite['name'],
                                       "enabled": "true" if sourceIPsecSite['enabled'] else "false",
                                       "localId": sourceIPsecSite['localId'],
                                       "externalIp": sourceIPsecSite['localIp'],
                                       "peerIp": sourceIPsecSite['peerId'],
                                       "RemoteIp": sourceIPsecSite['peerIp'],
                                       "psk": sourceIPsecSite['psk'],
                                       "connectorInitiationMode": " ",
                                       "securityType": "DEFAULT",
                                       "logging": "true" if ipsecConfigDict['logging']['enable'] else "false"
                                       }
                        filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
                        # creating payload data
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.CREATE_IPSEC_TEMPLATE)
                        payloadData = json.loads(payloadData)
                        # adding external ip cidr to payload
                        payloadData['localEndpoint']['localNetworks'] = externalIpCIDR
                        # adding remote ip cidr to payload
                        payloadData['remoteEndpoint']['remoteNetworks'] = RemoteIpCIDR
                        payloadData = json.dumps(payloadData)
                        self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                        # post api call to configure ipsec rules on target edge gateway
                        response = self.restClientObj.post(url, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            # if successful configuration of ipsec rules
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl=taskUrl)
                            # adding a key here to make sure the rule have configured successfully and when remediation skipping this rule
                            #self.rollback.apiData[sourceIPsecSite['name']] = True
                            ipsecConfigured.append(sourceIPsecSite['name'])
                            IPsecStatus.update({t1gatewayId: ipsecConfigured})
                            data['IPsecStatus'] = IPsecStatus
                            logger.debug('IPSEC is configured successfully on the Target Edge Gateway - {}'.format(targetEdgeGatewayName))
                        else:
                            # if failure configuration of ipsec rules
                            response = response.json()
                            raise Exception('Failed to configure configure IPSEC on Target Edge Gateway {} - {} '
                                            .format(targetEdgeGatewayName, response['message']))
                    # below function configures network property of ipsec rules
                    self.connectionPropertiesConfig(t1gatewayId, ipsecConfigDict)
                else:
                    # if no ipsec rules are configured on source edge gateway
                    logger.debug('No IPSEC rules configured in source edge gateway - {}'.format(targetEdgeGatewayName))
        except Exception:
            raise

    @isSessionExpired
    def getApplicationPortProfiles(self):
        """
        Description :   Get Application Port Profiles
        """
        try:
            # fetching name of NSX-T backed provider vdc
            tpvdcName = self.rollback.apiData['targetProviderVDC']['@name']

            # fetching NSX-T manager id
            nsxtManagerId = self.getNsxtManagerId(tpvdcName)

            url = "{}{}?filter=_context=={}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.APPLICATION_PORT_PROFILES,
                                                    nsxtManagerId)
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                resultTotal = responseDict['resultTotal']
            pageNo = 1
            pageSizeCount = 0
            resultList = list()
            logger.debug('Getting Application port profiles')
            while resultTotal > 0 and pageSizeCount < resultTotal:
                url = "{}{}?page={}&pageSize={}&filter=_context=={}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                        vcdConstants.APPLICATION_PORT_PROFILES, pageNo,
                                                        vcdConstants.APPLICATION_PORT_PROFILES_PAGE_SIZE,
                                                                            nsxtManagerId)
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    resultList.extend(responseDict['values'])
                    pageSizeCount += len(responseDict['values'])
                    logger.debug('Application Port Profiles result pageSize = {}'.format(pageSizeCount))
                    pageNo += 1
            logger.debug('Total Application Port Profiles result count = {}'.format(len(resultList)))
            logger.debug('Application Port Profiles successfully retrieved')
            return resultList
        except Exception:
            raise

    @isSessionExpired
    def _searchApplicationPortProfile(self, applicationPortProfilesList, protocol, port):
        """
        Description :   Search for specific Application Port Profile
        Parameters  :   applicationPortProfilesList - application port profiles list (LIST)
                        protocol - protocal for the Application Port profile (STRING)
                        port - Port for the application Port profile (STRING)
        """
        try:
            # fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # data = self.vcdUtils.readJsonData(fileName)
            data = self.rollback.apiData
            protocol = protocol.upper()
            for value in applicationPortProfilesList:
                if len(value['applicationPorts']) == 1:
                    if value['scope'] == 'SYSTEM':
                        if value['applicationPorts'][0]['protocol'] == protocol and value['applicationPorts'][0]['destinationPorts'][0] == port:
                            logger.debug('Application Port Profile for the specific protocol'
                                         ' and port retrieved successfully')
                            return value['name'], value['id']
                    elif value['scope'] == 'TENANT' and value.get('orgRef'):
                        if value['applicationPorts'][0]['protocol'] == protocol and value['applicationPorts'][0]['destinationPorts'][0] == port:
                            logger.debug('Application Port Profile for the specific protocol'
                                         ' and port retrieved successfully')
                            return value['name'], value['id']
            else:
                url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                    vcdConstants.APPLICATION_PORT_PROFILES)
                payloadDict = {
                    "name": "CUSTOM-" + protocol + "-" + port,
                    "applicationPorts": [{
                        "protocol": protocol,
                        "destinationPorts": [port]
                    }],
                    "orgRef": {
                        "name": data['Organization']['@name'],
                        "id": data['Organization']['@id']
                    },
                    "contextEntityId": data['targetOrgVDC']['@id'],
                    "scope": "TENANT"
                }
                payloadData = json.dumps(payloadDict)
                self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                response = self.restClientObj.post(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    portprofileID = self._checkTaskStatus(taskUrl=taskUrl, returnOutput=True)
                    logger.debug('Application port profile is created successfully ')
                    customID = 'urn:vcloud:applicationPortProfile:' + portprofileID
                    return payloadDict['name'], customID
                response = response.json()
                raise Exception('Failed to create application port profile {} '.format(response['message']))
        except Exception:
            raise

    @isSessionExpired
    def createNatRuleTask(self, payloadData, url):
        """
            Description :   Create NAT rule task
            Parameters  :   payloadData - payload data
                            url - NAT rule task URL (STRING)
        """
        try:
            if payloadData['ruleType'] == 'NO_SNAT':
                payloadData['externalAddresses'] = ''
            self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
            # post api call to configure nat services on target edge gateway
            response = self.restClientObj.post(url, self.headers, data=json.dumps(payloadData))
            if response.status_code == requests.codes.accepted:
                # successful configuration of nat services on target edge gateway
                taskUrl = response.headers['Location']
                self._checkTaskStatus(taskUrl=taskUrl)
                if payloadData['id'] != '':
                    return payloadData['id']
                else:
                    return payloadData['name']
            else:
                # failed to configure nat services on target edge gateway
                response = response.json()
                raise Exception('Failed to configure configure NAT on Target {} '.format(response['message']))
        except Exception:
            raise

    @description("configuration of Target NAT")
    @remediate
    def configureTargetNAT(self, noSnatDestSubnet=None):
        """
        Description :   Configure the NAT service to the Target Gateway
        Parameters  :   noSnatDestSubnet    -   destimation subnet address (OPTIONAL)
        """
        try:
            targetEdgeGateway = copy.deepcopy(self.rollback.apiData['targetEdgeGateway'])
            logger.debug('NAT rules are getting configured')
            for sourceEdgeGateway in self.rollback.apiData['sourceEdgeGateway']:
                logger.debug("Configuring NAT Services in Target Edge Gateway - {}".format(sourceEdgeGateway['name']))
                sourceEdgeGatewayId = sourceEdgeGateway['id'].split(':')[-1]
                t1gatewayId = list(filter(lambda edgeGatewayData: edgeGatewayData['name'] == sourceEdgeGateway['name'], targetEdgeGateway))[0]['id']
                data = self.getEdgeGatewayNatConfig(sourceEdgeGatewayId, validation=False)
                # checking whether NAT rule is enabled or present in the source org vdc
                if not data or not data['enabled']:
                    logger.debug('NAT is not configured or enabled on Target Edge Gateway - {}'.format(sourceEdgeGateway['name']))
                    return
                if data['natRules']:
                    # get details of static routing config
                    staticRoutingConfig = self.getStaticRoutesDetails(sourceEdgeGatewayId)
                    # get details of BGP configuration
                    bgpConfigDetails = self.getEdgegatewayBGPconfig(sourceEdgeGatewayId, validation=False)
                    #get routing config details
                    routingConfigDetails = self.getEdgeGatewayRoutingConfig(sourceEdgeGatewayId, validation=False)
                    # get details of all Non default gateway subnet, default gateway and noSnatRules
                    allnonDefaultGatewaySubnetList, defaultGatewayDict, noSnatRulesList = self.getEdgeGatewayAdminApiDetails(
                        sourceEdgeGatewayId, staticRouteDetails=staticRoutingConfig)
                    natRuleList = data['natRules']['natRule']
                    # checking natrules is a list if not converting it into a list
                    sourceNATRules = natRuleList if isinstance(natRuleList, list) else [natRuleList]
                    url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                          vcdConstants.ALL_EDGE_GATEWAYS,
                                          vcdConstants.T1_ROUTER_NAT_CONFIG.format(t1gatewayId))
                    version = data['version']
                    applicationPortProfilesList = self.getApplicationPortProfiles()
                    userDefinedNAT = [natrule for natrule in sourceNATRules if natrule['ruleType'] == 'user']
                    # if source NAT is enabled NAT rule congiguration starts
                    statusForNATConfiguration = self.rollback.apiData.get('NATstatus', {})
                    rulesConfigured = statusForNATConfiguration.get(t1gatewayId, [])
                    if data['enabled'] == 'true':
                        for sourceNATRule in userDefinedNAT:
                            destinationIpDict = dict()
                            # checking whether 'ConfigStatus' key is present or not if present skipping that rule while remediation
                            if sourceNATRule['ruleId'] in rulesConfigured or sourceNATRule['ruleTag'] in rulesConfigured:
                                logger.debug('Rule Id: {} already created'.format(sourceNATRule['ruleId']))
                                continue
                            # loop to iterate over all subnets to check if translatedAddr in source rule does not belong
                            # to default gateway and is matches to primaryIp or subAllocated IP address
                            for eachParticipant in allnonDefaultGatewaySubnetList:
                                if eachParticipant['ipRanges'] is not None:
                                    for ipRange in eachParticipant['ipRanges']['ipRange']:
                                        participantStartAddr = ipRange['startAddress']
                                        participantEndAddr = ipRange['endAddress']
                                elif eachParticipant['ipRanges'] is None or eachParticipant['ipRanges'] == []:
                                    participantStartAddr = participantEndAddr = eachParticipant['ipAddress']
                                # check if translatedAddress belongs to suballocated address pool or primary IP
                                if self.ifIpBelongsToIpRange(sourceNATRule['translatedAddress'], participantStartAddr, participantEndAddr) \
                                        is True or sourceNATRule['translatedAddress'] == eachParticipant['ipAddress']:
                                    destinationIpDict = {'gateway': eachParticipant['gateway'],
                                                            'netmask': eachParticipant['netmask']}
                                    break
                            payloadData = self.createNATPayloadData(sourceNATRule, applicationPortProfilesList, version,
                                                                    defaultGatewayDict, destinationIpDict, noSnatRulesList,
                                                                    bgpConfigDetails, routingConfigDetails, noSnatDestSubnet)
                            payloadData = payloadData if isinstance(payloadData, list) else [payloadData]
                            for eachPayloadData in payloadData:
                                currentRuleId = self.createNatRuleTask(eachPayloadData, url)
                                # adding a key here to make sure the rule have configured successfully and when remediation skipping this rule
                                rulesConfigured.append(currentRuleId)
                                statusForNATConfiguration.update({t1gatewayId: rulesConfigured})
                                self.rollback.apiData['NATstatus'] = statusForNATConfiguration
                    else:
                        logger.debug('No NAT rules configured in Source Edge Gateway - {}'.format(sourceEdgeGateway['name']))
            logger.debug('NAT rules configured successfully on target')
        except Exception:
            raise
        finally:
            self.saveMetadataInOrgVdc()

    @description("configuration of BGP")
    @remediate
    def configBGP(self):
        """
        Description :   Configure BGP on the Target Edge Gateway
        """
        try:
            logger.debug('BGP is getting configured')
            for sourceEdgeGateway in self.rollback.apiData['sourceEdgeGateway']:
                logger.debug("Configuring BGP Services in Target Edge Gateway - {}".format(sourceEdgeGateway['name']))
                sourceEdgeGatewayId = sourceEdgeGateway['id'].split(':')[-1]
                edgeGatewayID = list(filter(lambda edgeGatewayData: edgeGatewayData['name'] == sourceEdgeGateway['name'],
                                     self.rollback.apiData['targetEdgeGateway']))[0]['id']

                bgpConfigDict = self.getEdgegatewayBGPconfig(sourceEdgeGatewayId, validation=False)
                data = self.getEdgeGatewayRoutingConfig(sourceEdgeGatewayId, validation=False)
                # checking whether bgp rule is enabled or present in the source edge  gateway; returning if no bgp in source edge gateway
                if not isinstance(bgpConfigDict, dict) or bgpConfigDict['enabled'] == 'false':
                    logger.debug('BGP service is disabled or not configured in Source Edge Gateway - {}'.format(sourceEdgeGateway['name']))
                    return
                logger.debug('BGP is getting configured in Source Edge Gateway - {}'.format(sourceEdgeGateway['name']))
                ecmp = "true" if data['routingGlobalConfig']['ecmp'] == "true" else "false"
                # url to get the details of the bgp configuration on T1 router i.e target edge gateway
                bgpurl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                         vcdConstants.T1_ROUTER_BGP_CONFIG.format(edgeGatewayID))
                # get api call to retrieve the T1 router bgp details
                versionresponse = self.restClientObj.get(bgpurl, self.headers)
                if versionresponse.status_code == requests.codes.ok:
                    versionresponseDict = json.loads(versionresponse.content)
                    version = versionresponseDict['version']['version']
                else:
                    version = 1
                # creating payload to configure bgp
                bgpPayloaddict = {
                    "enabled": bgpConfigDict['enabled'],
                    "ecmp": ecmp,
                    "localASNumber": bgpConfigDict['localASNumber'],
                    "gracefulRestart": {

                    },
                    "version": {
                        "version": version
                    }
                }
                if bgpConfigDict['gracefulRestart'] != "true":
                    bgpPayloaddict['gracefulRestart']['mode'] = "DISABLE"
                bgpPayloaddata = json.dumps(bgpPayloaddict)
                self.headers['Content-Type'] = 'application/json'
                # put api call to configure bgp on target edge gateway
                response = self.restClientObj.put(bgpurl, self.headers, data=bgpPayloaddata)
                if response.status_code == requests.codes.accepted:
                    # successful configuration of bgp services on target edge gateway
                    taskUrl = response.headers['Location']
                    self._checkTaskStatus(taskUrl=taskUrl)
                    logger.debug('BGP configuration updated successfully.')
                else:
                    # failure in configuring bgp on target edge gateway
                    response = response.json()
                    raise Exception('Failed to configure BGP in Source Edge Gateway {} - {}'
                                    .format(sourceEdgeGateway['name'], response['message']))
                # checking if bgp neighbours exist in source edge gateway; else returning
                if bgpConfigDict.get('bgpNeighbours'):
                    bgpNeighbours = bgpConfigDict['bgpNeighbours']['bgpNeighbour'] if isinstance(bgpConfigDict['bgpNeighbours']['bgpNeighbour'], list) else [bgpConfigDict['bgpNeighbours']['bgpNeighbour']]
                    self.createBGPNeighbours(bgpNeighbours, edgeGatewayID)
                    logger.debug('Successfully configured BGP in Source Edge Gateway - {}'.format(sourceEdgeGateway['name']))
                else:
                    logger.debug('No BGP neighbours configured in source BGP')
                    return
        except Exception:
            raise


    @description("configuration of DNS")
    @remediate
    def configureDNS(self):
        """
        Description : Configure DNS on specified edge gateway
        Parameters : edgeGatewayID - source edge gateway ID (STRING)
        """
        try:
            logger.debug('DNS is getting configured')
            for sourceEdgeGateway in self.rollback.apiData['sourceEdgeGateway']:
                sourceEdgeGatewayId = sourceEdgeGateway['id'].split(':')[-1]
                edgeGatewayID = list(filter(lambda edgeGatewayData: edgeGatewayData['name'] == sourceEdgeGateway['name'],
                                     self.rollback.apiData['targetEdgeGateway']))[0]['id']

                data = self.getEdgeGatewayDnsConfig(sourceEdgeGatewayId, validation=False)
                # configure dns on target only if source dns is enabled
                if data:
                    logger.debug('Configuring DNS on target edge gateway - {}'.format(sourceEdgeGateway['name']))
                    if isinstance(data, list):
                        forwarders = [forwarder['ipAddress'] for forwarder in data]
                    elif isinstance(data, OrderedDict):
                        forwarders = data['ipAddress'] if isinstance(data['ipAddress'], list) else [data['ipAddress']]
                    else:
                        forwardersList = [data]
                        forwarders = [forwarder['ipAddress'] for forwarder in forwardersList]
                    # creating payload for dns configuration
                    payloadData = {"enabled": True,
                                   "listenerIp": None,
                                   "defaultForwarderZone":
                                       {"displayName": "Default",
                                        "upstreamServers": forwarders},
                                   "conditionalForwarderZones": None,
                                   "version": None}
                    payloadData = json.dumps(payloadData)
                    # creating url for dns config update
                    url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                          vcdConstants.ALL_EDGE_GATEWAYS,
                                          vcdConstants.CREATE_DNS_CONFIG.format(edgeGatewayID))
                    self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                    # put api call to configure dns
                    apiResponse = self.restClientObj.put(url, headers=self.headers, data=payloadData)
                    if apiResponse.status_code == requests.codes.accepted:
                        # successful configuration of dns
                        task_url = apiResponse.headers['Location']
                        self._checkTaskStatus(taskUrl=task_url)
                        logger.debug('DNS service configured successfully on target edge gateway - {}'.format(sourceEdgeGateway['name']))
                        url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                              vcdConstants.ALL_EDGE_GATEWAYS,
                                              vcdConstants.CREATE_DNS_CONFIG.format(edgeGatewayID))
                        self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                        # get api call to get dns listener ip
                        response = self.restClientObj.get(url, headers=self.headers)
                        if response.status_code == requests.codes.ok:
                            responseDict = response.json()
                            logger.warning(
                                "Use this IP address {} when configuring VM's DNS server and Org VDC network's"
                                " DNS server".format(responseDict['listenerIp']))
                    else:
                        # failure in configuring dns
                        errorResponse = apiResponse.json()
                        raise Exception('Failed to configure DNS on target edge gateway {} - {} '
                                        .format(sourceEdgeGateway['name'], errorResponse['message']))
        except:
            raise

    @remediate
    def connectionPropertiesConfig(self, edgeGatewayID, ipsecConfigDict):
        """
        Description : Configuring Connection properties for IPSEC rules
        Parameters : edgeGatewayID - source edge gateway ID (STRING)
        """
        try:
            if not ipsecConfigDict or not ipsecConfigDict['enabled']:
                logger.debug('IPSec is not enabled or configured on source Org VDC.')
                return
            # url to retrive the ipsec rules on target edge gateway
            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.T1_ROUTER_IPSEC_CONFIG.format(edgeGatewayID))
            ipsecRulesResponse = self.restClientObj.get(url, self.headers)
            if ipsecRulesResponse.status_code == requests.codes.ok:
                ipsecrules = json.loads(ipsecRulesResponse.content)
                ipesecrules = ipsecrules['values'] if isinstance(ipsecrules['values'], list) else [ipsecrules]
                sourceIPsecSites = ipsecConfigDict['sites']['sites'] if isinstance(ipsecConfigDict['sites']['sites'], list) else [ipsecConfigDict['sites']['sites']]
                for sourceIPsecSite in sourceIPsecSites:
                    for ipsecrule in ipesecrules:
                        if ipsecrule['name'] == sourceIPsecSite['name']:
                            ruleid = ipsecrule['id']
                            # checking whether 'ConfigStatus' key is present or not if present skipping that rule while remediation
                            if self.rollback.apiData.get(ruleid):
                                continue
                            propertyUrl = "{}{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                                            vcdConstants.T1_ROUTER_IPSEC_CONFIG.format(edgeGatewayID), vcdConstants.CONNECTION_PROPERTIES_CONFIG.format(ruleid))
                            payloadDict = {
                                    "securityType": "CUSTOM",
                                    "ikeConfiguration": {
                                        "ikeVersion": vcdConstants.CONNECTION_PROPERTIES_IKE_VERSION.get(sourceIPsecSite['ikeOption']),
                                        "dhGroups": [vcdConstants.CONNECTION_PROPERTIES_DH_GROUP.get(sourceIPsecSite['dhGroup'])],
                                        "digestAlgorithms": [vcdConstants.CONNECTION_PROPERTIES_DIGEST_ALGORITHM.get(sourceIPsecSite['digestAlgorithm'])],
                                        "encryptionAlgorithms": [vcdConstants.CONNECTION_PROPERTIES_ENCRYPTION_ALGORITHM.get(sourceIPsecSite['encryptionAlgorithm'])],
                                    },
                                    "tunnelConfiguration": {
                                        "perfectForwardSecrecyEnabled": "true" if sourceIPsecSite['enablePfs'] else "false",
                                        "dhGroups": [vcdConstants.CONNECTION_PROPERTIES_DH_GROUP.get(sourceIPsecSite['dhGroup'])],
                                        "encryptionAlgorithms": [vcdConstants.CONNECTION_PROPERTIES_ENCRYPTION_ALGORITHM.get(sourceIPsecSite['encryptionAlgorithm'])],
                                        "digestAlgorithms": [vcdConstants.CONNECTION_PROPERTIES_DIGEST_ALGORITHM.get(sourceIPsecSite['digestAlgorithm'])]
                                    }
                                }
                            payloadData = json.dumps(payloadDict)
                            self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                            # put api call to configure dns
                            apiResponse = self.restClientObj.put(propertyUrl, headers=self.headers, data=payloadData)
                            if apiResponse.status_code == requests.codes.accepted:
                                # successfully configured connection property of ipsec
                                task_url = apiResponse.headers['Location']
                                self._checkTaskStatus(taskUrl=task_url)
                                # adding a key here to make sure the rule have configured successfully and when remediation skipping this rule
                                self.rollback.apiData[ruleid] = True
                                logger.debug('Connection properties successfully configured for ipsec rule {}'.format(ipsecrule['name']))
                            else:
                                # failure in configuring ipsec configuration properties
                                errorResponse = apiResponse.json()
                                raise Exception('Failed to configure connection properties for ipsec rule {} with errors - {} '.format(ipsecrule['name'], errorResponse['message']))
        except Exception:
            raise

    def createSecurityGroup(self, networkID, firewallRule, edgeGatewayID):
        """
           Description: Create security groups in the target Edge gateway
           Paramater: networkID: ID of Org VDC network
                      firewallRule: Details of firewall rule
                      edgeGatewayID: Edgegateway ID
                      targetOrgVDCId - ID of target org vdc (STRING)
        """
        try:
            # taking target edge gateway id from apioutput json file
            targetOrgVdcId = self.rollback.apiData['targetOrgVDC']['@id']
            target_networks = self.retrieveNetworkListFromMetadata(targetOrgVdcId, orgVDCType='target')
            networkgroups = networkID
            firewallRule = firewallRule
            edgeGatewayId = edgeGatewayID
            firewallGroupIds = []
            groupId = []
            newMembers = []
            allGroupMembers = []
            newFirewallGroupIds = []
            # getting the network details for the creation of the firewall group
            members = list()
            logger.debug('Configuring security group for firewall {}.'.format(firewallRule['id']))
            for networkgroup in networkgroups:
                url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                    vcdConstants.GET_ORG_VDC_NETWORK_BY_ID.format(networkgroup))
                getnetworkResponse = self.restClientObj.get(url, self.headers)
                if getnetworkResponse.status_code == requests.codes.ok:
                    responseDict = json.loads(getnetworkResponse.content)
                    for target_network in target_networks:
                        if responseDict['name']+'-v2t' == target_network['name']:
                            network_name = target_network['name']
                            network_id = target_network['id']
                            members.append({'name': network_name, 'id': network_id})
            # getting the already created firewall groups summaries
            firewallGroupsUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                              vcdConstants.FIREWALL_GROUPS_SUMMARY)
            getsummaryResponse = self.restClientObj.get(firewallGroupsUrl, self.headers)
            if getsummaryResponse.status_code == requests.codes.ok:
                summaryResponseDict = json.loads(getsummaryResponse.content)
                summaryValues = summaryResponseDict['values']
                for summary in summaryValues:
                    # checking if the firewall group is already created for the given edge gateway
                    # if yes then appending the firewall group id to the list
                    if summary.get('edgeGatewayRef'):
                        if summary['edgeGatewayRef']['id'] == edgeGatewayId:
                            firewallGroupIds.append(summary['id'])
            for firewallGroupId in firewallGroupIds:
                # getting the details of specific firewall group
                groupIdUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                           vcdConstants.FIREWALL_GROUP.format(firewallGroupId))
                getGroupResponse = self.restClientObj.get(groupIdUrl, self.headers)
                if getGroupResponse.status_code == requests.codes.ok:
                    groupResponse = json.loads(getGroupResponse.content)
                    groupMembers = groupResponse['members']
                    if groupMembers:
                        # here appending all the group members to the list
                        for member in groupMembers:
                            allGroupMembers.append(member)
                            # for every group checking if both network and group members are same then appending it in list
                            if member in members:
                                groupId.append(firewallGroupId)
            for member in members:
                # validating if the network member doesn't exists in the members of the firewall groups which are already created
                # then adding it to the list which will be used for the creation of the new firewall group
                if member not in allGroupMembers:
                    newMembers.append(member)
            else:
                # if the newMembers list is empty then
                # return the id of that existing firewall group with same member present in it
                if not newMembers:
                    return groupId
                # else create the new firewall group
                else:
                    for member in newMembers:
                        # getting the new member name from the list
                        network_name = member['name'].split('-', -1)
                        # popping out '-v2t' from the name fetched above
                        network_name.pop(-1)
                        # joining the remaining substrings
                        network_name = '-'.join(network_name)
                        # creating payload data to create firewall group
                        firewallGroupDict = {'name': 'SecurityGroup-(' + network_name + ')'}
                        if self.rollback.apiData.get(firewallGroupDict['name']):
                            continue
                        firewallGroupDict['edgeGatewayRef'] = {'id': edgeGatewayId}
                        firewallGroupDict['members'] = [member]
                        firewallGroupDict['type'] = vcdConstants.SECURITY_GROUP
                        firewallGroupData = json.dumps(firewallGroupDict)
                        # url to create firewall group
                        firewallGroupUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                         vcdConstants.CREATE_FIREWALL_GROUP)
                        self.headers['Content-Type'] = 'application/json'
                        # post api call to create firewall group
                        response = self.restClientObj.post(firewallGroupUrl, self.headers,data=firewallGroupData)
                        if response.status_code == requests.codes.accepted:
                            # successful creation of firewall group
                            taskUrl = response.headers['Location']
                            firewallGroupId = self._checkTaskStatus(taskUrl=taskUrl, returnOutput=True)
                            self.rollback.apiData[firewallGroupDict['name']] = True
                            logger.debug('Successfully configured security group for firewall {}.'.format(firewallRule['id']))
                            # appending the new firewall group id
                            newFirewallGroupIds.append('urn:vcloud:firewallGroup:{}'.format(firewallGroupId))
                        else:
                            # failure in creation of firewall group
                            response = response.json()
                            raise Exception('Failed to create Security Group - {}'.format(response['message']))
                    # returning the firewall group ids list
                    return newFirewallGroupIds
        except Exception:
            raise

    @remediate
    def createBGPNeighbours(self, bgpNeighbours, edgeGatewayID):
        """
        Description: create BGP Neighbours in target edge gateway
        parameters: edgeGatewayID: edgegateway ID
                    bgpNeighbours: list of bgpNeighbours
        """
        try:
            # iterating over the source edge gateway's bgp neighbours
            for bgpNeighbour in bgpNeighbours:
                # if configStatus flag is already set means that the bgpNeighbor rule is already configured, if so then skipping the configuring of same rule and moving to the next bgpNeighbour rule
                if self.rollback.apiData.get(bgpNeighbour['ipAddress']):
                    continue
                # creating payload to configure same bgp neighbours in target edge gateway as those in source edge gateway
                bgpNeighbourpayloadDict = {
                    "neighborAddress": bgpNeighbour['ipAddress'],
                    "remoteASNumber": bgpNeighbour['remoteASNumber'],
                    "keepAliveTimer": int(bgpNeighbour['keepAliveTimer']),
                    "holdDownTimer": int(bgpNeighbour['holdDownTimer']),
                    "allowASIn": "false",
                    "neighborPassword": bgpNeighbour['password'] if bgpNeighbour.get('password') else ''
                }
                # checking for the bgp filters
                if bgpNeighbour.get("bgpFilters"):
                    # retrieving the list instance of bgp filters of source edge gateway
                    bgpFilters = bgpNeighbour['bgpFilters']['bgpFilter'] if isinstance(
                        bgpNeighbour['bgpFilters']['bgpFilter'], list) else [bgpNeighbour['bgpFilters']['bgpFilter']]
                    infilters = [bgpFilter for bgpFilter in bgpFilters if bgpFilter['direction'] == 'in']
                    outfilter = [bgpFilter for bgpFilter in bgpFilters if bgpFilter['direction'] == 'out']
                    if infilters:
                        inRoutesFilterRef = self.createBGPFilters(bgpFilters=infilters, edgeGatewayID=edgeGatewayID, filtertype='in', bgpNeighbour=bgpNeighbour)
                        bgpNeighbourpayloadDict['inRoutesFilterRef'] = inRoutesFilterRef if inRoutesFilterRef else ''
                    if outfilter:
                        outRoutesFilterRef = self.createBGPFilters(bgpFilters=outfilter, edgeGatewayID=edgeGatewayID, filtertype='out', bgpNeighbour=bgpNeighbour)
                        bgpNeighbourpayloadDict['outRoutesFilterRef'] = outRoutesFilterRef if outRoutesFilterRef else ''
                # time.sleep put bcoz prefix list still takes time after creation and the api response is success
                time.sleep(5)
                bgpNeighbourpayloadData = json.dumps(bgpNeighbourpayloadDict)
                # url to configure bgp neighbours
                bgpNeighboururl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                  vcdConstants.ALL_EDGE_GATEWAYS,
                                                  vcdConstants.CREATE_BGP_NEIGHBOR_CONFIG.format(edgeGatewayID))
                self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                # post api call to configure bgp neighbours
                bgpNeighbourresponse = self.restClientObj.post(bgpNeighboururl, headers=self.headers,
                                                               data=bgpNeighbourpayloadData)
                if bgpNeighbourresponse.status_code == requests.codes.accepted:
                    # successful configuration of bgp neighbours
                    task_url = bgpNeighbourresponse.headers['Location']
                    self._checkTaskStatus(taskUrl=task_url)
                    # setting the configStatus flag meaning the particular bgpNeighbour rule is configured successfully in order to skip its reconfiguration
                    self.rollback.apiData[bgpNeighbour['ipAddress']] = True
                    logger.debug('BGP neighbor created successfully')
                else:
                    # failure in configuring bgp neighbours
                    bgpNeighbourresponse = bgpNeighbourresponse.json()
                    raise Exception('Failed to create neighbors {} '.format(bgpNeighbourresponse['message']))
            logger.debug('BGP neighbors configured successfully')
        except Exception:
            raise

    @isSessionExpired
    def createBGPFilters(self, bgpFilters, edgeGatewayID, filtertype, bgpNeighbour):
        """
        Description: Create BGP in-filters and out-filters
        parameters: bgpfilters: in and out filters of bgp neighbours
                    edgeGatewayID: ID of edgegateway
                    filtertype: in/out
                    bgpNeighbour: details of BGP Neighbour
        """
        try:
            FilterpayloadDict = {'prefixes': []}
            # iterating over the bgp filters
            for bgpFilter in bgpFilters:
                FilterpayloadDict['prefixes'].append({
                    "network": bgpFilter['network'], "action": bgpFilter['action'].upper(),
                    "greaterThanEqualTo": bgpFilter['ipPrefixGe'] if 'ipPrefixGe' in bgpFilter.keys() else "",
                    "lessThanEqualTo": bgpFilter['ipPrefixLe'] if 'ipPrefixLe' in bgpFilter.keys() else ""})
            if filtertype == "in":
                FilterpayloadDict['name'] = bgpNeighbour['ipAddress'] + "-" + "IN-" + str(random.randint(1, 1000))
            elif filtertype == "out":
                FilterpayloadDict['name'] = bgpNeighbour['ipAddress'] + "-" + "OUT-" + str(random.randint(1, 1000))
            FilterpayloadDict = json.dumps(FilterpayloadDict)
            # url to configure in direction filtered bgp services
            infilterurl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                          vcdConstants.ALL_EDGE_GATEWAYS,
                                          vcdConstants.CREATE_PREFIX_LISTS_BGP.format(edgeGatewayID))
            self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
            # post api call to configure in direction filtered bgp services
            infilterresponse = self.restClientObj.post(infilterurl, headers=self.headers,
                                                       data=FilterpayloadDict)
            if infilterresponse.status_code == requests.codes.accepted:
                # successful configuration of in direction filtered bgp services
                taskUrl = infilterresponse.headers['Location']
                FilterpayloadDict = json.loads(FilterpayloadDict)
                self._checkTaskStatus(taskUrl=taskUrl)
                logger.debug('Successfully created BGP filter {}'.format(FilterpayloadDict['name']))
                # get api call to retrieve
                inprefixListResponse = self.restClientObj.get(infilterurl, self.headers)
                inprefixList = inprefixListResponse.json()
                values = inprefixList['values']
                for value in values:
                    if FilterpayloadDict['name'] == value['name']:
                        routesFilterRef = {"id": value['id'], "name": value['name']}
                        return routesFilterRef
            else:
                infilterresponseData = infilterresponse.json()
                raise Exception('Failed to create BGP filters {}'.format(infilterresponseData['message']))
        except Exception:
            raise

    def createNATPayloadData(self, sourceNATRule, applicationPortProfilesList, version,
                             defaultEdgeGateway, destinationIpDict, staticRoutesList, bgpDetails,
                             routingConfigDetails, noSnatDestSubnetList = None):
        """
                Description :   Creates the payload data for the NAT service to the Target Gateway
                Parameters  :   sourceNATRule   -   NAT Rule of source gateway  (DICT)
                                applicationPortProfilesList   -   Application Port Profiles  (LIST)
                                version         -   version
                                defaultEdgeGateway   -   default edge gateway details
                                destinationIpDict   -   destination IP dict
                                staticRoutesList    -   static rule configuration (LIST)
                                bgpDetails  -   BGP configuration details
                                routingConfigDetails - Edge gateway routing config
                                noSnatDestSubnetList    -   NoSNAT destination subnet from sample input
        """
        # creating common payload dict for both DNAT AND SNAT
        payloadDict = {
            "ruleId": sourceNATRule['ruleId'],
            "ruleTag": sourceNATRule['ruleTag'],
            "ruleDescription": sourceNATRule['description'] if sourceNATRule.get('description') else '',
            "enabled": "true" if sourceNATRule['enabled'] == "true" else "false",
            "action": sourceNATRule['action'].upper(),
            "loggingEnabled": "true" if sourceNATRule['loggingEnabled'] == "true" else "false",
            "version": version
        }
        # configuring DNAT
        if sourceNATRule['action'] == "dnat":
            translatedAddressCIDR = sourceNATRule['translatedAddress']
            # updating payload dict
            payloadDict.update({
                "originalAddress": sourceNATRule['originalAddress'],
                "translatedAddress": translatedAddressCIDR
            })
            # adding dnatExternalPort port profile to payload data
            if float(self.version) <= float(vcdConstants.API_VERSION_PRE_ZEUS):
                payloadDict["internalPort"] = sourceNATRule['originalPort'] if sourceNATRule[
                                                                                       'originalPort'] != 'any' else ''
            else:
                payloadDict["dnatExternalPort"] = sourceNATRule['originalPort'] if sourceNATRule[
                                                                                     'originalPort'] != 'any' else ''
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
            # creating payload data
            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.CREATE_DNAT_TEMPLATE, apiVersion=self.version)
            payloadData = json.loads(payloadData)
            # if protocol and port is not equal to any search or creating new application port profiles
            if sourceNATRule['protocol'] != "any" and sourceNATRule['translatedPort'] != "any":
                protocol_port_name, protocol_port_id = self._searchApplicationPortProfile(
                    applicationPortProfilesList, sourceNATRule['protocol'], sourceNATRule['translatedPort'])
                payloadData["applicationPortProfile"] = {"name": protocol_port_name, "id": protocol_port_id}
            # checking the protocol is icmp
            elif sourceNATRule['protocol'] == "icmp":
                # checking the icmptype is any
                if sourceNATRule['icmpType'] == "any":
                    for value in applicationPortProfilesList:
                        if value['name'] == vcdConstants.ICMP_ALL:
                            protocol_port_name, protocol_port_id = value['name'], value['id']
                            payloadData["applicationPortProfile"] = {"name": protocol_port_name,
                                                                     "id": protocol_port_id}
                else:
                    # getting icmp port profiles
                    icmpurl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                              vcdConstants.APPLICATION_PORT_PROFILES,
                                              vcdConstants.GET_ICMP_PORT_PROFILES_FILTER)
                    icmpResponse = self.restClientObj.get(icmpurl, self.headers)
                    if icmpResponse.status_code == requests.codes.ok:
                        icmpresponseDict = icmpResponse.json()
                        icmpvalues = icmpresponseDict['values']
                        # iterating through icmp values
                        for icmpvalue in icmpvalues:
                            # checking if icmp type is not any and icmp port is not ICMPv4-ALL
                            if sourceNATRule['icmpType'] != "any" and "-" not in icmpvalue['name']:
                                start = sourceNATRule['icmpType'].split('-')[0]
                                end = sourceNATRule['icmpType'].split('-')[-1]
                                sourceIcmpType = start + " " + end
                                protocol_Name = icmpvalue['name'].split("ICMP")
                                protocol_Name_id = "".join(protocol_Name)
                                protocol_Name_id = protocol_Name_id.strip()
                                # checking the source icmp type and target icmp type by converting it into upper
                                if sourceIcmpType.upper() == protocol_Name_id.upper():
                                    protocol_port_name, protocol_port_id = icmpvalue['name'], icmpvalue['id']
                                    payloadData['applicationPortProfile'] = {"name": protocol_port_name,
                                                                             "id": protocol_port_id}
                                    break
                                # checking source icmp redirect type and icmp redirect port profile
                                if sourceNATRule['icmpType'] == "redirect" and icmpvalue['name'] == "ICMP Redirect":
                                    protocol_port_name, protocol_port_id = icmpvalue['name'], icmpvalue[
                                        'id']
                                    payloadData["applicationPortProfile"] = {"name": protocol_port_name,
                                                                             "id": protocol_port_id}
                                    break
                            # for the icmp type which is not present in port profiles, will taking it as ICMPv4-ALL
                            elif icmpvalue['name'] == vcdConstants.ICMP_ALL:
                                protocol_port_name, protocol_port_id = icmpvalue['name'], icmpvalue['id']
                                payloadData["applicationPortProfile"] = {"name": protocol_port_name,
                                                                         "id": protocol_port_id}
                                break
            else:
                payloadData["applicationPortProfile"] = None
        # configuring SNAT
        if sourceNATRule['action'] == "snat":
            allSnatPayloadList = list()
            payloadDataList = list()
            ifbgpRouterIdAddress = bool()
            # if range present in source orginal address converting it into cidr
            if "-" in sourceNATRule['originalAddress']:
                translatedAddressCIDR = self.cidrCalculator(sourceNATRule['originalAddress'])
            else:
                translatedAddressCIDR = sourceNATRule['originalAddress']
            payloadDict.update({
                "originalAddress": sourceNATRule['translatedAddress'],
                "translatedAddress": translatedAddressCIDR
            })
            ipInSuAllocatedStatus = False
            if defaultEdgeGateway is {}:
                raise Exception('Default Gateway not configured on Edge Gateway')
            # If dynamic routerId belongs to default gateway subnet
            if isinstance(bgpDetails, dict):
                networkAddress = ipaddress.IPv4Network('{}/{}'.format(defaultEdgeGateway['gateway'],
                                                                           defaultEdgeGateway['subnetPrefixLength']),
                                                       strict=False)
                ifbgpRouterIdAddress = ipaddress.ip_address(routingConfigDetails['routingGlobalConfig']['routerId']) in \
                                       ipaddress.ip_network(networkAddress)

            # bgpRouterIdAddress = False
            for eachIpRange in defaultEdgeGateway['ipRanges']:
                startAddr, endAddr = eachIpRange.split('-')
                # if translated IP address belongs to default gateway Ip range return True
                ipInSuAllocatedStatus = self.ifIpBelongsToIpRange(sourceNATRule['translatedAddress'],
                                                                  startAddr, endAddr)
                if ipInSuAllocatedStatus:
                    if staticRoutesList:
                        for eachNetwork in staticRoutesList:
                            staticNoSnatPayloadDict = copy.deepcopy(payloadDict)
                            staticNoSnatPayloadDict['ruleId'] = ''
                            staticNoSnatPayloadDict['ruleTag'] = 'staticRouteNoSnat' + payloadDict['ruleTag']
                            staticNoSnatPayloadDict['action'] = 'NO_SNAT'
                            staticNoSnatPayloadDict['snatDestinationAddresses'] = eachNetwork
                            allSnatPayloadList.append(staticNoSnatPayloadDict)
                    if noSnatDestSubnetList is not None and isinstance(bgpDetails, dict) and \
                            bgpDetails['enabled'] == 'true' and ifbgpRouterIdAddress == False:
                        noSnatDestSubnetList = noSnatDestSubnetList if isinstance(noSnatDestSubnetList, list) else [noSnatDestSubnetList]
                        for eachExtNetwork in noSnatDestSubnetList:
                            bgpNoSnatPayloadDict = copy.deepcopy(payloadDict)
                            bgpNoSnatPayloadDict['ruleId'] = ''
                            bgpNoSnatPayloadDict['ruleTag'] = 'bgpNoSnat-' + payloadDict['ruleTag']
                            bgpNoSnatPayloadDict['action'] = 'NO_SNAT'
                            bgpNoSnatPayloadDict['snatDestinationAddresses'] = eachExtNetwork
                            allSnatPayloadList.append(bgpNoSnatPayloadDict)
            # iftranslated IP address does not belongs to default gateway update snatDestinationAddresses
            if ipInSuAllocatedStatus == False and destinationIpDict != {}:
                networkAddr = ipaddress.ip_network('{}/{}'.format(destinationIpDict['gateway'],
                                                                  destinationIpDict['netmask']),
                                                   strict=False)
                payloadDict.update({'snatDestinationAddresses': networkAddr.compressed})
            else:
                payloadDict.update({'snatDestinationAddresses': ''})
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
            # creating payload data
            allSnatPayloadList.append(payloadDict)
            for eachDict in allSnatPayloadList:
                payloadData = self.vcdUtils.createPayload(filePath, eachDict, fileType='json',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.CREATE_SNAT_TEMPLATE, apiVersion=self.version)
                payloadDataList.append(json.loads(payloadData))
            if payloadDataList:
                return payloadDataList
        return payloadData

    @isSessionExpired
    def createIPSET(self, ipsetgroups, edgeGatewayId):
        """
        Description : Create IPSET as security group for firewall
        Parameters: ipsetgroups - All the IPset's information in Source Org VDC
                    edgeGatewayId - The id of the Target edge gateway(for NSX API so entity id)
        """
        try:
            if ipsetgroups:
                logger.debug('Creating IPSET in Target Edge Gateway')
                firewallGroupIds = list()
                firewallGroupName = list()
                firewallIdDict = dict()
                # iterating over the ipset group list
                for ipsetgroup in ipsetgroups:
                    ipAddressList = list()
                    # url to retrieve the info of ipset group by id
                    ipseturl = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                             vcdConstants.GET_IPSET_GROUP_BY_ID.format(ipsetgroup['objectId']))
                    # get api call to retrieve the ipset group info
                    ipsetresponse = self.restClientObj.get(ipseturl, self.headers)
                    if ipsetresponse.status_code == requests.codes.ok:
                        # successful retrieval of ipset group info
                        ipsetresponseDict = xmltodict.parse(ipsetresponse.content)
                        if self.rollback.apiData.get('firewallIdDict'):
                            if self.rollback.apiData['firewallIdDict'].get(edgeGatewayId):
                                if self.rollback.apiData['firewallIdDict'][edgeGatewayId].get(ipsetresponseDict['ipset']['name']):
                                    continue
                        # storing the ip-address and range present in the IPSET
                        ipsetipaddress = ipsetresponseDict['ipset']['value']

                        description = ipsetresponseDict['ipset']['description'] if ipsetresponseDict['ipset'].get(
                            'description') else ''
                        # if multiple ip=address or range present in the ipset spliting it with ','
                        if "," in ipsetipaddress:
                            ipsetipaddresslist = ipsetipaddress.split(',')
                            ipAddressList.extend(ipsetipaddresslist)
                        else:
                            ipAddressList.append(ipsetipaddress)
                        # creating payload data to create firewall group
                        firewallGroupDict = {'name': ipsetresponseDict['ipset']['name'], 'description': description,
                                             'edgeGatewayRef': {'id': edgeGatewayId}, 'ipAddresses': ipAddressList}
                        firewallGroupDict = json.dumps(firewallGroupDict)
                        # url to create firewall group
                        firewallGroupUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                         vcdConstants.CREATE_FIREWALL_GROUP)
                        self.headers['Content-Type'] = 'application/json'
                        # post api call to create firewall group
                        response = self.restClientObj.post(firewallGroupUrl, self.headers,
                                                           data=firewallGroupDict)
                        if response.status_code == requests.codes.accepted:
                            # successful creation of firewall group
                            taskUrl = response.headers['Location']
                            firewallGroupId = self._checkTaskStatus(taskUrl=taskUrl, returnOutput=True)
                            self.rollback.apiData[ipsetgroup['objectId'].split(':')[-1]] = 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)
                            firewallGroupIds.append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
                            firewallGroupName.append(ipsetresponseDict['ipset']['name'])
                            # creating a dict with firewallName as key and firewallIDs as value
                            firewallIdDict = dict(zip(firewallGroupName, firewallGroupIds))
                        else:
                            errorResponse = response.json()
                            raise Exception('Failed to create IPSET - {}'.format(errorResponse['message']))
                    else:
                        errorResponse = ipsetresponse.json()
                        raise Exception('Failed to get IPSET details due to error - {}'.format(errorResponse['message']))
                if self.rollback.apiData.get('firewallIdDict'):
                    self.rollback.apiData['firewallIdDict'].update({edgeGatewayId: firewallIdDict})
                else:
                    self.rollback.apiData['firewallIdDict'] = {edgeGatewayId: firewallIdDict}
                logger.debug('Successfully configured IPSET in target')
                return firewallIdDict
        except Exception:
            raise

    @isSessionExpired
    def dhcpRollBack(self):
        """
        Description: Creating DHCP service in Source Org VDC for roll back
        """
        try:
            data = self.rollback.apiData['sourceEdgeGatewayDHCP']
            # ID of source edge gateway
            for sourceEdgeGatewayId in self.rollback.apiData['sourceEdgeGatewayId']:
                edgeGatewayId = sourceEdgeGatewayId.split(':')[-1]
                # url for dhcp configuration
                url = "{}{}{}?async=true".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                      vcdConstants.NETWORK_EDGES,
                                      vcdConstants.EDGE_GATEWAY_DHCP_CONFIG_BY_ID .format(edgeGatewayId))
                # if DHCP pool was present in the source
                if data[sourceEdgeGatewayId]['ipPools']:
                    del data[sourceEdgeGatewayId]['version']
                    payloadData = json.dumps(data[sourceEdgeGatewayId])
                    self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                    response = self.restClientObj.put(url, self.headers, data=payloadData)
                    if response.status_code == requests.codes.accepted:
                        # only need job ID from Location so spliting it
                        jobId = response.headers['Location'].split('/')[-1]
                        taskUrl = '{}{}{}'.format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress), vcdConstants.NETWORK_EDGES, vcdConstants.NSX_JOBS.format(jobId))
                        # initial time
                        timeout = 0.0
                        # polling till time exceeds
                        while timeout < vcdConstants.VCD_CREATION_TIMEOUT:
                            response = self.restClientObj.get(taskUrl, self.headers)
                            if response.status_code == requests.codes.ok:
                                responseDict = xmltodict.parse(response.content)
                                # checking for the status of each polling call for 'Completed'
                                if responseDict['edgeJob']['status'] == 'COMPLETED':
                                    logger.info('Rollback for dhcp is completed successfully')
                                    break
                                # checking if the task failed
                                if responseDict['edgeJob']['status'] == "FAILED":
                                    logger.debug("Failed configuring DHCP service in edge gateway {}".format(responseDict['edgeJob']['message']))
                                    raise Exception(responseDict['edgeJob']['message'])
        except Exception:
            raise

    @isSessionExpired
    def ipsecRollBack(self):
        """
        Description: Configuring IPSEC service in source Edge gateway for roll back
        """
        try:
            for sourceEdgeGateway in self.rollback.apiData['sourceEdgeGateway']:
                # ID of source edge gateway
                edgeGatewayId = sourceEdgeGateway['id'].split(':')[-1]
                data = self.rollback.apiData['ipsecConfigDict'][sourceEdgeGateway['name']]
                # url for ipsec configuration
                url = "{}{}{}&async=true".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                                 vcdConstants.NETWORK_EDGES,
                                                 vcdConstants.EDGE_GATEWAY_IPSEC_CONFIG.format(edgeGatewayId))
                if data['sites']:
                    del data['version']
                    for site in data['sites']['sites']:
                        del site['siteId']
                        if site.get('ConfigStatus'):
                            del site['ConfigStatus']
                    payloadData = json.dumps(data)
                    self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                    response = self.restClientObj.put(url, self.headers, data=payloadData)
                    if response.status_code == requests.codes.accepted:
                        # only need job ID from Location so spliting it
                        jobId = response.headers['Location'].split('/')[-1]
                        taskUrl = '{}{}{}'.format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                                  vcdConstants.NETWORK_EDGES, vcdConstants.NSX_JOBS.format(jobId))
                        # initial time
                        timeout = 0.0
                        # polling till time exceeds
                        while timeout < vcdConstants.VCD_CREATION_TIMEOUT:
                            response = self.restClientObj.get(taskUrl, self.headers)
                            if response.status_code == requests.codes.ok:
                                responseDict = xmltodict.parse(response.content)
                                # checking for the status of each polling call for 'Completed'
                                if responseDict['edgeJob']['status'] == 'COMPLETED':
                                    logger.debug('Rollback for IPSEC is completed successfully in {}'.format(sourceEdgeGateway['name']))
                                    break
                                    # checking if the task failed
                                if responseDict['edgeJob']['status'] == "FAILED":
                                    logger.debug("Failed configuring IPSEC VPN in edge gateway {}".format(responseDict['edgeJob']['message']))
                                    raise Exception(responseDict['edgeJob']['message'])
        except Exception:
            raise

    @isSessionExpired
    def getCerticatesFromTenant(self):
        """
            Description :   Fetch the names of certificates present in tenant portal
            Returns     :   dictionary of names and ids of certificates present in tenant portal
        """
        try:
            logger.debug('Getting the certificates present in vCD tenant portal')
            url = '{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.CERTIFICATE_URL)

            # updating headers for get request
            self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
            self.headers['X-VMWARE-VCLOUD-TENANT-CONTEXT'] = self.rollback.apiData['Organization']['@id'].split(':')[-1]

            response = self.restClientObj.get(url=url, headers=self.headers)
            if response.status_code == requests.codes.ok:
                logger.debug('Successfully retrieved load balancer certificates')
                responseDict = response.json()
                # Retrieving certificate names from certificates
                certificateNameIdDict = {certificate['alias']: certificate['id'] for certificate in responseDict.get('values', [])}

                # removing tenant context header after retrieving certificate from tenant portal
                del self.headers['X-VMWARE-VCLOUD-TENANT-CONTEXT']

                return certificateNameIdDict
            else:
                errorResponseDict = response.json()
                raise Exception("Failed to retrieve certificates from vcd due to error - {}".format(errorResponseDict[
                                                                                                        'message']))
        except:
            raise


    @isSessionExpired
    def uploadCertificate(self, certificate, certificateName):
        """
        Description :   Upload the certificate for load balancer HTTPS configuration
        Params      :   certificate - certificate to be uploaded in vCD (STRING)
                        certificateName - name of certificate that if required (STRING)
        """
        try:
            logger.debug('Upload the certificate for load balancer HTTPS configuration')
            pkcs8PemFileName = 'privateKeyPKCS8.pem'
            url = '{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.CERTIFICATE_URL)

            # reading pkcs8 format private key from file
            with open(pkcs8PemFileName, 'r', encoding='utf-8') as privateFile:
                privateKey = privateFile.read()

            payloadData = {
                "alias": certificateName,
                "privateKey": privateKey,
                "privateKeyPassphrase": "",
                "certificate": certificate,
                "description": ""
            }
            payloadData = json.dumps(payloadData)

            # updating headers for post request
            self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
            self.headers['X-VMWARE-VCLOUD-TENANT-CONTEXT'] = self.rollback.apiData['Organization']['@id'].split(':')[-1]

            response = self.restClientObj.post(url=url, headers=self.headers, data=payloadData)
            if response.status_code == requests.codes.created:
                logger.debug('Successfully uploaded load balancer certificate')
            else:
                errorResponseDict = response.json()
                raise Exception("Failed to upload certificate '{}' in vcd due to error - {}".format(certificateName, errorResponseDict['message']))

            # removing tenant context header after uploding certificate to tenant portal
            del self.headers['X-VMWARE-VCLOUD-TENANT-CONTEXT']
        except:
            raise
        finally:
            # Removing the pem file afte operation
            if os.path.exists(pkcs8PemFileName):
                os.remove(pkcs8PemFileName)

    @isSessionExpired
    def getPoolSumaryDetails(self, edgeGatewayId):
        """
            Description :   Fetch details of load balancer pools of a edge gateway
            Parameters  :   edgeGatewayId - ID of edge gateway whose data is to be fetched
            Returns     :   List of load balancer pools of edge gateway(LIST)
        """
        try:
            url = '{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.EDGE_GATEWAY_LOADBALANCER_POOLS_USING_ID.format(edgeGatewayId))

            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                logger.debug("Retrieved load balancer pool details successfully")
                responseDict = response.json()
                resultTotal = responseDict['resultTotal']
            else:
                raise Exception('Failed to fetch load balancer pool details')
            pageNo = 1
            pageSizeCount = 0
            targetLoadBalancerPoolSummary = []
            while resultTotal > 0 and pageSizeCount < resultTotal:
                url = "{}{}?page={}&pageSize={}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                        vcdConstants.EDGE_GATEWAY_LOADBALANCER_POOLS_USING_ID.format(
                                                            edgeGatewayId), pageNo,
                                                        25)
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    targetLoadBalancerPoolSummary.extend(responseDict['values'])
                    pageSizeCount += len(responseDict['values'])
                    logger.debug('pool summary result pageSize = {}'.format(pageSizeCount))
                    pageNo += 1
            return targetLoadBalancerPoolSummary
        except:
            raise

    @isSessionExpired
    def getVirtualServiceDetails(self, edgeGatewayId):
        """
            Description :   Fetch details of virtual service data of a edge gateway
            Parameters  :   edgeGatewayId - ID of edge gateway whose data is to be fetched
            Returns     :   List of virtual service data of edge gateway(LIST)
        """
        try:
            url = '{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.EDGE_GATEWAY_LOADBALANCER_VIRTUALSERVICE_USING_ID.format(edgeGatewayId))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                logger.debug("Retrieved load balancer virtual service details successfully")
                responseDict = response.json()
                resultTotal = responseDict['resultTotal']
            else:
                raise Exception('Failed to fetch load balancer virtual service details')
            pageNo = 1
            pageSizeCount = 0
            targetLoadBalancerVirtualServiceSummary = []
            while resultTotal > 0 and pageSizeCount < resultTotal:
                url = "{}{}?page={}&pageSize={}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                        vcdConstants.EDGE_GATEWAY_LOADBALANCER_VIRTUALSERVICE_USING_ID.format(
                                                            edgeGatewayId), pageNo,
                                                        25)
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    targetLoadBalancerVirtualServiceSummary.extend(responseDict['values'])
                    pageSizeCount += len(responseDict['values'])
                    logger.debug('virtual service summary result pageSize = {}'.format(pageSizeCount))
                    pageNo += 1
                else:
                    raise Exception('Failed to fetch load balancer virtual service details')
            return targetLoadBalancerVirtualServiceSummary
        except:
            raise

    @isSessionExpired
    def getServiceEngineGroupAssignment(self, edgeGatewayName):
        """
            Description :   Fetch details of service engine groups in a edge gateway
            Parameters  :   edgeGatewayName - Name of edge gateway whose data is to be fetched
            Returns     :   List of service engine groups present in edge gateway(LIST)
        """
        try:
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.ASSIGN_SERVICE_ENGINE_GROUP_URI)
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                logger.debug("Retrieved service engine group details successfully")
                responseDict = response.json()
                resultTotal = responseDict['resultTotal']
            else:
                raise Exception('Failed to fetch service engine group details')
            pageNo = 1
            pageSizeCount = 0
            serviceEngineGroupList = []
            while resultTotal > 0 and pageSizeCount < resultTotal:
                url = "{}{}?page={}&pageSize={}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                        vcdConstants.ASSIGN_SERVICE_ENGINE_GROUP_URI,
                                                        pageNo,
                                                        25)
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    serviceEngineGroupList.extend(responseDict['values'])
                    pageSizeCount += len(responseDict['values'])
                    logger.debug('virtual service summary result pageSize = {}'.format(pageSizeCount))
                    pageNo += 1
                else:
                    raise Exception('Failed to fetch load balancer virtual service details')
            serviceEngineGroupInEdgeGatewayList = list(filter(
                lambda seg: seg['gatewayRef']['name'] == edgeGatewayName, serviceEngineGroupList))
            return serviceEngineGroupInEdgeGatewayList
        except:
            raise

    def getPoolDataUsingPoolId(self, poolId):
        """
           Description :   Fetch data of a load balancer pool using pool id
           Parameters  :   poolId - ID of load balancer pool(STRING)
           Returns     :   data of load balancer pool(DICT)
        """
        try:
            # url to fetch pool data using pool id
            url = '{}{}/{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                   vcdConstants.EDGE_GATEWAY_LOADBALANCER_POOLS,
                                   poolId)
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                logger.debug("Retrieved pool details for pool id - {} successfully".format(poolId))
                responseDict = response.json()
                return responseDict
            else:
                raise Exception('Failed to fetch service engine group details')
        except:
            raise

    @isSessionExpired
    def loadBalancerRollback(self):
        """
        Description:  Rollback for load balancer service of target edge gateway
        """
        try:
            # check api version for load balancer rollback
            if float(self.version) <= float(vcdConstants.API_VERSION_PRE_ZEUS):
                return

            loggingDone = False

            # Iterating over edge gateway id list
            for edgeGateway in self.rollback.apiData['targetEdgeGateway']:
                logger.debug("Removing load balancer configuration from target edge gateway '{}'".format(edgeGateway['name']))
                edgeGatewayId = edgeGateway['id']
                # Fetching virtual service configured on edge gateway
                virtualServices = self.getVirtualServiceDetails(edgeGatewayId)
                # Fetcing load balancer pools configured on target edge gateway
                loadBalancerPools = self.getPoolSumaryDetails(edgeGatewayId)
                # Certificates list used for pools configuration
                certificatesIds = set()

                # Removing virtual services from target edge gateway
                # Iterating over virtual service list to delete them
                for virtualService in virtualServices:
                    if not loggingDone:
                        logger.info("Rollback: Removing load balancer configuration")
                        loggingDone = True
                    virtualServiceId = virtualService['id']
                    # Delete virtual service delete url
                    virtualServiceDeleteUrl = '{}{}/{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                               vcdConstants.EDGE_GATEWAY_LOADBALANCER_VIRTUAL_SERVER,
                                                               virtualServiceId)
                    response = self.restClientObj.delete(virtualServiceDeleteUrl, self.headers)
                    if response.status_code == requests.codes.accepted:
                        # successful deletion of virtual server from edge gateway
                        taskUrl = response.headers['Location']
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug(f'Deleted virtual service {virtualService["name"]} from edge gateway {edgeGateway["name"]}')
                    else:
                        # Error response dict in case of failure
                        errorResponse = response.json()
                        raise Exception(
                            "Failed to delete virtual service {} from edge gateway {} due to error {}".format(
                                virtualService["name"], edgeGateway["name"], errorResponse['message']))

                # Removing load balancer pools from target edge gateway
                # Iterating over load balancer pools list
                for pool in loadBalancerPools:
                    poolId = pool['id']

                    # Retrieving certificates used for pools creation
                    poolData = self.getPoolDataUsingPoolId(poolId)
                    if poolData.get('caCertificateRefs'):
                        for certificate in poolData.get('caCertificateRefs'):
                            certificatesIds.add(certificate['id'])

                    # Delete load balancer pool url
                    loadBalancerPoolDeleteUrl = '{}{}/{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                                 vcdConstants.EDGE_GATEWAY_LOADBALANCER_POOLS,
                                                                 poolId)
                    response = self.restClientObj.delete(loadBalancerPoolDeleteUrl, self.headers)
                    if response.status_code == requests.codes.accepted:
                        # successful deletion of virtual server from edge gateway
                        taskUrl = response.headers['Location']
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug(
                            f'Deleted load balancer pool {pool["name"]} from edge gateway {edgeGateway["name"]}')
                    else:
                        # Error response dict in case of failure
                        errorResponse = response.json()
                        raise Exception(
                            "Failed to delete load balancer pool {} from edge gateway {} due to error {}".format(
                                pool["name"], edgeGateway["name"], errorResponse['message']))

                # Removing service engine group from target edge gateway
                # Iterating over service engine groups list
                serviceEngineGroupList = self.getServiceEngineGroupAssignment(edgeGateway['name'])
                for serviceEngineGroup in serviceEngineGroupList:
                    serviceEngineGroupAssignmentId = serviceEngineGroup['id']
                    # Remove service engine group from edge gateway url
                    serviceEngineGroupDeleteUrl = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                                   vcdConstants.ASSIGN_SERVICE_ENGINE_GROUP_URI,
                                                                   serviceEngineGroupAssignmentId
                                                                   )
                    response = self.restClientObj.delete(serviceEngineGroupDeleteUrl, self.headers)
                    if response.status_code == requests.codes.accepted:
                        # successful removal of service engine group from edge gateway
                        taskUrl = response.headers['Location']
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug(
                            f'Removed service engine group {serviceEngineGroup["serviceEngineGroupRef"]["name"]} from edge gateway {edgeGateway["name"]}')
                    else:
                        # Error response dict in case of failure
                        errorResponse = response.json()
                        raise Exception(
                            "Failed to remove service engine group {} from edge gateway {} due to error {}".format(
                                serviceEngineGroup["serviceEngineGroupRef"]["name"], edgeGateway["name"], errorResponse['message']))

                # Disabling load balacer service from target edge gateway
                self.enableLoadBalancerService(edgeGatewayId, edgeGateway['name'], rollback=True)

                # Deleting certificates from vCD tenant portal
                # Getting certificates from org vdc tenant portal
                lbCertificates = self.getCerticatesFromTenant()
                # Deleting the certificates used in pool configuration
                for certId in certificatesIds:
                    if certId not in lbCertificates.values():
                        # If certicate not present then continue
                        logger.debug(f'Certificate {certId} already removed')
                    else:
                        # Delete certificate url
                        certDeleteUrl = '{}{}/{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                         'ssl/cetificateLibrary',
                                                         certId)
                        # Adding context header to delete certificate from tenant portal
                        self.headers['X-VMWARE-VCLOUD-TENANT-CONTEXT'] = \
                                        self.rollback.apiData['Organization']['@id'].split(':')[-1]
                        self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                        response = self.restClientObj.delete(certDeleteUrl, self.headers)
                        if response.status_code == requests.codes.no_content:
                            # successful delete of certificate from tenant portal
                            logger.debug(f'Certificate {certId} successfully deleted from tenant portal')
                            # Removing context header after successful deletion of certificate
                            del self.headers['X-VMWARE-VCLOUD-TENANT-CONTEXT']
                        else:
                            # Trying to delete certificate using different url
                            # Delete certificate url
                            certDeleteUrl = '{}{}/{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                             'ssl/certificateLibrary',
                                                             certId)
                            response = self.restClientObj.delete(certDeleteUrl, self.headers)
                            if response.status_code == requests.codes.no_content:
                                # successful delete of certificate from tenant portal
                                logger.debug(f'Certificate {certId} successfully deleted from tenant portal')
                                # Removing context header after successful deletion of certificate
                                del self.headers['X-VMWARE-VCLOUD-TENANT-CONTEXT']
                            else:
                                # Error response dict in case of failure
                                errorResponse = response.json()
                                raise Exception(
                                    "Failed to delete certificate {} from vCD tenant portal due to error {}".format(
                                        certId,
                                        errorResponse['message']))

        except:
            raise

    @description("configuration of LoadBalancer")
    @remediate
    def configureLoadBalancer(self, nsxvObj, ServiceEngineGroupName, loadBalancerVIPSubnet):
        """
        Description :   Configure LoadBalancer service target edge gateway
        Params      :   nsxvObj - NSXVOperations class object
                        ServiceEngineGroupName - Name of service engine group for load balancer configuration (STRING)
                        loadBalancerVIPSubnet - Subnet for loadbalancer virtual service VIP configuration
        """
        try:
            if float(self.version) >= float(vcdConstants.API_VERSION_ZEUS):
                logger.debug('Load Balancer is getting configured')

            for sourceEdgeGateway in self.rollback.apiData['sourceEdgeGateway']:
                sourceEdgeGatewayId = sourceEdgeGateway['id'].split(':')[-1]
                targetEdgeGatewayId = list(filter(lambda edgeGatewayData: edgeGatewayData['name'] == sourceEdgeGateway['name'],
                                self.rollback.apiData['targetEdgeGateway']))[0]['id']
                targetEdgeGatewayName = list(filter(lambda edgeGatewayData: edgeGatewayData['name'] == sourceEdgeGateway['name'],
                                self.rollback.apiData['targetEdgeGateway']))[0]['name']

                # url to retrieve the load balancer config info
                url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                      vcdConstants.NETWORK_EDGES,
                                      vcdConstants.EDGE_GATEWAY_LOADBALANCER_CONFIG.format(sourceEdgeGatewayId))
                # get api call to retrieve the load balancer config info
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = xmltodict.parse(response.content)
                    # checking if load balancer is enabled, if so raising exception
                    if responseDict['loadBalancer']['enabled'] == "true":
                        if not float(self.version) >= float(vcdConstants.API_VERSION_ZEUS):
                            raise Exception("Load Balancer service is configured in the Source edge gateway {} but not supported in the Target".format(sourceEdgeGateway['name']))
                        serviceEngineGroupResultList = self.getServiceEngineGroupDetails()
                        if not serviceEngineGroupResultList:
                             raise Exception('Service Engine Group does not exist.')

                        logger.debug("Configuring LoadBalancer Services in Target Edge Gateway - {}".format(sourceEdgeGateway['name']))
                        serviceEngineGroupDetails = [serviceEngineGroup for serviceEngineGroup in
                                                     serviceEngineGroupResultList if
                                                     serviceEngineGroup['name'] == ServiceEngineGroupName]
                        if not serviceEngineGroupDetails:
                            raise Exception("Service Engine Group {} is not present in Avi.".format(ServiceEngineGroupName))
                        self.serviceEngineGroupName = serviceEngineGroupDetails[0]['name']
                        self.serviceEngineGroupId = serviceEngineGroupDetails[0]['id']
                        # enable load balancer service
                        self.enableLoadBalancerService(targetEdgeGatewayId, targetEdgeGatewayName)
                        # service engine group assignment to target edge gateway
                        self.assignServiceEngineGroup(targetEdgeGatewayId, targetEdgeGatewayName, serviceEngineGroupDetails[0])
                        # creating pools
                        self.createLoadBalancerPools(sourceEdgeGatewayId, targetEdgeGatewayId, targetEdgeGatewayName, nsxvObj)
                        # creating load balancer virtual server
                        self.createLoadBalancerVirtualService(sourceEdgeGatewayId, targetEdgeGatewayId, targetEdgeGatewayName, loadBalancerVIPSubnet)
                    else:
                        logger.debug("LoadBalancer Service is in disabled state in Source Edge Gateway - {}".format(sourceEdgeGateway['name']))
                else:
                    errorResponseData = response.json()
                    raise Exception(
                        "Failed to fetch load balancer config from source edge gateway '{}' due to error {}".format(
                            targetEdgeGatewayName, errorResponseData['message']
                        ))
            logger.info('Target Edge gateway services got configured successfully.')
        except Exception:
            # Updating rollback key in metadata in case of failure
            self.rollback.key = 'configureLoadBalancer'
            self.createMetaDataInOrgVDC(self.rollback.apiData['sourceOrgVDC']['@id'],
                                        metadataDict={'rollbackKey': self.rollback.key}, domain='system')
            raise

    @isSessionExpired
    def createDNATRuleForLoadBalancer(self, edgeGatewayId, ruleName, sourceIP, destinationIp, port):
        """
            Description :   Create DNAT rule for a virtual service of load balancer
            Params      :   edgeGatewayId - ID of target edge gateway (STRING)
                            ruleName - Name of DNAT rule to be created (STRING)
                            sourceIP - VIP used in target edge gateway (STRING)
                            destinationIp - VIP used in source edge gateway (STRING)
                            port - port used for port forwarding (INT)
            """
        try:
            logger.debug(f"Creating DNAT rule {ruleName} for virtual service on edge gateway {edgeGatewayId}")
            # Create NAT rule url
            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                  vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.T1_ROUTER_NAT_CONFIG.format(edgeGatewayId))
            # Payload data for creating DNAT rule
            payloadDict = {
                "ruleId": ruleName,
                "ruleTag": ruleName,
                "ruleDescription": "",
                "enabled": "true",
                "action": "DNAT",
                "loggingEnabled": "true",
                "version": "",
                "originalAddress": destinationIp,
                "translatedAddress": sourceIP,
                "dnatExternalPort": port
            }

            # Filepath of template json file
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')

            # Creating payload for DNAT rule creation
            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.CREATE_DNAT_TEMPLATE, apiVersion=self.version)
            payloadData = json.loads(payloadData)

            # Deleting version key from payload data as it is not required
            del payloadData['version']

            # Getting the application port profile list
            applicationPortProfilesList = self.getApplicationPortProfiles()
            # Fetching name and id of specific application port profile for corresponding port
            protocol_port_name, protocol_port_id = self._searchApplicationPortProfile(
                applicationPortProfilesList, 'tcp', port)
            payloadData["applicationPortProfile"] = {"name": protocol_port_name, "id": protocol_port_id}

            # Create rule api call
            self.createNatRuleTask(payloadData, url)

        except:
            raise

    def createLoadBalancerVirtualService(self, sourceEdgeGatewayId, targetEdgeGatewayId, targetEdgeGatewayName, loadBalancerVIPSubnet):
        """
            Description :   Configure LoadBalancer virtual service on target edge gateway
            Params      :   sourceEdgeGatewayId - ID of source edge gateway (STRING)
                            targetEdgeGatewayId - ID of target edge gateway (STRING)
                            targetEdgeGatewayName - Name of target edge gateway (STRING)
                            loadBalancerVIPSubnet - Subnet for loadbalancer virtual service VIP configuration (STRING)
        """
        try:
            # Fetching virtual service configured on edge gateway
            virtualServices = self.getVirtualServiceDetails(targetEdgeGatewayId)

            poolNameIdDict = {}
            # url for getting edge gateway load balancer virtual servers configuration
            url = '{}{}'.format(
                vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                vcdConstants.EDGE_GATEWAY_VIRTUAL_SERVER_CONFIG.format(sourceEdgeGatewayId))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                virtualServersData = xmltodict.parse(response.content)
            else:
                raise Exception('Failed to get source edge gateway load balancer virtual servers configuration')

            # getting loadbalancer config
            url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_LOADBALANCER_CONFIG.format(sourceEdgeGatewayId))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                # Fetching pools data from response
                sourceLBPools = responseDict['loadBalancer'].get('pool') \
                    if isinstance(responseDict['loadBalancer'].get('pool'), list) \
                    else [responseDict['loadBalancer'].get('pool')]

                # Fetching application profiles data from response
                applicationProfiles = responseDict['loadBalancer'].get('applicationProfile') \
                    if isinstance(responseDict['loadBalancer'].get('applicationProfile'), list) \
                    else [responseDict['loadBalancer'].get('applicationProfile')]

            else:
                raise Exception('Failed to get load balancer configuration from source edge gateway - {}'.format(
                    targetEdgeGatewayName))

            # Fetching load balancer pools data
            targetLoadBalancerPoolSummary = self.getPoolSumaryDetails(targetEdgeGatewayId)

            # Iterating over pools to find the pool to be used in virtual service
            for pool in sourceLBPools:
                poolNameIdDict[pool['poolId']] = pool['name'], [targetPool for targetPool in
                                                                targetLoadBalancerPoolSummary
                                                                if targetPool['name'] == pool['name']
                                                                ][0]['id']

            virtualServersData = virtualServersData['loadBalancer']['virtualServer'] if isinstance(
                virtualServersData['loadBalancer']['virtualServer'], list) else \
                [virtualServersData['loadBalancer']['virtualServer']]

            # if subnet is not provided in user input use default subnet
            loadBalancerVIPSubnet = loadBalancerVIPSubnet if loadBalancerVIPSubnet else '192.168.255.128/28'

            # Creating a list of hosts in a subnet
            hostsListInSubnet = list(ipaddress.ip_network(loadBalancerVIPSubnet, strict=False).hosts())

            if len(hostsListInSubnet) < len(virtualServersData):
                raise Exception("Number of hosts in network - {} if less than the number of virtual server in edge gateway{}".format(loadBalancerVIPSubnet, targetEdgeGatewayName))

            for virtualServer in virtualServersData:
                # IP address to be used for VIP in virtual service
                virtualIpAddress = hostsListInSubnet.pop(0)

                # If virtual service is already created on target then skip it
                if virtualServer['name'] in [service['name'] for service in virtualServices]:
                    logger.debug(f'Virtual service {virtualServer["name"]} already created on target edge gateway {targetEdgeGatewayName}')
                    # Incrementing the IP address for next virtual service
                    hostsListInSubnet.pop(0)
                    continue
                payloadDict = {
                    'virtualServiceName': virtualServer['name'],
                    'description': virtualServer.get('description', ''),
                    'enabled': virtualServer['enabled'],
                    'ipAddress': str(virtualIpAddress),
                    'poolName': poolNameIdDict[virtualServer['defaultPoolId']][0],
                    'poolId': poolNameIdDict[virtualServer['defaultPoolId']][1],
                    'gatewayName': targetEdgeGatewayName,
                    'gatewayId': targetEdgeGatewayId,
                    'serviceEngineGroupName': self.serviceEngineGroupName,
                    'serviceEngineGroupId': self.serviceEngineGroupId,
                    'port': virtualServer['port'],
                    'sslEnabled': True if virtualServer['protocol'] == 'https' else False
                }

                filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
                payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                          componentName=vcdConstants.COMPONENT_NAME,
                                                          templateName=vcdConstants.CREATE_LOADBALANCER_VIRTUAL_SERVICE)
                payloadData = json.loads(payloadData)

                certificateForTCP = False

                if virtualServer['protocol'] == 'https' or virtualServer['protocol'] == 'tcp':
                    applicationProfileId = virtualServer['applicationProfileId']
                    applicationProfileData = [profile for profile in applicationProfiles
                                              if profile['applicationProfileId'] == applicationProfileId]

                    applicationProfileData = applicationProfileData[0] if applicationProfileData else None

                    if applicationProfileData:
                        certificateObjectId = applicationProfileData.get('clientSsl', {}).get('serviceCertificate', None)

                        if virtualServer['protocol'] == 'tcp' and certificateObjectId:
                            certificateForTCP = True

                        if certificateObjectId:
                            # Getting certificates from org vdc tenant portal
                            lbCertificates = self.getCerticatesFromTenant()

                            # Certificates payload
                            certificatePayload = {
                                'name': certificateObjectId,
                                'id': lbCertificates[certificateObjectId]
                                 }
                            payloadData["certificateRef"] = certificatePayload
                else:
                    payloadData["certificateRef"] = None

                applicationProfilePayload = {
                    "type": "HTTP" if virtualServer['protocol'] == 'http'
                    else "HTTPS" if virtualServer['protocol'] == 'https'
                    else "L4 TLS" if certificateForTCP
                    else "L4",
                    "systemDefined": True
                }
                payloadData['applicationProfile'] = applicationProfilePayload

                payloadData = json.dumps(payloadData)
                url = '{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.EDGE_GATEWAY_LOADBALANCER_VIRTUAL_SERVER)
                self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                # post api call to configure virtual server for load balancer service
                response = self.restClientObj.post(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    self._checkTaskStatus(taskUrl=taskUrl)
                    logger.debug('Successfully created virtual server - {} for load balancer on target edge gateway'.format(
                        virtualServer['name']
                    ))

                    # Name of DNAT rule to be created for load balancer virtual service
                    DNATRuleName = f'{virtualServer["name"]}-DNAT-RULE'
                    # Creating DNAT rule for virtual service
                    self.createDNATRuleForLoadBalancer(targetEdgeGatewayId, DNATRuleName, str(virtualIpAddress),
                                                       virtualServer['ipAddress'], virtualServer['port'])
                else:
                    errorResponseData = response.json()
                    raise Exception(
                        "Failed to create virtual server '{}' for load balancer on target edge gateway '{}' due to error {}".format(
                            virtualServer['name'], targetEdgeGatewayName, errorResponseData['message']
                        ))
        except:
            raise

    @isSessionExpired
    def createLoadBalancerPools(self, sourceEdgeGatewayId, targetEdgeGatewayId, targetEdgeGatewayName, nsxvObj):
        """
            Description :   Configure LoadBalancer service pools on target edge gateway
            Params      :   sourceEdgeGatewayId - ID of source edge gateway (STRING)
                            targetEdgeGatewayId - ID of target edge gateway (STRING)
                            targetEdgeGatewayName - Name of target edge gateway (STRING)
                            nsxvObj - NSXVOperations class object (OBJECT)
        """
        # Fetching load balancer pools configured on target edge gateway
        loadBalancerPools = self.getPoolSumaryDetails(targetEdgeGatewayId)
        # getting loadbalancer config
        url = "{}{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                              vcdConstants.NETWORK_EDGES,
                              vcdConstants.EDGE_GATEWAY_LOADBALANCER_CONFIG.format(sourceEdgeGatewayId))
        response = self.restClientObj.get(url, self.headers)
        if response.status_code == requests.codes.ok:
            responseDict = xmltodict.parse(response.content)
            # Fetching pools data from response
            pools = responseDict['loadBalancer'].get('pool') \
                if isinstance(responseDict['loadBalancer'].get('pool'), list) \
                else [responseDict['loadBalancer'].get('pool')]

            # Fetching health monitors data from response
            healthMonitors = responseDict['loadBalancer'].get('monitor') \
                if isinstance(responseDict['loadBalancer'].get('monitor'), list) \
                else [responseDict['loadBalancer'].get('monitor')]

            # Fetching application profiles data from response
            applicationProfiles = responseDict['loadBalancer'].get('applicationProfile') \
                if isinstance(responseDict['loadBalancer'].get('applicationProfile'), list) \
                else [responseDict['loadBalancer'].get('applicationProfile')]

            # url for getting edge gateway load balancer virtual servers configuration
            url = '{}{}'.format(
                vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                vcdConstants.EDGE_GATEWAY_VIRTUAL_SERVER_CONFIG.format(sourceEdgeGatewayId))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                virtualServersData = xmltodict.parse(response.content)
            else:
                raise Exception('Failed to get source edge gateway load balancer virtual servers configuration')

            virtualServersData = virtualServersData['loadBalancer']['virtualServer'] if isinstance(
                virtualServersData['loadBalancer']['virtualServer'], list) else \
                [virtualServersData['loadBalancer']['virtualServer']]

            # Fetching object id's of certificates used for https configuration
            objectIdsOfCertificates = [profile['clientSsl']['serviceCertificate'] for profile in applicationProfiles if profile.get('clientSsl')]

            # Getting certificates from org vdc tenant portal
            lbCertificates = self.getCerticatesFromTenant()

            # Uploading certificate to org vdc tenant portal
            for objectId in objectIdsOfCertificates:
                if objectId in lbCertificates:
                    logger.debug('Certificate {} already present in vCD tenant portal'.format(objectId))
                    continue
                else:
                    # Fetch certificate from nsx-v
                    certificate = nsxvObj.certRetrieval(objectId)
                    logger.debug('Uploading the certificate {} for load balancer HTTPS configuration'.format(objectId))
                    self.uploadCertificate(certificate, objectId)

            # Iterating over pools to create pools for load balancer in target
            for poolData in pools:

                persistenceProfile = {}

                # finding virtual service corresponding to this load balancer pool
                virtualServer = list(filter(lambda vserver: vserver['defaultPoolId'] == poolData['poolId'], virtualServersData))

                if virtualServer:
                    applicationProfileId = virtualServer[0]['applicationProfileId']
                    applicationProfileData = list(filter(lambda profile: profile['applicationProfileId'] == applicationProfileId, applicationProfiles))[0]

                    # creating persistence profile payload for pool creation
                    if applicationProfileData and applicationProfileData.get('persistence'):
                        persistenceData = applicationProfileData.get('persistence')
                        if persistenceData['method'] == 'cookie':
                            persistenceProfile = {
                                "type": "HTTP_COOKIE",
                                "value": persistenceData['cookieName']
                            }
                        if persistenceData['method'] == 'sourceip':
                            persistenceProfile = {
                                "type": "CLIENT_IP",
                                "value": ""}

                # If pool is already created on target then skip
                if poolData['name'] in [pool['name'] for pool in loadBalancerPools]:
                    logger.debug(f'Pool {poolData["name"]} already created on target edge gateway {targetEdgeGatewayName}')
                    continue

                # Filtering the health monitors used in pools
                healthMonitorUsedInPool = list(filter(
                    lambda montitor:montitor['monitorId'] == poolData.get('monitorId', None), healthMonitors))

                # Fetching pool memmers from pool data
                if poolData.get('member'):
                    poolMembers = poolData.get('member') if isinstance(poolData.get('member'), list) else [poolData.get('member')]
                else:
                    poolMembers = []

                # file path of template.json
                filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')

                # Creating pool dict for load balancer pool creation
                payloadDict = {
                    'poolName': poolData['name'],
                    'description': poolData.get('description', ''),
                    'algorithm': "LEAST_CONNECTIONS" if poolData['algorithm'] == 'leastconn'
                                                     else poolData['algorithm'].upper().replace('-', '_'),
                    'gatewayName': targetEdgeGatewayName,
                    'gatewayId': targetEdgeGatewayId
                }
                payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                          componentName=vcdConstants.COMPONENT_NAME,
                                                          templateName=vcdConstants.CREATE_LOADBALANCER_POOL)
                payloadData = json.loads(payloadData)

                # Adding pool members in pool payload
                targetPoolMembers = []
                for member in poolMembers:
                    memberDict = {
                                "ipAddress": member['ipAddress'],
                                "port": member['port'],
                                "ratio": member['weight'],
                                "enabled": True if member['condition'] == 'enabled' else False
                                }
                    targetPoolMembers.append(memberDict)
                payloadData['members'] = targetPoolMembers

                # adding persistence profile in payload
                if persistenceProfile:
                    payloadData['persistenceProfile'] = persistenceProfile

                # Adding health monitors in pool payload
                if healthMonitorUsedInPool:
                    healthMonitorsForPayload = [
                        {
                            "type": 'HTTP' if healthMonitorUsedInPool[0]['type'] == 'http'
                                          else 'HTTPS' if healthMonitorUsedInPool[0]['type'] == 'https'
                                          else 'TCP' if healthMonitorUsedInPool[0]['type'] == 'tcp'
                                          else 'UDP' if healthMonitorUsedInPool[0]['type'] == 'udp'
                                          else 'PING' if healthMonitorUsedInPool[0]['type'] == 'icmp'
                                          else None,
                            "systemDefined": True
                        }
                    ]

                    payloadData['healthMonitors'] = healthMonitorsForPayload

                # Adding certificates in pool payload if https config is present
                if healthMonitorUsedInPool and healthMonitorUsedInPool[0]['type'] == 'https':
                    lbCertificates = self.getCerticatesFromTenant()
                    certificatePayload = [{'name': objectId, 'id': lbCertificates[objectId]}for objectId in objectIdsOfCertificates]
                    payloadData["caCertificateRefs"] = certificatePayload
                else:
                    payloadData["caCertificateRefs"] = None

                payloadData = json.dumps(payloadData)

                # URL to create load balancer pools
                url = '{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.EDGE_GATEWAY_LOADBALANCER_POOLS)
                self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                # post api call to configure pool for load balancer service
                response = self.restClientObj.post(url, self.headers, data=payloadData)
                if response.status_code == requests.codes.accepted:
                    taskUrl = response.headers['Location']
                    self._checkTaskStatus(taskUrl=taskUrl)
                else:
                    # Error response JSON in case load balancer pool creation fails
                    errorResponseData = response.json()
                    raise Exception("Failed to create pool for load balancer on target edge gateway '{}' due to error {}".format(
                        targetEdgeGatewayName, errorResponseData['message']
                    ))
        else:
            raise Exception('Failed to get load balancer configuration from source edge gateway - {}'.format(targetEdgeGatewayName))

    @isSessionExpired
    def enableLoadBalancerService(self, targetEdgeGatewayId, targetEdgeGatewayName, rollback=False):
        """
            Description :   Enabling LoadBalancer virtual service on target edge gateway
            Params      :   targetEdgeGatewayId - ID of target edge gateway (STRING)
                            targetEdgeGatewayName - Name of target edge gateway (STRING)
                            rollback - flag to decide whether to disable or enable load balancer(BOOL)
        """
        try:
            if rollback:
                logger.debug('Disabling LoadBalancer service on target Edge Gateway-{} as a part of rollback'.format(
                    targetEdgeGatewayName))
                payloadDict = {"enabled": False}
            else:
                logger.debug('Enabling LoadBalancer service on target Edge Gateway-{}'.format(targetEdgeGatewayName))
                payloadDict = {"enabled": True}

            # url to enable loadbalancer service on target edge gateway
            url = "{}{}/{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                  vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.LOADBALANCER_ENABLE_URI.format(targetEdgeGatewayId))
            payloadData = json.dumps(payloadDict)
            self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE

            # get api call to fetch load balancer service status from edge gateaway
            response = self.restClientObj.get(url, self.headers, data=payloadData)
            if response.status_code == requests.codes.ok:
                responseData = response.json()
            else:
                errorResponseData = response.json()
                raise Exception('Failed to fetch LoadBalancer service data from target Edge Gateway-{} with error-{}'.format(
                    targetEdgeGatewayName, errorResponseData['message']))

            lbServiceStatus = responseData['enabled']
            if rollback and not lbServiceStatus:
                logger.debug('Load Balancer already disabled on target Edge Gateway-{}'.format(targetEdgeGatewayName))
                return

            if not rollback and lbServiceStatus:
                logger.debug('Load Balancer already enabled on target Edge Gateway-{}'.format(targetEdgeGatewayName))
                return

                # put api call to enable load balancer on target edge gateway
            response = self.restClientObj.put(url, self.headers, data=payloadData)
            if response.status_code == requests.codes.accepted:
                taskUrl = response.headers['Location']
                self._checkTaskStatus(taskUrl)
                if rollback:
                    logger.debug('Successfully disabled LoadBalancer service on target Edge Gateway-{}'.format(
                        targetEdgeGatewayName))
                else:
                    logger.debug('Successfully enabled LoadBalancer service on target Edge Gateway-{}'.format(targetEdgeGatewayName))
            else:
                errorResponseData = response.json()
                if rollback:
                    raise Exception(
                        'Failed to disable LoadBalancer service on target Edge Gateway-{} with error-{}'.format(
                            targetEdgeGatewayName, errorResponseData['message']))
                else:
                    raise Exception('Failed to enable LoadBalancer service on target Edge Gateway-{} with error-{}'.format(targetEdgeGatewayName, errorResponseData['message']))
        except Exception:
            raise

    @isSessionExpired
    def assignServiceEngineGroup(self, targetEdgeGatewayId, targetEdgeGatewayName, serviceEngineGroupDetails):
        """
            Description :   Assign Service Engine Group on target Edge Gateway-
            Params      :   targetEdgeGatewayId - ID of target edge gateway (STRING)
                            targetEdgeGatewayName - Name of target edge gateway (STRING)
                            serviceEngineGroupDetails - Details of service engine group (DICT)
        """
        try:
            logger.debug('Assigning Service Engine Group on target Edge Gateway-{}'.format(targetEdgeGatewayName))

            # Fetching list of service engine groups added in edge gateway
            serviceEngineGroupList = self.getServiceEngineGroupAssignment(targetEdgeGatewayName)
            for seg in serviceEngineGroupList:
                if seg['serviceEngineGroupRef']['name'] == self.serviceEngineGroupName:
                    logger.debug('Already assigned Service Engine Group on target Edge Gateway-{}'.format(
                        targetEdgeGatewayName))
                    return

            # url to assign avi service engine group on target edge gateway
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                  vcdConstants.ASSIGN_SERVICE_ENGINE_GROUP_URI)
            payloadDict = {
                            "minVirtualServices": 0,
                            "maxVirtualServices": serviceEngineGroupDetails['maxVirtualServices'],
                            "serviceEngineGroupRef": {
                                "name": self.serviceEngineGroupName,
                                "id": self.serviceEngineGroupId
                            },
                            "gatewayRef": {
                                "name": targetEdgeGatewayName,
                                "id": targetEdgeGatewayId
                            }
                        }
            payloadData = json.dumps(payloadDict)
            self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
            # post api call to configure ipsec rules on target edge gateway
            response = self.restClientObj.post(url, self.headers, data=payloadData)
            if response.status_code == requests.codes.accepted:
                # if successful configuration of ipsec rules
                taskUrl = response.headers['Location']
                self._checkTaskStatus(taskUrl)
                logger.debug('Successfully assigned Service Engine Group on target Edge Gateway-{}'.format(targetEdgeGatewayName))
            else:
                errorResponseData = response.json()
                raise Exception("Failed to assign Service Engine Group on target Edge Gateway-{} with error-{}".format(targetEdgeGatewayName, errorResponseData['message']))
        except:
            raise

    @description('Configuring source DFW rules in Target VDC groups')
    @remediate
    def configureDFW(self, sourceOrgVDCId):
        """
        Description: Configuring source DFW rules in Target VDC groups
        parameter: sourceOrgVDCId - ID of source orgVDC(NSX ID format not URN)
        """
        try:
            self.rollback.key = 'configureDFW'
            firewallIdDict = dict()
            isofirewallIdDict = dict()
            sourceipsetNames = list()
            desipsetNames = list()
            logger.info("Configuring DFW Services in VDC groups")
            orgvDCgroupIds = self.rollback.apiData['OrgVDCGroupID'].values() if self.rollback.apiData.get('OrgVDCGroupID') else []
            # getting all the L3 DFW rules
            allLayer3Rules = self.getDistributedFirewallConfig(sourceOrgVDCId)
            allLayer3Rules = allLayer3Rules if isinstance(allLayer3Rules, list) else [allLayer3Rules]
            # getting layer 3 services
            applicationPortProfilesList = self.getApplicationPortProfiles()
            vcdid = sourceOrgVDCId.split(':')[-1]
            url = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                vcdConstants.GET_IPSET_GROUP_BY_ID.format(
                                    vcdConstants.IPSET_SCOPE_URL.format(vcdid)))
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = xmltodict.parse(response.content)
                if responseDict.get('list'):
                    ipsetgroups = responseDict['list']['ipset'] if isinstance(responseDict['list']['ipset'],
                                                                              list) else [
                        responseDict['list']['ipset']]

                else:
                    ipsetgroups = []
                if ipsetgroups:
                    if self.rollback.apiData.get('firewallIdDict'):
                        firewallIdDict = self.rollback.apiData.get('firewallIdDict')
                    if self.rollback.apiData.get('ConflictNetworks'):
                        isofirewallIdDict = self.createDFWIPSET(ipsetgroups)
                    firewallIdDict = {**firewallIdDict, **isofirewallIdDict}
            ipsetIds = self.fetchipset(orgvDCgroupIds)
            for allLayer3Rule in allLayer3Rules:
                srcorgvDCgroupId, desorgvDCgroupId = str(), str()
                data = dict()
                applicationServicesList = list()
                sourcefirewallGroupList, destfirewallGroupList = list(), list()
                networkContextProfilesList = list()
                payloadDict = dict()
                sourcefirewallGroupId = list()
                destinationfirewallGroupId = list()
                if not self.rollback.apiData.get(allLayer3Rule['@id']):
                    if allLayer3Rule.get('sources', None):
                        if allLayer3Rule['sources'].get('source', None):
                            sources = allLayer3Rule['sources']['source'] if isinstance(allLayer3Rule['sources']['source'], list) else [allLayer3Rule['sources']['source']]
                            firewallGroupIdSource, srcorgvDCgroupId, sourceipsetNames, sourcefirewallGroupList = self.configureDFWgroups(sources, allLayer3Rule, firewallIdDict, source=True)
                            sourcefirewallGroupId.extend(firewallGroupIdSource)
                    if allLayer3Rule.get('destinations'):
                        if allLayer3Rule['destinations'].get('destination'):
                            destinations = allLayer3Rule['destinations']['destination'] if isinstance(
                                allLayer3Rule['destinations']['destination'], list) else [allLayer3Rule['destinations']['destination']]
                            firewallGroupIdDestination, desorgvDCgroupId, desipsetNames, destfirewallGroupList = self.configureDFWgroups(destinations, allLayer3Rule, firewallIdDict, source=False)
                            destinationfirewallGroupId.extend(firewallGroupIdDestination)
                    userDefinedRulesList = list()
                    if not srcorgvDCgroupId and not desorgvDCgroupId:
                        orgvDCgroupId = list(orgvDCgroupIds)[0]
                    if srcorgvDCgroupId:
                        orgvDCgroupId = srcorgvDCgroupId
                    if desorgvDCgroupId:
                        orgvDCgroupId = desorgvDCgroupId
                    if allLayer3Rule.get('sources', None):
                        if sourceipsetNames and srcorgvDCgroupId:
                            for ipsetName in sourceipsetNames:
                                for ipsetId in ipsetIds:
                                    if list(ipsetId.keys())[0] == orgvDCgroupId:
                                        if ipsetId[orgvDCgroupId].get(ipsetName):
                                            sourcefirewallGroupId.append({'id': ipsetId[orgvDCgroupId][ipsetName]})
                        elif sourceipsetNames:
                            for ipsetName in sourceipsetNames:
                                for ipsetId in ipsetIds:
                                    if list(ipsetId.keys())[0] == list(orgvDCgroupIds)[0]:
                                        if ipsetId[list(orgvDCgroupIds)[0]].get(ipsetName):
                                            sourcefirewallGroupId.append(
                                                {'id': ipsetId[list(orgvDCgroupIds)[0]][ipsetName]})
                        if orgvDCgroupId and sourcefirewallGroupList:
                            ipAddressGroupIds = sourcefirewallGroupList[orgvDCgroupId].keys()
                            for ids in list(ipAddressGroupIds):
                                id = {'id': ids}
                                sourcefirewallGroupId.append(id)
                        elif sourcefirewallGroupList:
                            ownerRef = orgvDCgroupIds[0]
                            ipAddressGroupIds = sourcefirewallGroupList[ownerRef].keys()
                            for ids in list(ipAddressGroupIds):
                                id = {'id': ids}
                                sourcefirewallGroupId.append(id)
                    if allLayer3Rule.get('destinations', None):
                        if desipsetNames and srcorgvDCgroupId:
                            for ipsetName in desipsetNames:
                                for ipsetId in ipsetIds:
                                    if list(ipsetId.keys())[0] == orgvDCgroupId:
                                        if ipsetId[orgvDCgroupId].get(ipsetName):
                                            destinationfirewallGroupId.append({'id': ipsetId[orgvDCgroupId][ipsetName]})
                        elif desipsetNames:
                            for ipsetName in desipsetNames:
                                for ipsetId in ipsetIds:
                                    if list(ipsetId.keys())[0] == list(orgvDCgroupIds)[0]:
                                        if ipsetId[list(orgvDCgroupIds)[0]].get(ipsetName):
                                            destinationfirewallGroupId.append(
                                                {'id': ipsetId[list(orgvDCgroupIds)[0]][ipsetName]})
                        if orgvDCgroupId and destfirewallGroupList:
                            ipAddressGroupIds = destfirewallGroupList[orgvDCgroupId].keys()
                            for ids in list(ipAddressGroupIds):
                                id = {'id': ids}
                                destinationfirewallGroupId.append(id)
                        elif destfirewallGroupList:
                            ownerRef = orgvDCgroupIds[0]
                            ipAddressGroupIds = destfirewallGroupList[ownerRef].keys()
                            for ids in list(ipAddressGroupIds):
                                id = {'id': ids}
                                destinationfirewallGroupId.append(id)
                    # URL to get dfw policies by vdc groud ID
                    policyURL = '{}{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                vcdConstants.GET_VDC_GROUP_BY_ID.format(orgvDCgroupId),
                                                vcdConstants.ENABLE_DFW_POLICY)
                    header = {'Authorization': self.headers['Authorization'],
                              'Accept': vcdConstants.VCD_API_HEADER}
                    policyResponse = self.restClientObj.get(policyURL, header)
                    if policyResponse.status_code == requests.codes.ok:
                        policyResponseDict = policyResponse.json()
                        policyID = policyResponseDict['defaultPolicy']['id']
                        dfwURL = '{}{}{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                   vcdConstants.GET_VDC_GROUP_BY_ID.format(orgvDCgroupId),
                                                   vcdConstants.ENABLE_DFW_POLICY, vcdConstants.GET_DFW_RULES.format(policyID))
                        # get api call to retrieve firewall info of target edge gateway
                        response = self.restClientObj.get(dfwURL, header)
                        if response.status_code == requests.codes.ok:
                            # successful retrieval of firewall info
                            responseDict = response.json()
                            userDefinedRulesList = responseDict['values']
                            # updating the payload with source firewall groups, destination firewall groups, user defined firewall rules, application port profiles
                            action = 'ALLOW' if allLayer3Rule['action'] == 'allow' else 'DROP'
                            payloadDict.update({'name': allLayer3Rule['name'] + "-" + allLayer3Rule['@id'] if allLayer3Rule['name'] != 'Default Allow Rule' else 'Default',
                                                'enabled': True if allLayer3Rule['@disabled'] == 'false' else 'false', 'action': action})
                            payloadDict['sourceFirewallGroups'] = sourcefirewallGroupId
                            payloadDict['destinationFirewallGroups'] = destinationfirewallGroupId
                            payloadDict['logging'] = "true" if allLayer3Rule['@logged'] == "true" else "false"
                            if allLayer3Rule['packetType'] == 'ipv4':
                                payloadDict['ipProtocol'] = "IPV4"
                            elif allLayer3Rule['packetType'] == 'ipv6':
                                payloadDict['ipProtocol'] = "IPV6"
                            else:
                                payloadDict['ipProtocol'] = "IPV4_IPV6"
                            if allLayer3Rule['direction'] == "out":
                                payloadDict['direction'] = "OUT"
                            elif allLayer3Rule['direction'] == "in":
                                payloadDict['direction'] = "IN"
                            else:
                                payloadDict['direction'] = "IN_OUT"
                            # checking for the application key in firewallRule
                            if allLayer3Rule.get('services'):
                                if allLayer3Rule['services'].get('service'):
                                    layer3AppServices = self.getApplicationServicesDetails(vcdid)
                                    allNetworkContextProfilesList = self.getNetworkContextProfiles()
                                    # list instance of application services
                                    firewallRules = allLayer3Rule['services']['service'] if isinstance(allLayer3Rule['services']['service'], list) else [allLayer3Rule['services']['service']]
                                    # iterating over the application services
                                    for applicationService in firewallRules:
                                        for service in layer3AppServices:
                                            if applicationService.get('protocolName'):
                                                if applicationService['protocolName'] == 'TCP' or applicationService['protocolName'] == 'UDP':
                                                    protocol_name, port_id = self._searchApplicationPortProfile(
                                                        applicationPortProfilesList, applicationService['protocolName'],
                                                        applicationService['destinationPort'])
                                                    applicationServicesList.append({'name': protocol_name, 'id': port_id})
                                                else:
                                                    # iterating over the application port profiles
                                                    for value in applicationPortProfilesList:
                                                        if value['name'] == vcdConstants.IPV6ICMP:
                                                            protocol_name, port_id = value['name'], value['id']
                                                            applicationServicesList.append(
                                                                {'name': protocol_name, 'id': port_id})
                                                break
                                            if service['objectId'] == applicationService['value']:
                                                if service['layer'] == 'layer3' or service['layer'] == 'layer4':
                                                    if applicationService['name'] != 'FTP' and applicationService['name'] != 'TFTP':
                                                        if service['element']['applicationProtocol'] == 'TCP' or \
                                                                service['element']['applicationProtocol'] == 'UDP':
                                                            protocol_name, port_id = self._searchApplicationPortProfile(applicationPortProfilesList, service['element']['applicationProtocol'], service['element']['value'])
                                                            applicationServicesList.append({'name': protocol_name, 'id': port_id})
                                                    else:
                                                        # protocol_name, port_id = [[values['name'], values['id']] for values in applicationPortProfilesList if values['name'] == 'FTP' or values['name'] == 'TFTP']
                                                        for values in applicationPortProfilesList:
                                                            if values['name'] == applicationService['name']:
                                                                applicationServicesList.append({'name': values['name'], 'id': values['id']})
                                                    # if protocol is IPV6ICMP
                                                    if service['element']['applicationProtocol'] == 'IPV6ICMP':
                                                        # iterating over the application port profiles
                                                        for value in applicationPortProfilesList:
                                                            if value['name'] == vcdConstants.IPV6ICMP:
                                                                protocol_name, port_id = value['name'], value['id']
                                                                applicationServicesList.append({'name': protocol_name, 'id': port_id})
                                                    # if protocal is IPV4ICMP
                                                    if service['element']['applicationProtocol'] == 'ICMP':
                                                        for value in applicationPortProfilesList:
                                                            if value['name'] == service['name'] or value['name'] == service['name'] + ' Request':
                                                                applicationServicesList.append({'name': value['name'], 'id': value['id']})
                                                if service['layer'] == 'layer7':
                                                    for contextProfile in allNetworkContextProfilesList.values():
                                                        if service['element']['appGuidName'] == contextProfile['name'] or applicationService['name'] == contextProfile['name']:
                                                            networkContextProfilesList.append({'name': contextProfile['name'], 'id': contextProfile['id']})
                                    payloadDict['applicationPortProfiles'] = applicationServicesList
                                    payloadDict['networkContextProfiles'] = networkContextProfilesList
                            else:
                                payloadDict['applicationPortProfiles'] = applicationServicesList
                                payloadDict['networkContextProfiles'] = networkContextProfilesList
                            if len(networkContextProfilesList) >1 and len(applicationServicesList) >=1:
                                for networkContextProfiles in networkContextProfilesList:
                                    payloadDict['networkContextProfiles'] = [networkContextProfiles]
                                    if payloadDict['name'] == 'Default':
                                        self.configDefaultDFW(payloadDict=payloadDict, orgVDCIds=orgvDCgroupIds)
                                        continue
                                    # get api call to retrieve firewall info of target edge gateway
                                    response = self.restClientObj.get(dfwURL, header)
                                    if response.status_code == requests.codes.ok:
                                        # successful retrieval of firewall info
                                        responseDict = response.json()
                                        userDefinedRulesList = responseDict['values']
                                    data['values'] = userDefinedRulesList + [payloadDict] if userDefinedRulesList else [payloadDict]
                                    payloadData = json.dumps(data)
                                    self.headers['Content-Type'] = 'application/json'
                                    # put api call to configure firewall rules on target edge gateway
                                    response = self.restClientObj.put(dfwURL, self.headers, data=payloadData)
                                    if response.status_code == requests.codes.accepted:
                                        # successful configuration of firewall rules on target edge gateway
                                        taskUrl = response.headers['Location']
                                        self._checkTaskStatus(taskUrl=taskUrl)
                                        logger.debug('DFW rule {} with multiple L7 service created successfully.'.format(allLayer3Rule['name']))
                                    else:
                                        # failure in configuration of firewall rules on target edge gateway
                                        response = response.json()
                                        raise Exception('Failed to create DFW rule on target - {}'.format(response['message']))
                                self.rollback.apiData[allLayer3Rule['@id']] = True
                            else:
                                if payloadDict['name'] == 'Default':
                                    self.configDefaultDFW(payloadDict=payloadDict, orgVDCIds=orgvDCgroupIds)
                                    continue
                                data['values'] = userDefinedRulesList + [payloadDict] if userDefinedRulesList else [
                                    payloadDict]
                                payloadData = json.dumps(data)
                                self.headers['Content-Type'] = 'application/json'
                                # put api call to configure firewall rules on target edge gateway
                                response = self.restClientObj.put(dfwURL, self.headers, data=payloadData)
                                if response.status_code == requests.codes.accepted:
                                    # successful configuration of firewall rules on target edge gateway
                                    taskUrl = response.headers['Location']
                                    self._checkTaskStatus(taskUrl=taskUrl)
                                    # setting the configStatus flag meaning the particular firewall rule is configured successfully in order to skip its reconfiguration
                                    # ruleStatus = {allLayer3Rule['@id']: True}
                                    self.rollback.apiData[allLayer3Rule['@id']] = True
                                    logger.debug('DFW rule {} created successfully.'.format(
                                        allLayer3Rule['name']))
                                else:
                                    # failure in configuration of firewall rules on target edge gateway
                                    response = response.json()
                                    raise Exception(
                                        'Failed to create DFW rule on target - {}'.format(response['message']))
        except Exception:
            self.saveMetadataInOrgVdc()
            raise
        finally:
            self.createMetaDataInOrgVDC(sourceOrgVDCId,
                                        metadataDict={'rollbackKey': self.rollback.key}, domain='system')

    @isSessionExpired
    def createDFWIPSET(self, ipsetgroups):
        """
        Description : Create IPSET as security group for firewall
        Parameters: ipsetgroups - All the IPset's information in Source Org VDC
        """
        try:
            if ipsetgroups:
                logger.debug('Creating IPSET in isolated network VDC groups')
                firewallGroupIds = list()
                firewallGroupName = list()
                firewallIdDict = dict()
                conflictnetworks = self.rollback.apiData['ConflictNetworks'] if self.rollback.apiData.get('ConflictNetworks') else []
                ownerRefIds = self.rollback.apiData['OrgVDCGroupID']
                orgvDCgroupIds = list()
                for networks in conflictnetworks:
                    if ownerRefIds.get(networks['id']):
                        orgvDCgroupIds.append(ownerRefIds[networks['id']])
                # iterating over the ipset group list
                for ipsetgroup in ipsetgroups:
                    for orgVDCGroupID in orgvDCgroupIds:
                        # orgVDCGroupID = list(orgVDCGroupID.values())[0]
                        ipAddressList = list()
                        # url to retrieve the info of ipset group by id
                        ipseturl = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                                 vcdConstants.GET_IPSET_GROUP_BY_ID.format(ipsetgroup['objectId']))
                        # get api call to retrieve the ipset group info
                        ipsetresponse = self.restClientObj.get(ipseturl, self.headers)
                        if ipsetresponse.status_code == requests.codes.ok:
                            # successful retrieval of ipset group info
                            ipsetresponseDict = xmltodict.parse(ipsetresponse.content)
                            if self.rollback.apiData.get('DFWIdDict'):
                                if self.rollback.apiData['DFWIdDict'].get(orgVDCGroupID):
                                    if self.rollback.apiData['DFWIdDict'][orgVDCGroupID].get(ipsetresponseDict['ipset']['name']):
                                        continue
                            # storing the ip-address and range present in the IPSET
                            ipsetipaddress = ipsetresponseDict['ipset']['value']

                            description = ipsetresponseDict['ipset']['description'] if ipsetresponseDict['ipset'].get(
                                'description') else ''
                            # if multiple ip=address or range present in the ipset spliting it with ','
                            if "," in ipsetipaddress:
                                ipsetipaddresslist = ipsetipaddress.split(',')
                                ipAddressList.extend(ipsetipaddresslist)
                            else:
                                ipAddressList.append(ipsetipaddress)
                            # creating payload data to create firewall group
                            firewallGroupDict = {'name': ipsetresponseDict['ipset']['name'], 'description': description,
                                                 'ownerRef': {'id': orgVDCGroupID}, 'ipAddresses': ipAddressList}
                            firewallGroupDict = json.dumps(firewallGroupDict)
                            # url to create firewall group
                            firewallGroupUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                             vcdConstants.CREATE_FIREWALL_GROUP)
                            self.headers['Content-Type'] = 'application/json'
                            # post api call to create firewall group
                            response = self.restClientObj.post(firewallGroupUrl, self.headers,
                                                               data=firewallGroupDict)
                            if response.status_code == requests.codes.accepted:
                                # successful creation of firewall group
                                taskUrl = response.headers['Location']
                                firewallGroupId = self._checkTaskStatus(taskUrl, returnOutput=True)
                                logger.debug('Successfully configured IPSET- {} in target'.format(ipsetresponseDict['ipset']['name']))
                                self.rollback.apiData[ipsetgroup['objectId'].split(':')[-1]] = True
                                firewallGroupIds.append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
                                firewallGroupName.append(ipsetresponseDict['ipset']['name'])
                                # creating a dict with firewallName as key and firewallIDs as value
                                firewallIdDict = dict(zip(firewallGroupName, firewallGroupIds))
                                self.rollback.apiData['DFWIdDict'] = {orgVDCGroupID: firewallIdDict}
                            else:
                                errorResponse = response.json()
                                raise Exception('Failed to create IPSET - {}'.format(errorResponse['message']))
                        else:
                            errorResponse = ipsetresponse.json()
                            raise Exception('Failed to get IPSET details due to error - {}'.format(errorResponse['message']))
                return firewallIdDict
        except Exception:
            raise
        else:
            self.rollback.apiData['DFWIPSET'] = True
        finally:
            self.saveMetadataInOrgVdc()

    @isSessionExpired
    def createDFWSecurityGroups(self, networkid):
        """
        Description: Create security groups for network scoped to org vdc group
        parameter:  networkid - urn id of a target network
        """
        try:
            # taking target edge gateway id from apioutput json file
            targetOrgVdcId = self.rollback.apiData['targetOrgVDC']['@id']
            members = list()
            target_networks = self.retrieveNetworkListFromMetadata(targetOrgVdcId, dfwStatus=True, orgVDCType='target')
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.GET_ORG_VDC_NETWORK_BY_ID.format(networkid))
            getnetworkResponse = self.restClientObj.get(url, self.headers)
            if getnetworkResponse.status_code == requests.codes.ok:
                responseDict = json.loads(getnetworkResponse.content)
                for target_network in target_networks:
                    if responseDict['name'] + '-v2t' == target_network['name']:
                        ownerRefID = target_network['ownerRef']['id']
                        network_name = target_network['name']
                        network_id = target_network['id']
                        members.append({'name': network_name, 'id': network_id})
                        # getting the new member name from the list
                        network_name = network_name.split('-')
                        # popping out '-v2t' from the name fetched above
                        network_name.pop(-1)
                        # joining the remaining substrings
                        network_name = '-'.join(network_name)
                        # creating payload data to create firewall group
                        firewallGroupDict = {'name': 'SecurityGroup-(' + network_name + ')'}
                        if self.rollback.apiData.get('vdcGroups'):
                            if self.rollback.apiData['vdcGroups'].get(firewallGroupDict['name']):
                                return self.rollback.apiData['vdcGroups'][firewallGroupDict['name']], ownerRefID
                        # getting the already created firewall groups summaries
                        firewallGroupsUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                          vcdConstants.FIREWALL_GROUPS_SUMMARY)
                        getsummaryResponse = self.restClientObj.get(firewallGroupsUrl, self.headers)
                        if getsummaryResponse.status_code == requests.codes.ok:
                            summaryResponseDict = json.loads(getsummaryResponse.content)
                            summaryValues = summaryResponseDict['values']
                            for summary in summaryValues:
                                # checking if the firewall group is already created for the given edge gateway
                                # if yes then appending the firewall group id to the list
                                if summary['ownerRef']['id'] == ownerRefID and summary['name'] == firewallGroupDict['name']:
                                    ownerRefID = summary['ownerRef']['id']
                                    return summary['id'], ownerRefID
                                    # firewallGroupIds.append(summary['id'])
                        firewallGroupDict['ownerRef'] = {'id': ownerRefID}
                        firewallGroupDict['members'] = members
                        firewallGroupDict['type'] = vcdConstants.SECURITY_GROUP
                        firewallGroupData = json.dumps(firewallGroupDict)
                        # url to create firewall group
                        firewallGroupUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                         vcdConstants.CREATE_FIREWALL_GROUP)
                        self.headers['Content-Type'] = 'application/json'
                        # post api call to create firewall group
                        response = self.restClientObj.post(firewallGroupUrl, self.headers, data=firewallGroupData)
                        if response.status_code == requests.codes.accepted:
                            # successful creation of firewall group
                            taskUrl = response.headers['Location']
                            firewallGroupId = self._checkTaskStatus(taskUrl=taskUrl, returnOutput=True)
                            logger.debug('Successfully configured security group for {}.'.format(
                                network_name))
                            # appending the new firewall group id
                            newFirewallGroupIds = 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)
                            if not self.rollback.apiData.get('vdcGroups'):
                                self.rollback.apiData['vdcGroups'] = dict()
                            self.rollback.apiData['vdcGroups'][firewallGroupDict['name']] = newFirewallGroupIds
                            # returning the firewall group ids
                            return newFirewallGroupIds, ownerRefID
                        else:
                            # failure in creation of firewall group
                            response = response.json()
                            raise Exception('Failed to create Security Group - {}'.format(response['message']))
        except Exception:
            raise
        finally:
            self.saveMetadataInOrgVdc()

    @description('Increase the scope of the network to OrgVDC group')
    @remediate
    def increaseScopeforNetworks(self, rollback=False):
        """
        Description: Increase the scope of the network to OrgVDC group
        parameter:  rollback- True to decrease the scope of networks from NSX-T ORg VDC
        """
        try:
            targetOrgVdcId = self.rollback.apiData['targetOrgVDC']['@id']
            ownerRefID = self.rollback.apiData['OrgVDCGroupID'] if self.rollback.apiData.get('OrgVDCGroupID') else {}
            target_networks = self.retrieveNetworkListFromMetadata(targetOrgVdcId, dfwStatus=True, orgVDCType='target')
            if ownerRefID:
                logger.info(' The scope of the networks is getting changed')
                for target_network in target_networks:
                    url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                        vcdConstants.GET_ORG_VDC_NETWORK_BY_ID.format(target_network['id']))
                    header = {'Authorization': self.headers['Authorization'],
                              'Accept': vcdConstants.OPEN_API_CONTENT_TYPE}
                    response = self.restClientObj.get(url, header)
                    if response.status_code == requests.codes.ok:
                        responseDict = response.json()
                        if target_network['networkType'] == 'ISOLATED':
                            # rollback is true to decrease the scope of ORG VDC networks
                            if rollback:
                                # changing the owner reference from  org VDC group to org VDC
                                responseDict['ownerRef'] = {'id': targetOrgVdcId}
                            else:
                                # changing the owner reference from org VDC to org VDC group
                                responseDict['ownerRef'] = {'id': list(ownerRefID.values())[0] if target_network['id'] not in list(ownerRefID.keys()) else ownerRefID[target_network['id']]}
                            payloadData = json.dumps(responseDict)
                            self.headers['Content-Type'] = 'application/json'
                            # post api call to create firewall group
                            response = self.restClientObj.put(url, self.headers, data=payloadData)
                            if response.status_code == requests.codes.accepted:
                                # successful creation of firewall group
                                taskUrl = response.headers['Location']
                                self._checkTaskStatus(taskUrl, returnOutput=False)
                                logger.debug('The nework - {} scope has been changed successfully'.format(responseDict['name']))
                            else:
                                errorResponse = response.json()
                                # failure in increase scope of the network
                                raise Exception('Failed to change scope of the network {} - {}'.format(responseDict['name'], errorResponse['message']))
                    else:
                        responseDict = response.json()
                        raise Exception('Failed to retrieve network- {}'.format(responseDict['message']))
        except Exception:
            raise

    @isSessionExpired
    def configureDFWgroups(self, entities, allLayer3Rule, firewallIdDict, source=True):
        """
        Description: Configures Firewall group in VDC group
        parameters: entities: This refers source or destination in a DFW rule
                    allLayer3Rule: L3 dfw rule
                    source: True/False to denote the entities is for source or destination
                   firewallIdDict:
        """
        try:
            firewallGroupId = list()
            ipAddressList = list()
            orgvDCgroupId = str()
            ownerRefId = list()
            firewallGroupList = dict()
            orgvDCgroupIds = list(self.rollback.apiData['OrgVDCGroupID'].values()) if self.rollback.apiData.get('OrgVDCGroupID') else []
            ownerRefIds = self.rollback.apiData['OrgVDCGroupID'] if self.rollback.apiData.get('OrgVDCGroupID') else []
            conflictnetworks = self.rollback.apiData['ConflictNetworks'] if self.rollback.apiData.get('ConflictNetworks') else []
            ipsetNames = list()
            for entity in entities:
                if entity['type'] == 'Ipv4Address':
                    ipAddressList.append(entity['value'])
                    for orgvDCgroupId in orgvDCgroupIds:
                        # creating payload data to create firewall group
                        firewallGroupDict = {
                            'name': allLayer3Rule['name'] + '-' + 'Source-' + str(random.randint(1, 1000)) if source else allLayer3Rule['name'] + '-' + 'Destination-' + str(random.randint(1, 1000)),
                            'ownerRef': {'id': orgvDCgroupId},
                            'ipAddresses': ipAddressList}
                        firewallGroupDict = json.dumps(firewallGroupDict)
                        # url to create firewall group
                        firewallGroupUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                         vcdConstants.CREATE_FIREWALL_GROUP)
                        self.headers['Content-Type'] = 'application/json'
                        # post api call to create firewall group
                        response = self.restClientObj.post(firewallGroupUrl, self.headers, data=firewallGroupDict)
                        if response.status_code == requests.codes.accepted:
                            # successful creation of firewall group
                            taskUrl = response.headers['Location']
                            firewallGroup = self._checkTaskStatus(taskUrl=taskUrl, returnOutput=True)
                            if firewallGroupList.get(orgvDCgroupId):
                                firewallGroupList[orgvDCgroupId].update({'urn:vcloud:firewallGroup:{}'.format(firewallGroup): orgvDCgroupId})
                            else:
                                firewallGroupList[orgvDCgroupId] = {
                                    'urn:vcloud:firewallGroup:{}'.format(firewallGroup): orgvDCgroupId}
                            # firewallGroupList.update({'urn:vcloud:firewallGroup:{}'.format(firewallGroup): orgvDCgroupId})
                            # firewallGroupId.append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroup)})
                        else:
                            errorResponse = response.json()
                            raise Exception('Failed to create Firewall group - {}'.format(errorResponse['message']))
                if entity['type'] == 'IPSet':
                    # url to retrieve the info of ipset group by id
                    ipseturl = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress), vcdConstants.GET_IPSET_GROUP_BY_ID.format(entity['value']))
                    # get api call to retrieve the ipset group info
                    ipsetresponse = self.restClientObj.get(ipseturl, self.headers)
                    if ipsetresponse.status_code == requests.codes.ok:
                        # successful retrieval of ipset group info
                        ipsetresponseDict = xmltodict.parse(ipsetresponse.content)
                        ipsetNames.append(ipsetresponseDict['ipset']['name'])
                if entity['type'] == 'Network':
                    securityGroupID, ownerRefId = self.createDFWSecurityGroups(networkid=entity['value'])
                    firewallGroupId.append({'id': securityGroupID})
            return firewallGroupId, ownerRefId, ipsetNames, firewallGroupList
        except Exception:
            raise

    @isSessionExpired
    def dfwRulesRollback(self, rollback=True):
        """
            Description: Removing DFW rules from datacenter group for rollback
        """
        try:
            orgVDCGroupID = list(self.rollback.apiData['OrgVDCGroupID'].values()) if self.rollback.apiData.get('OrgVDCGroupID') else []
            if orgVDCGroupID:
                logger.debug('Removing DFW rules as a part of DFW rollback') if rollback else logger.debug('Removing Default rules in DFW')
                for orgVDCGroupID in orgVDCGroupID:
                    policyURL = '{}{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                vcdConstants.GET_VDC_GROUP_BY_ID.format(orgVDCGroupID),
                                                vcdConstants.ENABLE_DFW_POLICY)
                    header = {'Authorization': self.headers['Authorization'],
                              'Accept': vcdConstants.VCD_API_HEADER}
                    # Fetching policy id
                    policyResponse = self.restClientObj.get(policyURL, header)
                    if policyResponse.status_code == requests.codes.ok:
                        policyResponseDict = policyResponse.json()
                        policyID = policyResponseDict['defaultPolicy']['id']
                    else:
                        errorResponse = policyResponse.json()
                        raise Exception(
                            "Failed to fetch policy details for datacenter group - {}".format(errorResponse['message']))

                    # url to fetch dfw rules
                    dfwURL = '{}{}{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                               vcdConstants.GET_VDC_GROUP_BY_ID.format(orgVDCGroupID),
                                               vcdConstants.ENABLE_DFW_POLICY, vcdConstants.GET_DFW_RULES.format(policyID))
                    # get api call to retrieve dfw rules from datacenter group
                    response = self.restClientObj.get(dfwURL, header)
                    if response.status_code == requests.codes.ok:
                        # successful retrieval of dfw rules
                        responseDict = response.json()
                        userDefinedRulesList = responseDict['values']
                    else:
                        errorResponse = response.json()
                        raise Exception("Failed to fetch dfw rules from target - {}".format(errorResponse['message']))

                    # iterating over rules list to delete the rules using rule id
                    for rule in userDefinedRulesList:
                        deleteRuleUrl = dfwURL + f"/{rule['id']}"
                        response = self.restClientObj.delete(deleteRuleUrl, self.headers)
                        if response.status_code == requests.codes.accepted:
                            # successful deletion of DFW rules from datacenter group
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl=taskUrl)
                            logger.debug("Successfully deleted DFW rule '{}'".format(rule['name']))
                        else:
                            response = response.json()
                            raise Exception(
                                "Failed to delete DFW rule '{}' on target - {}".format(rule['name'], response['message']))
                    logger.debug('Successfully removed DFW rules as a part of DFW rollback') if rollback else logger.debug('Successfully removed default DFW rules')
        except:
            raise

    @isSessionExpired
    def dfwGroupsRollback(self):
        """
            Description: Removing DFW groups from datacenter group for rollback
        """
        try:
            orgVDCGroupID = list(self.rollback.apiData['OrgVDCGroupID'].values()) if self.rollback.apiData.get('OrgVDCGroupID') else []
            if orgVDCGroupID:
                logger.info('Removing DFW groups as a part of DFW rollback')
                # url to fetch firewall groups summary
                firewallGroupUrl = '{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                    vcdConstants.FIREWALL_GROUPS_SUMMARY)
                response = self.restClientObj.get(firewallGroupUrl, self.headers)

                # Fetching firewall groups summary
                firewallGroupsSummary = []
                if response.status_code == requests.codes.ok:
                    logger.debug("Retrieved firewall groups details successfully")
                    responseDict = response.json()
                    resultTotal = responseDict['resultTotal']
                    pageNo = 1
                    pageSizeCount = 0
                else:
                    response = response.json()
                    raise Exception(
                        "Failed to fetch firewall group summary from target - {}".format(response['message']))

                while resultTotal > 0 and pageSizeCount < resultTotal:
                    url = "{}?page={}&pageSize={}".format(firewallGroupUrl, pageNo, vcdConstants.FIREWALL_GROUPS_SUMMARY_PAGE_SIZE)
                    response = self.restClientObj.get(url, self.headers)
                    if response.status_code == requests.codes.ok:
                        responseDict = response.json()
                        firewallGroupsSummary.extend(responseDict['values'])
                        pageSizeCount += len(responseDict['values'])
                        logger.debug('firewall group summary result pageSize = {}'.format(pageSizeCount))
                        pageNo += 1
                    else:
                        response = response.json()
                        raise Exception(
                            "Failed to fetch firewall group summary from target - {}".format(response['message']))

                # Filtering firewall groups corresponding to org vdc group
                firewallGroupsSummary = list(
                    filter(lambda firewallGroup: firewallGroup['ownerRef']['id'] in orgVDCGroupID,
                           firewallGroupsSummary))

                # Iterating over dfw groups to delete the groups using firewall group id
                for firewallGroup in firewallGroupsSummary:
                    deleteFirewallGroupUrl = '{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                           vcdConstants.FIREWALL_GROUP.format(firewallGroup['id']))
                    response = self.restClientObj.delete(deleteFirewallGroupUrl, self.headers)
                    if response.status_code == requests.codes.accepted:
                        taskUrl = response.headers['Location']
                        self._checkTaskStatus(taskUrl=taskUrl)
                        logger.debug("Successfully deleted firewall group '{}'".format(firewallGroup['name']))
                    else:
                        response = response.json()
                        raise Exception(
                            "Failed to delete firewall group '{}' from target - {}".format(firewallGroup['name'],
                                                                                           response['message']))
                logger.debug('Successfully removed DFW groups as a part of DFW rollback')
        except:
            raise

    @isSessionExpired
    def firewallruleRollback(self):
        """
        Description: Removing DFW rules from datacenter group for rollback
        """
        try:
            orgVDCGroupID = list(self.rollback.apiData['OrgVDCGroupID'].values()) if self.rollback.apiData.get('OrgVDCGroupID') else []
            if orgVDCGroupID:
                logger.info('Removing firewall rule as a part of rollback')
                targetEdgeGatewayIdList = [edgeGateway['id'] for edgeGateway in
                                           self.rollback.apiData['targetEdgeGateway']]
                for edgeGatewayId in targetEdgeGatewayIdList:
                    # url to configure firewall rules on target edge gateway
                    firewallUrl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                  vcdConstants.ALL_EDGE_GATEWAYS,
                                                  vcdConstants.T1_ROUTER_FIREWALL_CONFIG.format(edgeGatewayId))
                    response = self.restClientObj.delete(firewallUrl, self.headers)
                    if response.status_code == requests.codes.accepted:
                        taskUrl = response.headers['Location']
                        self._checkTaskStatus(taskUrl=taskUrl)
                    else:
                        response = response.json()
                        raise Exception(
                            "Failed to delete firewall Rules from target - {}".format(response['message']))
                logger.debug('Successfully removed firewall rule as a part of rollback')
        except Exception:
            raise

    @isSessionExpired
    def fetchipset(self, orgVDCgroupIds):
        """
        Description: Fetich IPSET scoped to Orgvdc Groups
        parameters : orgVDCgroupIds - Ids of the org VDC group
        return : ipsetIds - Ids of the ipsets
        """
        try:
            ipsetIds = list()
            # url to fetch firewall groups summary
            firewallGroupsUrl = '{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.FIREWALL_GROUPS_SUMMARY)
            response = self.restClientObj.get(firewallGroupsUrl, self.headers)
            # Fetching firewall groups summary
            firewallGroupsSummary = []
            if response.status_code == requests.codes.ok:
                logger.debug("Retrieved firewall groups details successfully")
                responseDict = response.json()
                resultTotal = responseDict['resultTotal']
                pageNo = 1
                pageSizeCount = 0
            else:
                response = response.json()
                raise Exception(
                    "Failed to fetch firewall group summary from target - {}".format(response['message']))
            while resultTotal > 0 and pageSizeCount < resultTotal:
                url = "{}?page={}&pageSize={}".format(firewallGroupsUrl, pageNo,
                                                      vcdConstants.FIREWALL_GROUPS_SUMMARY_PAGE_SIZE)
                response = self.restClientObj.get(url, self.headers)
                if response.status_code == requests.codes.ok:
                    responseDict = response.json()
                    firewallGroupsSummary.extend(responseDict['values'])
                    pageSizeCount += len(responseDict['values'])
                    logger.debug('firewall group summary result pageSize = {}'.format(pageSizeCount))
                    pageNo += 1
                else:
                    response = response.json()
                    raise Exception(
                        "Failed to fetch firewall group summary from target - {}".format(response['message']))
            # Filtering firewall groups corresponding to org vdc group
            firewallGroupsSummary = list(filter(lambda firewallGroup: firewallGroup['ownerRef']['id'] in orgVDCgroupIds, firewallGroupsSummary))
            for groups in firewallGroupsSummary:
                if groups['type'] == 'IP_SET':
                    ownerRef = groups['ownerRef']['id']
                    ipsetId = groups['id']
                    ipsetName = groups['name']
                    ipsetIds.append({ownerRef: {ipsetName: ipsetId}})
            return ipsetIds
        except Exception:
            raise

    @isSessionExpired
    def configDefaultDFW(self, payloadDict, orgVDCIds):
        """
        Description: Configure default rule in all org vdc groups
        parameters: payloadDict - payload data of the default rules
                    orgVDCIds -  Ids of all org vdcs
        """
        try:
            data = dict()
            for orgvDCgroupId in orgVDCIds:
                # URL to get dfw policies by vdc groud ID
                policyURL = '{}{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                            vcdConstants.GET_VDC_GROUP_BY_ID.format(orgvDCgroupId),
                                            vcdConstants.ENABLE_DFW_POLICY)
                header = {'Authorization': self.headers['Authorization'],
                          'Accept': vcdConstants.VCD_API_HEADER}
                policyResponse = self.restClientObj.get(policyURL, header)
                if policyResponse.status_code == requests.codes.ok:
                    policyResponseDict = policyResponse.json()
                    policyID = policyResponseDict['defaultPolicy']['id']
                    dfwURL = '{}{}{}{}'.format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                               vcdConstants.GET_VDC_GROUP_BY_ID.format(orgvDCgroupId),
                                               vcdConstants.ENABLE_DFW_POLICY, vcdConstants.GET_DFW_RULES.format(policyID))
                    # get api call to retrieve firewall info of target edge gateway
                    response = self.restClientObj.get(dfwURL, header)
                    if response.status_code == requests.codes.ok:
                        # successful retrieval of firewall info
                        responseDict = response.json()
                        userDefinedRulesList = responseDict['values']
                        # get api call to retrieve firewall info of target edge gateway
                        response = self.restClientObj.get(dfwURL, header)
                        if response.status_code == requests.codes.ok:
                            # successful retrieval of firewall info
                            responseDict = response.json()
                            userDefinedRulesList = responseDict['values']
                        data['values'] = userDefinedRulesList + [payloadDict] if userDefinedRulesList else [payloadDict]
                        payloadData = json.dumps(data)
                        self.headers['Content-Type'] = 'application/json'
                        # put api call to configure firewall rules on target edge gateway
                        response = self.restClientObj.put(dfwURL, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            # successful configuration of firewall rules on target edge gateway
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl=taskUrl)
                            logger.debug('Default DFW rule created successfully in VDC group Id: {}.'.format(orgvDCgroupId))
                        else:
                            # failure in configuration of firewall rules on target edge gateway
                            response = response.json()
                            raise Exception('Failed to create DFW rule on target - {}'.format(response['message']))
                else:
                    response = policyResponse.json()
                    raise Exception('Failed to create DFW rule on target - {}'.format(response['message']))
        except Exception:
            raise