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

import requests
import xmltodict

import src.core.vcd.vcdConstants as vcdConstants

from src.core.vcd.vcdValidations import VCDMigrationValidation, isSessionExpired, remediate, description

logger = logging.getLogger('mainLogger')


class ConfigureEdgeGatewayServices(VCDMigrationValidation):
    """
    Description : Class having edge gateway services configuration operations
    """
    def configureServices(self, metadata):
        """
        Description :   Configure the  service to the Target Gateway
        Parameters  :   metadata - Status of service configuration (DICT)
        """
        try:
            edgeGatewayId = self.rollback.apiData['targetEdgeGateway']['id']
            ipsecConfigDict = self.rollback.apiData['ipsecConfigDict']

            # reading data from metadata
            data = self.rollback.apiData
            # taking target edge gateway id from apioutput json file
            targetOrgVdcId = data['targetOrgVDC']['@id']

            # Configuring target IPSEC
            self.configTargetIPSEC(edgeGatewayId, ipsecConfigDict)
            # Configuring target NAT
            self.configureTargetNAT(edgeGatewayId)
            # Configuring firewall
            statusForFirewall = metadata.get('configureFirewall')
            self.configureFirewall(edgeGatewayId, targetOrgVdcId, networktype=False, successStatus=statusForFirewall)
            # Configuring BGP
            self.configBGP(edgeGatewayId)
            # Configuring DNS
            self.configureDNS(edgeGatewayId)
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
            start = rangeofips.split('-')[0]
            end = rangeofips.split('-')[-1]
            # to check the network splitting the ip's into octet
            last_oct_start = int(start.split('.')[-1])
            last_oct_end = int(end.split('.')[-1])
            iplist = end.split('.')
            # checking whether the ip is a network
            if last_oct_start == 1:
                diff = (last_oct_end - last_oct_start) + 1
            else:
                diff = last_oct_end - last_oct_start
                if diff == 0:
                    diff = 1
                    value = vcdConstants.CIDR_DICT[str(diff)]
                    iplist.pop()
                    iplist.append(str(0))
                    ip = '.'.join(iplist)
                    result = str(ip) + '/' + value
                    return str(result)
            for i in range(0, 9):
                # to calculate total usable ips
                subnet = 2 ** i
                # checking the total ips and difference and taking the values from CIDR_Dict constant
                if subnet >= diff:
                    value = vcdConstants.CIDR_DICT[str(subnet)]
                    iplist.pop()
                    iplist.append(str(0))
                    ip = '.'.join(iplist)
                    result = str(ip) + '/' + str(value)
                    return str(result)
        except Exception:
            raise

    @description("configuration of Firewall")
    @remediate
    def configureFirewall(self, edgeGatewayId, targetOrgVdcId, networktype=False, successStatus=None):
        """
        Description :   Configure Firewall rules on target edge gateway
        Parameters  :   edgeGatewayId   -   id of the edge gateway (STRING)
                        targetOrgVDCId - ID of target org vdc (STRING)
                        networktype- False/true whether to configure security group or not
                                    default value will be false
        """
        try:
            logger.debug("Configuring Firewall Services in Target Edge Gateway")
            sourceEdgeGatewayId = self.rollback.apiData['sourceEdgeGatewayId'].split(':')[-1]
            data = self.getEdgeGatewayFirewallConfig(sourceEdgeGatewayId, validation=False)
            # retrieving list instance of firewall rules from source edge gateway
            sourceFirewallRules = data if isinstance(data, list) else [data]
            #getting vcd id
            vcdid = self.rollback.apiData['sourceOrgVDC']['@id']
            vcdid = vcdid.split(':')[-1]
            # url to configure firewall rules on target edge gateway
            firewallUrl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                          vcdConstants.ALL_EDGE_GATEWAYS,
                                          vcdConstants.T1_ROUTER_FIREWALL_CONFIG.format(edgeGatewayId))
            # if firewall rules are configured on source edge gateway
            if sourceFirewallRules:
                if not networktype:
                    logger.info('Firewall is getting configured')
                    # retrieving the application port profiles
                    applicationPortProfilesList = self.getApplicationPortProfiles()
                    url = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress), vcdConstants.GET_IPSET_GROUP_BY_ID.format(vcdConstants.IPSET_SCOPE_URL.format(vcdid)))
                    response = self.restClientObj.get(url, self.headers)
                    if response.status_code == requests.codes.ok:
                        responseDict = xmltodict.parse(response.content)
                        if responseDict.get('list'):
                            ipsetgroups = responseDict['list']['ipset'] if isinstance(responseDict['list']['ipset'], list) else [responseDict['list']['ipset']]
                        else:
                            ipsetgroups = []
                        if ipsetgroups:
                            if (successStatus and not successStatus.get('createIPSET')) or not successStatus:
                                firewallIdDict = self.createIPSET(ipsetgroups, edgeGatewayId)
                                # creating a dict with firewallName as key and firewallIDs as value
                                # firewallIdDict = dict(zip(firewallName, firewallIDs))
                        firewallIdDict = self.rollback.apiData.get('firewallIdDict')
                # firstTime variable is to check whether security groups are getting configured for the first time
                firstTime = True
                # iterating over the source edge gateway firewall rules
                for firewallRule in sourceFirewallRules:
                    # if configStatus flag is already set means that the firewall rule is already configured, if so then skipping the configuring of same rule and moving to the next firewall rule
                    if self.rollback.apiData.get(firewallRule['id']) and not networktype:
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
                            ipAddressList = firewallRule['source']['ipAddress'] if isinstance(firewallRule['source']['ipAddress'], list) else [firewallRule['source']['ipAddress']]
                        ipsetgroups = list()
                        networkgroups = list()
                        # retrieving ipset list source edge gateway firewall rule
                        if firewallRule['source'].get("groupingObjectId", None):
                            groups = firewallRule['source']['groupingObjectId'] if isinstance(firewallRule['source']['groupingObjectId'], list) else [firewallRule['source']['groupingObjectId']]
                            ipsetgroups = [group for group in groups if "ipset" in group]
                            networkgroups = [group for group in groups if "network" in group]
                        # checking if the networktype is false
                        if not networktype:
                            if ipAddressList:
                                # creating payload data to create firewall group
                                firewallGroupDict = {'name': firewallRule['name'] + '-' + 'Source-' + str(random.randint(1, 1000)),
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
                                    firewallGroupId = self._checkTaskStatus(taskUrl,
                                                                            vcdConstants.CREATE_FIREWALL_GROUP_TASK_NAME,
                                                                            returnOutput=True)
                                    sourcefirewallGroupId.append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
                                else:
                                    errorResponse = response.json()
                                    raise Exception('Failed to create Firewall group - {}'.format(errorResponse['message']))
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
                                        if ipsetresponseDict['ipset']['name'] in firewallIdDict:
                                            sourcefirewallGroupId.append(firewallIdDict[ipsetresponseDict['ipset']['name']])
                        # checking if any routed org vdc networks added in the firewall rule and networktype should be true
                        if networkgroups and networktype:
                            # checking if there are any network present in the fire wall rule
                            if len(networkgroups) != 0 and firstTime:
                                logger.info('Configuring security groups in the firewall')
                                #Changing it into False because only want to log first time
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
                                        firewallGroupId = self.createSecurityGroup(networkgroups, firewallRule, edgeGatewayId)
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
                                        response = self.restClientObj.put(firewallUrl, self.headers, data=payloadData)
                                        if response.status_code == requests.codes.accepted:
                                            # successful configuration of firewall rules on target edge gateway
                                            taskUrl = response.headers['Location']
                                            self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_FIREWALL_RULES_TASK_NAME)
                                            logger.debug('Firewall rule {} updated successfully with security group.'.format(firewallRule['name']))
                                        else:
                                            # failure in configuration of firewall rules on target edge gateway
                                            response = response.json()
                                            raise Exception('Failed to update Firewall rule - {}'.format(response['message']))
                    ipAddressList = list()
                    # checking for the destination key in firewallRule dictionary
                    if firewallRule.get('destination', None):
                        # retrieving ip address list source edge gateway firewall rule
                        if firewallRule['destination'].get("ipAddress", None):
                            ipAddressList = firewallRule['destination']['ipAddress'] if isinstance(firewallRule['destination']['ipAddress'], list) else [firewallRule['destination']['ipAddress']]
                        ipsetgroups = list()
                        networkgroups = list()
                        # retrieving ipset group list source edge gateway firewall rule
                        if firewallRule['destination'].get("groupingObjectId", None):
                            groups = firewallRule['destination']['groupingObjectId'] if isinstance(firewallRule['destination']['groupingObjectId'], list) else [firewallRule['destination']['groupingObjectId']]
                            ipsetgroups = [group for group in groups if "ipset" in group]
                            networkgroups = [group for group in groups if "network" in group]
                        # checking if networktype is false
                        if not networktype:
                            if ipAddressList:
                                # creating payload data to create firewall group
                                firewallGroupDict = {'name': firewallRule['name'] + '-' + 'destination-' + str(random.randint(1, 1000)),'edgeGatewayRef': {'id': edgeGatewayId},
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
                                    firewallGroupId = self._checkTaskStatus(taskUrl,
                                                                            vcdConstants.CREATE_FIREWALL_GROUP_TASK_NAME,
                                                                            returnOutput=True)
                                    destinationfirewallGroupId.append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
                                else:
                                    errorResponse = response.json()
                                    raise Exception('Failed to create Firewall group - {}'.format(errorResponse['message']))
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
                                        if ipsetresponseDict['ipset']['name'] in firewallIdDict:
                                            destinationfirewallGroupId.append(firewallIdDict[ipsetresponseDict['ipset']['name']])
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
                                        response = self.restClientObj.put(firewallUrl, self.headers, data=payloadData)
                                        if response.status_code == requests.codes.accepted:
                                            # successful configuration of firewall rules on target edge gateway
                                            taskUrl = response.headers['Location']
                                            self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_FIREWALL_RULES_TASK_NAME)
                                            logger.debug('Firewall rule {} updated successfully with security group.'.format(firewallRule['name']))
                                        else:
                                            # failure in configuration of firewall rules on target edge gateway
                                            response = response.json()
                                            raise Exception('Failed to update Firewall rule - {}'.format(response['message']))
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
                        payloadDict.update({'name': firewallRule['name'] +"-"+firewallRule['id'], 'enabled': firewallRule['enabled'], 'action': action})
                        payloadDict['sourceFirewallGroups'] = sourcefirewallGroupId if firewallRule.get('source', None) else []
                        payloadDict['destinationFirewallGroups'] = destinationfirewallGroupId if firewallRule.get('destination', None) else []
                        payloadDict['logging'] = "true" if firewallRule['loggingEnabled'] == "true" else "false"
                        # checking for the application key in firewallRule
                        if firewallRule.get('application'):
                            if firewallRule['application'].get('service'):
                                # list instance of application services
                                firewallRules = firewallRule['application']['service'] if isinstance(firewallRule['application']['service'], list) else [firewallRule['application']['service']]
                                # iterating over the application services
                                for applicationService in firewallRules:
                                    # if protocol is not icmp
                                    if applicationService['protocol'] != "icmp":
                                        protocol_name, port_id = self._searchApplicationPortProfile(applicationPortProfilesList,
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
                                                applicationServicesList.append({'name': protocol_name, 'id': port_id})
                                                payloadDict["applicationPortProfiles"] = applicationServicesList
                        else:
                            payloadDict['applicationPortProfiles'] = applicationServicesList
                        data['userDefinedRules'] = userDefinedRulesList + [payloadDict] if userDefinedRulesList else [payloadDict]
                        payloadData = json.dumps(data)
                        self.headers['Content-Type'] = 'application/json'
                        # put api call to configure firewall rules on target edge gateway
                        response = self.restClientObj.put(firewallUrl, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            # successful configuration of firewall rules on target edge gateway
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_FIREWALL_RULES_TASK_NAME)
                            # setting the configStatus flag meaning the particular firewall rule is configured successfully in order to skip its reconfiguration
                            self.rollback.apiData[firewallRule['id']] = True
                            logger.debug('Firewall rule {} created successfully.'.format(firewallRule['name']))
                        else:
                            # failure in configuration of firewall rules on target edge gateway
                            response = response.json()
                            raise Exception('Failed to create Firewall rule - {}'.format(response['message']))
                if not networktype:
                    logger.info('Firewall rules configured succesfully on target Edge gateway')
                if not firstTime:
                    logger.info('Successfully configured security groups')
        except Exception:
            raise

    @description("configuration of Target IPSEC")
    @remediate
    def configTargetIPSEC(self, t1gatewayId, ipsecConfigDict):
        """
        Description :   Configure the IPSEC service to the Target Gateway
        Parameters  :   edgeGatewayId   -   Id of the Target Edge Gateway  (STRING)
        """
        try:
            logger.info('Configuring Target Edge gateway services.')
            logger.debug("Configuring IPSEC Services in Target Edge Gateway")
            data = self.rollback.apiData
            # checking if ipsec is enabled on source org vdc edge gateway, if not then returning
            if not ipsecConfigDict or not ipsecConfigDict['enabled']:
                logger.debug('IPSec is not enabled or configured on source Org VDC.')
                return
            # if enabled then retrieveing the list instance of source  ipsec
            sourceIPsecSite = ipsecConfigDict['sites']['sites'] if isinstance(ipsecConfigDict['sites']['sites'], list) else [ipsecConfigDict['sites']['sites']]
            # url to configure the ipsec rules on target edge gateway
            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.T1_ROUTER_IPSEC_CONFIG.format(t1gatewayId))
            # if configured ipsec rules on source org vdc edge gateway, then configuring the same on target edge gateway
            if ipsecConfigDict['enabled']:
                logger.info('IPsec is getting configured')
                for sourceIPsecSite in sourceIPsecSite:
                    # if configStatus flag is already set means that the sourceIPsecSite rule is already configured, if so then skipping the configuring of same rule and moving to the next sourceIPsecSite rule
                    if data.get(sourceIPsecSite['name']):
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
                        self._checkTaskStatus(taskUrl, vcdConstants.CREATE_IPSEC_VPN_TASK_NAME)
                        # adding a key here to make sure the rule have configured successfully and when remediation skipping this rule
                        self.rollback.apiData[sourceIPsecSite['name']] = True
                        logger.debug('IPSEC is configured successfully on the Target')
                    else:
                        # if failure configuration of ipsec rules
                        response = response.json()
                        raise Exception('Failed to configure configure IPSEC on Target {} '.format(response['message']))
                logger.info('IPSEC rules configured successfully on the Target')
                # below function configures network property of ipsec rules
                self.connectionPropertiesConfig(t1gatewayId, ipsecConfigDict)
            else:
                # if no ipsec rules are configured on source edge gateway
                logger.info('No IPSEC rules configured in source edge gateway')
        except Exception:
            raise

    @isSessionExpired
    def getApplicationPortProfiles(self):
        """
        Description :   Get Application Port Profiles
        """
        try:
            url = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                vcdConstants.APPLICATION_PORT_PROFILES)
            response = self.restClientObj.get(url, self.headers)
            if response.status_code == requests.codes.ok:
                responseDict = response.json()
                resultTotal = responseDict['resultTotal']
            pageNo = 1
            pageSizeCount = 0
            resultList = list()
            logger.debug('Getting Application port profiles')
            while resultTotal > 0 and pageSizeCount < resultTotal:
                url = "{}{}?page={}&pageSize={}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                        vcdConstants.APPLICATION_PORT_PROFILES, pageNo,
                                                        vcdConstants.APPLICATION_PORT_PROFILES_PAGE_SIZE)
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
                    portprofileID = self._checkTaskStatus(taskUrl, vcdConstants.CREATE_APPLICATION_PORT_PROFILE_TASK_NAME, returnOutput=True)
                    logger.debug('Application port profile is created successfully ')
                    customID = 'urn:vcloud:applicationPortProfile:' + portprofileID
                    return payloadDict['name'], customID
                response = response.json()
                raise Exception('Failed to create application port profile {} '.format(response['message']))
        except Exception:
            raise

    @description("configuration of Target NAT")
    @remediate
    def configureTargetNAT(self, t1gatewayId):
        """
        Description :   Configure the NAT service to the Target Gateway
        Parameters  :   edgeGatewayId   -   Id of the Target Edge Gateway  (STRING)
        """
        try:
            logger.debug("Configuring NAT Services in Target Edge Gateway")
            # reading saved apiData
            sourceEdgeGatewayId = self.rollback.apiData['sourceEdgeGatewayId'].split(':')[-1]
            data = self.getEdgeGatewayNatConfig(sourceEdgeGatewayId, validation=False)
            # checking whether NAT rule is enabled or present in the source org vdc
            if not data or not data['enabled']:
                logger.debug('NAT is not configured or enabled on source Org VDC.')
                return
            if data['natRules']:
                natRuleList = data['natRules']['natRule']
                # checking natrules is a list if not converting it into a list
                sourceNATRules = natRuleList if isinstance(natRuleList, list) else [natRuleList]
                url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                      vcdConstants.T1_ROUTER_NAT_CONFIG.format(t1gatewayId))
                version = data['version']
                logger.info('NAT rules are getting configured')
                applicationPortProfilesList = self.getApplicationPortProfiles()
                userDefinedNAT = [natrule for natrule in sourceNATRules if natrule['ruleType'] == 'user']
                # if source NAT is enabled NAT rule congiguration starts
                if data['enabled']:
                    for sourceNATRule in userDefinedNAT:
                        # checking whether 'ConfigStatus' key is present or not if present skipping that rule while remediation
                        if self.rollback.apiData.get(sourceNATRule['ruleId']):
                            continue
                        payloadData = self.createNATPayloadData(sourceNATRule, applicationPortProfilesList, version)
                        payloadData = json.dumps(payloadData)
                        self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                        # post api call to configure nat services on target edge gateway
                        response = self.restClientObj.post(url, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            # successful configuration of nat services on target edge gateway
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl, vcdConstants.CREATE_NAT_RULE_TASK_NAME)
                            # adding a key here to make sure the rule have configured successfully and when remediation skipping this rule
                            self.rollback.apiData[sourceNATRule['ruleId']] = True
                            logger.debug('NAT is configured successfully on the Target')
                        else:
                            # failed to configure nat services on target edge gateway
                            response = response.json()
                            raise Exception('Failed to configure configure NAT on Target {} '.format(response['message']))
                    logger.info('NAT rules configured successfully on target')
                else:
                    logger.info('No NAT rules configured in Source edge gateway')
        except Exception:
            raise

    @description("configuration of BGP")
    @remediate
    def configBGP(self, edgeGatewayID):
        """
        Description :   Configure BGP on the Target Edge Gateway
        """
        try:
            logger.debug("Configuring BGP Services in Target Edge Gateway")
            sourceEdgeGatewayId = self.rollback.apiData['sourceEdgeGatewayId'].split(':')[-1]
            bgpConfigDict = self.getEdgegatewayBGPconfig(sourceEdgeGatewayId, validation=False)
            data = self.getEdgeGatewayRoutingConfig(sourceEdgeGatewayId, validation=False)
            # checking whether bgp rule is enabled or present in the source edge  gateway; returning if no bgp in source edge gateway
            if not bgpConfigDict or bgpConfigDict['enabled'] != "true":
                logger.debug('BGP service is disabled or configured in Source')
                return
            logger.info('BGP is getting configured')
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
                self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_BGP_CONFIG_TASK_NAME)
                logger.debug('BGP configuration updated successfully.')
            else:
                # failure in configuring bgp on target edge gateway
                response = response.json()
                raise Exception('Failed to configure BGP  - {}'.format(response['message']))
            # checking if bgp neighbours exist in source edge gateway; else returning
            if bgpConfigDict.get('bgpNeighbours'):
                bgpNeighbours = bgpConfigDict['bgpNeighbours']['bgpNeighbour'] if isinstance(bgpConfigDict['bgpNeighbours']['bgpNeighbour'], list) else [bgpConfigDict['bgpNeighbours']['bgpNeighbour']]
                self.createBGPNeighbours(bgpNeighbours, edgeGatewayID)
                logger.info('Successfully configured BGP')
            else:
                logger.debug('No BGP neighbours configured in source BGP')
                return
        except Exception:
            raise

    @description("configuration of DNS")
    @remediate
    def configureDNS(self, edgeGatewayID):
        """
        Description : Configure DNS on specified edge gateway
        Parameters : edgeGatewayID - source edge gateway ID (STRING)
        """
        try:
            # reading apiOutput.json
            sourceEdgeGatewayId = self.rollback.apiData['sourceEdgeGatewayId'].split(':')[-1]
            data = self.getEdgeGatewayDnsConfig(sourceEdgeGatewayId, validation=False)
            # configure dns on target only if source dns is enabled
            if data:
                logger.info('Configuring DNS on target edge gateway')
                forwardersList = data if isinstance(data, list) else [data]
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
                # createing url for dns config update
                url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                      vcdConstants.ALL_EDGE_GATEWAYS,
                                      vcdConstants.CREATE_DNS_CONFIG.format(edgeGatewayID))
                self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                # put api call to configure dns
                apiResponse = self.restClientObj.put(url, headers=self.headers, data=payloadData)
                if apiResponse.status_code == requests.codes.accepted:
                    # successful configuration of dns
                    task_url = apiResponse.headers['Location']
                    self._checkTaskStatus(task_url, vcdConstants.CONFIGURE_DNS_TASK_NAME)
                    logger.info('DNS service configured successfully')
                    url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                          vcdConstants.ALL_EDGE_GATEWAYS,
                                          vcdConstants.CREATE_DNS_CONFIG.format(edgeGatewayID))
                    self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                    # get api call to get dns listener ip
                    response = self.restClientObj.get(url, headers=self.headers)
                    if response.status_code == requests.codes.ok:
                        responseDict = response.json()
                        logger.warning("Use this IP address {} when configuring VM's DNS server and Org VDC network's"
                                       " DNS server".format(responseDict['listenerIp']))
                else:
                    # failure in configuring dns
                    errorResponse = apiResponse.json()
                    raise Exception('Failed to configure DNS {} '.format(errorResponse['message']))
            logger.info('Target Edge gateway services got configured successfully.')
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
                                self._checkTaskStatus(task_url, vcdConstants.UPDATE_IPSEC_TUNNEL_PROPERTIES)
                                # adding a key here to make sure the rule have configured successfully and when remediation skipping this rule
                                self.rollback.apiData[ruleid] = True
                                logger.debug('Connection properties successfully configured for ipsec rule {}'.format(ipsecrule['name']))
                            else:
                                # failure in configuring ipsec configuration properties
                                errorResponse = apiResponse.json()
                                raise Exception('Failed to configure connection properties for ipsec rule {} with errors - {} '.format(ipsecrule['name'], errorResponse['message']))
        except Exception:
            raise

    @remediate
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
                            firewallGroupId = self._checkTaskStatus(taskUrl, vcdConstants.CREATE_FIREWALL_GROUP_TASK_NAME,
                                                                    returnOutput=True)
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
                    self._checkTaskStatus(task_url, vcdConstants.CREATE_BGP_NEIGHBOR_TASK_NAME)
                    # setting the configStatus flag meaning the particular bgpNeighbour rule is configured successfully in order to skip its reconfiguration
                    self.rollback.apiData[bgpNeighbour['ipAddress']] = True
                    logger.debug('BGP neighbor created successfully')
                else:
                    # failure in configuring bgp neighbours
                    bgpNeighbourresponse = bgpNeighbourresponse.json()
                    raise Exception('Failed to create neighbors {} '.format(bgpNeighbourresponse['message']))
            logger.info('BGP neighbors configured successfully')
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
                self._checkTaskStatus(taskUrl, vcdConstants.CREATE_PREFIX_LISTS_TASK_NAME)
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

    def createNATPayloadData(self, sourceNATRule, applicationPortProfilesList, version):
        """
                Description :   Creates the payload data for the NAT service to the Target Gateway
                Parameters  :   sourceNATRule   -   NAT Rule of source gateway  (DICT)
                                applicationPortProfilesList   -   Application Port Profiles  (LIST)
                                version         -
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
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
            # creating payload data
            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.CREATE_DNAT_TEMPLATE)
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
                                # checking source icmp redirect type and icmp redirect port profile
                                if sourceNATRule['icmpType'] == "redirect" and icmpvalue['name'] == "ICMP Redirect":
                                    protocol_port_name, protocol_port_id = icmpvalue['name'], icmpvalue[
                                        'id']
                                    payloadData["applicationPortProfile"] = {"name": protocol_port_name,
                                                                             "id": protocol_port_id}
                            # for the icmp type which is not present in port profiles, will taking it as ICMPv4-ALL
                            elif icmpvalue['name'] == vcdConstants.ICMP_ALL:
                                protocol_port_name, protocol_port_id = icmpvalue['name'], icmpvalue['id']
                                payloadData["applicationPortProfile"] = {"name": protocol_port_name,
                                                                         "id": protocol_port_id}
            else:
                payloadData["applicationPortProfile"] = None
        # configuring SNAT
        if sourceNATRule['action'] == "snat":
            # if range present in source orginal address converting it into cidr
            if "-" in sourceNATRule['originalAddress']:
                translatedAddressCIDR = self.cidrCalculator(sourceNATRule['originalAddress'])
            else:
                translatedAddressCIDR = sourceNATRule['originalAddress']
            payloadDict.update({
                "originalAddress": sourceNATRule['translatedAddress'],
                "translatedAddress": translatedAddressCIDR
            })
            filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
            # creating payload data
            payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                      componentName=vcdConstants.COMPONENT_NAME,
                                                      templateName=vcdConstants.CREATE_SNAT_TEMPLATE)
            payloadData = json.loads(payloadData)
        # # adding internal port profile to payload data
        payloadData["internalPort"] = sourceNATRule['originalPort'] if sourceNATRule['originalPort'] != "any" else None
        return payloadData

    @remediate
    def createIPSET(self, ipsetgroups, edgeGatewayId):
        """
        Description : Create IPSET as security group for firewall
        Parameters: ipsetgroups - All the IPset's information in Source Org VDC
                    edgeGatewayId - The id of the Target edhe gateway
        """
        try:
            if ipsetgroups:
                logger.info('Creating IPSET in Target Edge Gateway')
                firewallGroupIds = list()
                firewallGroupName = list()
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
                            if self.rollback.apiData['firewallIdDict'].get(ipsetresponseDict['ipset']['name']):
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
                            firewallGroupId = self._checkTaskStatus(taskUrl, vcdConstants.CREATE_FIREWALL_GROUP_TASK_NAME,
                                                                    returnOutput=True)
                            self.rollback.apiData[ipsetgroup['objectId'].split(':')[-1]] = True
                            firewallGroupIds.append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
                            firewallGroupName.append(ipsetresponseDict['ipset']['name'])
                            # creating a dict with firewallName as key and firewallIDs as value
                            firewallIdDict = dict(zip(firewallGroupName, firewallGroupIds))
                            self.rollback.apiData['firewallIdDict'] = firewallIdDict
                        else:
                            errorResponse = response.json()
                            raise Exception('Failed to create IPSET - {}'.format(errorResponse['message']))
                logger.info('Successfully configured IPSET in target')
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
            edgeGatewayId = self.rollback.apiData['sourceEdgeGatewayId'].split(':')[-1]
            # url for dhcp configuration
            url = "{}{}{}?async=true".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                  vcdConstants.NETWORK_EDGES,
                                  vcdConstants.EDGE_GATEWAY_DHCP_CONFIG_BY_ID .format(edgeGatewayId))
            # if DHCP pool was present in the source
            if data['ipPools']:
                del data['version']
                logger.info(' RollBack: Configuring DHCP in source edge gateway service')
                payloadData = json.dumps(data)
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
                                return 
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
            data = self.rollback.apiData['ipsecConfigDict']
            # ID of source edge gateway
            edgeGatewayId = self.rollback.apiData['sourceEdgeGatewayId'].split(':')[-1]
            # url for ipsec configuration
            url = "{}{}{}&async=true".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                             vcdConstants.NETWORK_EDGES,
                                             vcdConstants.EDGE_GATEWAY_IPSEC_CONFIG.format(edgeGatewayId))
            if data['sites']:
                del data['version']
                logger.info(' RollBack: Configuring IPSEC in source edge gateway service')
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
                                logger.info('Rollback for IPSEC is completed successfully')
                                return
                                # checking if the task failed
                            if responseDict['edgeJob']['status'] == "FAILED":
                                logger.debug("Failed configuring IPSEC VPN in edge gateway {}".format(responseDict['edgeJob']['message']))
                                raise Exception(responseDict['edgeJob']['message'])
        except Exception:
            raise
