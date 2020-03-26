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

from src.core.vcd.vcdValidations import VCDMigrationValidation

logger = logging.getLogger('mainLogger')


class ConfigureEdgeGatewayServices(VCDMigrationValidation):
    """
    Description : Class having edge gateway services configuration operations
    """
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

    def configureServices(self, bgpConfigDict, ipsecConfigDict):
        """
        Description :   Configure the  service to the Target Gateway
        Parameters: bgpConfigDict - BGP Configuration details (DICT)
                    ipsecConfigDict - IPSEC Configuration details (DICT)
        """
        try:
            # login to vmware cloud director
            self.vcdLogin()
            # opening apioutput json file and load it in data
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
            # taking target edge gateway id from apioutput jsin file
            edgeGatewayId = data['targetEdgeGateway']['id']
            # calling all the supported edge gateway services
            self.configTargetIPSEC(edgeGatewayId, ipsecConfigDict)
            self.configureTargetNAT(edgeGatewayId)
            self.configureFirewall(edgeGatewayId, networktype=False)
            self.configBGP(edgeGatewayId, bgpConfigDict)
            self.configureDNS(edgeGatewayId)
            logger.debug("Edge Gateway services configured successfully")
        except Exception:
            raise

    @_isSessionExpired
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

    def configureFirewall(self, edgeGatewayId, networktype=False):
        """
        Description :   Configure Firewall rules on target edge gateway
        Parameters  :   edgeGatewayId   -   id of the edge gateway (STRING)
                        networktype- False/true whether to configure security group or not
                                    default value will be false
        """
        try:
            logger.debug("Configuring Firewall Services in Target Edge Gateway")
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # retrieving list instance of firewall rules from source edge gateway
            sourceFirewallRules = data['sourceEdgeGatewayFirewall'] if isinstance(data['sourceEdgeGatewayFirewall'], list) else [data['sourceEdgeGatewayFirewall']]
            # if firewall rules are configured on source edge gateway
            if sourceFirewallRules:
                logger.info('Firewall is getting configured')
                # url to configure firewall rules on target edge gateway
                firewallUrl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                              vcdConstants.ALL_EDGE_GATEWAYS,
                                              vcdConstants.T1_ROUTER_FIREWALL_CONFIG.format(edgeGatewayId))
                # retrieving the application port profiles
                applicationPortProfilesList = self.getApplicationPortProfiles()
                # iterating over the source edge gateway firewall rules
                for firewallRule in sourceFirewallRules:
                    data = {}
                    ipAddressList = []
                    applicationServicesList = []
                    payloadDict = {}
                    sourcefirewallGroupId = []
                    destinationfirewallGroupId = []
                    # checking for the source key in firewallRule dictionary
                    if firewallRule.get('source', None):
                        # retrieving ip address list source edge gateway firewall rule
                        if firewallRule['source'].get("ipAddress", None):
                            ipAddressList = firewallRule['source']['ipAddress'] if isinstance(firewallRule['source']['ipAddress'], list) else [firewallRule['source']['ipAddress']]
                        ipsetgroups = []
                        networkgroups = []
                        # retrieving ipset list source edge gateway firewall rule
                        if firewallRule['source'].get("groupingObjectId", None):
                            groups = firewallRule['source']['groupingObjectId'] if isinstance(firewallRule['source']['groupingObjectId'], list) else [firewallRule['source']['groupingObjectId']]
                            ipsetgroups = [group for group in groups if "ipset" in group]
                            networkgroups = [group for group in groups if "network" in group]
                        # checking if ipaddress or ipset exist and the networktype should be false
                        if ipsetgroups or ipAddressList and networktype is not True:
                            description = ''
                            # iterating over the ipset group list
                            for ipsetgroup in ipsetgroups:
                                # url to retrieve the info of ipset group by id
                                ipseturl = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                                         vcdConstants.GET_IPSET_GROUP_BY_ID.format(ipsetgroup))
                                # get api call to retrieve the ipset group info
                                ipsetresponse = self.restClientObj.get(ipseturl, self.headers)
                                if ipsetresponse.status_code == requests.codes.ok:
                                    # successful retrieval of ipset group info
                                    ipsetresponseDict = xmltodict.parse(ipsetresponse.content)
                                    ipsetipaddress = ipsetresponseDict['ipset']['value']
                                    description = ipsetresponseDict['ipset']['description'] if ipsetresponseDict['ipset'].get('description') else ''
                                    if "," in ipsetipaddress:
                                        ipsetipaddresslist = ipsetipaddress.split(',')
                                        ipAddressList.extend(ipsetipaddresslist)
                                    else:
                                        ipAddressList.append(ipsetipaddress)
                            # creating payload data to create firewall group
                            firewallGroupDict = {'name': firewallRule['name'] + '-' + str(random.randint(1, 1000))}
                            firewallGroupDict['description'] = description
                            firewallGroupDict['edgeGatewayRef'] = {'id': edgeGatewayId}
                            firewallGroupDict['ipAddresses'] = ipAddressList
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
                                firewallGroupId = self._checkTaskStatus(taskUrl, vcdConstants.CREATE_FIREWALL_GROUP_TASK_NAME, returnOutput=True)
                                sourcefirewallGroupId.append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
                        # checking if any routed org vdc networks added in the firewall rule and networktype should be true
                        if networkgroups and networktype is not False:
                            # get api call to retrieve firewall info of target edge gateway
                            response = self.restClientObj.get(firewallUrl, self.headers)
                            if response.status_code == requests.codes.ok:
                                userDefinedRulesList = []
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
                                            rule['sourceFirewallGroups'].append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
                                            data['userDefinedRules'] = userDefinedRulesList + [rule]
                                        else:
                                            sourcefirewallGroupId.append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
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
                    ipAddressList = []
                    # checking for the destination key in firewallRule dictionary
                    if firewallRule.get('destination', None):
                        # retrieving ip address list source edge gateway firewall rule
                        if firewallRule['destination'].get("ipAddress", None):
                            ipAddressList = firewallRule['destination']['ipAddress'] if isinstance(firewallRule['destination']['ipAddress'], list) else [firewallRule['destination']['ipAddress']]
                        ipsetgroups = []
                        networkgroups = []
                        # retrieving ipset group list source edge gateway firewall rule
                        if firewallRule['destination'].get("groupingObjectId", None):
                            groups = firewallRule['destination']['groupingObjectId'] if isinstance(firewallRule['destination']['groupingObjectId'], list) else [firewallRule['destination']['groupingObjectId']]
                            ipsetgroups = [group for group in groups if "ipset" in group]
                            networkgroups =[group for group in groups if "network" in group]
                        # checking if ipaddress or ipset exist and the networktype should be false
                        if ipsetgroups or ipAddressList and networktype is not True:
                            description = ''
                            # iterating over the ipset group list
                            for ipsetgroup in ipsetgroups:
                                # url to retrieve the info of ipset group by id
                                ipseturl = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                                         vcdConstants.GET_IPSET_GROUP_BY_ID.format(ipsetgroup))
                                # get api call to retrieve the ipset group info
                                ipsetresponse = self.restClientObj.get(ipseturl, self.headers)
                                if ipsetresponse.status_code == requests.codes.ok:
                                    # successful retrieval of ipset group info
                                    ipsetresponseDict = xmltodict.parse(ipsetresponse.content)
                                    ipsetipaddress = ipsetresponseDict['ipset']['value']
                                    description = ipsetresponseDict['ipset']['description'] if ipsetresponseDict['ipset'].get('description') else ''
                                    if "," in ipsetipaddress:
                                        ipsetipaddresslist = ipsetipaddress.split(',')
                                        ipAddressList.extend(ipsetipaddresslist)
                                    else:
                                        ipAddressList.append(ipsetipaddress)
                            # creating payload data to create firewall group
                            firewallGroupDict = {'name': firewallRule['name'] + '-' + str(random.randint(1, 1000))}
                            firewallGroupDict['description'] = description
                            firewallGroupDict['edgeGatewayRef'] = {'id': edgeGatewayId}
                            firewallGroupDict['ipAddresses'] = ipAddressList
                            firewallGroupDict = json.dumps(firewallGroupDict)
                            # url to create firewall group
                            firewallGroupUrl = "{}{}".format(
                                vcdConstants.OPEN_API_URL.format(self.ipAddress),
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
                        # checking if any routed org vdc networks added in the firewall rule and networktype should be true
                        if networkgroups and networktype is not False:
                            # get api call to retrieve firewall info of target edge gateway
                            response = self.restClientObj.get(firewallUrl, self.headers)
                            if response.status_code == requests.codes.ok:
                                userDefinedRulesList = []
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
                                            rule['destinationFirewallGroups'].append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
                                            data['userDefinedRules'] = userDefinedRulesList + [rule]
                                        else:
                                            destinationfirewallGroupId.append({'id': 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)})
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
                    userDefinedRulesList = []
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
                    data['userDefinedRules'] = userDefinedRulesList + [payloadDict] if userDefinedRulesList else [payloadDict]
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
                    payloadData = json.dumps(data)
                    self.headers['Content-Type'] = 'application/json'
                    if networktype is not True:
                        # put api call to configure firewall rules on target edge gateway
                        response = self.restClientObj.put(firewallUrl, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            # successful configuration of firewall rules on target edge gateway
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_FIREWALL_RULES_TASK_NAME)
                            logger.debug('Firewall rule {} created successfully.'.format(firewallRule['name']))
                        else:
                            # failure in configuration of firewall rules on target edge gateway
                            response = response.json()
                            raise Exception('Failed to create Firewall rule - {}'.format(response['message']))
                logger.info('Firewall rules configured succesfully on target Edge gateway')
            else:
                logger.info('No Firewall rules configured in the Source gateway')
        except Exception:
            raise

    @_isSessionExpired
    def configTargetIPSEC(self, t1gatewayId, ipsecConfigDict):
        """
        Description :   Configure the IPSEC service to the Target Gateway
        Parameters  :   edgeGatewayId   -   Id of the Target Edge Gateway  (STRING)
        """
        try:
            logger.debug("Configuring IPSEC Services in Target Edge Gateway")
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # checking if ipsec is enabled on source org vdc edge gateway, if not then returning
            if not ipsecConfigDict or ipsecConfigDict['enabled'] != "true":
                logger.debug('IPSec is not enabled or configured on source Org VDC.')
                return
            # if enabled then retrieveing the list instance of source  ipsec
            sourceIPsecSite = ipsecConfigDict['sites']['site'] if isinstance(ipsecConfigDict['sites']['site'], list) else [ipsecConfigDict['sites']['site']]
            # retrieving the local address from apiOutput.json of target edge gateway
            localAddress = data['targetEdgeGateway']['edgeGatewayUplinks'][0]['subnets']['values'][0]['primaryIp']
            # url to configure the ipsec rules on target edge gateway
            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.T1_ROUTER_IPSEC_CONFIG.format(t1gatewayId))
            # if configured ipsec rules on source org vdc edge gateway, then configuring the same on target edge gateway
            if ipsecConfigDict['enabled'] == "true":
                logger.info('IPsec is getting configured')
                for sourceIPsecSite in sourceIPsecSite:
                    # if the subnet is not a list converting it in the list
                    externalIpCIDR = sourceIPsecSite['localSubnets']['subnet'] if isinstance(sourceIPsecSite['localSubnets']['subnet'], list) else [sourceIPsecSite['localSubnets']['subnet']]
                    RemoteIpCIDR = sourceIPsecSite['peerSubnets']['subnet'] if isinstance(sourceIPsecSite['peerSubnets']['subnet'], list) else [sourceIPsecSite['peerSubnets']['subnet']]
                    # creating payload dictionary
                    payloadDict = {"name": sourceIPsecSite['name'],
                                   "enabled": "true" if sourceIPsecSite['enabled'] == "true" else "false",
                                   "localId": sourceIPsecSite['localId'],
                                   "externalIp": localAddress,
                                   "peerIp": sourceIPsecSite['peerId'],
                                   "RemoteIp": sourceIPsecSite['peerIp'],
                                   "psk": sourceIPsecSite['psk'],
                                   "connectorInitiationMode": " ",
                                   "securityType": "DEFAULT",
                                   "logging": "true" if ipsecConfigDict['logging']['enable'] == "true" else "false"
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

    @_isSessionExpired
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
            resultList = []
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

    @_isSessionExpired
    def _searchApplicationPortProfile(self, applicationPortProfilesList, protocol, port):
        """
        Description :   Search for specific Application Port Profile
        Parameters  :   applicationPortProfilesList - application port profiles list (LIST)
                        protocol - protocal for the Application Port profile (STRING)
                        port - Port for the application Port profile (STRING)
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
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

    @_isSessionExpired
    def configureTargetNAT(self, t1gatewayId):
        """
        Description :   Configure the NAT service to the Target Gateway
        Parameters  :   edgeGatewayId   -   Id of the Target Edge Gateway  (STRING)
        """
        try:
            logger.debug("Configuring NAT Services in Target Edge Gateway")
            # reading apiOutput.json
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
            # checking whether NAT rule is enabled or present in the source org vdc
            if not data['sourceEdgeGatewayNAT'] or data['sourceEdgeGatewayNAT']['enabled'] != "true":
                logger.debug('NAT is not configured or enabled on source Org VDC.')
                return
            natRuleList = data['sourceEdgeGatewayNAT']['natRules']['natRule']
            # checking natrules is a list if not converting it into a list
            sourceNATRules = natRuleList if isinstance(natRuleList, list) else [natRuleList]
            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.T1_ROUTER_NAT_CONFIG.format(t1gatewayId))
            localAddress = data['targetEdgeGateway']['edgeGatewayUplinks'][0]['subnets']['values'][0]['primaryIp']
            version = data['sourceEdgeGatewayNAT']['version']
            logger.info('NAT rules are getting configured')
            applicationPortProfilesList = self.getApplicationPortProfiles()
            userDefinedNAT = [natrule for natrule in sourceNATRules if natrule['ruleType'] == 'user']
            # if source NAT is enabled NAT rule congiguration starts
            if data['sourceEdgeGatewayNAT']['enabled'] == "true":
                for sourceNATRule in userDefinedNAT:
                    # configuring DNAT
                    if sourceNATRule['action'] == "dnat":
                        translatedAddressCIDR = sourceNATRule['translatedAddress']
                        payloadDict = {
                            "ruleId": sourceNATRule['ruleId'],
                            "ruleTag": sourceNATRule['ruleTag'],
                            "ruleDescription": sourceNATRule['description'] if sourceNATRule.get('description') else '',
                            "enabled": "true" if sourceNATRule['enabled'] == "true" else "false",
                            "action": sourceNATRule['action'].upper(),
                            "originalAddress": sourceNATRule['originalAddress'],
                            "translatedAddress": translatedAddressCIDR,
                            "loggingEnabled": "true" if sourceNATRule['loggingEnabled'] == "true" else "false",
                            "version": version
                        }
                        filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
                        # creating payload data
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.CREATE_DNAT_TEMPLATE)
                        payloadData = json.loads(payloadData)
                        # if protocol and port is not equal to any search or creating new application port profiles
                        if sourceNATRule['protocol'] != "any" and sourceNATRule['translatedPort'] != "any":
                            protocol_port_name, protocol_port_id = self._searchApplicationPortProfile(applicationPortProfilesList, sourceNATRule['protocol'], sourceNATRule['translatedPort'])
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
                        payloadData["internalPort"] = sourceNATRule['originalPort'] if sourceNATRule['originalPort'] != "any" else None
                        payloadData = json.dumps(payloadData)
                        self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                        # post api call to configure nat services on target edge gateway
                        response = self.restClientObj.post(url, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl, vcdConstants.CREATE_NAT_RULE_TASK_NAME)
                            logger.debug('NAT is configured successfully on the Target')
                        else:
                            response = response.json()
                            raise Exception('Failed to configure configure NAT on Target {} '.format(response['message']))
                    # configuring SNAT
                    if sourceNATRule['action'] == "snat":
                        # if range present in source orginal address converting it into cidr
                        if "-" in sourceNATRule['originalAddress']:
                            translatedAddressCIDR = self.cidrCalculator(sourceNATRule['originalAddress'])
                        else:
                            translatedAddressCIDR = sourceNATRule['originalAddress']
                        payloadDict = {
                            "ruleId": sourceNATRule['ruleId'],
                            "ruleTag": sourceNATRule['ruleTag'],
                            "ruleDescription": sourceNATRule['description'] if sourceNATRule.get('description') else '',
                            "enabled": "true" if sourceNATRule['enabled'] == "true" else "false",
                            "action": sourceNATRule['action'].upper(),
                            "originalAddress":  sourceNATRule['translatedAddress'],
                            "translatedAddress": translatedAddressCIDR,
                            "loggingEnabled": "true" if sourceNATRule['loggingEnabled'] == "true" else "false",
                            "version": version
                        }
                        filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
                        # creating payload data
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.CREATE_SNAT_TEMPLATE)
                        payloadData = json.loads(payloadData)
                        # if protocol and port is not equal to any search or creating new application port profiles
                        if sourceNATRule['protocol'] != "any" and sourceNATRule['translatedPort'] != "any":
                            protocol_port_name, protocol_port_id = self._searchApplicationPortProfile(
                                applicationPortProfilesList, sourceNATRule['protocol'], sourceNATRule['translatedPort'])
                            # adding application port profile to payload data
                            payloadData["applicationPortProfile"] = {"name": protocol_port_name, "id": protocol_port_id}
                        # if protocal is icmp taking ICMPv4-ALL
                        elif sourceNATRule['protocol'] == "icmp":
                            for value in applicationPortProfilesList:
                                if value['name'] == vcdConstants.ICMP_ALL:
                                    protocol_port_name, protocol_port_id = value['name'], value['id']
                                    # adding application port profile to payload data
                                    payloadData["applicationPortProfile"] = {"name": protocol_port_name,
                                                                             "id": protocol_port_id}
                        else:
                            # setting application port profile None otherwise
                            payloadData["applicationPortProfile"] = None
                        # adding internal port profile to payload data
                        payloadData["internalPort"] = sourceNATRule['originalPort'] if sourceNATRule['originalPort'] != "any" else None
                        payloadData = json.dumps(payloadData)
                        self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                        # post api call to configure nat services on target edge gateway
                        response = self.restClientObj.post(url, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            # successful configuration of nat services on target edge gateway
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl, vcdConstants.CREATE_NAT_RULE_TASK_NAME)
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

    @_isSessionExpired
    def configBGP(self, edgeGatewayID, bgpConfigDict):
        """
        Description :   Configure BGP on the Target Edge Gateway
        """
        try:
            logger.debug("Configuring BGP Services in Target Edge Gateway")
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # checking whether bgp rule is enabled or present in the source edge  gateway; returning if no bgp in source edge gateway
            if not bgpConfigDict or bgpConfigDict['enabled'] != "true":
                logger.debug('BGP service is disabled or configured in Source')
                return
            logger.info('BGP is getting configured')
            ecmp = data['sourceEdgeGatewayRouting']['routingGlobalConfig']['ecmp']
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
            else:
                return
            # iterating over the source edge gateway's bgp neighbours
            for bgpNeighbour in bgpNeighbours:
                # creating payload to configure same bgp neighbours in target edge gateway as those in source edge gateway
                bgpNeighbourpayloadDict = {
                    "neighborAddress": bgpNeighbour['ipAddress'],
                    "remoteASNumber": bgpNeighbour['remoteASNumber'],
                    "keepAliveTimer": int(bgpNeighbour['keepAliveTimer']),
                    "holdDownTimer": int(bgpNeighbour['holdDownTimer']),
                    "allowASIn": "false",
                    "neighborPassword": bgpNeighbour['password']
                }
                # checking for the bgp filters
                if bgpNeighbour.get("bgpFilters"):
                    # retrieving the list instance of bgp filters of source edge gateway
                    bgpFilters = bgpNeighbour['bgpFilters']['bgpFilter'] if isinstance(bgpNeighbour['bgpFilters']['bgpFilter'], list) else [bgpNeighbour['bgpFilters']['bgpFilter']]
                    # iterating over the bgp filters
                    for bgpFilter in bgpFilters:
                        if bgpFilter:
                            # in direction bgp filters
                            if bgpFilter['direction'] == "in":
                                inFilterpayloadDict = {
                                    "name": bgpNeighbour['ipAddress'] + "-" + "IN-" +str(random.randint(1, 1000)),
                                    "prefixes": [
                                        {
                                            "network": bgpFilter['network'],
                                            "action": bgpFilter['action'].upper(),
                                            "greaterThanEqualTo": " ",
                                            "lessThanEqualTo": " "
                                        }
                                    ]
                                }
                                if len(bgpFilter) > 3:
                                    inFilterpayloadDict['prefixes'][0]['greaterThanEqualTo'] = int(bgpFilter['ipPrefixGe'])
                                    inFilterpayloadDict['prefixes'][0]['lessThanEqualTo'] = int(bgpFilter['ipPrefixLe'])
                                inFilterpayloadDict = json.dumps(inFilterpayloadDict)
                                # url to configure in direction filtered bgp services
                                infilterurl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                              vcdConstants.ALL_EDGE_GATEWAYS,
                                                              vcdConstants.CREATE_PREFIX_LISTS_BGP.format(edgeGatewayID))
                                self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                                # post api call to configure in direction filtered bgp services
                                infilterresponse = self.restClientObj.post(infilterurl, headers=self.headers,
                                                                           data=inFilterpayloadDict)
                                if infilterresponse.status_code == requests.codes.accepted:
                                    # successful configuration of in direction filtered bgp services
                                    taskUrl = response.headers['Location']
                                    self._checkTaskStatus(taskUrl, vcdConstants.CREATE_PREFIX_LISTS_TASK_NAME,
                                                          returnOutput=True)
                                    inFilterpayloadDict = json.loads(inFilterpayloadDict)
                                    # get api call to retrieve
                                    inprefixListResponse = self.restClientObj.get(infilterurl, self.headers)
                                    inprefixList = inprefixListResponse.json()
                                    values = inprefixList['values']
                                    for value in values:
                                        if inFilterpayloadDict['name'] == value['name']:
                                            bgpNeighbourpayloadDict['inRoutesFilterRef'] = {"id": value['id'],
                                                                                            "name": value['name']}
                            # out direction bgp filters
                            if bgpFilter['direction'] == "out":
                                outFilterpayloadDict = {
                                    "name": bgpNeighbour['ipAddress'] + "-" + "OUT-" +str(random.randint(1, 1000)),
                                    "prefixes": [
                                        {
                                            "network": bgpFilter['network'],
                                            "action": bgpFilter['action'].upper(),
                                            "greaterThanEqualTo": " ",
                                            "lessThanEqualTo": " "
                                        }
                                    ]
                                }
                                if len(bgpFilter) > 3:
                                    outFilterpayloadDict['prefixes'][0]['greaterThanEqualTo'] = int(bgpFilter['ipPrefixGe'])
                                    outFilterpayloadDict['prefixes'][0]['lessThanEqualTo'] = int(bgpFilter['ipPrefixLe'])
                                outFilterpayloadDict = json.dumps(outFilterpayloadDict)
                                # url to configure out direction filtered bgp services
                                outfilterurl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                               vcdConstants.ALL_EDGE_GATEWAYS,
                                                               vcdConstants.CREATE_PREFIX_LISTS_BGP.format(edgeGatewayID))
                                self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                                # post api call to configure out direction filtered bgp services
                                outfilterresponse = self.restClientObj.post(outfilterurl, headers=self.headers,
                                                                            data=outFilterpayloadDict)
                                outFilterpayloadDict = json.loads(outFilterpayloadDict)
                                if outfilterresponse.status_code == requests.codes.accepted:
                                    # successful configuration of in direction filtered bgp services
                                    taskUrl = response.headers['Location']
                                    self._checkTaskStatus(taskUrl, vcdConstants.CREATE_PREFIX_LISTS_TASK_NAME,
                                                          returnOutput=True)
                                    outprefixListResponse = self.restClientObj.get(outfilterurl, self.headers)
                                    outprefixList = outprefixListResponse.json()
                                    values = outprefixList['values']
                                    for value in values:
                                        if outFilterpayloadDict['name'] == value['name']:
                                            bgpNeighbourpayloadDict['outRoutesFilterRef'] = {"id": value['id'],
                                                                                             "name": value['name']}
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
                        logger.debug('BGP neighbor created successfully')
                    else:
                        # failure in configuring bgp neighbours
                        bgpNeighbourresponse = bgpNeighbourresponse.json()
                        raise Exception('Failed to create neighbors {} '.format(bgpNeighbourresponse['message']))
            logger.info('BGP neighbors configured successfully')
        except Exception:
            raise

    def configureDNS(self, edgeGatewayID):
        """
        Description : Configure DNS on specified edge gateway
        Parameters : edgeGatewayID - source edge gateway ID (STRING)
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            # configure dns on target only if source dns is enabled
            if data.get('sourceEdgeGatewayDNS'):
                logger.info('Configuring DNS on target edge gateway')
                forwardersList = data['sourceEdgeGatewayDNS'] if isinstance(data['sourceEdgeGatewayDNS'], list) else [data['sourceEdgeGatewayDNS']]
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
                    return
                else:
                    # failure in configuring dns
                    errorResponse = apiResponse.json()
                    raise Exception('Failed to configure DNS {} '.format(errorResponse['message']))
        except:
            raise

    @_isSessionExpired
    def connectionPropertiesConfig(self, edgeGatewayID, ipsecConfigDict):
        """
        Description : Configuring Connection properties for IPSEC rules
        Parameters : edgeGatewayID - source edge gateway ID (STRING)
        """
        try:
            if not ipsecConfigDict or ipsecConfigDict['enabled'] != "true":
                logger.debug('IPSec is not enabled or configured on source Org VDC.')
                return
            # url to retrive the ipsec rules on target edge gateway
            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.T1_ROUTER_IPSEC_CONFIG.format(edgeGatewayID))
            ipsecRulesResponse = self.restClientObj.get(url, self.headers)
            if ipsecRulesResponse.status_code == requests.codes.ok:
                ipsecrules = json.loads(ipsecRulesResponse.content)
                ipesecrules = ipsecrules['values'] if isinstance(ipsecrules['values'], list) else [ipsecrules]
                sourceIPsecSites = ipsecConfigDict['sites']['site'] if isinstance(ipsecConfigDict['sites']['site'], list) else [ipsecConfigDict['sites']['site']]
                for sourceIPsecSite in sourceIPsecSites:
                    for ipsecrule in ipesecrules:
                        if ipsecrule['name'] == sourceIPsecSite['name']:
                            ruleid = ipsecrule['id']
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
                                        "perfectForwardSecrecyEnabled": "true" if sourceIPsecSite['enablePfs'] == "true" else "false",
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
                                logger.debug('Connection properties successfully configured for ipsec rule {}'.format(ipsecrule['name']))
                            else:
                                # failure in configuring ipsec configuration properties
                                errorResponse = apiResponse.json()
                                raise Exception('Failed to configure connection properties for ipsec rule {} with errors - {} '.format(ipsecrule['name'], errorResponse['message']))
        except Exception:
            raise

    def createSecurityGroup(self, networkID, firewallRule, edgeGatewayID):
        """
       Description: Create IPSET in the target Edge gateway
       Paramater: ID of source IPSET
        """
        try:
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            # reading data from apiOutput.json
            with open(fileName, 'r') as f:
                data = json.load(f)
            target_networks = data['targetOrgVDCNetworks']
            networkgroups = networkID
            firewallRule = firewallRule
            edgeGatewayId = edgeGatewayID
            members = []
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
            # creating payload data to create firewall group
            firewallGroupDict = {'name': 'SecurityGroup('+ firewallRule['name']+ ')-' + str(random.randint(1, 1000))}
            firewallGroupDict['edgeGatewayRef'] = {'id': edgeGatewayId}
            firewallGroupDict['members'] = members
            firewallGroupDict['type'] = vcdConstants.SECURITY_GROUP
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
                firewallGroupId = self._checkTaskStatus(taskUrl, vcdConstants.CREATE_FIREWALL_GROUP_TASK_NAME, returnOutput=True)
                logger.debug('Successfully configured security group for firewall {}.'.format(firewallRule['id']))
                return firewallGroupId
            else:
                # failure in creation of firewall group
                response = response.json()
                raise Exception('Failed to create Security Group - {}'.format(response['message']))
        except Exception:
            raise
