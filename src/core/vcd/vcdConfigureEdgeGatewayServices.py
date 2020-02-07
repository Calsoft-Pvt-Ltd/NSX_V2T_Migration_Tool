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

            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
            edgeGatewayId = data['targetEdgeGateway']['id']
            self.configTargetIPSEC(edgeGatewayId, ipsecConfigDict)
            self.configureTargetNAT(edgeGatewayId)
            self.configureFirewall(edgeGatewayId)
            self.configBGP(edgeGatewayId, bgpConfigDict)
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
            start = rangeofips.split('-')[0]
            end = rangeofips.split('-')[-1]
            last_oct_start = int(start.split('.')[-1])
            last_oct_end = int(end.split('.')[-1])
            iplist = end.split('.')
            diff = 0
            cidr = {
                "1": "32", "2": "31", "4": "30", "8": "29", "16": "28", "32": "27", "64": "26", "128": "25", "256": "24"
            }
            if last_oct_start == 1:
                diff = (last_oct_end - last_oct_start) + 1
            else:
                diff = last_oct_end - last_oct_start
                if diff == 0:
                    diff = 1
                    value = cidr[str(diff)]
                    iplist.pop()
                    iplist.append(str(0))
                    ip = '.'.join(iplist)
                    result = str(ip) + '/' + value
                    return str(result)
            for i in range(0, 9):
                subnet = 2 ** i
                if subnet >= diff:
                    value = cidr[str(subnet)]
                    iplist.pop()
                    iplist.append(str(0))
                    ip = '.'.join(iplist)
                    result = str(ip) + '/' + str(value)
                    return str(result)
        except Exception:
            raise

    def configureFirewall(self, edgeGatewayId):
        """
        Description :   Configure Firewall rules on target edge gateway
        Parameters  :   edgeGatewayId   -   id of the edge gateway (STRING)
        """
        try:
            logger.debug("Configuring Firewall Services in Target Edge Gateway")
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            with open(fileName, 'r') as f:
                data = json.load(f)
            if isinstance(data['sourceEdgeGatewayFirewall'], list):
                sourceFirewallRules = data['sourceEdgeGatewayFirewall']
            else:
                sourceFirewallRules = [data['sourceEdgeGatewayFirewall']]

            if sourceFirewallRules:
                logger.info('Firewall is getting configured')
                firewallUrl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                              vcdConstants.ALL_EDGE_GATEWAYS,
                                              vcdConstants.T1_ROUTER_FIREWALL_CONFIG.format(edgeGatewayId))
                sourcefirewallGroupId = ''
                destinationfirewallGroupId = ''
                applicationPortProfilesList = self.getApplicationPortProfiles()
                for firewallRule in sourceFirewallRules:
                    data = {}
                    ipAddressList = []
                    applicationServicesList = []
                    payloadDict = {}
                    if firewallRule.get('source', None):
                        if firewallRule['source'].get("ipAddress", None):
                            if isinstance(firewallRule['source']['ipAddress'], list):
                                ipAddressList = firewallRule['source']['ipAddress']
                            else:
                                ipAddressList = [firewallRule['source']['ipAddress']]
                        if firewallRule['source'].get("groupingObjectId", None):
                            if isinstance(firewallRule['source']['groupingObjectId'], list):
                                ipsetgroups = firewallRule['source']['groupingObjectId']
                            else:
                                ipsetgroups = [firewallRule['source']['groupingObjectId']]
                            for ipsetgroup in ipsetgroups:
                                ipseturl = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                                         vcdConstants.GET_IPSET_GROUP_BY_ID.format(ipsetgroup))
                                ipsetresponse = self.restClientObj.get(ipseturl, self.headers)
                                if ipsetresponse.status_code == requests.codes.ok:
                                    ipsetresponseDict = xmltodict.parse(ipsetresponse.content)
                                    ipsetipaddress = ipsetresponseDict['ipset']['value']
                                    if "," in ipsetipaddress:
                                        ipsetipaddresslist = ipsetipaddress.split(',')
                                        ipAddressList.extend(ipsetipaddresslist)
                                    else:
                                        ipAddressList.append(ipsetipaddress)
                        firewallGroupDict = {'name': firewallRule['name'] + '-' + str(random.randint(1, 1000))}
                        firewallGroupDict['edgeGatewayRef'] = {'id': edgeGatewayId}
                        firewallGroupDict['ipAddresses'] = ipAddressList
                        firewallGroupDict = json.dumps(firewallGroupDict)
                        firewallGroupUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                         vcdConstants.CREATE_FIREWALL_GROUP)
                        self.headers['Content-Type'] = 'application/json'
                        response = self.restClientObj.post(firewallGroupUrl, self.headers, data=firewallGroupDict)
                        if response.status_code == requests.codes.accepted:
                            taskUrl = response.headers['Location']
                            firewallGroupId = self._checkTaskStatus(taskUrl,
                                                                    vcdConstants.CREATE_FIREWALL_GROUP_TASK_NAME,
                                                                    returnOutput=True)
                            sourcefirewallGroupId = 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)
                        else:
                            response = response.json()
                            raise Exception('Failed to create Security Group - {}'.format(response['message']))
                    ipAddressList = []
                    if firewallRule.get('destination', None):
                        if firewallRule['destination'].get("ipAddress", None):
                            if isinstance(firewallRule['destination']['ipAddress'], list):
                                ipAddressList = firewallRule['destination']['ipAddress']
                            else:
                                ipAddressList = [firewallRule['destination']['ipAddress']]
                        if firewallRule['destination'].get("groupingObjectId", None):
                            if isinstance(firewallRule['destination']['groupingObjectId'], list):
                                ipsetgroups = firewallRule['destination']['groupingObjectId']
                            else:
                                ipsetgroups = [firewallRule['destination']['groupingObjectId']]
                            for ipsetgroup in ipsetgroups:
                                ipseturl = "{}{}".format(vcdConstants.XML_VCD_NSX_API.format(self.ipAddress),
                                                         vcdConstants.GET_IPSET_GROUP_BY_ID.format(ipsetgroup))
                                ipsetresponse = self.restClientObj.get(ipseturl, self.headers)
                                if ipsetresponse.status_code == requests.codes.ok:
                                    ipsetresponseDict = xmltodict.parse(ipsetresponse.content)
                                    ipsetipaddress = ipsetresponseDict['ipset']['value']
                                    if "," in ipsetipaddress:
                                        ipsetipaddresslist = ipsetipaddress.split(',')
                                        ipAddressList.extend(ipsetipaddresslist)
                                    else:
                                        ipAddressList.append(ipsetipaddress)
                        firewallGroupDict = {'name': firewallRule['name'] + '-' + str(random.randint(1, 1000))}
                        firewallGroupDict['edgeGatewayRef'] = {'id': edgeGatewayId}
                        firewallGroupDict['ipAddresses'] = ipAddressList
                        firewallGroupDict = json.dumps(firewallGroupDict)
                        firewallGroupUrl = "{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                         vcdConstants.CREATE_FIREWALL_GROUP)
                        self.headers['Content-Type'] = 'application/json'
                        response = self.restClientObj.post(firewallGroupUrl, self.headers, data=firewallGroupDict)
                        if response.status_code == requests.codes.accepted:
                            taskUrl = response.headers['Location']
                            firewallGroupId = self._checkTaskStatus(taskUrl,
                                                                    vcdConstants.CREATE_FIREWALL_GROUP_TASK_NAME,
                                                                    returnOutput=True)
                            destinationfirewallGroupId = 'urn:vcloud:firewallGroup:{}'.format(firewallGroupId)
                        else:
                            response = response.json()
                            raise Exception('Failed to create Security Group - {}'.format(response['message']))
                    userDefinedRulesList = []
                    response = self.restClientObj.get(firewallUrl, self.headers)
                    if response.status_code == requests.codes.ok:
                        responseDict = response.json()
                        userDefinedRulesList = responseDict['userDefinedRules']
                    action = 'ALLOW' if firewallRule['action'] == 'accept' else 'DROP'
                    payloadDict.update({'name': firewallRule['name'], 'enabled': firewallRule['enabled'], 'action': action})
                    if firewallRule.get('source', None):
                        payloadDict['sourceFirewallGroups'] = [{'id': sourcefirewallGroupId}]
                    else:
                        payloadDict['sourceFirewallGroups'] = []
                    if firewallRule.get('destination', None):
                        payloadDict['destinationFirewallGroups'] = [{'id': destinationfirewallGroupId}]
                    else:
                        payloadDict['destinationFirewallGroups'] = []
                    if userDefinedRulesList:
                        data['userDefinedRules'] = userDefinedRulesList + [payloadDict]
                    else:
                        data['userDefinedRules'] = [payloadDict]
                    if firewallRule.get('application'):
                        if firewallRule['application'].get('service'):
                            firewallRules = firewallRule['application']['service'] if isinstance(firewallRule['application']['service'], list) else [firewallRule['application']['service']]
                            for applicationService in firewallRules:
                                if applicationService['protocol'] != "icmp":
                                    protocol_name, port_id = self._searchApplicationPortProfile(
                                        applicationPortProfilesList,
                                        applicationService['protocol'], applicationService['port'])
                                    applicationServicesList.append({'name': protocol_name, 'id': port_id})
                                    payloadDict['applicationPortProfiles'] = applicationServicesList
                                else:
                                    for value in applicationPortProfilesList:
                                        if value['name'] == vcdConstants.ICMP_ALL:
                                            protocol_name, port_id = value['name'], value['id']
                                            applicationServicesList.append({'name': protocol_name, 'id': port_id})
                                            payloadDict["applicationPortProfiles"] = applicationServicesList
                    else:
                        payloadDict['applicationPortProfiles'] = applicationServicesList
                    payloadData = json.dumps(data)
                    self.headers['Content-Type'] = 'application/json'
                    response = self.restClientObj.put(firewallUrl, self.headers, data=payloadData)
                    if response.status_code == requests.codes.accepted:
                        taskUrl = response.headers['Location']
                        self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_FIREWALL_RULES_TASK_NAME)
                        logger.debug('Firewall rule {} created successfully.'.format(firewallRule['name']))
                    else:
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
            with open(fileName, 'r') as f:
                data = json.load(f)
            if ipsecConfigDict is None or ipsecConfigDict['enabled'] != "true":
                logger.debug('IPSec is not enabled or configured on source Org VDC.')
                return
            if isinstance(ipsecConfigDict['sites']['site'], list):
                sourceIPsecSite = ipsecConfigDict['sites']['site']
            else:
                sourceIPsecSite = [ipsecConfigDict['sites']['site']]
            localAddress = data['targetEdgeGateway']['edgeGatewayUplinks'][0]['subnets']['values'][0]['primaryIp']
            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.T1_ROUTER_IPSEC_CONFIG.format(t1gatewayId))
            if ipsecConfigDict['enabled'] == "true":
                logger.info('IPsec is getting configured')
                for sourceIPsecSite in sourceIPsecSite:
                    # if the subnet is not a list converting it in the list
                    if isinstance(sourceIPsecSite['localSubnets']['subnet'], list):
                        externalIpCIDR = sourceIPsecSite['localSubnets']['subnet']
                    else:
                        externalIpCIDR = [sourceIPsecSite['localSubnets']['subnet']]
                    if isinstance(sourceIPsecSite['peerSubnets']['subnet'], list):
                        RemoteIpCIDR = sourceIPsecSite['peerSubnets']['subnet']
                    else:
                        RemoteIpCIDR = [sourceIPsecSite['peerSubnets']['subnet']]
                    payloadDict = {"name": sourceIPsecSite['name'],
                                   "enabled": sourceIPsecSite['enabled'],
                                   "localId": sourceIPsecSite['localId'],
                                   "externalIp": localAddress,
                                   "peerIp": sourceIPsecSite['peerId'],
                                   "RemoteIp": sourceIPsecSite['peerIp'],
                                   "psk": sourceIPsecSite['psk'],
                                   "connectorInitiationMode": " ",
                                   "securityType": "DEFAULT"
                                   }
                    filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
                    payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                              componentName=vcdConstants.COMPONENT_NAME,
                                                              templateName=vcdConstants.CREATE_IPSEC_TEMPLATE)
                    payloadData = json.loads(payloadData)
                    payloadData['localEndpoint']['localNetworks'] = externalIpCIDR
                    payloadData['remoteEndpoint']['remoteNetworks'] = RemoteIpCIDR
                    payloadData = json.dumps(payloadData)
                    self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                    response = self.restClientObj.post(url, self.headers, data=payloadData)
                    if response.status_code == requests.codes.accepted:
                        taskUrl = response.headers['Location']
                        self._checkTaskStatus(taskUrl, vcdConstants.CREATE_IPSEC_VPN_TASK_NAME)
                        logger.debug('IPSEC is configured successfully on the Target')
                    else:
                        response = response.json()
                        raise Exception('Failed to configure configure IPSEC on Target {} '.format(response['message']))
                logger.info('IPSEC rules configured successfully on the Target')
            else:
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
                time.sleep(5)
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
            # checking whether NAT rule is enabled ot present in the source org vdc
            if data['sourceEdgeGatewayNAT'] is None or data['sourceEdgeGatewayNAT']['enabled'] != "true":
                logger.debug('NAT is not configured or enabled on source Org VDC.')
                return
            natRuleList = data['sourceEdgeGatewayNAT']['natRules']['natRule']
            # checking natrules is a list if not converting it into a list
            if isinstance(natRuleList, list):
                sourceNATRules = natRuleList
            else:
                sourceNATRules = [natRuleList]

            url = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                  vcdConstants.T1_ROUTER_NAT_CONFIG.format(t1gatewayId))
            localAddress = data['targetEdgeGateway']['edgeGatewayUplinks'][0]['subnets']['values'][0]['primaryIp']
            version = data['sourceEdgeGatewayNAT']['version']
            applicationPortProfilesList = self.getApplicationPortProfiles()
            userDefinedNAT = [natrule for natrule in sourceNATRules if natrule['ruleType'] == 'user']
            # if source NAT is enabled NAT rule congiguration starts
            if data['sourceEdgeGatewayNAT']['enabled'] == "true":
                logger.info('NAT rules are getting configured')
                for sourceNATRule in userDefinedNAT:
                    # configuring DNAT
                    if sourceNATRule['action'] == "dnat":
                        translatedAddressCIDR = sourceNATRule['translatedAddress']
                        payloadDict = {
                            "ruleId": sourceNATRule['ruleId'],
                            "ruleTag": sourceNATRule['ruleTag'],
                            "enabled": sourceNATRule['enabled'],
                            "action": sourceNATRule['action'].upper(),
                            "originalAddress": localAddress,
                            "translatedAddress": translatedAddressCIDR,
                            "loggingEnabled": sourceNATRule['loggingEnabled'],
                            "version": version
                        }
                        filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
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
                        if sourceNATRule['originalPort'] != "any":
                            payloadData["internalPort"] = sourceNATRule['originalPort']
                        else:
                            payloadData["internalPort"] = None
                        payloadData = json.dumps(payloadData)
                        self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                        response = self.restClientObj.post(url, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl, vcdConstants.CREATE_NAT_RULE_TASK_NAME)
                            logger.debug('NAT is configured successfully on the Target')
                        else:
                            response = response.json()
                            raise Exception(
                                'Failed to configure configure NAT on Target {} '.format(response['message']))
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
                            "enabled": sourceNATRule['enabled'],
                            "action": sourceNATRule['action'].upper(),
                            "originalAddress": localAddress,
                            "translatedAddress": translatedAddressCIDR,
                            "loggingEnabled": sourceNATRule['loggingEnabled'],
                            "version": version
                        }
                        filePath = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'template.json')
                        payloadData = self.vcdUtils.createPayload(filePath, payloadDict, fileType='json',
                                                                  componentName=vcdConstants.COMPONENT_NAME,
                                                                  templateName=vcdConstants.CREATE_SNAT_TEMPLATE)
                        payloadData = json.loads(payloadData)
                        # if protocol and port is not equal to any search or creating new application port profiles
                        if sourceNATRule['protocol'] != "any" and sourceNATRule['translatedPort'] != "any":
                            protocol_port_name, protocol_port_id = self._searchApplicationPortProfile(
                                applicationPortProfilesList, sourceNATRule['protocol'], sourceNATRule['translatedPort'])
                            payloadData["applicationPortProfile"] = {"name": protocol_port_name, "id": protocol_port_id}
                        # if protocal is icmp taking ICMPv4-ALL
                        elif sourceNATRule['protocol'] == "icmp":
                            for value in applicationPortProfilesList:
                                if value['name'] == vcdConstants.ICMP_ALL:
                                    protocol_port_name, protocol_port_id = value['name'], value['id']
                                    payloadData["applicationPortProfile"] = {"name": protocol_port_name,
                                                                             "id": protocol_port_id}
                        else:
                            payloadData["applicationPortProfile"] = None
                        if sourceNATRule['originalPort'] != "any":
                            payloadData["internalPort"] = sourceNATRule['originalPort']
                        else:
                            payloadData["internalPort"] = None
                        payloadData = json.dumps(payloadData)
                        self.headers["Content-Type"] = vcdConstants.OPEN_API_CONTENT_TYPE
                        response = self.restClientObj.post(url, self.headers, data=payloadData)
                        if response.status_code == requests.codes.accepted:
                            taskUrl = response.headers['Location']
                            self._checkTaskStatus(taskUrl, vcdConstants.CREATE_NAT_RULE_TASK_NAME)
                            logger.debug('NAT is configured successfully on the Target')
                        else:
                            response = response.json()
                            raise Exception(
                                'Failed to configure configure NAT on Target {} '.format(response['message']))
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
            with open(fileName, 'r') as f:
                data = json.load(f)
            if bgpConfigDict is None or bgpConfigDict['enabled'] != "true":
                logger.debug('BGP service is disabled or configured in Source')
                return
            logger.info('BGP is getting configured')
            ecmp = data['sourceEdgeGatewayRouting']['routingGlobalConfig']['ecmp']
            bgpurl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress), vcdConstants.ALL_EDGE_GATEWAYS,
                                     vcdConstants.T1_ROUTER_BGP_CONFIG.format(edgeGatewayID))
            versionresponse = self.restClientObj.get(bgpurl, self.headers)
            if versionresponse.status_code == requests.codes.ok:
                versionresponseDict = json.loads(versionresponse.content)
                version = versionresponseDict['version']['version']
            else:
                version = 1
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
            response = self.restClientObj.put(bgpurl, self.headers, data=bgpPayloaddata)
            if response.status_code == requests.codes.accepted:
                taskUrl = response.headers['Location']
                self._checkTaskStatus(taskUrl, vcdConstants.UPDATE_BGP_CONFIG_TASK_NAME)
                logger.debug('BGP configuration updated successfully.')
            else:
                response = response.json()
                raise Exception('Failed to configure BGP  - {}'.format(response['message']))
            if bgpConfigDict.get('bgpNeighbours'):
                if isinstance(bgpConfigDict['bgpNeighbours']['bgpNeighbour'], list):
                    bgpNeighbours = bgpConfigDict['bgpNeighbours']['bgpNeighbour']
                else:
                    bgpNeighbours = [bgpConfigDict['bgpNeighbours']['bgpNeighbour']]
            else:
                return
            for bgpNeighbour in bgpNeighbours:
                bgpNeighbourpayloadDict = {
                    "neighborAddress": bgpNeighbour['ipAddress'],
                    "remoteASNumber": bgpNeighbour['remoteASNumber'],
                    "keepAliveTimer": int(bgpNeighbour['keepAliveTimer']),
                    "holdDownTimer": int(bgpNeighbour['holdDownTimer']),
                    "allowASIn": "false",
                    "neighborPassword": bgpNeighbour['password']
                }
                if bgpNeighbour.get("bgpFilters"):
                    if isinstance(bgpNeighbour['bgpFilters']['bgpFilter'], list):
                        bgpFilters = bgpNeighbour['bgpFilters']['bgpFilter']
                    else:
                        bgpFilters = [bgpNeighbour['bgpFilters']['bgpFilter']]
                    for bgpFilter in bgpFilters:
                        if bgpFilter:
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
                                infilterurl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                              vcdConstants.ALL_EDGE_GATEWAYS,
                                                              vcdConstants.CREATE_PREFIX_LISTS_BGP.format(edgeGatewayID))
                                self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                                infilterresponse = self.restClientObj.post(infilterurl, headers=self.headers,
                                                                           data=inFilterpayloadDict)
                                if infilterresponse.status_code == requests.codes.accepted:
                                    taskUrl = response.headers['Location']
                                    self._checkTaskStatus(taskUrl, vcdConstants.CREATE_PREFIX_LISTS_TASK_NAME,
                                                          returnOutput=True)
                                    inFilterpayloadDict = json.loads(inFilterpayloadDict)
                                    inprefixListResponse = self.restClientObj.get(infilterurl, self.headers)
                                    inprefixList = inprefixListResponse.json()
                                    values = inprefixList['values']
                                    for value in values:
                                        if inFilterpayloadDict['name'] == value['name']:
                                            bgpNeighbourpayloadDict['inRoutesFilterRef'] = {"id": value['id'],
                                                                                            "name": value['name']}
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
                                outfilterurl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                               vcdConstants.ALL_EDGE_GATEWAYS,
                                                               vcdConstants.CREATE_PREFIX_LISTS_BGP.format(edgeGatewayID))
                                self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                                outfilterresponse = self.restClientObj.post(outfilterurl, headers=self.headers,
                                                                            data=outFilterpayloadDict)
                                outFilterpayloadDict = json.loads(outFilterpayloadDict)
                                if outfilterresponse.status_code == requests.codes.accepted:
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
                    bgpNeighboururl = "{}{}{}".format(vcdConstants.OPEN_API_URL.format(self.ipAddress),
                                                      vcdConstants.ALL_EDGE_GATEWAYS,
                                                      vcdConstants.CREATE_BGP_NEIGHBOR_CONFIG.format(edgeGatewayID))
                    self.headers['Content-Type'] = vcdConstants.OPEN_API_CONTENT_TYPE
                    bgpNeighbourresponse = self.restClientObj.post(bgpNeighboururl, headers=self.headers,
                                                                   data=bgpNeighbourpayloadData)
                    if bgpNeighbourresponse.status_code == requests.codes.accepted:
                        task_url = bgpNeighbourresponse.headers['Location']
                        self._checkTaskStatus(task_url, vcdConstants.CREATE_BGP_NEIGHBOR_TASK_NAME)
                        logger.debug('BGP neighbor created successfully')
                    else:
                        bgpNeighbourresponse = bgpNeighbourresponse.json()
                        raise Exception('Failed to create neighbors {} '.format(bgpNeighbourresponse['message']))
            logger.info('BGP neighbors configured successfully')
        except Exception:
            raise
