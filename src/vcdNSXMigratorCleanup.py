# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which performs all the clean-up tasks after migrating the VMware Cloud Director from NSX-V to NSX-T
"""

import ipaddress
import logging
import os
import sys

# Set path till src folder in PYTHONPATH
cwd = os.getcwd()
parentDir = os.path.abspath(os.path.join(cwd, os.pardir))
sys.path.append(parentDir)

class VMwareCloudDirectorNSXMigratorCleanup():
    """
    Description :   The class has methods which do all the clean-up tasks(like deleting, resetting, etc) after migrating the VMware vCloud Director from NSX-V to NSX-T
    """
    def __init__(self, inputDict, vcdObj, nsxtObj, passFilePath):
        """
        Description :   Initializer method of all clean-up tasks
        """
        self.consoleLogger = logging.getLogger("consoleLogger")
        self.mainLogfile = logging.getLogger('mainLogger').handlers[0].baseFilename
        self.inputDict = inputDict
        self.nsxtObj = nsxtObj
        self.vcdObj = vcdObj
        self.passFilePath = passFilePath

    def run(self):
        """
        Description :   Deletes the source Organization VDC and renames target
        """
        try:
            orgName = self.inputDict.OrgName
            sourceOrgVDCName = self.inputDict.OrgVDCName

            # getting the organization details
            self.consoleLogger.info('Getting the Organization {} details.'.format(orgName))
            orgUrl = self.vcdObj.getOrgUrl(orgName)

            # getting the source provider VDC details and checking if its NSX-V backed
            self.consoleLogger.info('Getting the source Provider VDC - {} details.'.format(self.inputDict.NSXVProviderVDCName))
            sourceProviderVDCId, isNSXTbacked = self.vcdObj.getProviderVDCId(self.inputDict.NSXVProviderVDCName)

            # getting the source organization vdc details from the above organization
            self.consoleLogger.info('Getting the source Organization VDC {} details.'.format(sourceOrgVDCName))
            sourceOrgVDCId = self.vcdObj.getOrgVDCDetails(orgUrl, sourceOrgVDCName, 'sourceOrgVDC', saveResponse=False)

            # getting source external network data
            self.consoleLogger.info('Getting the source external networks details.')
            metadata = self.vcdObj.getOrgVDCMetadata(sourceOrgVDCId, domain='general')
            sourceExternalNetworkData = metadata.get('sourceExternalNetwork', [])


            # validating whether source org vdc is NSX-V backed
            self.consoleLogger.info('Validating whether source Org VDC is NSX-V backed')
            self.vcdObj.validateOrgVDCNSXbacking(sourceOrgVDCId, sourceProviderVDCId, isNSXTbacked)

            # getting the source edge gateway details
            edgeGatewayDetails = self.vcdObj.getOrgVDCEdgeGateway(sourceOrgVDCId)['values']

            #  getting the target provider VDC details and checking if its NSX-T backed
            self.consoleLogger.info('Getting the target Provider VDC - {} details.'.format(self.inputDict.NSXTProviderVDCName))
            targetProviderVDCId, isNSXTbacked = self.vcdObj.getProviderVDCId(self.inputDict.NSXTProviderVDCName)

            # getting the target organization vdc details from the above organization
            self.consoleLogger.info('Getting the target Organization VDC {} details.'.format(sourceOrgVDCName + '-v2t'))
            targetOrgVDCId = self.vcdObj.getOrgVDCDetails(orgUrl, sourceOrgVDCName + '-v2t', 'targetOrgVDC', saveResponse=False)

            # validating whether target org vdc is NSX-T backed
            self.consoleLogger.info('Validating whether target Org VDC is NSX-T backed')
            self.vcdObj.validateOrgVDCNSXbacking(targetOrgVDCId, targetProviderVDCId, isNSXTbacked)

            # validating if target org vdc is enabled or disabled
            self.consoleLogger.info('Validating whether target Org VDC is enabled')
            self.vcdObj.validateTargetOrgVDCState(targetOrgVDCId)

            # getting the target organization vdc details from the above organization
            self.consoleLogger.info('Getting the target Organization VDC {} network details.'.format(sourceOrgVDCName + '-v2t'))
            dfwStatus = True if metadata.get('OrgVDCGroupID') else False
            orgVDCNetworkList = self.vcdObj.getOrgVDCNetworks(targetOrgVDCId, 'targetOrgVDCNetworks', saveResponse=False, dfwStatus=dfwStatus)

            # validating media is connected to any of the vms
            self.consoleLogger.info('Validating whether media is attached to any vApp VMs')
            self.vcdObj.validateVappVMsMediaNotConnected(targetOrgVDCId, raiseError=True)

            # migrating catalog items - vApp Templates and media objects
            self.consoleLogger.info('Migrating catalog items - vApp Templates & media objects.')
            self.vcdObj.migrateCatalogItems(sourceOrgVDCId, targetOrgVDCId, orgUrl)

            # clearing nsx-t bridging
            self.consoleLogger.info('Removing bridging from NSX-T')
            self.nsxtObj.clearBridging(orgVDCNetworkList)

            # delete the source org vdc networks
            self.consoleLogger.info('Deleting the source Org VDC Networks.')
            self.vcdObj.deleteOrgVDCNetworks(sourceOrgVDCId)

            # delete the source edge gateway
            self.consoleLogger.info('Deleting the source Org VDC Edge Gateway.')
            self.vcdObj.deleteNsxVBackedOrgVDCEdgeGateways(sourceOrgVDCId)

            # delete the source Org VDC
            self.consoleLogger.info('Deleting the source Org VDC.')
            self.vcdObj.deleteOrgVDC(sourceOrgVDCId)

            # renaming the target Org VDC networks
            self.consoleLogger.info('Renaming the target Org VDC networks')
            self.vcdObj.renameTargetNetworks(targetOrgVDCId)

            # rename target Org VDC
            self.consoleLogger.info('Renaming target Org VDC.')
            self.vcdObj.renameOrgVDC(sourceOrgVDCName, targetOrgVDCId)

            # getting the source external network details from source edge gateway and creating a dict of subnet and corresponding ip values used
            edgeGatewaySubnetDict = {}
            for edgeGateway in edgeGatewayDetails:
                for edgeGatewayUplink in edgeGateway['edgeGatewayUplinks']:
                    for subnet in edgeGatewayUplink['subnets']['values']:
                        # Getting value of primary ip
                        primaryIp = subnet.get('primaryIp')
                        # Creating ip range for primary ip
                        subIpRange = [{'startAddress': primaryIp, 'endAddress': primaryIp}]

                        networkAddress = ipaddress.ip_network('{}/{}'.format(subnet['gateway'], subnet['prefixLength']),
                                                              strict=False)

                        # adding primary ip to sub alloacated ip pool
                        if primaryIp and ipaddress.ip_address(primaryIp) in networkAddress:
                            subnet['ipRanges']['values'].extend(subIpRange)

                        if networkAddress in edgeGatewaySubnetDict:
                            edgeGatewaySubnetDict[networkAddress].extend(subnet['ipRanges']['values'])
                        else:
                            edgeGatewaySubnetDict[networkAddress] = subnet['ipRanges']['values']

            self.consoleLogger.info('Updating the source External network.')
            for sourceExternalNetwork in sourceExternalNetworkData:
                # update the source external network ip pools
                self.vcdObj.updateSourceExternalNetwork(sourceExternalNetwork['name'], edgeGatewaySubnetDict)

            self.consoleLogger.info('Successfully cleaned up Source Org VDC.')
            self.consoleLogger.warning('Please remove the password file - "{}" if not required, for security reasons'.format(self.passFilePath))

            # deleting the current user api session of vmware cloud director
            self.consoleLogger.debug('Logging out the current VMware Cloud Director user')
            self.vcdObj.deleteSession()

        except Exception:
            raise
