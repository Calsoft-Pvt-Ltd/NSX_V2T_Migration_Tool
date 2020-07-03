# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which performs all the clean-up tasks after migrating the VMware Cloud Director from NSX-V to NSX-T
"""

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
    def __init__(self, inputDict, vcdObj, nsxtObj):
        """
        Description :   Initializer method of all clean-up tasks
        """
        self.consoleLogger = logging.getLogger("consoleLogger")
        self.mainLogfile = logging.getLogger('mainLogger').handlers[0].baseFilename
        self.inputDict = inputDict
        self.nsxtObj = nsxtObj
        self.vcdObj = vcdObj

    def run(self):
        """
        Description :   Deletes the source Organization VDC and renames target
        """
        try:
            orgName = self.inputDict.OrgName
            sourceOrgVDCName = self.inputDict.OrgVDCName
            sourceExternalNetworkName = self.inputDict.NSXVProviderVDCExternalNetwork

            # getting the organization details
            self.consoleLogger.info('Getting the Organization {} details.'.format(orgName))
            orgUrl = self.vcdObj.getOrgUrl(orgName)

            # getting the source provider VDC details and checking if its NSX-V backed
            self.consoleLogger.info('Getting the source Provider VDC - {} details.'.format(self.inputDict.NSXVProviderVDCName))
            sourceProviderVDCId, isNSXTbacked = self.vcdObj.getProviderVDCId(self.inputDict.NSXVProviderVDCName)

            # getting the source organization vdc details from the above organization
            self.consoleLogger.info('Getting the source Organization VDC {} details.'.format(sourceOrgVDCName))
            sourceOrgVDCId = self.vcdObj.getOrgVDCDetails(orgUrl, sourceOrgVDCName, 'sourceOrgVDC', saveResponse=False)

            # validating whether source org vdc is NSX-V backed
            self.consoleLogger.info('Validating whether source Org VDC is NSX-V backed')
            self.vcdObj.validateOrgVDCNSXbacking(sourceOrgVDCId, sourceProviderVDCId, isNSXTbacked)

            # getting the source edge gateway details
            edgeGatewayDetails = self.vcdObj.getOrgVDCEdgeGateway(sourceOrgVDCId)

            #  getting the target provider VDC details and checking if its NSX-T backed
            self.consoleLogger.info('Getting the target Provider VDC - {} details.'.format(self.inputDict.NSXTProviderVDCName))
            targetProviderVDCId, isNSXTbacked = self.vcdObj.getProviderVDCId(self.inputDict.NSXTProviderVDCName)

            # getting the target organization vdc details from the above organization
            self.consoleLogger.info('Getting the target Organization VDC {} details.'.format(sourceOrgVDCName + '-t'))
            targetOrgVDCId = self.vcdObj.getOrgVDCDetails(orgUrl, sourceOrgVDCName + '-t', 'targetOrgVDC', saveResponse=False)

            # validating whether target org vdc is NSX-T backed
            self.consoleLogger.info('Validating whether target Org VDC is NSX-T backed')
            self.vcdObj.validateOrgVDCNSXbacking(targetOrgVDCId, targetProviderVDCId, isNSXTbacked)

            # validating if target org vdc is enabled or disabled
            self.consoleLogger.info('Validating whether target Org VDC is enabled')
            self.vcdObj.validateTargetOrgVDCState(targetOrgVDCId)

            # getting the target organization vdc details from the above organization
            self.consoleLogger.info('Getting the target Organization VDC {} network details.'.format(sourceOrgVDCName + '-t'))
            orgVDCNetworkList = self.vcdObj.getOrgVDCNetworks(targetOrgVDCId, 'targetOrgVDCNetworks', saveResponse=False)

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

            # getting the source external network details from source edge gateway
            sourceExternalNetwork = [uplink for uplink in edgeGatewayDetails['values'][0]['edgeGatewayUplinks'] if uplink['uplinkName'] == sourceExternalNetworkName]
            if sourceExternalNetwork:
                if sourceExternalNetwork[0]['subnets']['values'][0]['ipRanges']['values']:
                    ipRanges = sourceExternalNetwork[0]['subnets']['values'][0]['ipRanges']['values']

                    # update the source external network ip pools
                    self.consoleLogger.info('Updating the source External network.')
                    self.vcdObj.updateSourceExternalNetwork(sourceExternalNetworkName, ipRanges)
            self.consoleLogger.info('Successfully cleaned up Source Org VDC.')

            # deleting the current user api session of vmware cloud director
            self.consoleLogger.debug('Logging out the current VMware Cloud Director user')
            self.vcdObj.deleteSession()

        except Exception:
            raise
