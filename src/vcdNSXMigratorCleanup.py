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

import src.core.vcd.vcdConstants as vcdConstants
from src.commonUtils.logConf import Logger
from src.core.vcd.vcdOperations import VCloudDirectorOperations
from src.core.nsxt.nsxtOperations import NSXTOperations


class VMwareCloudDirectorNSXMigratorCleanup():
    """
    Description :   The class has methods which do all the clean-up tasks(like deleting, resetting, etc) after migrating the VMware vCloud Director from NSX-V to NSX-T
    """
    def __init__(self, vcdDict, nsxtDict):
        """
        Description :   Initializer method of all clean-up tasks
        """
        self.loggerObj = Logger()
        self.consoleLogger = logging.getLogger("consoleLogger")
        self.mainLogfile = logging.getLogger('mainLogger').handlers[0].baseFilename
        self.vcdDetails = vcdDict
        self.nsxtDict = nsxtDict

    def run(self):
        """
        Description :   Deletes the Organization VDC
        """
        try:
            # targetOrgVDCName = input("Please enter Target Org VDC Name: ")
            commonDict = self.vcdDetails['Common']
            orgName = self.vcdDetails['Organization']['OrgName']
            sourceOrgVDCName = self.vcdDetails['SourceOrgVDC']['OrgVDCName']
            sourceExternalNetworkName = self.vcdDetails['NSXVProviderVDC']['ExternalNetwork']
            vcdObj = VCloudDirectorOperations(commonDict['ipAddress'],
                                              commonDict['username'],
                                              commonDict['password'])

            # preparing the nsxt dict for bridging
            nsxtCommonDict = self.nsxtDict['Common']
            nsxtObj = NSXTOperations(nsxtCommonDict['ipAddress'], nsxtCommonDict['username'],
                                     nsxtCommonDict['password'])

            # login to the VMware cloud director for getting the bearer token
            self.consoleLogger.info('Login into the VMware Cloud Director {}'.format(commonDict['ipAddress']))
            vcdObj.vcdLogin()

            # login to the nsx-t
            self.consoleLogger.info('Login into the NSX-T - {}'.format(nsxtCommonDict['ipAddress']))
            nsxtObj.getComputeManagers()

            # getting the organization details
            self.consoleLogger.info('Getting the Organization {} details.'.format(orgName))
            orgUrl = vcdObj.getOrgUrl(orgName)

            # getting the source organization vdc details from the above organization
            self.consoleLogger.info('Getting the source Organization VDC {} details.'.format(sourceOrgVDCName))
            sourceOrgVDCId = vcdObj.getOrgVDCDetails(orgUrl, sourceOrgVDCName, 'sourceOrgVDC', saveResponse=False)

            # getting the source edge gateway details
            edgeGatewayDetails = vcdObj.getOrgVDCEdgeGateway(sourceOrgVDCId)

            # getting the target organization vdc details from the above organization
            self.consoleLogger.info('Getting the target Organization VDC {} details.'.format(sourceOrgVDCName + '-t'))
            targetOrgVDCId = vcdObj.getOrgVDCDetails(orgUrl, sourceOrgVDCName + '-t', 'targetOrgVDC', saveResponse=False)

            # getting the target organization vdc details from the above organization
            self.consoleLogger.info('Getting the target Organization VDC {} network details.'.format(sourceOrgVDCName + '-t'))
            orgVDCNetworkList = vcdObj.getOrgVDCNetworks(targetOrgVDCId, 'targetOrgVDCNetworks', saveResponse=False)

            # migrating catalog items - vApp Templates and media objects
            self.consoleLogger.info('Migrating catalog items - vApp Templates & media objects.')
            vcdObj.migrateCatalogItems(sourceOrgVDCId, targetOrgVDCId, orgUrl)

            # clearing nsx-t bridging
            self.consoleLogger.info('Removing bridging from NSX-T')
            nsxtObj.clearBridging(orgVDCNetworkList)

            # power off source vApps
            self.consoleLogger.info('Powering off source vApps')
            vcdObj.powerOffSourceVapp(sourceOrgVDCId)

            # delete source vApps
            self.consoleLogger.info('Deleting source vApps')
            vcdObj.deleteOrgVDCvApps(sourceOrgVDCId)

            # delete the source org vdc networks
            self.consoleLogger.info('Deleting the source Org VDC Networks.')
            vcdObj.deleteOrgVDCNetworks(sourceOrgVDCId)

            # delete the source edge gateway
            self.consoleLogger.info('Deleting the source Org VDC Edge Gateway.')
            vcdObj.deleteNsxVBackedOrgVDCEdgeGateways(sourceOrgVDCId)

            # delete the source Org VDC
            self.consoleLogger.info('Deleting the source Org VDC.')
            vcdObj.deleteOrgVDC(sourceOrgVDCId)

            # rename target vApps
            self.consoleLogger.info('Renaming the vApps in target Org VDC')
            vcdObj.renameTargetOrgVDCVapps(targetOrgVDCId)

            # rename target Org VDC
            self.consoleLogger.info('Renaming target Org VDC.')
            vcdObj.renameOrgVDC(sourceOrgVDCName, targetOrgVDCId)

            # getting the source external network details from source edge gateway
            sourceExternalNetwork = [uplink for uplink in edgeGatewayDetails['values'][0]['edgeGatewayUplinks'] if uplink['uplinkName'] == sourceExternalNetworkName]
            if sourceExternalNetwork:
                if sourceExternalNetwork[0]['subnets']['values'][0]['ipRanges']['values']:
                    ipRanges = sourceExternalNetwork[0]['subnets']['values'][0]['ipRanges']['values']

                    # update the source external network ip pools
                    self.consoleLogger.info('Updating the source External network.')
                    vcdObj.updateSourceExternalNetwork(sourceExternalNetworkName, ipRanges)
            self.consoleLogger.info('Successfully cleaned up Source Org VDC.')
        except Exception:
            raise
