# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description: Module which performs all the clean-up tasks after migrating the VMware Cloud Director from NSX-V to NSX-T
"""

import ipaddress
import logging
import os
import sys
import threading
import traceback

# Set path till src folder in PYTHONPATH
cwd = os.getcwd()
parentDir = os.path.abspath(os.path.join(cwd, os.pardir))
sys.path.append(parentDir)

from src import constants


class VMwareCloudDirectorNSXMigratorCleanup():
    """
    Description :   The class has methods which do all the clean-up tasks(like deleting, resetting, etc) after migrating the VMware vCloud Director from NSX-V to NSX-T
    """
    def __init__(self, orgvdcdict=None, inputDict=None, vcdObj=None, nsxtObj=None, passFilePath=None):
        """
        Description :   Initializer method of all clean-up tasks
        """
        self.consoleLogger = logging.getLogger("consoleLogger")
        self.mainLogfile = logging.getLogger('mainLogger').handlers[0].baseFilename
        self.inputDict = inputDict
        self.orgvdcdict = orgvdcdict
        self.nsxtObj = nsxtObj
        self.vcdObj = vcdObj
        self.targetOrgVDCId = None
        self.orgUrl = None
        self.passFilePath = passFilePath

    def checkTargetOrgVDCStatus(self):
        """
        Description:   Check status of target org vdc and backing type
        """
        try:
            # Changing the name of the thread with the name of org vdc
            threading.current_thread().name = self.orgvdcdict["OrgVDCName"]

            # Getting Organization details.
            orgName = self.inputDict['VCloudDirector']['Organization']['OrgName']
            sourceOrgVDCName = self.orgvdcdict["OrgVDCName"]
            self.consoleLogger.info('Getting the Organization {} details.'.format(orgName))
            self.orgUrl = self.vcdObj.getOrgUrl(orgName)

            #  getting the target provider VDC details and checking if its NSX-T backed
            self.consoleLogger.info(
                'Getting the target Provider VDC - {} details.'.format(self.orgvdcdict['NSXTProviderVDCName']))
            targetProviderVDCId, isNSXTbacked = self.vcdObj.getProviderVDCId(self.orgvdcdict['NSXTProviderVDCName'])

            # getting the target organization vdc details from the above organization
            self.consoleLogger.info('Getting the target Organization VDC {} details.'.format(sourceOrgVDCName + '-v2t'))
            self.targetOrgVDCId = self.vcdObj.getOrgVDCDetails(self.orgUrl, sourceOrgVDCName + '-v2t', 'targetOrgVDC',
                                                               saveResponse=False)

            # validating whether target org vdc is NSX-T backed
            self.consoleLogger.info('Validating whether target Org VDC is NSX-T backed')
            self.vcdObj.validateOrgVDCNSXbacking(self.targetOrgVDCId, targetProviderVDCId, isNSXTbacked)

            # validating if target org vdc is enabled or disabled
            self.consoleLogger.info('Validating whether target Org VDC is enabled')
            self.vcdObj.validateTargetOrgVDCState(self.targetOrgVDCId)

            # validating media is connected to any of the vms
            self.consoleLogger.info('Validating whether media is attached to any vApp VMs')
            self.vcdObj.validateVappVMsMediaNotConnected(self.targetOrgVDCId, raiseError=True)
        except:
            self.consoleLogger.error(traceback.format_exc())
            raise

    def cleanupBridging(self, vcdObjList, nsxtObj):
        """
        Description :   Clears the bridging after cleanup task completes
        Parameters  :   vcdObjList - List of objects of vcd operations class (LIST)
                        nsxtObj    - Object of NSX-T operations class (OBJECT)
        """
        try:
            # Get current thread name
            currentThreadName = threading.currentThread().getName()
            # Changing current thread name
            threading.current_thread().name = "cleanupBridging"

            # Check if bridging is configured from metadata
            if vcdObjList[0].rollback.metadata.get('configureNSXTBridging'):
                self.consoleLogger.info('Removing bridging from NSX-T')
                # Fetching networks list that are bridged
                bridgedNetworksList = list()
                for vcdObject in vcdObjList:
                    # getting the target org vdc urn
                    dfw = True if vcdObject.rollback.apiData.get('OrgVDCGroupID') else False
                    if vcdObject.rollback.apiData.get('targetOrgVDC', {}).get('@id'):
                        bridgedNetworksList += vcdObject.retrieveNetworkListFromMetadata(
                            vcdObject.rollback.apiData.get('targetOrgVDC', {}).get('@id'), orgVDCType='target',
                            dfwStatus=dfw)
                nsxtObj.clearBridging(self.inputDict["NSXT"]["EdgeClusterName"], bridgedNetworksList)
        except:
            raise
        else:
            if vcdObjList[0].rollback.metadata.get('configureNSXTBridging'):
                # If bridging cleanup is successful, remove the bridging key from metadata
                vcdObjList[0].deleteMetadataApiCall(key='configureNSXTBridging-system-v2t',
                                                    orgVDCId=vcdObjList[0].rollback.apiData.get('sourceOrgVDC', {}).get('@id'))
            # Restore thread name
            threading.current_thread().name = currentThreadName

    def run(self):
        """
        Description :   Deletes the source Organization VDC and renames target
        """
        try:
            # Changing the name of the thread with the name of org vdc
            threading.current_thread().name = self.orgvdcdict["OrgVDCName"]

            # Getting Organization details.
            sourceOrgVDCName = self.orgvdcdict["OrgVDCName"]

            # getting the source provider VDC details and checking if its NSX-V backed
            self.consoleLogger.info('Getting the source Provider VDC - {} details.'.format(self.orgvdcdict['NSXVProviderVDCName']))
            sourceProviderVDCId, isNSXTbacked = self.vcdObj.getProviderVDCId(self.orgvdcdict['NSXVProviderVDCName'])

            # getting the source organization vdc details from the above organization
            self.consoleLogger.info('Getting the source Organization VDC {} details.'.format(sourceOrgVDCName))
            sourceOrgVDCId = self.vcdObj.getOrgVDCDetails(self.orgUrl, sourceOrgVDCName, 'sourceOrgVDC', saveResponse=False)

            # getting source external network data
            self.consoleLogger.info('Getting the source external networks details.')
            metadata = self.vcdObj.getOrgVDCMetadata(sourceOrgVDCId, domain='general')
            sourceExternalNetworkData = metadata.get('sourceExternalNetwork', [])


            # validating whether source org vdc is NSX-V backed
            self.consoleLogger.info('Validating whether source Org VDC is NSX-V backed')
            self.vcdObj.validateOrgVDCNSXbacking(sourceOrgVDCId, sourceProviderVDCId, isNSXTbacked)

            # getting the source edge gateway details
            edgeGatewayDetails = self.vcdObj.getOrgVDCEdgeGateway(sourceOrgVDCId)

            # getting the target organization vdc details from the above organization
            self.consoleLogger.info('Getting the target Organization VDC {} network details.'.format(sourceOrgVDCName + '-v2t'))
            dfwStatus = True if metadata.get('OrgVDCGroupID') else False
            orgVDCNetworkList = self.vcdObj.getOrgVDCNetworks(self.targetOrgVDCId, 'targetOrgVDCNetworks', saveResponse=False, dfwStatus=dfwStatus)

            # migrating catalog items - vApp Templates and media objects
            self.consoleLogger.info('Migrating catalog items - vApp Templates & media objects.')
            self.vcdObj.migrateCatalogItems(sourceOrgVDCId, self.targetOrgVDCId, self.orgUrl)

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
            self.vcdObj.renameTargetNetworks(self.targetOrgVDCId)

            # rename target Org VDC
            self.consoleLogger.info('Renaming target Org VDC.')
            self.vcdObj.renameOrgVDC(sourceOrgVDCName, self.targetOrgVDCId)

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
                self.vcdObj.updateSourceExternalNetwork(sourceExternalNetwork['name'], edgeGatewaySubnetDict, self.orgvdcdict)

            self.consoleLogger.info("Syncing DC Groups created")
            self.vcdObj.syncOrgVDCGroup(self.vcdObj.rollback.apiData.get('OrgVDCGroupID', {}))
            self.consoleLogger.info('Successfully cleaned up Source Org VDC.')

            self.consoleLogger.warning('Please remove the password file - "{}" if not required, for security reasons'.format(self.passFilePath))

            # deleting the current user api session of vmware cloud director
            self.consoleLogger.debug('Logging out the current VMware Cloud Director user')
            self.vcdObj.deleteSession()

        except Exception:
            self.consoleLogger.error(traceback.format_exc())
            raise
