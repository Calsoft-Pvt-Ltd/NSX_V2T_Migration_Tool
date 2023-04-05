# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description: Module which performs all the clean-up tasks after migrating the VMware Cloud Director from NSX-V to NSX-T
"""

import copy
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
    def __init__(self, orgvdcdict=None, inputDict=None, vcdObj=None, nsxtObj=None, passFilePath=None, timeout=None):
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
        self.timeoutForMoveCatalog = timeout
        # function call creating all the key values required for rollback
        self._createCleanupKeyValues()

    def _createCleanupKeyValues(self):
        """
        Description :   Method that creates all the key value pair for cleanup tasks
        """
        self.cleanupValidationTask = [
            ["'Validating whether target Org VDC is NSX-T backed'",
                "self.vcdObj.validateOrgVDCNSXbacking(self.targetOrgVDCId, targetProviderVDCId, isNSXTbacked)"],
            ["'Validating whether target Org VDC is enabled'",
                "self.vcdObj.validateTargetOrgVDCState(self.targetOrgVDCId)"],
            ["'Validating whether media is attached to any vApp VMs'",
                "self.vcdObj.validateVappVMsMediaNotConnected(self.targetOrgVDCId, raiseError=True)"],
            ["'Validating whether Subscribed Catalog exists in Source Org VDC'",
                "self.vcdObj.getOrgVDCPublishedCatalogs(sourceOrgVDCId, self.inputDict['VCloudDirector']['Organization']['OrgName'], Migration=True)"]
        ]
        self.cleanupTask = [
            ["'Validating whether source Org VDC is NSX-V backed'",
                "self.vcdObj.validateOrgVDCNSXbacking(sourceOrgVDCId, sourceProviderVDCId, isNSXTbacked)"],
            ["'Migrating catalog items - vApp Templates & media objects.'",
                "self.vcdObj.migrateCatalogItems(sourceOrgVDCId, self.targetOrgVDCId, self.inputDict['VCloudDirector']['Organization']['OrgName'], self.timeoutForMoveCatalog)"],
            ["'Deleting empty vApps.'",
             "self.vcdObj.deleteEmptyvApp(sourceOrgVDCId)"],
            ["'Deleting the source Org VDC Networks.'",
                "self.vcdObj.deleteOrgVDCNetworks(sourceOrgVDCId)"],
            ["'Deleting the source Org VDC Edge Gateway.'",
                "self.vcdObj.deleteNsxVBackedOrgVDCEdgeGateways(sourceOrgVDCId)"],
            ["'Deleting the source Org VDC.'",
                "self.vcdObj.deleteOrgVDC(sourceOrgVDCId)"],
            ["'Renaming the target Org VDC networks'",
                "self.vcdObj.renameTargetNetworks(self.targetOrgVDCId)"],
            ["'Renaming target Org VDC.'",
                "self.vcdObj.renameOrgVDC(sourceOrgVDCName, self.targetOrgVDCId)"],
            ["'Updating the source External network.'",
                "self.vcdObj.updateSourceExternalNetwork(sourceExternalNetworkData, edgeGatewaySubnetDict, self.targetOrgVDCId)"],
            ["'Syncing DC Groups created'",
                "self.vcdObj.syncOrgVDCGroup(self.vcdObj.rollback.apiData.get('OrgVDCGroupID', {}))"]]

    def checkTargetOrgVDCStatus(self):
        """
        Description:   Check status of target org vdc and backing type
        """
        try:
            cleanupValidationTasks = self.vcdObj.rollback.metadata.get('cleanupValidationTasks')
            if cleanupValidationTasks:
                return

            # Changing the name of the thread with the name of org vdc
            threading.current_thread().name = self.orgvdcdict["OrgVDCName"]

            self.targetOrgVDCId = self.vcdObj.rollback.apiData.get('targetOrgVDC', {}).get('@id')
            sourceOrgVDCId = self.vcdObj.rollback.apiData.get('sourceOrgVDC', {}).get('@id')
            targetProviderVDCId, isNSXTbacked = self.vcdObj.getProviderVDCId(self.orgvdcdict['NSXTProviderVDCName'])

            for validationTask in self.cleanupValidationTask:
                # Performing cleanup validation task
                self.consoleLogger.info(validationTask[0])
                eval(validationTask[1])
            # Saving the cleanup validation tasks status in metadata
            self.vcdObj.createMetaDataInOrgVDC(
                self.targetOrgVDCId, metadataDict={'cleanupValidationTasks': True}, domain='system')
        except:
            self.consoleLogger.error(traceback.format_exc())
            raise

    def cleanupBridging(self, vcdObjList, nsxtObj):
        """
        Description :   Clears the bridging after cleanup task completes
        Parameters  :   vcdObjList - List of objects of vcd operations class (LIST)
                        nsxtObj    - Object of NSX-T operations class (OBJECT)
        """
        if not vcdObjList[0].rollback.metadata.get('configureNSXTBridging'):
            return
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
                nsxtObj.clearBridging(bridgedNetworksList, vcdObjList[0])
                nsxtObj.deleteTransportZone(vcdObjList[0])
        except:
            raise
        else:
            if vcdObjList[0].rollback.metadata.get('configureNSXTBridging'):
                # If bridging cleanup is successful, remove the bridging key from metadata
                vcdObjList[0].deleteMetadataApiCall(key='configureNSXTBridging-system-v2t',
                                                    orgVDCId=vcdObjList[0].rollback.apiData.get('targetOrgVDC', {}).get('@id'))
            # Restore thread name
            threading.current_thread().name = currentThreadName

    def run(self):
        """
        Description :   Deletes the source Organization VDC and renames target
        """

        # Changing the name of the thread with the name of org vdc
        threading.current_thread().name = self.orgvdcdict["OrgVDCName"]

        # Getting Organization details.
        sourceOrgVDCName = self.orgvdcdict["OrgVDCName"]
        self.orgUrl = self.vcdObj.rollback.apiData.get('Organization', {}).get('@href')

        # getting the source provider VDC details and checking if its NSX-V backed
        self.consoleLogger.info('Getting the source Provider VDC - {} details.'.format(self.orgvdcdict['NSXVProviderVDCName']))
        sourceProviderVDCId, isNSXTbacked = self.vcdObj.getProviderVDCId(self.orgvdcdict['NSXVProviderVDCName'])

        # getting the source organization vdc details from the above organization
        self.consoleLogger.info('Getting the source Organization VDC {} details.'.format(sourceOrgVDCName))
        sourceOrgVDCId = self.vcdObj.rollback.apiData.get('sourceOrgVDC', {}).get('@id')

        # getting source external network data
        self.consoleLogger.info('Getting the source external networks details.')
        sourceExternalNetworkData = self.vcdObj.rollback.apiData.get('sourceExternalNetwork', [])

        # getting the source edge gateway details
        edgeGatewayDetails = self.vcdObj.rollback.apiData.get('sourceEdgeGateway')

        # getting the target organization vdc details from the above organization
        self.consoleLogger.info('Getting the target Organization VDC {} network details.'.format(sourceOrgVDCName + '-v2t'))
        self.targetOrgVDCId = self.vcdObj.rollback.apiData.get('targetOrgVDC', {}).get('@id')
        dfwStatus = True if self.vcdObj.rollback.apiData.get('OrgVDCGroupID') else False
        orgVDCNetworkList = self.vcdObj.getOrgVDCNetworks(self.targetOrgVDCId, 'targetOrgVDCNetworks', saveResponse=False, dfwStatus=dfwStatus)

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

        try:
            # List of tasks to be performed as part of cleanup
            listOfCleanupTasks = []
            if self.vcdObj.rollback.metadata.get('cleanupTasks'):
                self.consoleLogger.info("Continuing cleanup from its last failed state")
                listOfCleanupTasks = self.vcdObj.rollback.metadata.get('cleanupTasks')
            # Checking if rollback key exists
            else:
                listOfCleanupTasks = self.cleanupTask
            if listOfCleanupTasks:
                # List of task left to pe performed as part of cleanup
                cleanupTasksLeft = copy.deepcopy(listOfCleanupTasks)
                # Iterating over the list of cleanup tasks corresponding the cleanup key
                for cleanupTask in listOfCleanupTasks:
                    # Performing cleanup task
                    self.consoleLogger.info(cleanupTask[0])
                    eval(cleanupTask[1])
                    # Removing task from cleanup tasks left list after the task has been performed successfully
                    cleanupTasksLeft.pop(0)
                    # Saving the remaining rollback tasks in metadata
                    self.vcdObj.createMetaDataInOrgVDC(self.targetOrgVDCId, metadataDict={'cleanupTasks': cleanupTasksLeft},
                                                  domain='system')
        except AttributeError as err:
            self.consoleLogger.error(err)
            # Saving the list of tasks left as part of cleanup in metadata to continue cleanup from the same step
            self.vcdObj.createMetaDataInOrgVDC(self.targetOrgVDCId, metadataDict={'cleanupTasks': cleanupTasksLeft}, domain='system')
            raise
        except Exception as error:
            self.consoleLogger.exception(error)
            self.consoleLogger.debug(traceback.format_exc())
            # Saving the list of tasks left as part of cleanup in metadata to continue cleanup from the same step
            self.vcdObj.createMetaDataInOrgVDC(self.targetOrgVDCId,
                                            metadataDict={'cleanupTasks': cleanupTasksLeft}, domain='system')
            raise
        else:
            # Deleting metadata created in the source org vdc after rollback
            self.vcdObj.deleteMetadata(self.targetOrgVDCId, entity='target')

            self.consoleLogger.warning('Please remove the password file - "{}" if not required, for security reasons'.format(self.passFilePath))

            # deleting the current user api session of vmware cloud director
            self.consoleLogger.debug('Logging out the current VMware Cloud Director user')
            self.vcdObj.deleteSession()