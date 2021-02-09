# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which performs all the clean-up tasks after migrating the VMware Cloud Director from NSX-V to NSX-T
"""

import logging
import os
import prettytable
import sys

# Set path till src folder in PYTHONPATH
cwd = os.getcwd()
parentDir = os.path.abspath(os.path.join(cwd, os.pardir))
sys.path.append(parentDir)

from src.commonUtils.threadUtils import Thread

class VMwareCloudDirectorNSXMigratorAssessmentMode():
    """
    Description :   The class has methods which does validation tasks from NSX-V to NSX-T
    """
    def __init__(self, inputDict, vcdValidationObj, nsxtObj):
        """
        Description : This method initializes the basic configurations reqired to run Assessment mode
        """
        self.validationFailures = list()
        self.orgExceptionList = list()
        self.consoleLogger = logging.getLogger("consoleLogger")
        self.preAssessmentLogs = logging.getLogger("precheckLogger").handlers[0].baseFilename
        self.inputDict = inputDict
        # initializing thread class with specified number of threads
        if self.inputDict.MaxThreadCount:
            self.thread = Thread(maxNumberOfThreads=self.inputDict.MaxThreadCount)
        else:
            self.thread = Thread()
        self.vcdValidationObj = vcdValidationObj
        self.nsxtValidationObj = nsxtObj
        self.vcdValidationObj.vcdLogin()
        self.vcdValidationMapping = dict()
        self.currentDateTime = os.path.basename(self.preAssessmentLogs).replace('VCD-NSX-Migrator-preCheck-Summary-', '').replace('.log', '')
        self.summaryIntroData = 'Start Time: ' + self.currentDateTime + "\nOrganization VDC: " + self.inputDict.OrgVDCName + "\n"
        with open(self.preAssessmentLogs, 'w') as preCheckSummary:
            preCheckSummary.write(self.summaryIntroData)

    def checkOrgDetails(self):
        """
            Description : This method fetches the details of OrgUrl and OrgVDCDetails
        """
        try:
            self.orgUrl = self.vcdValidationObj.getOrgUrl(self.inputDict.OrgName)
            self.consoleLogger.info('Getting NSX-V backed Org VDC {} details'.format(self.inputDict.OrgVDCName))
            self.sourceOrgVDCId = self.vcdValidationObj.getOrgVDCDetails(self.orgUrl, self.inputDict.OrgVDCName, 'sourceOrgVDC')

            # Get Source Provider VDC Id and details
            self.consoleLogger.info('Getting NSX-V backed Provider VDC {} details'.format(self.inputDict.NSXVProviderVDCName))
            self.sourceProviderVDCId, self.isSourceNSXTbacked = self.vcdValidationObj.getProviderVDCId(self.inputDict.NSXVProviderVDCName)
            self.vcdValidationObj.getProviderVDCDetails(self.sourceProviderVDCId, self.isSourceNSXTbacked)

            # Get Target Provider VDC Id and details
            self.consoleLogger.info('Getting NSX-T backed Provider VDC {} details'.format(self.inputDict.NSXTProviderVDCName))
            self.targetProviderVDCId, self.isTargetNSXTbacked = self.vcdValidationObj.getProviderVDCId(self.inputDict.NSXTProviderVDCName)
            self.vcdValidationObj.getProviderVDCDetails(self.targetProviderVDCId,self.isTargetNSXTbacked)
        except Exception as e:
            self.orgExceptionList.append(e)

    def initializePreCheck(self):
        """
            Description : This method fetches the necessary details to run validations
        """
        try:
            getSourceExternalNetworkDesc = 'Getting NSX-V backed Provider VDC External network {} details'
            getTargetExternalNetworkDesc = 'Getting NSX-V backed Provider VDC External network {} details'
            getDummyExternalNetworkDesc = 'Getting NSX-V backed Provider VDC External network {} details'
            self.consoleLogger.info('Starting NSX-V migration to NSX-T backed in Assessment mode')
            self.consoleLogger.info('Getting NSX-V backed Org VDC network details')
            self.thread.spawnThread(self.vcdValidationObj.getOrgVDCNetworks, self.sourceOrgVDCId, 'sourceOrgVDCNetworks', saveOutputKey='getNSXVOrgVdcNetwork')
            self.consoleLogger.info(getSourceExternalNetworkDesc.format(self.inputDict.NSXVProviderVDCExternalNetwork))
            self.thread.spawnThread(self.vcdValidationObj.getExternalNetwork, self.inputDict.NSXVProviderVDCExternalNetwork, saveOutputKey='sourceExternalNetwork')
            self.consoleLogger.info(getTargetExternalNetworkDesc.format(self.inputDict.NSXTProviderVDCExternalNetwork))
            self.thread.spawnThread(self.vcdValidationObj.getExternalNetwork, self.inputDict.NSXTProviderVDCExternalNetwork, saveOutputKey='targetExternalNetwork')
            self.consoleLogger.info(getDummyExternalNetworkDesc.format(self.inputDict.NSXVProviderVDCDummyExternalNetwork))
            self.thread.spawnThread(self.vcdValidationObj.getExternalNetwork, self.inputDict.NSXVProviderVDCDummyExternalNetwork, saveOutputKey='dummyNetwork', isDummyNetwork=True)
            # Halt the main thread till all the threads finish executing
            self.thread.joinThreads()
            # Fetching values returned by threads
            self.orgVdcNetworkList = self.thread.returnValues['getNSXVOrgVdcNetwork']
            if self.thread.returnValues['sourceExternalNetwork'] and isinstance(self.thread.returnValues['sourceExternalNetwork'], Exception):
                self.validationFailures.append([getSourceExternalNetworkDesc.format(self.inputDict.NSXVProviderVDCExternalNetwork), self.thread.returnValues['sourceExternalNetwork'], 'Failed'])
            if self.thread.returnValues['targetExternalNetwork'] and isinstance(self.thread.returnValues['targetExternalNetwork'], Exception):
                self.validationFailures.append([getTargetExternalNetworkDesc.format(self.inputDict.NSXTProviderVDCExternalNetwork), self.thread.returnValues['targetExternalNetwork'], 'Failed'])
            if self.thread.returnValues['dummyNetwork'] and isinstance(self.thread.returnValues['dummyNetwork'], Exception):
                self.validationFailures.append([getDummyExternalNetworkDesc.format(self.inputDict.NSXVProviderVDCDummyExternalNetwork), self.thread.returnValues['dummyNetwork'], 'Failed'])

            # Validation methods reference
            self.vcdValidationMapping = {
                'Validating NSX-T Bridge Uplink Profile does not exist': [self.nsxtValidationObj.validateBridgeUplinkProfile],
                'Validating Edge Cluster exists in NSX-T and Edge Transport Nodes are not in use': [self.nsxtValidationObj.validateEdgeNodesNotInUse, self.inputDict.EdgeClusterName],
                'Validating Transport Zone exists in NSX-T': [self.nsxtValidationObj.validateTransportZoneExistsInNSXT, self.inputDict.TransportZoneName],
                'Validating if target OrgVDC do not exists': [self.vcdValidationObj.validateNoTargetOrgVDCExists, self.inputDict.OrgVDCName],
                'Validating if empty vApps do not exist in source org VDC':[ self.vcdValidationObj.validateNoEmptyVappsExistInSourceOrgVDC, self.sourceOrgVDCId],
                'Validating VMs in suspended state do not exists any source vApps': [self.vcdValidationObj.validateSourceSuspendedVMsInVapp, self.sourceOrgVDCId],
                'Validating VMs in vApp are not connected to media': [self.vcdValidationObj.validateVappVMsMediaNotConnected, self.sourceOrgVDCId, True],
                'Validating vApps do not have routed vApp networks': [self.vcdValidationObj.validateNoVappNetworksExist, self.sourceOrgVDCId],
                'Validating vApps do not have isolated vApp networks with DHCP enabled': [self.vcdValidationObj.validateDHCPOnIsolatedvAppNetworks, self.sourceOrgVDCId],
                'Validating whether source Org VDC is fast provisioned': [self.vcdValidationObj.validateOrgVDCFastProvisioned],
                'Validating whether single Edge gateway exist in source Org VDC': [self.vcdValidationObj.validateSingleEdgeGatewayExistForOrgVDC, self.sourceOrgVDCId],
                'Validating whether Edge gateways are using dedicated external network': [self.vcdValidationObj.validateDedicatedExternalNetwork],
                'Validating Source Network Pool is VXLAN or VLAN backed': [self.vcdValidationObj.validateSourceNetworkPools],
                'Validating whether source Org VDC is NSX-V backed': [self.vcdValidationObj.validateOrgVDCNSXbacking, self.sourceOrgVDCId, self.sourceProviderVDCId, self.isSourceNSXTbacked],
                'Validating Target Provider VDC is enabled': [self.vcdValidationObj.validateTargetProviderVdc],
                'Validating Hardware version of Source Provider VDC: {} and Target Provider VDC: {}'.format(self.inputDict.NSXVProviderVDCName, self.inputDict.NSXTProviderVDCName): [self.vcdValidationObj.validateHardwareVersion],
                'Validating if fencing is enabled on vApps in source OrgVDC': [self.vcdValidationObj.validateVappFencingMode, self.sourceOrgVDCId],
                'Validating whether source Org VDC placement policies are present in target PVDC': [self.vcdValidationObj.validateVMPlacementPolicy, self.sourceOrgVDCId],
                'Validating storage profiles in source Org VDC and target Provider VDC': [self.vcdValidationObj.validateStorageProfiles],
                'Validating if source and target External networks have same subnets': [self.vcdValidationObj.validateExternalNetworkSubnets],
                'Validating if all edge gateways interfaces are in use': [self.vcdValidationObj.validateEdgeGatewayUplinks],
                'Validating whether DHCP is enabled on source Isolated Org VDC network': [self.vcdValidationObj.validateDHCPEnabledonIsolatedVdcNetworks, self.orgVdcNetworkList],
                'Validating whether Org VDC networks are shared': [self.vcdValidationObj.validateOrgVDCNetworkShared, self.orgVdcNetworkList],
                'Validating whether Org VDC have Direct networks': [self.vcdValidationObj.validateOrgVDCNetworkDirect, self.orgVdcNetworkList],
                'Validating if Independent Disks exist in Source Org VDC': [self.vcdValidationObj.validateIndependentDisksDoesNotExistsInOrgVDC, self.sourceOrgVDCId],
                'Validating Source Edge gateway services': [self.vcdValidationObj.getEdgeGatewayServices],
                'Validating whether external ips are added in sub-allocated ip pool of source edge gateway': [self.vcdValidationObj.validateNatIpInSrcEdgeSuballocatedPool, self.sourceOrgVDCId, self.inputDict.NSXVProviderVDCExternalNetwork],
                'Validating OrgVDC Network and Edge transport Nodes': [self.nsxtValidationObj.validateOrgVdcNetworksAndEdgeTransportNodes, self.inputDict.EdgeClusterName, self.orgVdcNetworkList]
            }
        except Exception as e:
            self.validationFailures.append(e)

    def run(self):
        """
        Description : Sequentially executes list of method
        """
        try:
            validationReturnDict = dict()
            self.checkOrgDetails()
            if self.orgExceptionList:
                # if error occurs in any precheck, then deleting the session before returning
                self.vcdValidationObj.deleteSession()
                return
            self.initializePreCheck()
            for desc, method in self.vcdValidationMapping.items():
                methodName = method.pop(0)
                argsList = method
                if desc == 'Validating Source Edge gateway services' or \
                        desc == 'Validating if all edge gateways interfaces are in use' or \
                        desc == 'Validating whether external ips are added in sub-allocated ip pool of source edge gateway' or \
                        desc == 'Validating whether Edge gateways are using dedicated external network':
                    if validationReturnDict['Validating whether single Edge gateway exist in source Org VDC']:
                        argsList.append(validationReturnDict['Validating whether single Edge gateway exist in source Org VDC'])
                    else:
                        for eachExceptionList in self.validationFailures:
                            if eachExceptionList[0] == 'Validating whether single Edge gateway exist in source Org VDC':
                                self.validationFailures.append([desc, eachExceptionList[1], 'Failed'])
                                break
                        continue
                self.consoleLogger.info(desc)
                validateReturn = self.runAssessmentMode(desc, methodName, argsList)
                validationReturnDict[desc] = validateReturn
            # deleting the current user api session of vmware cloud director
            self.vcdValidationObj.deleteSession()
        except Exception:
            raise

    def runAssessmentMode(self, desc, method, args):
        """
        Description : Executes the validation method and arguments passed as parameters as stores exceptions raised
        Parameters : desc - Description of the method to be executed (STRING)
                     method - Reference of method (METHOD REFERENCE)
                     args - arguments passed to the method (LIST)
        """
        try:
            validationReturn = method(*args)
            return validationReturn
        except Exception as e:
            self.validationFailures.append([desc, e, 'Failed'])

    def updateInventoryLogs(self):
        """
        Description : This method creates detailed inventory logs of exceptions raised in validations
        """
        try:
            precheckLogger = logging.getLogger("precheckLogger")
            getExceptionTableObj = prettytable.PrettyTable()
            getExceptionTableObj.field_names = ['OrgVDC Details', 'Status']
            assessmentTableObj = prettytable.PrettyTable(hrules=prettytable.ALL)
            assessmentTableObj.field_names = ['Validation Name', 'Exception', 'Status']
            if self.orgExceptionList:
                for each_error in self.orgExceptionList:
                    getExceptionTableObj.add_row([each_error, 'Not Present'])
                getExceptionTable = getExceptionTableObj.get_string()
                precheckLogger.info(getExceptionTable)
                self.consoleLogger.error('Incorrect details in sampleUserInput.yml. '
                                         'Please check VCD Organization or OrgVDC details in {}'.format(
                    self.preAssessmentLogs))
                return
            if self.validationFailures:
                for each_failure in self.validationFailures:
                    assessmentTableObj.add_row(each_failure)
                # Storing the assessment table output in string format
                preCheckTable = assessmentTableObj.get_string()
                precheckLogger.info('\n{}'.format(preCheckTable))
                self.consoleLogger.error('Check {} file for failed validations.'.format(self.preAssessmentLogs))
                return
            else:
                precheckLogger.info('All the pre-migration validations have passed successfully.')
                return
        except:
            raise