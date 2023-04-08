# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description: Module which performs all the clean-up tasks after migrating the VMware Cloud Director from NSX-V to NSX-T
"""

import logging
import math
import os
import traceback

import prettytable
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from functools import reduce

# Set path till src folder in PYTHONPATH
cwd = os.getcwd()
parentDir = os.path.abspath(os.path.join(cwd, os.pardir))
sys.path.append(parentDir)

from src.commonUtils.threadUtils import Thread, waitForThreadToComplete
import src.constants as mainConstants
import src.core.vcd.vcdConstants as vcdConstants

class VMwareCloudDirectorNSXMigratorAssessmentMode():
    """
    Description :   The class has methods which does validation tasks from NSX-V to NSX-T
    """
    def __init__(self, inputDict, vcdObjList, nsxtObjList, nsxvObj, vcenterObj, executeList):
        """
        Description : This method initializes the basic configurations reqired to run Assessment mode
        """
        self.consoleLogger = logging.getLogger("consoleLogger")
        self.preAssessmentLogs = logging.getLogger("precheckLogger").handlers[0].baseFilename
        self.inputDict = inputDict
        # Steps to perform for migration
        self.executeList = executeList
        self.threadCount = inputDict["Common"].get("MaxThreadCount", 75)
        self.NSXTProviderVDCImportedNeworkTransportZone = inputDict["VCloudDirector"].get("ImportedNetworkTransportZone", None)
        self.vcdObjList = vcdObjList
        self.nsxtObjList = nsxtObjList
        self.nsxvObj = nsxvObj
        self.vcenterObj = vcenterObj
        self.currentDateTime = os.path.basename(self.preAssessmentLogs).replace('VCD-NSX-Migrator-preCheck-Summary-', '').replace('.log', '')
        self.summaryIntroData = 'Start Time: ' + self.currentDateTime + "\n\n"
        with open(self.preAssessmentLogs, 'w') as preCheckSummary:
            preCheckSummary.write(self.summaryIntroData)
        # Dictionary to store the org vdc and failures mapping
        self.orgVDCerrors = dict()
        self.bridgingCheckFailures = list()
        self.sharedNetworkCheckFailures = list()

    def checkOrgDetails(self, vcdValidationObj, orgVDCDict, orgExceptionList):
        """
        Description : This method fetches the details of OrgUrl and OrgVDCDetails
        Parameters :  vcdValidationObj - Object the holds reference to class with all the validation methods (OBJECT)
                      orgVDCDict - Dictionary holding the org vdc details from the input file (DICT)
                      orgExceptionList - List used to store the exceptions and error faced while fetching org vdc details (LIST)
        """
        sourceOrgVDCId, sourceProviderVDCId, isSourceNSXTbacked = str(), str(), str()
        try:
            orgUrl = vcdValidationObj.getOrgUrl(self.inputDict["VCloudDirector"]["Organization"]["OrgName"])
            self.consoleLogger.info('Getting NSX-V backed Org VDC {} details'.format(orgVDCDict["OrgVDCName"]))
            sourceOrgVDCId = vcdValidationObj.getOrgVDCDetails(orgUrl, orgVDCDict["OrgVDCName"], 'sourceOrgVDC')

            # Get Source Provider VDC Id and details
            self.consoleLogger.info('Getting NSX-V backed Provider VDC {} details'.format(orgVDCDict["NSXVProviderVDCName"]))
            sourceProviderVDCId, isSourceNSXTbacked = vcdValidationObj.getProviderVDCId(orgVDCDict["NSXVProviderVDCName"])
            vcdValidationObj.getProviderVDCDetails(sourceProviderVDCId, isSourceNSXTbacked)

            # Get Target Provider VDC Id and details
            self.consoleLogger.info('Getting NSX-T backed Provider VDC {} details'.format(orgVDCDict["NSXTProviderVDCName"]))
            targetProviderVDCId, isTargetNSXTbacked = vcdValidationObj.getProviderVDCId(orgVDCDict["NSXTProviderVDCName"])
            vcdValidationObj.getProviderVDCDetails(targetProviderVDCId, isTargetNSXTbacked)
        except Exception as e:
            logging.debug(traceback.format_exc())
            orgExceptionList.append(e)
        finally:
            return sourceOrgVDCId, sourceProviderVDCId, isSourceNSXTbacked

    def initializePreCheck(self, vcdValidationObj, orgVDCDict, validationFailures, sourceOrgVDCId, sourceProviderVDCId, isSourceNSXTbacked, threadObj, nsxtObj, vcdObjList, noSnatDestSubnet=None, edgeGatewayDeploymentEdgeCluster=None):
        """
        Description : This method fetches the necessary details to run validations
        Parameters :  vcdValidationObj - Object the holds reference to class with all the validation methods (OBJECT)
                      orgVDCDict - Dictionary holding the org vdc details from the input file (DICT)
                      validationFailures - List that holds all the errors along with description (LIST)
                      sourceOrgVDCId - ID of the source org vdc to be evaluated (STRING)
                      sourceProviderVDCId - ID of the source provider vdc (STRING)
                      isSourceNSXTbacked - Flag that defines whether the org vdc is NSX-T backed or not (BOOLEAN)
                      threadObj - Object of threading class (OBJECT)
        """
        try:
            vcdValidationObj.updateEdgeGatewayInputDict(sourceOrgVDCId)

            getSourceExternalNetworkDesc = 'Getting NSX-V backed Provider VDC External network details'
            getTargetExternalNetworkDesc = 'Getting NSX-T backed Provider VDC External network details'
            getDummyExternalNetworkDesc = 'Getting NSX-V backed Provider VDC External network {} details'
            getEdgeGatewayDesc = 'Getting details of source edge gateway list'
            getOrgVdcNetworkDesc = 'Getting NSX-V backed Org VDC network details'
            # fetch details of edge gateway
            self.consoleLogger.info(getEdgeGatewayDesc)
            sourceEdgeGatewayData = vcdValidationObj.getOrgVDCEdgeGateway(sourceOrgVDCId)
            edgeGatewayIdList = vcdValidationObj.getOrgVDCEdgeGatewayId(sourceEdgeGatewayData, saveResponse=True)
            # fetch details of source external network
            self.consoleLogger.info(getSourceExternalNetworkDesc)
            threadObj.spawnThread(vcdValidationObj.getSourceExternalNetwork,
                                sourceEdgeGatewayData, saveOutputKey='sourceExternalNetwork')
            # fetch details of target External network
            self.consoleLogger.info(getTargetExternalNetworkDesc)
            threadObj.spawnThread(vcdValidationObj.getTargetExternalNetworks,
                                    sourceEdgeGatewayData,
                                    saveOutputKey='targetExternalNetwork')
            # fetch details of dummy external network
            self.consoleLogger.info(getDummyExternalNetworkDesc.format(self.inputDict["VCloudDirector"].get("DummyExternalNetwork")))
            threadObj.spawnThread(vcdValidationObj.getDummyExternalNetwork,
                                    self.inputDict["VCloudDirector"].get("DummyExternalNetwork"),
                                    saveOutputKey='dummyNetwork')
            self.consoleLogger.info(getOrgVdcNetworkDesc)
            threadObj.spawnThread(vcdValidationObj.getOrgVDCNetworks, sourceOrgVDCId,
                                    'sourceOrgVDCNetworks', saveOutputKey='getNSXVOrgVdcNetwork')

            # Halt the main thread till all the threads finish executing
            threadObj.joinThreads()
            # Fetching values returned by threads
            if threadObj.returnValues['sourceExternalNetwork'] and isinstance(threadObj.returnValues['sourceExternalNetwork'], Exception):
                validationFailures.append([getSourceExternalNetworkDesc, threadObj.returnValues['sourceExternalNetwork'], 'Failed'])
            if threadObj.returnValues['targetExternalNetwork'] and isinstance(threadObj.returnValues['targetExternalNetwork'], Exception):
                validationFailures.append([getTargetExternalNetworkDesc, threadObj.returnValues['targetExternalNetwork'], 'Failed'])
            if threadObj.returnValues['dummyNetwork'] and isinstance(threadObj.returnValues['dummyNetwork'], Exception):
                validationFailures.append([getDummyExternalNetworkDesc.format(self.inputDict["VCloudDirector"]["DummyExternalNetwork"]), threadObj.returnValues['dummyNetwork'], 'Failed'])
            if threadObj.returnValues['getNSXVOrgVdcNetwork'] and isinstance(threadObj.returnValues['getNSXVOrgVdcNetwork'], Exception):
                validationFailures.append([getOrgVdcNetworkDesc, threadObj.returnValues['getNSXVOrgVdcNetwork', 'Failed']])
            orgVdcNetworkList = threadObj.returnValues['getNSXVOrgVdcNetwork']

            # Validation methods reference
            vcdValidationMapping = {
                'Validating Target External Networks': [vcdValidationObj.validateProviderGateways],
                'Validating NSX-T manager Ip Address and version': [vcdValidationObj.getNsxDetails, self.inputDict["NSXT"]["Common"]["ipAddress"]],
                'Validating if target OrgVDC do not exists': [vcdValidationObj.validateNoTargetOrgVDCExists, orgVDCDict["OrgVDCName"]],
                'Validating external network mapping with Gateway mentioned in userInput file': [vcdValidationObj.validateEdgeGatewayToExternalNetworkMapping, sourceEdgeGatewayData],
                'Validating whether other Edge gateways are using dedicated external network': [vcdValidationObj.validateDedicatedExternalNetwork, self.inputDict],
                'Validating Source Network Pool backing': [vcdValidationObj.validateSourceNetworkPools, self.inputDict["VCloudDirector"].get("CloneOverlayIds")],
                'Validating whether source Org VDC is NSX-V backed': [vcdValidationObj.validateOrgVDCNSXbacking, sourceOrgVDCId, sourceProviderVDCId, isSourceNSXTbacked],
                'Validating Target Provider VDC is enabled': [vcdValidationObj.validateTargetProviderVdc],
                'Validating Hardware version of Source Provider VDC: {} and Target Provider VDC: {}'.format(orgVDCDict["NSXVProviderVDCName"], orgVDCDict["NSXTProviderVDCName"]): [vcdValidationObj.validateHardwareVersion],
                'Validating whether source Org VDC placement policies are present in target PVDC': [vcdValidationObj.validateVMPlacementPolicy, sourceOrgVDCId],
                'Validating storage profiles in source Org VDC and target Provider VDC': [vcdValidationObj.validateStorageProfiles],
                'Validating if source and target External networks have same subnets': [vcdValidationObj.validateExternalNetworkSubnets],
                'Validating ovelapping Org VDC Network subnets in case of IP Space enabled edges': [vcdValidationObj.validateOvelappingNetworksubnets, vcdObjList],
                'Validating Org VDC network subnets conflicts with existing IP Spaces Internal Scopes available to tenant': [vcdValidationObj.validateOrgVDCNetworkSubnetConflict],
                'Validating multiple subnets in directly connected external network': [vcdValidationObj.validateExternalNetworkMultipleSubnets],
                'Validating Target External Network with NSXT provided in input file': [vcdValidationObj.validateExternalNetworkWithNSXT],
                'Validating if all edge gateways interfaces are in use': [vcdValidationObj.validateEdgeGatewayUplinks, sourceOrgVDCId, edgeGatewayIdList, True],
                'Validating whether DHCP is enabled on source Isolated Org VDC network': [vcdValidationObj.validateDHCPEnabledonIsolatedVdcNetworks, orgVdcNetworkList, edgeGatewayIdList, edgeGatewayDeploymentEdgeCluster, nsxtObj],
                'Validating Isolated OrgVDCNetwork DHCP configuration': [vcdValidationObj.getOrgVDCNetworkDHCPConfig, orgVdcNetworkList],
                'Validating Org VDC Network Static IP pool configuration for non distributed routing': [vcdValidationObj.validateStaticIpPoolForNonDistributedRouting, orgVdcNetworkList],
                'Validating whether shared networks are supported or not': [vcdValidationObj.validateOrgVDCNetworkShared, sourceOrgVDCId],
                'Validating Source OrgVDC Direct networks': [vcdValidationObj.validateOrgVDCNetworkDirect, orgVdcNetworkList, self.NSXTProviderVDCImportedNeworkTransportZone, nsxtObj],
                'Validating Edge cluster for target edge gateway deployment': [vcdValidationObj.validateEdgeGatewayDeploymentEdgeCluster, edgeGatewayDeploymentEdgeCluster, nsxtObj],
                'Validating whether the source NSX-V Segment ID Pool is subset of target NSX-T VNI pool or not': [vcdValidationObj.validateVniPoolRanges, nsxtObj, self.nsxvObj, self.inputDict["VCloudDirector"].get("CloneOverlayIds")],
                'Validating Target NSX-T backed Network Pools': [vcdValidationObj.validateTargetPvdcNetworkPools, orgVDCDict.get('NSXTNetworkPoolName', None)],
                'Validating Cross VDC Networking is enabled or not': [vcdValidationObj.validateCrossVdcNetworking, sourceOrgVDCId],
                'Validating published/subscribed catalogs in source org VDC': [vcdValidationObj.getOrgVDCPublishedCatalogs, sourceOrgVDCId, self.inputDict['VCloudDirector']['Organization']['OrgName']],
            }
            # Perform these validations only if vapps are to be migrated
            if mainConstants.MOVEVAPP_KEYWORD in self.executeList:
                vcdValidationMapping.update({
                    'Validating whether the vApp name exceeds the 118 character limit': [vcdValidationObj.validateVappNameLength, sourceOrgVDCId],
                    'Validating if empty vApps or vApps in failed creation/unresolved/unrecognized/inconsistent state do not exist in source org VDC': [vcdValidationObj.validateNoEmptyVappsExistInSourceOrgVDC, sourceOrgVDCId],
                    'Validating if fencing is enabled on vApps in source OrgVDC': [vcdValidationObj.validateVappFencingMode, sourceOrgVDCId],
                    'Validating VMs/vApps in suspended/partially suspended state or in maintenance mode do not exists in source OrgVDC': [vcdValidationObj.validateSourceSuspendedVMsInVapp, sourceOrgVDCId],
                    'Validating VMs in vApp are not connected to media': [vcdValidationObj.validateVappVMsMediaNotConnected, sourceOrgVDCId, True],
                    'Validating routed vApp networks': [vcdValidationObj.validateRoutedVappNetworks, sourceOrgVDCId, False, nsxtObj],
                    'Validating vApps isolated vApp networks with DHCP enabled': [vcdValidationObj.validateDHCPOnIsolatedvAppNetworks, sourceOrgVDCId, edgeGatewayDeploymentEdgeCluster, nsxtObj],
                    'Validating Independent Disks': [vcdValidationObj.validateIndependentDisks, sourceOrgVDCId, False],
                    'Validating a VM does not have independent disks with different storage policies when fast provisioning is enabled': [vcdValidationObj.validateNamedDiskWithFastProvisioned, sourceOrgVDCId],
                })
            # Perform these validations only if services are to be configured
            if mainConstants.SERVICES_KEYWORD in self.executeList:
                vcdValidationMapping.update({
                    'Validating Source Edge gateway services': [vcdValidationObj.getEdgeGatewayServices, nsxtObj, self.nsxvObj, noSnatDestSubnet, True],
                    'Validating Distributed Firewall configuration': [vcdValidationObj.getDistributedFirewallConfig, sourceOrgVDCId, True, True, False]
                })

            # Perform segment backed network check in case of multiple Org VDCs
            vcdValidationMapping.update({
                'Validating segment backed network in case of multiple Org VDCs': [vcdValidationObj.checkVlanSegmentFromMultipleVDCs, vcdObjList]
            })

            return vcdValidationMapping
        except Exception as e:
            raise
            # validationFailures.append(e)

    def bridgingChecks(self):
        """
        Description : This method performs all the bridging checks
        """
        try:
            vcdValidationObj = self.vcdObjList[0]

            nsxtObj = self.nsxtObjList[0]
            # Iterating over the list org vdc/s to fetch the org vdc id
            orgVDCIdList = list()
            for orgVDCDict in self.inputDict["VCloudDirector"]["SourceOrgVDC"]:
                orgUrl = vcdValidationObj.getOrgUrl(self.inputDict["VCloudDirector"]["Organization"]["OrgName"])
                # Fetch org vdc id
                sourceOrgVDCId = vcdValidationObj.getOrgVDCDetails(orgUrl, orgVDCDict["OrgVDCName"], 'sourceOrgVDC',
                                                                     saveResponse=False)
                orgVDCIdList.append(sourceOrgVDCId)

            networkList = list()
            for orgVDCId in orgVDCIdList:
                networkList += vcdValidationObj.getOrgVDCNetworks(orgVDCId, 'sourceOrgVDCNetworks', saveResponse=False,
                                                                  sharedNetwork=False)

            filteredList = list(filter(lambda network: network['networkType'] != 'DIRECT', networkList))

            # Checking if any org vdc has VXLAN backed network pool
            vxlanBackingPresent = any([True if
                                       vcdObj.getSourceNetworkPoolBacking() == vcdConstants.VXLAN
                                       else False
                                       for vcdObj in self.vcdObjList])

            # Restoring thread name
            threading.current_thread().name = "MainThread"

            if filteredList:
                self.consoleLogger.info("Performing checks related to bridging components")
                checksMapping = {
                    'Validating Edge Cluster exists in NSX-T and Edge Transport Nodes are not in use': [nsxtObj.validateEdgeNodesNotInUse, self.inputDict, filteredList, self.vcdObjList, True],
                    'Validating whether the edge transport nodes are accessible via ssh or not': [nsxtObj.validateIfEdgeTransportNodesAreAccessibleViaSSH],
                    'Validating whether the edge transport nodes are deployed on v-cluster or not': [nsxtObj.validateEdgeNodesDeployedOnVCluster, self.vcenterObj, vxlanBackingPresent],
                    'Validating the max limit of bridge endpoint profiles in NSX-T': [nsxtObj.validateLimitOfBridgeEndpointProfile, filteredList],
                    'Validating MAC Address of the NSX-T Virtual Distributed Router': [nsxtObj.validateDlrMacAddress]
                }
                for desc, method in checksMapping.items():
                    methodName = method.pop(0)
                    argsList = method
                    self.consoleLogger.info(desc)
                    self.runAssessmentMode(desc, methodName, argsList, self.bridgingCheckFailures)

                self.updateInventoryLogs(bridgingReport=True)
        except:
            raise

    def sharedNetworkChecks(self):
        """
        Description : This method performs all the sharedNetwork Checks.
        """
        try:
            # Shared networks are supported starting from Andromeda build
            if float(self.vcdObjList[0].version) < float(vcdConstants.API_VERSION_ANDROMEDA):
                return
            vcdValidationObj = self.vcdObjList[0]
            # Get source OrgVdc names from input file.
            sourceOrgVdcData = self.inputDict["VCloudDirector"]["SourceOrgVDC"]
            sourceOrgVdcList = []
            for orgvdc in sourceOrgVdcData:
                sourceOrgVdcList.append(orgvdc['OrgVDCName'])

            # get list shared network
            orgVdcNetworkSharedList = vcdValidationObj.checkSharedNetworksUsedByOrgVdc(self.inputDict)

            # get list of vApp which uses shared network.
            vAppList = vcdValidationObj.getVappUsingSharedNetwork(orgVdcNetworkSharedList)

            # get OrgVDC which belongs to vApp which uses shared network.
            orgVdcvApplist, orgVdcNameList = vcdValidationObj.getOrgVdcOfvApp(vAppList)

            # Restoring thread name
            threading.current_thread().name = "MainThread"

            self.consoleLogger.info("Performing checks related to shared networks")
            checksMapping = {
                'Validating number of Org Vdc/s to be migrated are less/equal to max limit': [vcdValidationObj.checkMaxOrgVdcCount, sourceOrgVdcList, orgVdcNetworkSharedList],
                'Validating if any Org Vdc is using shared network other than those mentioned in input file': [vcdValidationObj.checkextraOrgVdcsOnSharedNetwork, orgVdcNameList, sourceOrgVdcList],
                'Validating if the owner of shared networks are also part of migration or not': [vcdValidationObj.checkIfOwnerOfSharedNetworkAreBeingMigrated, self.inputDict],
                'Validating distributed firewall default rule in all Org VDCs is same': [vcdValidationObj.validateDfwDefaultRuleForSharedNetwork, self.vcdObjList, sourceOrgVdcList, orgVdcNetworkSharedList, self.inputDict, None],
            }
            for desc, method in checksMapping.items():
                methodName = method.pop(0)
                argsList = method
                self.consoleLogger.info(desc)
                self.runAssessmentMode(desc, methodName, argsList, self.sharedNetworkCheckFailures)

        except:
            raise
        finally:
            threading.current_thread().name = "MainThread"

    def execute(self, orgVDCDict, vcdValidationObj, nsxtObj, vcdObjList):
        """
        Description : This method fetches the necessary details to run validations
        Parameters : orgVDCDict - Dictionary holding the org vdc details from the input file (DICT)
                     vcdValidationObj -
                     nsxtObj
        """
        # List that holds all the errors/failures encountered during the validations
        validationFailures, orgExceptionList = list(), list()
        try:
            # Changing the name of the thread with the name of org vdc
            threading.current_thread().name = orgVDCDict["OrgVDCName"]

            # Calculating number of threads for each org vdc
            maxNumberOfThreads = 1 if not math.floor(
                self.threadCount / self.numberOfParallelMigrations) else math.floor(
                self.threadCount / self.numberOfParallelMigrations)

            # creating object of thread class with specified number of threads in the user input file
            threadObj = Thread(maxNumberOfThreads=maxNumberOfThreads)

            sourceOrgVDCId, sourceProviderVDCId, isSourceNSXTbacked = self.checkOrgDetails(vcdValidationObj, orgVDCDict, orgExceptionList)
            if orgExceptionList:
                return

            vcdValidationMapping = self.initializePreCheck(
                vcdValidationObj, orgVDCDict, validationFailures, sourceOrgVDCId, sourceProviderVDCId,
                isSourceNSXTbacked, threadObj, nsxtObj, vcdObjList,
                noSnatDestSubnet=orgVDCDict.get("NoSnatDestinationSubnet"),
                edgeGatewayDeploymentEdgeCluster=orgVDCDict.get('EdgeGatewayDeploymentEdgeCluster', None)
            )
            for desc, method in vcdValidationMapping.items():
                methodName = method.pop(0)
                argsList = method
                self.consoleLogger.info(desc)
                skipHere = False
                for eachArg in argsList:
                    if isinstance(eachArg, Exception):
                        validationFailures.append([desc, eachArg, 'Failed'])
                        skipHere = True
                        break
                if skipHere == True:
                    continue
                else:
                    self.runAssessmentMode(desc, methodName, argsList, validationFailures)
        except:
            raise
        finally:
            self.orgVDCerrors[orgVDCDict["OrgVDCName"]] = [validationFailures, orgExceptionList]

    def run(self):
        """
        Description : Spawn/Start the threads for the org vdc/s to complete assessment
        """
        try:
            self.consoleLogger.info(
                f'Starting NSX-V migration to NSX-T backed in Assessment mode for org vdc/s - "{", ".join([vdc["OrgVDCName"] for vdc in self.inputDict["VCloudDirector"]["SourceOrgVDC"]])}"')
            # List the will hold reference to all the threads/futures
            futures = list()

            # Fetching the number of parallel migrations
            self.numberOfParallelMigrations = min(len(self.inputDict["VCloudDirector"]["SourceOrgVDC"]),
                                                  self.threadCount)

            # Create the threads along with specifying the target function
            with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                # Iterating over the org vdc/s
                for orgVDCDict, vcdValidationObj, nsxtObj in zip(self.inputDict["VCloudDirector"]["SourceOrgVDC"], self.vcdObjList, self.nsxtObjList):
                    futures.append(executor.submit(self.execute, orgVDCDict, vcdValidationObj, nsxtObj, self.vcdObjList))
                waitForThreadToComplete(futures)

            # Check if there was exception related to shared network.
            if not reduce(lambda a, b: a + b, [errors[1] for errors in self.orgVDCerrors.values()]):
                # Perform Shared Network related checks
                self.sharedNetworkChecks()
            else:
                self.consoleLogger.error(
                    "Cannot perform shared network related checks, due to failures related to input file. Please fix that errors first")

            # Check if there was exception related to org vdc
            if not reduce(lambda a, b: a + b, [errors[1] for errors in self.orgVDCerrors.values()]) \
                    and mainConstants.BRIDGING_KEYWORD in self.executeList:
                # Perform bridging related checks
                self.bridgingChecks()
            elif mainConstants.BRIDGING_KEYWORD not in self.executeList:
                self.consoleLogger.warning("Skipping Bridging checks as per inputs parameters provided")
            else:
                self.consoleLogger.error("Cannot perform bridging checks, due to failures related to input file. Please fix that errors first")

            # Updating the precheck logs in log file
            self.updateInventoryLogs()
        except Exception:
            raise

    def runAssessmentMode(self, desc, method, args, validationFailures):
        """
        Description : Executes the validation method and arguments passed as parameters as stores exceptions raised
        Parameters : desc - Description of the method to be executed (STRING)
                     method - Reference of method (METHOD REFERENCE)
                     args - arguments passed to the method (LIST)
                     validationFailures - List that holds all the errors along with description (LIST)
        """
        try:
            method(*args)
        except Exception as e:
            logging.debug(traceback.format_exc())
            validationFailures.append([desc, e, 'Failed'])

    def updateInventoryLogs(self, bridgingReport=False):
        """
        Description : This method creates detailed inventory logs of exceptions raised in validations
        """
        try:
            precheckLogger = logging.getLogger("precheckLogger")
            if bridgingReport:
                if self.bridgingCheckFailures:
                    getBridgingExceptionTableObj = prettytable.PrettyTable()
                    getBridgingExceptionTableObj.field_names = ['Bridging Check Name', 'Exception', 'Status']
                    for each_failure in self.bridgingCheckFailures:
                        getBridgingExceptionTableObj.add_row(each_failure)
                        # Storing the assessment table output in string format
                    bridgingCheckTable = getBridgingExceptionTableObj.get_string()
                    precheckLogger.info('Validation Checks Failed for Bridging\n{}\n'.format(bridgingCheckTable))
                else:
                    precheckLogger.info('All checks passed for bridging related components\n')
            else:
                for orgVDCName, errors in self.orgVDCerrors.items():
                    validationFailures, orgExceptionList = errors
                    getExceptionTableObj = prettytable.PrettyTable()
                    getExceptionTableObj.field_names = ['OrgVDC Details', 'Status']
                    assessmentTableObj = prettytable.PrettyTable(hrules=prettytable.ALL)
                    assessmentTableObj.field_names = ['Validation Name', 'Exception', 'Status']
                    if orgExceptionList:
                        for each_error in orgExceptionList:
                            getExceptionTableObj.add_row([each_error, 'Not Present'])
                        getExceptionTable = getExceptionTableObj.get_string()
                        self.consoleLogger.error(f'Incorrect details in sampleUserInput.yml for org vdc "{orgVDCName}". Please check VCD Organization or OrgVDC details')
                        precheckLogger.info("Organization VDC: " + orgVDCName + "\n" + getExceptionTable + "\n")
                        continue
                    if validationFailures:
                        for each_failure in validationFailures:
                            assessmentTableObj.add_row(each_failure)
                        # Storing the assessment table output in string format
                        preCheckTable = assessmentTableObj.get_string()
                        self.consoleLogger.error(f'Assessment mode validations failed for org vdc "{orgVDCName}".\n')
                        precheckLogger.info('\nOrganization VDC: "{}"\n{}'.format(orgVDCName, preCheckTable))
                        continue
                    else:
                        precheckLogger.info(f'All the org vdc related validations have passed successfully for org vdc "{orgVDCName}"\n')
                # Check for shared network related validations.
                if self.sharedNetworkCheckFailures:
                    getSharedNetworkExceptionObj = prettytable.PrettyTable()
                    getSharedNetworkExceptionObj.field_names = ['Shared Network Check Name', 'Exception', 'Status']
                    for each_failure in self.sharedNetworkCheckFailures:
                        getSharedNetworkExceptionObj.add_row(each_failure)
                    # Storing the assessment table output in string format
                    sharedNetworkCheckTable = getSharedNetworkExceptionObj.get_string()
                    precheckLogger.info('Validation Checks Failed for Shared Networks\n{}\n'.format(sharedNetworkCheckTable))
                elif float(self.vcdObjList[0].version) >= float(vcdConstants.API_VERSION_ANDROMEDA) and not orgExceptionList:
                    precheckLogger.info(f'All shared networks related validations successfully for org vdc/s - {", ".join([vdc["OrgVDCName"] for vdc in self.inputDict["VCloudDirector"]["SourceOrgVDC"]])}.\n')

                # Check if any org vdc encountered any error in validations
                if reduce(lambda a, b: a + b,
                          [errors[0] + errors[1] for errors in self.orgVDCerrors.values()]) + self.bridgingCheckFailures:
                    self.consoleLogger.error("Assessment mode for NSX-V migration to NSX-T failed")
                    self.consoleLogger.error(
                        'Check {} file for failed validations.'.format(self.preAssessmentLogs))
                else:
                    self.consoleLogger.info(
                        f'Assessment mode for NSX-V migration to NSX-T successfully completed for org vdc/s - {", ".join([vdc["OrgVDCName"] for vdc in self.inputDict["VCloudDirector"]["SourceOrgVDC"]])}')
        except:
            raise
