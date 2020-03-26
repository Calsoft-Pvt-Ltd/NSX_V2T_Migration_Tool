# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which is a run file that does the migration of VMware Cloud Director from NSX-V to NSX-T.
"""

import argparse
import getpass
import json
import os
import re
import signal
import sys
import logging
import time

import requests
import colorlog
import yaml

# Set path till src folder in PYTHONPATH
cwd = os.getcwd()
parentDir = os.path.abspath(os.path.join(cwd, os.pardir))
sys.path.append(parentDir)

from prettytable import PrettyTable

import src.constants as mainConstants
import src.core.vcd.vcdConstants as vcdConstants

from src.commonUtils.logConf import Logger
from src.commonUtils.utils import Utilities
from src.core.nsxt.nsxtOperations import NSXTOperations
from src.core.vcd.vcdConfigureEdgeGatewayServices import ConfigureEdgeGatewayServices
from src.core.vcd.vcdOperations import VCloudDirectorOperations
from src.core.vcd.vcdValidations import VCDMigrationValidation
from src.core.vcenter.vcenterApis import VcenterApi
from src.vcdNSXMigratorCleanup import VMwareCloudDirectorNSXMigratorCleanup


class VMwareCloudDirectorNSXMigrator():
    """
    Description: VMware Cloud Directory class that migrates the it from NSX-V to NSX-T
    """
    CLEAN_UP_SCRIPT_RUN = False

    def __init__(self):
        """
        Description : This method initializes the basic logging configuration ans migration related stuff
        """
        self.utils = Utilities()
        self.loggerObj = Logger()
        self.consoleLogger = logging.getLogger("consoleLogger")
        self.mainLogfile = logging.getLogger('mainLogger').handlers[0].baseFilename
        self.cleanup = None
        self.userInputFilePath = None

        parser = argparse.ArgumentParser(description='Arguments supported by V2T migration tool')
        parser.add_argument("--filepath", dest='filePath', help="Path of the userInput spec file to run VMware VCD NSX Migrator/Cleanup workflow (REQUIRED ARGUMENT)")
        parser.add_argument("--cleanup", dest="cleanupValue", action="store_const", help='Cleanup workflow (OPTIONAL ARGUMENT)',
                            const=True, default=False, required=False)

        args = parser.parse_args()
        if args.cleanupValue:
            self.cleanup = args.cleanupValue
        if args.filePath:
            self.userInputFilePath = args.filePath
        if (not args.cleanupValue and not args.filePath) or (not args.filePath and args.cleanupValue):
            parser.print_help()
            raise Exception("Invalid Input Arguments")
        # handling the CNTRL+C  i.e keyboard interrupt
        signal.signal(signal.SIGINT, self.signalHandler)

    def _getPasswordFromUser(self):
        """
        Description : this method prompts user for password
        """
        self.vCloudDirectorPassword = getpass.getpass(prompt="Please enter VMware Cloud Director Password: ")
        if not self.vCloudDirectorPassword:
            raise ValueError("VMware Cloud Director password must be provided")
        self.nsxtPassword = getpass.getpass(prompt="Please enter NSX-T Password: ")
        if not self.nsxtPassword:
            raise ValueError("NSXT password must be provided")
        self.vcenterPassword = getpass.getpass(prompt="Please enter Vcenter Password: ")
        if not self.vcenterPassword:
            raise ValueError("Vcenter password must be provided")

    def inputValidation(self):
        """
        Description - Validation of user input values
        """
        errorInputDict = {}
        for componentName, componentValues in self.inputDict.items():
            for componentKey, componentValue in componentValues.items():
                if isinstance(componentValue, dict):
                    for item, value in componentValue.items():
                        dictKey = "{}['{}']['{}']".format(componentName, componentKey, item)
                        if not componentValue[item] and not isinstance(componentValue[item], bool):
                            errorInputDict[dictKey] = "Value must be provided."
                        # validate verify key value is boolean or not
                        if item == 'verify' and not isinstance(componentValue[item], bool):
                            errorInputDict[dictKey] = "Value must be boolean i.e either True or False."
                        # validate ip address or fqdn
                        if item == 'ipAddress':
                            isFqdn = not all(host.isdigit() for host in str(value).split(".")[:-1]) and \
                                     not str(value).split(".")[-1].isdigit()
                            # validate fqdn
                            if isFqdn:
                                if len(str(value)) > 255:
                                    errorInputDict[dictKey] = "Input IP/FQDN value is empty or has more than 255 characters"
                                else:
                                    if "." in value:
                                        allowed = re.compile(mainConstants.FQDN_REGEX, re.IGNORECASE)
                                        if not all(allowed.match(host) for host in value.split(".")):
                                            errorInputDict[dictKey] = "Input FQDN value is not in proper fqdn format"
                            # validate ip address
                            else:
                                validIp = re.search(mainConstants.VALID_IP_REGEX, value) if value else None
                                if not validIp:
                                    errorInputDict[dictKey] = "Input IP value is not in proper ip format"
                if isinstance(componentValue, type(None)):
                    # do not check for certificate validation here it should be checked based on verify parameter
                    if componentKey != 'CertificatePath':
                        errorInputDict[componentKey] = 'Value must be provided for key - {}'.format(componentKey)
                if isinstance(componentValue, str):
                    if not componentValue:
                        errorInputDict[componentKey] = 'Please enter proper Value for key - {}'.format(componentKey)

        if bool(errorInputDict):
            raise Exception('Input Validation Error - {}'.format(errorInputDict))

    def run(self):
        """
        Description : This method runs the migration process of VMware Cloud Director from V2T
        """
        try:
            vcdObj, nsxtObj, configureEdgeGatewayServiceObj, vcenterObj = None, None, None, None
            if not os.path.exists(self.userInputFilePath):
                raise Exception("User Input File: '{}' does not Exist".format(self.userInputFilePath))
            # deleting the api output json file
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            if os.path.exists(fileName):
                os.remove(fileName)
            # reading the release yaml file
            releaseFile = os.path.join(mainConstants.rootDir, "release.yml")
            with open(releaseFile) as f:
                releaseData = yaml.safe_load(f)
            self.consoleLogger.info("Build Version: {}".format(releaseData['Build']))
            self.consoleLogger.info("Build Release Date: {}".format(releaseData['ReleaseDate']))
            # password prompt from user
            self._getPasswordFromUser()
            # reading the input yaml file
            with open(self.userInputFilePath) as f:
                self.inputDict = yaml.safe_load(f)
            # validating user input
            self.inputValidation()
            # updating the password in the input dict
            self.inputDict['VCloudDirector']['Common']['password'] = self.vCloudDirectorPassword
            self.inputDict['NSXT']['Common']['password'] = self.nsxtPassword
            self.inputDict['Vcenter']['Common']['password'] = self.vcenterPassword
            # getting vcd related information from user input
            vcdDict = self.inputDict['VCloudDirector']
            # getting nsxt related information from userinput
            nsxtDict = self.inputDict['NSXT']
            # getting the vcenter related information from userinput
            vcenterDict = self.inputDict['Vcenter']
            # if verify is set to True on any one component then we have to update certificates in requests
            if vcdDict['Common']['verify'] or nsxtDict['Common']['verify'] or vcenterDict['Common']['verify']:
                certPath = self.inputDict['Common']['CertificatePath']
                # checking for certificate path is present in user input
                if not certPath:
                    self.consoleLogger.error("Please enter the certificate path in user Input file.")
                    os._exit(0)
                # checking for the path provided in user input whether its valid
                if not os.path.exists(certPath):
                    self.consoleLogger.error("The provided certificate path in user Input file does not exist.")
                    os._exit(0)
                # update certificate path in requests
                self.utils.updateRequestsPemCert(certPath)
            if self.cleanup:
                self.CLEAN_UP_SCRIPT_RUN = True
                VMwareCloudDirectorNSXMigratorCleanup(vcdDict, nsxtDict).run()
            else:
                self.consoleLogger.info('Started migration of NSX-V backed Org VDC to NSX-T backed.')

                # getting the common info from vcd related dict
                vcdCommonDict = vcdDict['Common']
                # initializing vmware cloud director pre migration validation class
                vcdValidationObj = VCDMigrationValidation(vcdCommonDict['ipAddress'], vcdCommonDict['username'],
                                                          vcdCommonDict['password'], vcdCommonDict['verify'])
                # initializing vmware cloud director Operations class
                vcdObj = VCloudDirectorOperations(vcdCommonDict['ipAddress'], vcdCommonDict['username'],
                                                  vcdCommonDict['password'], vcdCommonDict['verify'])
                # initializing vmware cloud director target edge gateway services configuration class
                configureEdgeGatewayServiceObj = ConfigureEdgeGatewayServices(vcdCommonDict['ipAddress'], vcdCommonDict['username'],
                                                                              vcdCommonDict['password'], vcdCommonDict['verify'])

                # preparing the nsxt dict for bridging
                nsxtCommonDict = nsxtDict['Common']
                nsxtObj = NSXTOperations(nsxtCommonDict['ipAddress'], nsxtCommonDict['username'],
                                         nsxtCommonDict['password'], nsxtCommonDict['verify'])

                # initializing vcenter Api class
                vcenterObj = VcenterApi(vcenterDict['Common'])

                # login to the vmware cloud director for getting the bearer token
                self.consoleLogger.info('Login into the VMware Cloud Director - {}'.format(vcdCommonDict['ipAddress']))
                vcdObj.vcdLogin()

                # login to the nsx-t
                self.consoleLogger.info('Login into the NSX-T - {}'.format(nsxtCommonDict['ipAddress']))
                nsxtObj.getComputeManagers()

                # login to vcenter
                self.consoleLogger.info('Login into the Vcenter - {}'.format(vcenterDict['Common']['ipAddress']))
                vcenterObj.getTimezone()

                self.consoleLogger.info('Starting with PreMigration validation tasks')

                self.consoleLogger.info('Validating NSX-T Bridge Uplink Profile doesnot exist')
                nsxtObj.validateBridgeUplinkProfile()

                self.consoleLogger.info('Validating Edge Transport Nodes are not in use')
                nsxtObj.validateEdgeNodesNotInUse(nsxtDict['EdgeClusterName'])
                self.consoleLogger.info('Successfully validated Edge Transport Nodes are not in use')

                sourceOrgVDCId, orgVdcNetworkList, sourceEdgeGatewayId, bgpConfigDict, ipsecConfigDict = vcdValidationObj.preMigrationValidation(vcdDict)

                # writing the promiscuous mode and forged mode details to apiOutput.json
                vcdObj.getPromiscModeForgedTransmit(orgVdcNetworkList)

                nsxtObj.validateOrgVdcNetworksAndEdgeTransportNodes(nsxtDict['EdgeClusterName'], orgVdcNetworkList)
                self.consoleLogger.info('Successfully completed PreMigration validation tasks')

                self.consoleLogger.info('Preparing Target VDC.')
                targetOrgVdcId, portGroupList = vcdObj.prepareTargetVDC(orgVdcNetworkList, bgpConfigDict)
                self.consoleLogger.info('Successfully prepared Target VDC.')

                # only if org vdc networks exist bridging will be configured
                if orgVdcNetworkList:
                    self.consoleLogger.info('Configuring NSXT Bridging.')
                    edgeNodeList = nsxtObj.configureNSXTBridging(nsxtDict, portGroupList)
                    self.consoleLogger.info('Successfully configured NSXT Bridging.')

                    self.consoleLogger.info('Verifying bridging connectivity')
                    time.sleep(180)
                    # get source edge gateway vm id
                    edgeVMId = vcdObj.getEdgeVmId(sourceEdgeGatewayId)
                    # get routed network interface details of the nsx-v edge vm using vcenter api's
                    interfaceDetails = vcenterObj.getEdgeVmNetworkDetails(edgeVMId)
                    # get the source edge gateway mac address for routed networks
                    macAddressList = vcdObj.getSourceEdgeGatewayMacAddress(portGroupList, interfaceDetails)
                    # verify bridge connectivity
                    nsxtObj.verifyBridgeConnectivity(edgeNodeList, macAddressList)
                    self.consoleLogger.info('Successfully verified bridging connectivity')
                else:
                    self.consoleLogger.warning('Skipping the NSXT Bridging configuration and verifying connectivity check as no source Org VDC network exist')

                self.consoleLogger.info('Configure Target Edge gateway services.')
                configureEdgeGatewayServiceObj.configureServices(bgpConfigDict, ipsecConfigDict)
                self.consoleLogger.info('Target Edge gateway services got configured successfully.')

                # configuring target vdc i.e reconnecting target vdc networks and edge gateway
                vcdObj.configureTargetVDC(orgVdcNetworkList, sourceEdgeGatewayId)

                # migrate source vapps
                vcdObj.migrateVapps()

                # disabling target vdc only if source org vdc is disabled
                vcdObj.disableOrgVDC(targetOrgVdcId, isSourceDisable=False)
                self.consoleLogger.info('Successfully migrated NSX-V backed Org VDC to NSX-T backed.')

                # deleting the current user api session of vmware cloud director
                self.consoleLogger.debug('Log out the current vmware cloud director user')
                vcdObj.deleteSession()

                # deleting the current user api session of vcenter server
                self.consoleLogger.debug('Log out the current vmware vcenter server user')
                vcenterObj.deleteSession()
        except requests.exceptions.SSLError as e:
            # catching the exception for ssl error.
            # exception of HTTPSConnectionPool(host={hostname}, port=443)
            # using regex getting the first match of () to get host ip
            host = re.findall(r'\'(.*?)\'', str(e))
            self.consoleLogger.error('Certificate Validation Failed. Unable to login - {}.'.format(host[0]))
        except requests.exceptions.ConnectionError as e:
            # catching the exception for ssl error.
            # exception of HTTPSConnectionPool(host={hostname}, port=443)
            # using regex getting the first match of string within '()' to get host ip
            host = re.findall(r'\'(.*?)\'', str(e))
            self.consoleLogger.error('Connection Failed. Unable to connect to remote server - {}.'.format(host[0]))
        except Exception as err:
            self.consoleLogger.exception(err)
            if not self.CLEAN_UP_SCRIPT_RUN:
                if nsxtObj:
                    if not vcdObj.PROMISCUCOUS_MODE_ALREADY_DISABLED:
                        if nsxtObj.DISABLE_PROMISC_MODE or vcenterObj.DISABLE_PROMISC_MODE or vcdObj.DISABLE_PROMISC_MODE:
                            self.consoleLogger.info("RollBack: Disable Promiscuous Mode and Forged Mode")
                            vcdObj.enableDisablePromiscModeForgedTransmit(None, enable=False)
                    if nsxtObj.CLEAR_NSX_T_BRIDGING:
                        orgVDCNetworkList = vcdObj.getOrgVDCNetworks(targetOrgVdcId, 'targetOrgVDCNetworks', saveResponse=False)
                        self.consoleLogger.info("RollBack: Clear NSX-T Bridging")
                        nsxtObj.clearBridging(orgVDCNetworkList)
                        self.consoleLogger.info("RollBack: Enable Source Org VDC")
                        vcdObj.enableSourceOrgVdc(sourceOrgVDCId)
                        self.consoleLogger.info("RollBack: Enable Source vApp Affinity Rules")
                        vcdObj.enableOrDisableSourceAffinityRules(sourceOrgVDCId, enable=True)
                        self.consoleLogger.info("RollBack: Delete Target Org VDC Networks")
                        vcdObj.deleteOrgVDCNetworks(targetOrgVdcId, source=False)
                        self.consoleLogger.info("RollBack: Delete Target Edge Gateway")
                        vcdObj.deleteNsxTBackedOrgVDCEdgeGateways(targetOrgVdcId)
                        self.consoleLogger.info("RollBack: Delete Target Org VDC")
                        vcdObj.deleteOrgVDC(targetOrgVdcId)
                    elif nsxtObj.ENABLE_SOURCE_ORG_VDC_AFFINITY_RULES:
                        self.consoleLogger.info("RollBack: Enable Source Org VDC")
                        vcdObj.enableSourceOrgVdc(sourceOrgVDCId)
                        self.consoleLogger.info("RollBack: Enable Source vApp Affinity Rules")
                        vcdObj.enableOrDisableSourceAffinityRules(sourceOrgVDCId, enable=True)
                if vcdObj and vcdObj.VCD_SESSION_CREATED:
                    # deleting the current user api session of vmware cloud director
                    self.consoleLogger.debug('Log out the current vmware cloud director user')
                    vcdObj.deleteSession()
                if vcenterObj and vcenterObj.VCENTER_SESSION_CREATED:
                    # deleting the current user api session of vcenter server
                    self.consoleLogger.debug('Log out the current vmware vcenter server user')
                    vcenterObj.deleteSession()
            self.consoleLogger.critical("VCD V2T Migration Tool failed due to errors. For more details, please refer "
                                        "main log file {}".format(self.mainLogfile))
        finally:
            # clear the requests certificates entries
            self.utils.clearRequestsPemCert()

    @staticmethod
    def updateInventoryLogs():
        """
        Description : This method creates deatiled inventory logs of the components in VMware vCloud Director
        """
        try:
            # creating source org vdc information table
            fileName = os.path.join(vcdConstants.VCD_ROOT_DIRECTORY, 'apiOutput.json')
            if os.path.exists(fileName):
                # reading data from apiOutput.json
                with open(fileName, 'r') as f:
                    data = json.load(f)
            else:
                return
            # getting the table logger object
            tableLogger = logging.getLogger("tableLogger")
            # source org vdc pretty-table object
            sourceTableObj = PrettyTable()
            sourceTableObj.field_names = ['Source Org VDC Details', '']
            # getting source org vdc name
            if data.get('sourceOrgVDC'):
                sourceTableObj.add_row(['Name', data['sourceOrgVDC']['@name']])
            else:
                return
            sourceTableObj.add_row(['', ''])
            # getting source provider vdc
            if data.get('sourceProviderVDC'):
                sourceTableObj.add_row(['Provider VDC', data['sourceProviderVDC']['@name']])
            else:
                return
            sourceTableObj.add_row(['', ''])
            # getting source org vdc external networks
            if data.get('sourceExternalNetwork'):
                sourceExternalNetworks = data['sourceExternalNetwork'] if isinstance(data['sourceExternalNetwork'], list) else [data['sourceExternalNetwork']]
                index = 0
                for externalNetwork in sourceExternalNetworks:
                    index += 1
                    if index == 1:
                        sourceTableObj.add_row(['External Networks', externalNetwork['name']])
                    else:
                        sourceTableObj.add_row(['', externalNetwork['name']])
            else:
                sourceTableObj.add_row(['External Networks', ' - '])
            sourceTableObj.add_row(['', ''])
            # getting source org vdc networks
            if data.get('sourceOrgVDCNetworks'):
                sourceOrgVdcNetworks = data['sourceOrgVDCNetworks'] if isinstance(data['sourceOrgVDCNetworks'], list) else [data['sourceOrgVDCNetworks']]
                index = 0
                for orgVdcNetwork in sourceOrgVdcNetworks:
                    index += 1
                    if index == 1:
                        sourceTableObj.add_row(['Org VDC Networks', orgVdcNetwork['name']])
                    else:
                        sourceTableObj.add_row(['', orgVdcNetwork['name']])
            else:
                sourceTableObj.add_row(['Org VDC Networks', ' - '])
            sourceTableObj.add_row(['', ''])
            # getting source edge gateway
            if data.get('sourceEdgeGateway'):
                sourceTableObj.add_row(['Edge Gateway', data['sourceEdgeGateway']['name']])
            else:
                sourceTableObj.add_row(['Edge Gateway', ' - '])
            sourceTableObj.add_row(['', ''])
            # getting source org vdc vapps
            if data['sourceOrgVDC'].get('ResourceEntities'):
                sourceResourceEntities = data['sourceOrgVDC']['ResourceEntities']['ResourceEntity'] if isinstance(data['sourceOrgVDC']['ResourceEntities']['ResourceEntity'], list) else [data['sourceOrgVDC']['ResourceEntities']['ResourceEntity']]
                index = 0
                for resourceEntity in sourceResourceEntities:
                    if resourceEntity['@type'] == 'application/vnd.vmware.vcloud.vApp+xml':
                        index += 1
                        if index == 1:
                            sourceTableObj.add_row(['vApps', resourceEntity['@name']])
                        else:
                            sourceTableObj.add_row(['', resourceEntity['@name']])
            else:
                sourceTableObj.add_row(['vApps', ' - '])
            sourceTableObj.add_row(['', ''])
            sourceTableObj.align = 'l'
            tableLogger.info(sourceTableObj)

            if not data.get('targetOrgVDC'):
                return
            # target org vdc pretty-table object
            targetTableObj = PrettyTable()
            targetTableObj.field_names = ['Target Org VDC Details', '']
            # getting target org vdc name
            if data.get('targetOrgVDC'):
                targetTableObj.add_row(['Name', data['targetOrgVDC']['@name']])
            else:
                targetTableObj.add_row(['Name', ' - '])
            targetTableObj.add_row(['', ''])
            # getting target provider vdc
            if data.get('targetProviderVDC'):
                targetTableObj.add_row(['Provider VDC', data['targetProviderVDC']['@name']])
            else:
                targetTableObj.add_row(['Provider VDC', ' - '])
            targetTableObj.add_row(['', ''])
            # getting target org vdc external networks
            if data.get('targetExternalNetwork'):
                targetExternalNetworks = data['targetExternalNetwork'] if isinstance(data['targetExternalNetwork'], list) else [data['targetExternalNetwork']]
                index = 0
                for externalNetwork in targetExternalNetworks:
                    index += 1
                    if index == 1:
                        targetTableObj.add_row(['External Networks', externalNetwork['name']])
                    else:
                        targetTableObj.add_row(['', externalNetwork['name']])
            else:
                targetTableObj.add_row(['External Networks', ' - '])
            targetTableObj.add_row(['', ''])
            # getting target org vdc networks
            if data.get('targetOrgVDCNetworks'):
                targetOrgVdcNetworks = data['targetOrgVDCNetworks'] if isinstance(data['targetOrgVDCNetworks'], list) else [data['targetOrgVDCNetworks']]
                index = 0
                for orgVdcNetwork in targetOrgVdcNetworks:
                    index += 1
                    if index == 1:
                        targetTableObj.add_row(['Org VDC Networks', orgVdcNetwork['name']])
                    else:
                        targetTableObj.add_row(['', orgVdcNetwork['name']])
            else:
                targetTableObj.add_row(['Org VDC Networks', ' - '])
            targetTableObj.add_row(['', ''])
            # getting target edge gateway
            if data.get('targetEdgeGateway'):
                targetTableObj.add_row(['Edge Gateway', data['targetEdgeGateway']['name']])
            else:
                targetTableObj.add_row(['Edge Gateway', ' - '])
            targetTableObj.add_row(['', ''])
            # getting target org vdc vapps
            if data['targetOrgVDC'].get('ResourceEntities'):
                targetResourceEntities = data['targetOrgVDC']['ResourceEntities']['ResourceEntity'] if isinstance(data['targetOrgVDC']['ResourceEntities']['ResourceEntity'], list) else [data['targetOrgVDC']['ResourceEntities']['ResourceEntity']]
                index = 0
                for resourceEntity in targetResourceEntities:
                    if resourceEntity['@type'] == 'application/vnd.vmware.vcloud.vApp+xml':
                        index += 1
                        if index == 1:
                            targetTableObj.add_row(['vApps', resourceEntity['@name']])
                        else:
                            targetTableObj.add_row(['', resourceEntity['@name']])
            else:
                targetTableObj.add_row(['vApps', ' - '])
            targetTableObj.add_row(['', ''])
            targetTableObj.align = 'l'
            tableLogger.info(targetTableObj)
        except Exception:
            raise

    def signalHandler(self, sig, frame):
        """
        Description: Hanlding the Ctrl+C i.e abruptly closing the script
        """
        self.consoleLogger.warning('Aborting the VCD NSX Migrator tool execution due to keyboard interrupt.')
        # clear the requests certificates entries
        self.utils.clearRequestsPemCert()
        os._exit(0)

if __name__ == '__main__':

    vcdMigrateObj = VMwareCloudDirectorNSXMigrator()
    vcdMigrateObj.run()
    vcdMigrateObj.updateInventoryLogs()
