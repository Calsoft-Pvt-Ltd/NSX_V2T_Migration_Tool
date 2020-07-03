# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which is a run file that does the migration of VMware Cloud Director from NSX-V to NSX-T.
"""

import argparse
import copy
import getpass
import os
import re
import signal
import sys
import logging
from collections import namedtuple

import requests
import colorlog
import yaml

# Set path till src folder in PYTHONPATH
cwd = os.getcwd()
parentDir = os.path.abspath(os.path.join(cwd, os.pardir))
sys.path.append(parentDir)

import src.constants as mainConstants

from src.rollback import Rollback
from src.commonUtils.logConf import Logger
from src.commonUtils.utils import Utilities
from src.commonUtils.passwordUtils import PasswordUtilities
from src.core.nsxt.nsxtOperations import NSXTOperations
from src.core.vcd.vcdOperations import VCloudDirectorOperations
from src.core.vcd.vcdValidations import VCDMigrationValidation
from src.core.vcenter.vcenterApis import VcenterApi
from src.vcdNSXMigratorCleanup import VMwareCloudDirectorNSXMigratorCleanup
from src.vcdNSXMigratorAssessmentMode import VMwareCloudDirectorNSXMigratorAssessmentMode


class VMwareCloudDirectorNSXMigrator():
    """
    Description: VMware Cloud Directory class that migrates the it from NSX-V to NSX-T
    """
    CLEAN_UP_SCRIPT_RUN = False

    def __init__(self):
        """
        Description : This method initializes the basic logging configuration ans migration related stuff
        """
        self.sourceOrgVDCId = None
        self.passwordUtils = PasswordUtilities()
        self.utils = Utilities()
        self.executionMode = None
        self.cleanup = None
        self.assessmentMode = None
        self.userInputFilePath = None
        self.loginErrorDict = {
            self._loginToVcd.__name__: False,
            self._loginToNsxt.__name__: False,
            self._loginToVcenter.__name__: False
        }
        self.defaultPassFileName = 'passfile'

        parser = argparse.ArgumentParser(description='Arguments supported by V2T migration tool')
        parser.add_argument("--filepath", dest='filePath',
                            help="Path of the userInput spec file to run VMware VCD NSX Migrator/Cleanup workflow (REQUIRED ARGUMENT)")
        parser.add_argument("--cleanup", dest="cleanupValue", action="store_const",
                            help='Cleanup workflow (OPTIONAL ARGUMENT)',
                            const=True, default=False, required=False)

        parser.add_argument("--preCheck", dest='preCheck', help='PreCheck workflow (OPTIONAL ARGUMENT)', \
                            action="store_true", default=False, required=False)
        parser.add_argument("--passwordFile", dest="passwordFilePath",
                            help="Run migration tool with generated password File", required=False)
        parser.add_argument("--rollback", dest='rollback', help='retry rollback (OPTIONAL ARGUMENT)', \
                            action="store_true", default=False, required=False)

        args = parser.parse_args()
        # Set the execution mode flag based in the input arguments passed
        if args.cleanupValue:
            self.cleanup = args.cleanupValue
            self.executionMode = 'cleanup'
        elif args.preCheck:
            self.executionMode = 'preCheck'
            self.assessmentMode = args.preCheck
        else:
            self.executionMode = 'Main'
        if args.filePath:
            self.userInputFilePath = args.filePath
        # if retry argument is provided then previously saved password will be used
        self.passFile = args.passwordFilePath
        # if rollback argument is provided then rollback is retried from its last failed state
        self.retryRollback = args.rollback

        #Initialize logger object with the migrator execution mode
        self.loggerObj = Logger(self.executionMode)
        self.consoleLogger = logging.getLogger("consoleLogger")
        self.rollback = Rollback(self.consoleLogger)
        self.rollback.retryRollback = self.retryRollback
        self.mainLogfile = logging.getLogger('mainLogger').handlers[0].baseFilename
        self.rollback.mainLogfile = self.mainLogfile
        #Check if invalid arguements are passed
        if (not args.cleanupValue and not args.filePath) or \
            (not args.filePath and args.cleanupValue) or \
            (args.cleanupValue and args.preCheck) or \
            (not args.filePath and args.preCheck) or \
            (args.cleanupValue and args.rollback) or \
                (args.preCheck and args.rollback):
            parser.print_help()
            raise Exception("Invalid Input Arguments")
        # handling the CNTRL+C  i.e keyboard interrupt
        signal.signal(signal.SIGINT, self.signalHandler)

    def releaseVersion(self):
        """
        Description : Read and write migration tool release version
        """
        # reading the release yaml file
        releaseFile = os.path.join(mainConstants.rootDir, "release.yml")
        with open(releaseFile) as f:
            releaseData = yaml.safe_load(f)
        self.consoleLogger.info("Build Version: {}".format(releaseData['Build']))
        self.consoleLogger.info("Build Release Date: {}".format(releaseData['ReleaseDate']))

    def _getVcloudDirectorPassword(self):
        """
        Description :   getting VMware Cloud Director password from user
        """
        self.vCloudDirectorPassword = getpass.getpass(prompt="Please enter VMware Cloud Director Password: ")
        if not self.vCloudDirectorPassword:
            raise ValueError("VMware Cloud Director password must be provided")

    def _getNsxtPassword(self):
        """
        Description :   getting NSX-T password from user
        """
        self.nsxtPassword = getpass.getpass(prompt="Please enter NSX-T Password: ")
        if not self.nsxtPassword:
            raise ValueError("NSX-T password must be provided")

    def _getVcenterPassword(self):
        """
        Description :   getting vCenter password from user
        """
        self.vcenterPassword = getpass.getpass(prompt="Please enter vCenter Password: ")
        if not self.vcenterPassword:
            raise ValueError("vCenter password must be provided")

    def _encryptAndSavePasswords(self):
        """
        Description :   Encrypt the passwords and write passwords and master key to the file
        """
        # generating the master key
        masterKey = self.passwordUtils.generateMasterKey()
        # generating the encryption key
        encryptionKey = self.passwordUtils.generateKey(masterKey)
        # creating a list to store passwords
        passList = list()
        # Encrypting passwords and appending the passwords to a list
        passList.append(masterKey)
        passList.append(self.passwordUtils.encrpyt(encryptionKey, self.vCloudDirectorPassword).decode())
        passList.append(self.passwordUtils.encrpyt(encryptionKey, self.nsxtPassword).decode())
        passList.append(self.passwordUtils.encrpyt(encryptionKey, self.vcenterPassword).decode())
        # Writing the list to file
        if self.passFile:
            self.passwordUtils.writePassFile('\n'.join(passList), self.passFile)
        else:
            self.passwordUtils.writePassFile('\n'.join(passList), self.defaultPassFileName)

    def _getPasswordFromUser(self):
        """
        Description : this method prompts user for password
        """
        try:
            #If password file path is provided
            if self.passFile:
                # Reading master key and passwords from file
                if os.path.exists(self.passFile):
                    masterKey, vCloudDirectorPassword, nsxtPassword, vcenterPassword = self.passwordUtils.readPassFile(self.passFile)
                    # generating the decryption key
                    decryptionKey = self.passwordUtils.generateKey(masterKey)
                    # Decrypting passwords using the decrypting key
                    self.vCloudDirectorPassword = self.passwordUtils.decrypt(decryptionKey, vCloudDirectorPassword.encode())
                    self.nsxtPassword = self.passwordUtils.decrypt(decryptionKey, nsxtPassword.encode())
                    self.vcenterPassword = self.passwordUtils.decrypt(decryptionKey, vcenterPassword.encode())
                else:
                    self.consoleLogger.error("Incorrect password file path")
                    os._exit(0)
            # if password file path id not provided
            else:
                if self.loginErrorDict[self._loginToVcd.__name__] is False:
                    self._getVcloudDirectorPassword()
                if self.loginErrorDict[self._loginToNsxt.__name__] is False:
                    self._getNsxtPassword()
                if self.loginErrorDict[self._loginToVcenter.__name__] is False:
                    self._getVcenterPassword()
        except:
            raise

    def inputValidation(self):
        """
        Description - Validation of user input values and convert nested user spec dict to simple dict
        """
        errorInputDict = dict()
        newInputDict = dict()
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
                                    errorInputDict[
                                        dictKey] = "Input IP/FQDN value is empty or has more than 255 characters"
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
                        inputKey = ''
                        if componentKey == 'Common':
                            inputKey = componentName + item.capitalize()
                            newInputDict[inputKey] = value
                        elif componentKey == 'NSXVProviderVDC':
                            if item == 'ProviderVDCName':
                                inputKey = 'NSXV' + item
                                newInputDict[inputKey] = value
                            else:
                                inputKey = componentKey + item
                                newInputDict[inputKey] = value
                        elif componentKey == 'NSXTProviderVDC':
                            if item == 'ProviderVDCName':
                                inputKey = 'NSXT' + item
                                newInputDict[inputKey] = value
                            else:
                                inputKey = componentKey + item
                                newInputDict[inputKey] = value
                        else:
                            newInputDict[item] = value
                if isinstance(componentValue, type(None)):
                    # do not check for certificate validation here it should be checked based on verify parameter
                    if componentKey != 'CertificatePath':
                        errorInputDict[componentKey] = 'Value must be provided for key - {}'.format(componentKey)
                if isinstance(componentValue, str):
                    if not componentValue:
                        errorInputDict[componentKey] = 'Please enter proper Value for key - {}'.format(componentKey)
                if not isinstance(componentValue, dict):
                    newInputDict[componentKey] = componentValue
        if bool(errorInputDict):
            raise Exception('Input Validation Error - {}'.format(errorInputDict))
        self.inputDict = newInputDict

        # converting user spec to tuple
        self.inputDict = namedtuple('InputDict', self.inputDict.keys())(**self.inputDict)

        # Validating thread count in user input yaml file
        try:
            self.threadCount = self.inputDict.MaxThreadCount
        except AttributeError:
            self.threadCount = None

        # Validating timeout for vapp migration task
        try:
            self.timeoutForVappMigration = int(self.inputDict.TimeoutForVappMigration)
        except (AttributeError, ValueError):
            # Setting default value for vapp migration i.e. 3600 seconds if not provided in user input file
            self.timeoutForVappMigration = 3600

    def _loginToVcd(self):
        """
        Description :   Login to VMware Cloud Director
        """
        self.consoleLogger.info('Login into the VMware Cloud Director - {}'.format(self.vcdObj.ipAddress))
        try:
            self.vcdValidationObj.password = self.vCloudDirectorPassword
            self.vcdObj.password = self.vCloudDirectorPassword
            self.vcdObj.vcdLogin()
            self.loginErrorDict[self._loginToVcd.__name__] = True
        except Exception as err:
            logging.error(str(err))
            if re.search(r'Failed to login .* with the given credentials', str(err)):
                self.loginErrorDict[self._loginToVcd.__name__] = False
            else:
                raise

    def _loginToNsxt(self):
        """
        Description :   Login to VMware NSX-T
        """
        self.consoleLogger.info('Login into the NSX-T - {}'.format(self.nsxtObj.ipAddress))
        try:
            self.nsxtObj.password = self.nsxtPassword
            self.nsxtObj.getComputeManagers()
            self.loginErrorDict[self._loginToNsxt.__name__] = True
        except Exception as err:
            logging.error(str(err))
            if re.search(r'Failed to login .* with the given credentials', str(err)):
                self.loginErrorDict[self._loginToNsxt.__name__] = False
            else:
                raise

    def _loginToVcenter(self):
        """
        Description :   Login to vCenter
        Parameters  :   vcenterObj   -   Object of vcenter operations class (object)
                        ipAdress     -   IP of  vCenter (STRING)
        """
        self.consoleLogger.info('Login into the vCenter - {}'.format(self.vcenterObj.ipAddress))
        try:
            self.vcenterObj.password = self.vcenterPassword
            self.vcenterObj.getTimezone()
            self.loginErrorDict[self._loginToVcenter.__name__] = True
        except Exception as err:
            logging.error(str(err))
            if re.search(r'Failed to login .* with the given credentials', str(err)):
                self.loginErrorDict[self._loginToVcenter.__name__] = False
            else:
                raise

    def loginToAllComponents(self):
        """
        Description : This method login to 3 VMware components i.e VMware vCloud Director, NSX and vCenter server
        """
        try:
            # login to the vmware cloud director for getting the bearer token
            if self.loginErrorDict[self._loginToVcd.__name__] is False:
                self._loginToVcd()
            # login to the nsx-t
            if self.loginErrorDict[self._loginToNsxt.__name__] is False:
                self._loginToNsxt()
            # login to vcenter
            if self.loginErrorDict[self._loginToVcenter.__name__] is False:
                self._loginToVcenter()
        except Exception:
            raise

    def validateLogin(self):
        """
        Description : Validate for any login related errors
        """
        try:
            # Retry login if password read from file are incorrect
            # If login has failed and password file is provided
            if False in self.loginErrorDict.values() and self.passFile:
                self.consoleLogger.error('Unable to proceed due to incorrect credentials in password File')
                tempPassPath = self.passFile
                self.passFile = None
                self._getPasswordFromUser()
                self.loginToAllComponents()
                self.passFile = tempPassPath
                self._encryptAndSavePasswords()
                if False in self.loginErrorDict.values():
                    self.consoleLogger.error(
                        'Unable to proceed due to incorrect credentials. Please enter valid credentials')
                    os._exit(0)
            # If login has failed and password file is not provided
            elif False in self.loginErrorDict.values() and not self.passFile:
                self.consoleLogger.error(
                    'Unable to proceed due to incorrect credentials. Please enter valid credentials')
                os._exit(0)
            else:
                if not self.passFile:
                    self._encryptAndSavePasswords()
                    self.consoleLogger.info(
                        'Password file is saved at location: {}'.format(os.path.join(os.path.dirname(os.path.abspath('passFile')), 'passFile')))
        except Exception:
            raise

    def fetchMetadataFromOrgVDC(self):
        """
            Description: Fetching metadata from source Org VDC and performing all metadata related operations
        """
        # Fetching source Org VDC Id
        orgUrl = self.vcdObj.getOrgUrl(self.inputDict.OrgName)
        self.sourceOrgVDCId = self.vcdObj.getOrgVDCDetails(orgUrl, self.inputDict.OrgVDCName, 'sourceOrgVDC')

        # Fetching metadata from source orgVDC
        metadata = self.vcdObj.getOrgVDCMetadata(self.sourceOrgVDCId, domain='system')

        self.rollback.metadata = copy.deepcopy(metadata)

        # Fetching apiData from metadata and send apiData to every class
        if metadata:
            self.rollback.apiData.update(self.vcdObj.getOrgVDCMetadata(self.sourceOrgVDCId, domain='general'))

        # Fetching rollback key from metadata
        if metadata.get('rollbackKey'):
            self.rollback.key = metadata.get('rollbackKey')

        # Performing rollback if rollback parameter is provided
        if self.retryRollback:
            if self.rollback.key:
                self.rollback.perform(self.vcdObj, self.vcdValidationObj, self.nsxtObj,
                                      rollbackTasks=metadata.get('rollbackTasks'))
            else:
                self.consoleLogger.warning("No rollback task exist, exiting the migration tool execution.")
                raise KeyboardInterrupt

        return metadata

    def run(self):
        """
        Description : This method runs the migration process of VMware Cloud Director from V2T
        """
        try:
            if not os.path.exists(self.userInputFilePath):
                raise Exception("User Input File: '{}' does not Exist".format(self.userInputFilePath))

            # read release version
            self.releaseVersion()

            # password prompt from user
            self._getPasswordFromUser()

            # reading the input yaml file
            with open(self.userInputFilePath) as f:
                self.inputDict = yaml.safe_load(f)

            # updating the password in the input dict
            self.inputDict['VCloudDirector']['Common']['password'] = self.vCloudDirectorPassword
            self.inputDict['NSXT']['Common']['password'] = self.nsxtPassword
            self.inputDict['Vcenter']['Common']['password'] = self.vcenterPassword

            # validating user input
            self.inputValidation()

            # Saving vcdDict in Rollback class
            self.rollback.vcdDict = self.inputDict

            # if verify is set to True on any one component then we have to update certificates in requests
            if self.inputDict.VCloudDirectorVerify or self.inputDict.NSXTVerify or self.inputDict.VcenterVerify:
                certPath = self.inputDict.CertificatePath
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

            # initializing vmware cloud director pre migration validation class
            self.vcdValidationObj = VCDMigrationValidation(self.inputDict.VCloudDirectorIpaddress, self.inputDict.VCloudDirectorUsername,
                                                           self.inputDict.VCloudDirectorPassword, self.inputDict.VCloudDirectorVerify,
                                                           self.rollback, self.threadCount)
            # initializing vmware cloud director Operations class
            self.vcdObj = VCloudDirectorOperations(self.inputDict.VCloudDirectorIpaddress, self.inputDict.VCloudDirectorUsername,
                                                   self.inputDict.VCloudDirectorPassword, self.inputDict.VCloudDirectorVerify,
                                                   self.rollback, self.threadCount)

            # preparing the nsxt dict for bridging
            self.nsxtObj = NSXTOperations(self.inputDict.NSXTIpaddress, self.inputDict.NSXTUsername,
                                          self.inputDict.NSXTPassword, self.rollback, self.vcdObj, self.inputDict.NSXTVerify)

            # initializing vcenter Api class
            self.vcenterObj = VcenterApi(self.inputDict.VcenterIpaddress, self.inputDict.VcenterUsername,
                                         self.inputDict.VcenterPassword, self.inputDict.VcenterVerify)

            # Initiate login
            self.loginToAllComponents()

            # validate login
            self.validateLogin()

            # Running cleanup script if cleanup parameter is provided
            if self.cleanup:
                self.CLEAN_UP_SCRIPT_RUN = True
                VMwareCloudDirectorNSXMigratorCleanup(self.inputDict, self.vcdObj, self.nsxtObj).run()
                os._exit(0)

            # Running migration script in assessment Mode
            if self.assessmentMode:
                assessmentModeObj = VMwareCloudDirectorNSXMigratorAssessmentMode\
                    (self.inputDict, self.vcdValidationObj, self.nsxtObj)
                assessmentModeObj.run()
                assessmentModeObj.updateInventoryLogs()
                os._exit(0)

            if not self.retryRollback:
                self.consoleLogger.info('Started migration of NSX-V backed Org VDC to NSX-T backed.')

            # Fetching metadata and performing all metadata related operation required for migration
            metadata = self.fetchMetadataFromOrgVDC()

            # Performing premigration validations
            self.vcdObj.preMigrationValidation(self.inputDict, self.sourceOrgVDCId, self.nsxtObj)

            # writing the promiscuous mode and forged mode details to apiData dict
            self.vcdObj.getPromiscModeForgedTransmit(self.sourceOrgVDCId)

            # Preparing Target VDC
            self.vcdObj.prepareTargetVDC(self.sourceOrgVDCId)

            # Getting source org vdc network list
            orgVdcNetworkList = self.vcdObj.retrieveNetworkListFromMetadata(self.sourceOrgVDCId, orgVDCType='source')
            # only if org vdc networks exist bridging will be configured
            if orgVdcNetworkList:
                # Fetching target VDC Id
                targetOrgVdcId = self.rollback.apiData['targetOrgVDC']['@id']
                # Getting target org vdc network list
                targetOrgVdcNetworkList = self.vcdObj.retrieveNetworkListFromMetadata(targetOrgVdcId, orgVDCType='target')

                # Configuring Bridging
                self.nsxtObj.configureNSXTBridging(self.inputDict.EdgeClusterName, self.inputDict.TransportZoneName,
                                                   targetOrgVdcNetworkList)

                # verify bridge connectivity
                self.nsxtObj.verifyBridgeConnectivity(self.vcdObj, self.vcenterObj)
            else:
                self.consoleLogger.warning('Skipping the NSXT Bridging configuration and verifying connectivity check as no source Org VDC network exist')

            # Configuring services
            self.vcdObj.configureServices(metadata)

            # configuring target vdc i.e reconnecting target vdc networks and edge gateway
            self.vcdObj.configureTargetVDC()

            try:
                self.vcdObj.migrateVapps(self.inputDict.OrgVDCName, metadata, self.timeoutForVappMigration)
            except:
                # We are not supporting rollback in case in vApp migration failure so exiting code here
                self.vcdObj.deleteSession()
                self.utils.clearRequestsPemCert()
                self.consoleLogger.critical(
                    "VCD V2T Migration Tool failed due to errors. For more details, please refer "
                    "main log file {}".format(self.mainLogfile))
                os._exit(0)

            # disabling target vdc only if source org vdc is disabled
            self.vcdObj.disableTargetOrgVDC()
            self.consoleLogger.info('Successfully migrated NSX-V backed Org VDC to NSX-T backed.')

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
        except KeyboardInterrupt:
            self.consoleLogger.error('Aborting the VCD NSX Migrator tool execution')
        except Exception as err:
            self.consoleLogger.exception(err)
            self.consoleLogger.critical("VCD V2T Migration Tool failed due to errors. For more details, please refer "
                                        "main log file {}".format(self.mainLogfile))
        finally:
            # logging out vcd user
            if self.vcdObj and self.vcdObj.VCD_SESSION_CREATED:
                self.vcdObj.deleteSession()
            # logging out the vcenter user
            if self.vcenterObj and self.vcenterObj.VCENTER_SESSION_CREATED:
                self.vcenterObj.deleteSession()
            # clear the requests certificates entries
            self.utils.clearRequestsPemCert()

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
