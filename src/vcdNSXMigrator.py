# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description: Module which is a run file that does the migration of VMware Cloud Director from NSX-V to NSX-T.
"""

import argparse
import colorlog
import copy
import getpass
import logging
import math
import os
import prettytable
import re
import requests
import signal
import sys
import threading
import traceback
import yaml
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

# Importing and Setting _MAXHEADERS = 500(to take care of APIs returning a lot of response headers)
import http.client
http.client._MAXHEADERS = 500

# Set path till src folder in PYTHONPATH
cwd = os.getcwd()
parentDir = os.path.abspath(os.path.join(cwd, os.pardir))
sys.path.append(parentDir)

import src.constants as mainConstants
import codecs

from src.commonUtils.threadUtils import Thread, waitForThreadToComplete
from src.rollback import Rollback
from src.commonUtils.logConf import Logger
from src.commonUtils.utils import Utilities
from src.commonUtils.passwordUtils import PasswordUtilities
from src.core.nsxt.nsxtOperations import NSXTOperations
from src.core.nsxv.nsxvOperations import NSXVOperations
from src.core.vcd import vcdConstants
from src.core.vcd.vcdOperations import VCloudDirectorOperations
from src.core.vcd.vcdValidations import VDCNotFoundError
from src.core.vcenter.vcenterApis import VcenterApi
from src.vcdNSXMigratorCleanup import VMwareCloudDirectorNSXMigratorCleanup
from src.vcdNSXMigratorAssessmentMode import VMwareCloudDirectorNSXMigratorAssessmentMode
from src.vcdNSXMigratorV2TAssessment import VMwareCloudDirectorNSXMigratorV2T


class VMwareCloudDirectorNSXMigrator():
    """
    Description: VMware Cloud Directory class that migrates the it from NSX-V to NSX-T
    """
    CLEAN_UP_SCRIPT_RUN = False

    def __init__(self):
        """
        Description : This method initializes the basic logging configuration ans migration related stuff
        """
        # Dict to store org vdc data
        self.orgVDCData = dict()
        self.passwordUtils = PasswordUtilities()
        self.utils = Utilities()
        self.executionMode = None
        self.cleanup = None
        self.assessmentMode = None
        self.v2tAssessment = None
        self.userInputFilePath = None
        # List of workflows to execute
        self.executeList = mainConstants.VALID_EXECUTE_VALUES
        # List of workflows to skip
        skipList = list()
        self.buildVersion = None
        self.numberOfParallelMigrations = 0
        self.loginErrorDict = {
            self._loginToVcd.__name__: False,
            self._loginToNsxt.__name__: False,
            self._loginToVcenter.__name__: False,
            self._loginToNsxv.__name__: False,

        }
        self.defaultPassFileName = 'passfile'

        parser = argparse.ArgumentParser(description='Arguments supported by V2T migration tool\n\nNOTE: v2tAssessment mode does not take password file as parameter.', formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument("--filepath", dest='filePath',
                            help="Path of the userInput spec file to run VMware VCD NSX Migrator/Cleanup workflow (REQUIRED ARGUMENT)")
        parser.add_argument("--cleanup", dest="cleanupValue", action="store_const",
                            help='Cleanup workflow (OPTIONAL ARGUMENT)',
                            const=True, default=False, required=False)
        parser.add_argument("--preCheck", dest='preCheck', help='PreCheck workflow (OPTIONAL ARGUMENT)',
                            action="store_true", default=False, required=False)
        parser.add_argument("--passwordFile", dest="passwordFilePath",
                            help="Run migration tool with generated password File", required=False)
        parser.add_argument("--rollback", dest='rollback', help='retry rollback (OPTIONAL ARGUMENT)',
                            action="store_true", default=False, required=False)
        parser.add_argument("--v2tAssessment", dest="v2tAssessment", help='run v2tAssessment mode(OPTIONAL ARGUMENT)',
                            action="store_true", default=False, required=False)
        parser.add_argument("-s", "--skip", dest="skip", default=False, nargs="?",
                            help=f"Comma separated values of steps to SKIP while running migration/precheck. Allowed values - [{', '.join(mainConstants.VALID_SKIP_VALUES)}] (OPTIONAL ARGUMENT)", required=False)
        parser.add_argument("-e", "--execute", dest="execute", default=False, nargs="?",
                            help=f"Comma separated values of steps to EXECUTE while running migration/precheck. Allowed values - [{', '.join(mainConstants.VALID_EXECUTE_VALUES)}] (OPTIONAL ARGUMENT)", required=False)

        args = parser.parse_args()
        # Set the execution mode flag based in the input arguments passed
        if args.cleanupValue:
            self.cleanup = args.cleanupValue
            self.executionMode = 'cleanup'
        elif args.preCheck:
            self.executionMode = 'preCheck'
            self.assessmentMode = args.preCheck
        elif args.v2tAssessment:
            self.executionMode = 'v2tAssessment'
            self.v2tAssessment = args.v2tAssessment
        else:
            self.executionMode = 'Main'

        # Set skip or execute parameters on based of input arguments
        if args.execute is None:
            parser.print_help()
            raise Exception(
                "No values provided with execute parameter, atleast one should be provided. Allowed values are 'topology', 'bridging', 'services', 'movevapp'.")

        if args.skip:
            skipList = list(map(lambda value: value.lower().strip(), args.skip.split(',')))
        elif args.execute:
            self.executeList = list(map(lambda value: value.lower().strip(), args.execute.split(',')))

        if args.filePath:
            self.userInputFilePath = args.filePath
        # if retry argument is provided then previously saved password will be used
        self.passFile = args.passwordFilePath
        # if rollback argument is provided then rollback is retried from its last failed state
        self.retryRollback = args.rollback

        self.renderInputFile()

        # Initialize logger object with the migrator execution mode
        self.loggerObj = Logger(self.executionMode, self.inputDict)
        self.consoleLogger = logging.getLogger("consoleLogger")
        self.mainLogfile = logging.getLogger('mainLogger').handlers[0].baseFilename

        # Check if no arguments are passed
        if not any(args.__dict__.values()):
            # If no args are provided show only help
            parser.print_help()
            os._exit(0)
        # Check if invalid arguments are passed
        if (not args.cleanupValue and not args.filePath) or \
            (not args.filePath and args.cleanupValue) or \
            (args.cleanupValue and args.preCheck) or \
            (not args.filePath and args.preCheck) or \
            (args.cleanupValue and args.rollback) or \
            (args.preCheck and args.rollback) or \
            (args.cleanupValue and args.v2tAssessment) or \
            (args.v2tAssessment and not args.filePath) or \
            (args.preCheck and args.v2tAssessment) or \
            (args.skip and args.execute) or \
            (args.v2tAssessment and (args.cleanupValue or args.preCheck or args.rollback)) or \
            (args.v2tAssessment and (args.skip or args.execute)) or \
            (args.cleanupValue and (args.skip or args.execute)) or \
            (args.rollback and (args.skip or args.execute)):
            parser.print_help()
            raise Exception("Invalid Input Arguments")

        if skipList and [value for value in skipList if value not in mainConstants.VALID_SKIP_VALUES]:
            raise Exception(f"Invalid Value Provided for --skip parameter. Allowed Values - {mainConstants.VALID_SKIP_VALUES}")
        if self.executeList and [value for value in self.executeList if value not in mainConstants.VALID_EXECUTE_VALUES]:
            raise Exception(f"Invalid Value Provided for --execute parameter. Allowed Values - {mainConstants.VALID_EXECUTE_VALUES}")

        # Finalizing the workflows to execute from input params
        self.executeList = list(set(self.executeList)-(set(skipList)))

        # handling the CTRL+C  i.e keyboard interrupt
        signal.signal(signal.SIGINT, self.signalHandler)

    def releaseVersion(self):
        """
        Description : Read and write migration tool release version
        """
        # reading the release yaml file
        releaseFile = os.path.join(mainConstants.rootDir, "release.yml")
        with open(releaseFile) as f:
            releaseData = yaml.safe_load(f)
        self.buildVersion = releaseData['Build']
        self.consoleLogger.info("Build Version: {}".format(releaseData['Build']))
        self.consoleLogger.info("Release Date: {}".format(releaseData['ReleaseDate']))

    def _getVcloudDirectorPassword(self):
        """
        Description :   getting VMware Cloud Director password from user
        """
        self.vCloudDirectorPassword = getpass.getpass(prompt="Please enter VMware Cloud Director Password: ")
        if not self.vCloudDirectorPassword:
            raise ValueError("VMware Cloud Director password must be provided")

    def _getNsxvPassword(self):
        """
        Description :   getting NSX-V password from user
        """
        # Getting NSX-V password if NSXV details are provided in userInput
        if (isinstance(self.inputDict, dict) and self.inputDict.get('NSXV', {}).get('Common', {}).get('ipAddress', None) and \
                self.inputDict.get('NSXV', {}).get('Common', {}).get('username', None)) or \
                (getattr(self.inputDict, 'NSXVUsername', None) and getattr(self.inputDict, 'NSXVIpaddress', None)):
            self.nsxvPassword = getpass.getpass(prompt="Please enter NSX-V Password: ")
            if not self.nsxtPassword:
                raise ValueError("NSX-V password must be provided")
        else:
            self.nsxvPassword = str()

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
        passList.append(self.passwordUtils.encrpyt(encryptionKey, self.nsxvPassword).decode())
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
                    masterKey, vCloudDirectorPassword, nsxtPassword, vcenterPassword, nsxvPassword = self.passwordUtils.readPassFile(self.passFile)
                    # generating the decryption key
                    decryptionKey = self.passwordUtils.generateKey(masterKey)
                    # Decrypting passwords using the decrypting key
                    self.vCloudDirectorPassword = self.passwordUtils.decrypt(decryptionKey, vCloudDirectorPassword.encode())
                    self.nsxtPassword = self.passwordUtils.decrypt(decryptionKey, nsxtPassword.encode())
                    self.vcenterPassword = self.passwordUtils.decrypt(decryptionKey, vcenterPassword.encode())
                    self.nsxvPassword = self.passwordUtils.decrypt(decryptionKey, nsxvPassword.encode())
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
                if self.loginErrorDict[self._loginToNsxv.__name__] is False:
                    self._getNsxvPassword()
        except:
            raise

    def inputValidation(self):
        """
        Description - Validation of user input values and convert nested user spec dict to simple dict
        """
        errorInputDict = dict()

        # Level 1: VCloudDirector, NSXT, NSXV, Vcenter
        for componentName, componentValues in self.inputDict.items():
            # Level 2: Common, Organization, SourceOrgVDC
            for componentKey, componentValue in componentValues.items():
                if isinstance(componentValue, dict):
                    # Level 3: ipAddress, username, verify, OrgName
                    for item, value in componentValue.items():
                        dictKey = "{}['{}']['{}']".format(componentName, componentKey, item)
                        if not value and not isinstance(value, bool):
                            errorInputDict[dictKey] = "Value must be provided."
                        # validate verify key value is boolean or not
                        if item == 'verify' and not isinstance(value, bool):
                            errorInputDict[dictKey] = "Value must be boolean i.e either True or False."
                        # validate ip address or fqdn
                        if item == 'ipAddress':
                            isFqdn = not all(host.isdigit() for host in str(value).split("."))
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
                if isinstance(componentValue, type(None)):
                    # do not check for certificate validation here it should be checked based on verify parameter
                    if componentKey not in ['CertificatePath', 'ServiceEngineGroupName']:
                        errorInputDict[componentKey] = 'Value must be provided for key - {}'.format(componentKey)
                if isinstance(componentValue, str):
                    if not componentValue:
                        errorInputDict[componentKey] = 'Please enter proper Value for key - {}'.format(componentKey)
                if isinstance(componentValue, list):
                    if componentKey == 'SourceOrgVDC':
                        for idx, sourceOrgVdc in enumerate(componentValue):
                            dictKey = "{}['{}'][{}]".format(componentName, componentKey, idx)
                            if sourceOrgVdc.get('LegacyDirectNetwork') and not isinstance(
                                    sourceOrgVdc.get('LegacyDirectNetwork'), bool):
                                errorInputDict[dictKey] = "Value must be boolean i.e either True or False."

        if not isinstance(self.inputDict['VCloudDirector'].get('SourceOrgVDC'), list):
            errorInputDict["VCloudDirector['SourceOrgVDC']"] = 'Value should be list'

        if bool(errorInputDict):
            raise Exception('Input Validation Error - {}'.format(errorInputDict))
        if 'EdgeClusterName' not in self.inputDict["NSXT"]:
            self.inputDict["NSXT"]["EdgeClusterName"] = []

        # Validating thread count in user input yaml file
        try:
            self.threadCount = int(self.inputDict['Common']['MaxThreadCount'])
        except (AttributeError, ValueError):
            self.threadCount = 75
        self.inputDict['Common']['MaxThreadCount'] = self.threadCount

        # Validating timeout for vApp migration task
        try:
            self.timeoutForVappMigration = int(self.inputDict['Common']['TimeoutForVappMigration'])
        except (AttributeError, ValueError):
            # Setting default value for vapp migration i.e. 3600 seconds if not provided in user input file
            self.timeoutForVappMigration = 3600
        self.inputDict['Common']['TimeoutForVappMigration'] = self.timeoutForVappMigration

    def _loginToVcd(self):
        """
        Description :   Login to VMware Cloud Director
        """
        self.consoleLogger.info('Login into the VMware Cloud Director - {}'.format(self.vcdObjList[0].ipAddress))
        try:
            for vcdObject in self.vcdObjList:
                vcdObject.password = self.vCloudDirectorPassword
                vcdObject.vcdLogin()
            self.loginErrorDict[self._loginToVcd.__name__] = True
        except Exception as err:
            logging.error(str(err))
            logging.debug(traceback.format_exc())
            if re.search(r'Failed to login .* with the given credentials', str(err)):
                self.loginErrorDict[self._loginToVcd.__name__] = False
            else:
                raise
        self.consoleLogger.info('VMware Cloud Director Version - {}'.format(self.vcdObjList[0].getVCDVersion()))

    def _loginToNsxv(self):
        """
        Description :  Login to VMware NSX-V
        """
        if self.inputDict.get("NSXV", {}).get("Common", {}).get("ipAddress", None) and self.inputDict.get("NSXV", {}).get("Common", {}).get("username", None):
            self.consoleLogger.info('Login into the NSX-V - {}'.format(self.inputDict.get("NSXV", {})["Common"]["ipAddress"]))
            try:
                self.nsxvObj.password = self.nsxvPassword
                self.nsxvObj.login()
                self.loginErrorDict[self._loginToNsxv.__name__] = True
            except Exception as err:
                logging.error(str(err))
                logging.debug(traceback.format_exc())
                if re.search(r'Failed to login .* with the given credentials', str(err)):
                    self.loginErrorDict[self._loginToNsxv.__name__] = False
                else:
                    raise
            self.consoleLogger.info('NSX-V Version - {}'.format(self.nsxvObj.getNsxvVersion()))
        else:
            self.loginErrorDict[self._loginToNsxv.__name__] = True

    def _loginToNsxt(self):
        """
        Description :   Login to VMware NSX-T
        """
        self.consoleLogger.info('Login into the NSX-T - {}'.format(self.nsxtObjList[0].ipAddress))
        try:
            for nsxtObj in self.nsxtObjList:
                nsxtObj.password = self.nsxtPassword
                nsxtObj.getComputeManagers()
                nsxtObj.getNsxtAPIVersion()
            self.loginErrorDict[self._loginToNsxt.__name__] = True
        except Exception as err:
            logging.error(str(err))
            logging.debug(traceback.format_exc())
            if re.search(r'Failed to login .* with the given credentials', str(err)):
                self.loginErrorDict[self._loginToNsxt.__name__] = False
            else:
                raise
        self.consoleLogger.info('NSX-T Version - {}'.format(nsxtObj.getNsxtVersion()))

    def _loginToVcenter(self):
        """
        Description :   Login to vCenter
        Parameters  :   vcenterObj   -   Object of vcenter operations class (object)
                        ipAddress     -   IP of  vCenter (STRING)
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
            # login to the vcenter
            if self.loginErrorDict[self._loginToVcenter.__name__] is False:
                self._loginToVcenter()
            # login to the nsx-v
            if self.loginErrorDict[self._loginToNsxv.__name__] is False:
                self._loginToNsxv()
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
                    self.consoleLogger.warning(
                        'Password file is saved at location: {}'.format(os.path.join(os.path.dirname(os.path.abspath('passFile')), 'passfile')))
        except Exception:
            raise

    def runRollback(self):
        """
        Description : Perform rollback if rollback parameter is provided
        """
        try:
            if self.retryRollback and any([vcdObj.rollback.metadata for vcdObj in self.vcdObjList]):
                self.consoleLogger.info("Performing rollback")

            if self.retryRollback:
                # Rollback: Copying direct network IP's from NSX-T segment backed external network to source external network
                futures = list()
                with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                    for vcdObj in self.vcdObjList:
                        if vcdObj.rollback.metadata:
                            futures.append(executor.submit(vcdObj.copyIPToSegmentBackedExtNet, rollback=True))
                    waitForThreadToComplete(futures)

                # Adding segment to the exclusion list
                for vcdObject in self.vcdObjList:
                    self.nsxtObjList[0].addGroupToExclusionlist(vcdObject)

                # if vApp migration was performed do rollback
                self.vcdObjList[0].vappRollback(
                    self.vcdObjList, self.inputDict, self.timeoutForVappMigration, threadCount=self.threadCount)
                self.vcdObjList[0].moveNamedDisksRollback(
                    self.vcdObjList, self.timeoutForVappMigration, threadCount=self.threadCount)

                # Perform prerollback tasks
                futures = list()
                with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                    for vcdObj, nsxtObj in zip(self.vcdObjList, self.nsxtObjList):
                        if vcdObj.rollback.metadata:
                            futures.append(executor.submit(vcdObj.rollback.perform, vcdObj, nsxtObj, self.vcdObjList,
                                                           rollbackTasks=vcdObj.rollback.metadata.get(
                                                               'preRollbackTasks'), preRollback=True))
                    waitForThreadToComplete(futures)

                # If bridging is configured do rollback
                self.nsxtObjList[0].rollbackBridging(self.vcdObjList)
                self.nsxtObjList[0].deleteTransportZone(self.vcdObjList[0], rollback=True)

                # untag the used nodes in bridging if remaining
                if self.vcdObjList[0].rollback.apiData.get('taggedNodesList'):
                    self.nsxtObjList[0].untagEdgeTransportNodes(
                            self.vcdObjList, self.inputDict, self.vcdObjList[0].rollback.apiData.get('taggedNodesList'))

                # Removing Segment from Exclusion List
                for vcdObject in self.vcdObjList:
                    self.nsxtObjList[0].removeGroupFromExclusionlist(vcdObject)

                # Rollback dfw/firewall rules
                futures = list()
                with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                    for vcdObj in self.vcdObjList:
                        if vcdObj.rollback.metadata:
                            futures.append(executor.submit(vcdObj.dfwRulesRollback))
                            futures.append(executor.submit(vcdObj.firewallruleRollback))
                    waitForThreadToComplete(futures)

                futures = list()
                with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                    for vcdObj in self.vcdObjList:
                        if vcdObj.rollback.metadata:
                            futures.append(executor.submit(vcdObj.rollback.performDfwRollback, vcdObj))
                    waitForThreadToComplete(futures)

                # Perform other rollback tasks
                futures = list()
                with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                    for vcdObj, nsxtObj in zip(self.vcdObjList, self.nsxtObjList):
                        if vcdObj.rollback.metadata:
                            futures.append(executor.submit(vcdObj.rollback.perform, vcdObj, nsxtObj,self.vcdObjList,
                                                           rollbackTasks=vcdObj.rollback.metadata.get('rollbackTasks')))
                        else:
                            self.consoleLogger.warning(f"No rollback task exist for org vdc {vcdObj.orgVdcInput['OrgVDCName']}.")
                            continue
                    waitForThreadToComplete(futures)
            if self.retryRollback and not any([vcdObj.rollback.metadata for vcdObj in self.vcdObjList]):
                raise KeyboardInterrupt
            if self.retryRollback:
                for vcdObj in self.vcdObjList:
                    # logging out vcd user
                    vcdObj.deleteSession()
                    # clear the requests certificates entries
                self.utils.clearRequestsPemCert()
                # Removing empty end state log file if exists during rollback.
                if logging.getLogger("endstateLogger").handlers:
                    filePath = logging.getLogger("endstateLogger").handlers[0].baseFilename
                    logging.getLogger("endstateLogger").handlers[0].close()
                    if os.stat(filePath).st_size == 0:
                        os.remove(filePath)
                os._exit(0)
        except:
            raise

    def fetchMetadataFromOrgVDC(self, vcdObj):
        """
            Description: Fetching metadata from source Org VDC and performing all metadata related operations
        """
        try:
            # Setting thread name same as the org vdc name
            threading.current_thread().name = vcdObj.orgVdcInput["OrgVDCName"]
            self.consoleLogger.info(f"Fetching metadata for org vdc '{vcdObj.orgVdcInput['OrgVDCName']}'")

            # Creating key of org vdc name to store data
            if vcdObj.orgVdcInput["OrgVDCName"] not in self.orgVDCData:
                self.orgVDCData[vcdObj.orgVdcInput["OrgVDCName"]] = dict()

            # Fetching source Org VDC Id
            orgUrl = vcdObj.getOrgUrl(self.inputDict["VCloudDirector"]["Organization"]["OrgName"])

            # Fetching target org vdc id for metadata
            if self.cleanup:
                # Fetch target ord vdc id in case of cleanup
                try:
                    # During cleanup before removing '-v2t' suffix from target org vdc name(Ord VDC name will be -v2t suffixed)
                    orgVDCId = vcdObj.getOrgVDCDetails(orgUrl, vcdObj.orgVdcInput["OrgVDCName"] + '-v2t', 'targetOrgVDC', saveResponse=False)
                except VDCNotFoundError:
                    # During cleanup after removing '-v2t' suffix from target org vdc name(Ord VDC name will not be -v2t suffixed)
                    orgVDCId = vcdObj.getOrgVDCDetails(orgUrl, vcdObj.orgVdcInput["OrgVDCName"], 'targetOrgVDC', saveResponse=False)
            else:
                # Fetch source ord vdc id in case of precheck, migration and rollback
                orgVDCId = vcdObj.getOrgVDCDetails(orgUrl, vcdObj.orgVdcInput["OrgVDCName"], 'sourceOrgVDC')

            self.orgVDCData[vcdObj.orgVdcInput["OrgVDCName"]]["id"] = orgVDCId

            # Fetching metadata from source orgVDC
            metadata = vcdObj.getOrgVDCMetadata(orgVDCId, domain='system')

            # self.orgVDCData[vcdObj.orgVdcInput["OrgVDCName"]]["metadata"] = metadata

            vcdObj.rollback.metadata = copy.deepcopy(metadata)

            # Fetching apiData from metadata and send apiData to every class
            if metadata:
                vcdObj.rollback.apiData.update(vcdObj.getOrgVDCMetadata(orgVDCId, domain='general'))
        except:
            self.consoleLogger.error(traceback.format_exc())
            raise

    def skipWorkflowsTable(self):
        """
        Description: This method logs the table for the info and details of workflows that will be skipped
        """
        try:
            # Execution mode should only be precheck or migration
            if (self.executionMode != "preCheck" and self.executionMode != 'Main') or self.retryRollback:
                return

            table = prettytable.PrettyTable(hrules=prettytable.ALL)

            # Adding data to table
            table.field_names = ["Keyword", "Description", "Value"]

            # Left align the data in the table
            table.align["Keyword"] = "l"
            table.align["Description"] = "l"

            # Iterating over the workflows to be skipped
            for workflow in mainConstants.VALID_EXECUTE_VALUES:
                if workflow not in self.executeList and workflow != mainConstants.REPLICATION_KEYWORD:
                    table.add_row([workflow, mainConstants.DESCRIPTION_OF_WORKFLOWS[workflow], "skipped"])
                else:
                    table.add_row([workflow, mainConstants.DESCRIPTION_OF_WORKFLOWS[workflow], "included"])

            # Adding title to table
            if self.assessmentMode:
                title = "Validation for phases included/excluded in V2T preCheck"
            else:
                title = "Phases included/excluded in V2T Migration"

            self.consoleLogger.warning(f"\n{title}\n{table.get_string()}")
        except:
            raise

    def renderInputFile(self):
        if not os.path.exists(self.userInputFilePath):
            raise Exception("User Input File: '{}' does not Exist".format(self.userInputFilePath))

        # reading the input yaml file
        with codecs.open(self.userInputFilePath, encoding = "utf_8") as f:
            self.inputDict = yaml.safe_load(f)
            # Render dict values as strings
            Utilities.renderInputDict(self.inputDict)

    def runV2tAssessment(self):
        V2TAssessmentModeObj = VMwareCloudDirectorNSXMigratorV2T(self.inputDict, buildVersion=self.buildVersion, passfile=self.passFile)
        self.consoleLogger.info('Starting V2T-Assessment mode for NSX-V migration to NSX-T')

        # Executing v2t-Assessment mode
        V2TAssessmentModeObj.run()
        # Creating csv report
        V2TAssessmentModeObj.createReport()

    def getPassword(self):
        # password prompt from user
        self._getPasswordFromUser()

        # updating the password in the input dict
        self.inputDict['VCloudDirector']['Common']['password'] = self.vCloudDirectorPassword
        self.inputDict['NSXT']['Common']['password'] = self.nsxtPassword
        self.inputDict['Vcenter']['Common']['password'] = self.vcenterPassword
        if self.inputDict.get("NSXV"):
            self.inputDict['NSXV']['Common']['password'] = self.nsxvPassword

    def certificateValidation(self):
        # if verify is false on any component then logging a message
        if not all([self.inputDict["VCloudDirector"]["Common"]["verify"], self.inputDict["NSXT"]["Common"]["verify"], self.inputDict["Vcenter"]["Common"]["verify"]]):
            componentsWithCertificateValidationDisabled = ['VMware vCloud Director' if not self.inputDict["VCloudDirector"]["Common"]["verify"] else str(),
                            'NSX-T' if not self.inputDict["NSXT"]["Common"]["verify"] else str(),
                            'vCenter' if not self.inputDict["Vcenter"]["Common"]["verify"] else str(),
                            'NSX-V' if self.inputDict.get("NSXV", {}).get("Common", {}).get("verify", {}) is False else str()]

            warningMessage = '\n'+'*'*100+'\n*'+(('Certificate validation disabled for - ' +
                             ', '.join([component for component in componentsWithCertificateValidationDisabled if component != str()]))
                             .center(98)+'*\n'+'*'*100)
            logging.warning(warningMessage)

        # if verify is set to True on any one component then we have to update certificates in requests
        if self.inputDict["VCloudDirector"]["Common"]["verify"] or self.inputDict["NSXT"]["Common"]["verify"] or self.inputDict["Vcenter"]["Common"]["verify"] or self.inputDict.get('NSXV', {}).get("Common", {}).get("verify", None):
            certPath = self.inputDict["Common"].get("CertificatePath")
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

    def initialization(self):
        # Initializing the list of objects that will hold all the vcd and nsxt objects
        self.vcdObjList, self.nsxtObjList = list(), list()

        # lock object common for all objects/classes
        lockObj = threading.RLock()

        # Fetching the number of parallel migrations
        self.numberOfParallelMigrations = len(self.inputDict["VCloudDirector"]["SourceOrgVDC"])

        # Calculating number of threads for each org vdc
        maxNumberOfThreads = 1 if not math.floor(self.threadCount / self.numberOfParallelMigrations) else math.floor(
            self.threadCount / self.numberOfParallelMigrations)

        # Iterating over the org vdcs provided in the user input and creating desired number of objects
        for index, orgVdcInput in enumerate(self.inputDict["VCloudDirector"]["SourceOrgVDC"]):
            # Initializing thread class with specified number of threads common for all objects
            threadObj = Thread(maxNumberOfThreads=maxNumberOfThreads)

            # Creating object of rollback class and initializing the class the variables
            rollback = Rollback(self.consoleLogger)
            rollback.retryRollback = self.retryRollback
            rollback.mainLogfile = self.mainLogfile
            rollback.vcdDict = self.inputDict
            rollback.timeoutForVappMigration = self.timeoutForVappMigration
            # initializing vmware cloud director Operations class
            self.vcdObjList.append(VCloudDirectorOperations(
                self.inputDict, None, rollback, threadObj, lockObj=lockObj, orgVdcInput=orgVdcInput,
            ))

            # preparing the nsxt dict for bridging
            self.nsxtObjList.append(NSXTOperations(self.inputDict["NSXT"]["Common"]["ipAddress"], self.inputDict["NSXT"]["Common"]["username"],
                                          self.inputDict["NSXT"]["Common"]["password"], rollback, self.vcdObjList[index], self.inputDict["NSXT"]["Common"]["verify"],
                                                   self.inputDict["NSXT"]["EdgeClusterName"]))

        # initializing nsxv operations class
        if self.inputDict.get("NSXV", None):
            self.nsxvObj = NSXVOperations(self.inputDict.get("NSXV", {})["Common"]["ipAddress"], self.inputDict.get("NSXV", {})["Common"]["username"],
                                      self.nsxvPassword, self.inputDict.get("NSXV", {})["Common"]["verify"])
        else:
            self.nsxvObj = NSXVOperations()

        # initializing vcenter Api class
        self.vcenterObj = VcenterApi(self.inputDict["Vcenter"]["Common"]["ipAddress"], self.inputDict["Vcenter"]["Common"]["username"],
                                     self.inputDict["Vcenter"]["Common"]["password"], self.inputDict["Vcenter"]["Common"]["verify"])

    def runPrecheck(self):
        assessmentModeObj = VMwareCloudDirectorNSXMigratorAssessmentMode \
            (self.inputDict, self.vcdObjList, self.nsxtObjList, self.nsxvObj, self.vcenterObj, self.executeList)
        assessmentModeObj.run()

    def runPreparation(self):
        # Warning table for workflows that will be skipped
        self.skipWorkflowsTable()
        if not self.retryRollback:
            self.consoleLogger.info(
                f'Started migration of NSX-V backed Org VDC to NSX-T backed for org vdc/s - "'
                f'{", ".join([vdc["OrgVDCName"] for vdc in self.inputDict["VCloudDirector"]["SourceOrgVDC"]])}"')

        # Fetching metadata and performing all metadata related operation required for migration
        futures = list()
        with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
            for vcdObj in self.vcdObjList:
                futures.append(executor.submit(self.fetchMetadataFromOrgVDC, vcdObj))
            waitForThreadToComplete(futures)

        futures = list()
        with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
            for vcdObj in self.vcdObjList:
                futures.append(executor.submit(
                    vcdObj.updateEdgeGatewayInputDict,
                    self.orgVDCData[vcdObj.orgVdcInput["OrgVDCName"]]["id"]
                ))
            waitForThreadToComplete(futures)

    def runCleanup(self):
        self.CLEAN_UP_SCRIPT_RUN = True
        passFilePath = self.passFile if self.passFile else self.defaultPassFileName

        cleanupObjectsList = [
            VMwareCloudDirectorNSXMigratorCleanup(orgVDCDict, self.inputDict, vcdObj, nsxtObj, passFilePath, self.timeoutForVappMigration
                                                  )
            for orgVDCDict, nsxtObj, vcdObj in zip(
                self.inputDict["VCloudDirector"]["SourceOrgVDC"], self.nsxtObjList, self.vcdObjList)
        ]

        # Spawning threads for org vdc cleanup
        futures = list()
        with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
            for cleanup in cleanupObjectsList:
                # Passing corresponding vcdobj, nsxtobj, orgvdcdict and inputdict to cleanup.
                futures.append(executor.submit(cleanup.checkTargetOrgVDCStatus))
            waitForThreadToComplete(futures)

        # Bridging cleanup
        VMwareCloudDirectorNSXMigratorCleanup(inputDict=self.inputDict).cleanupBridging(self.vcdObjList,
                                                                                        self.nsxtObjList[0])

        # Spawning threads for org vdc cleanup
        futures = list()
        with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
            for cleanup in cleanupObjectsList:
                futures.append(executor.submit(cleanup.run))
            waitForThreadToComplete(futures)

    def runPreMigrationValidation(self):
        # Perform premigration validations
        futures = list()
        with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
            for vcdObj, nsxtObj in zip(self.vcdObjList, self.nsxtObjList):
                futures.append(executor.submit(vcdObj.preMigrationValidation, self.inputDict,
                                               self.orgVDCData[vcdObj.orgVdcInput["OrgVDCName"]]["id"], nsxtObj,
                                               self.nsxvObj, self.vcdObjList,
                                               validateVapp=mainConstants.MOVEVAPP_KEYWORD in self.executeList,
                                               validateServices=mainConstants.SERVICES_KEYWORD in self.executeList))
            waitForThreadToComplete(futures)

        # Check if bridging is to be performed or not
        if mainConstants.BRIDGING_KEYWORD in self.executeList:
            # Getting source org vdc network list
            orgVdcNetworkList = list()
            for orgVDCId, vcdObj in zip([data["id"] for data in self.orgVDCData.values()], self.vcdObjList):
                orgVdcNetworkList += vcdObj.retrieveNetworkListFromMetadata(orgVDCId, orgVDCType='source')
            # filtering the org vdc list as direct networks do not need to be bridged
            filteredList = copy.deepcopy(orgVdcNetworkList)
            filteredList = list(filter(lambda network: network['networkType'] != 'DIRECT', filteredList))
            if filteredList:
                # Perform checks related to bridging
                orgVDCIDList = [data["id"] for data in self.orgVDCData.values()]
                self.vcdObjList[0].checkBridgingComponents(orgVDCIDList, self.inputDict, self.nsxtObjList[0],
                                                           self.vcenterObj, self.vcdObjList)

        # Perform check for sharedNetwork.
        self.vcdObjList[0].sharedNetworkChecks(self.inputDict, self.vcdObjList, self.orgVDCData)

    def runPrepareTarget(self):
        # Preparing Target VDC
        futures = list()
        with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
            for vcdObj, nsxtObj in zip(self.vcdObjList, self.nsxtObjList):
                futures.append(executor.submit(vcdObj.prepareTargetVDC, self.vcdObjList,
                                               self.orgVDCData[vcdObj.orgVdcInput["OrgVDCName"]]["id"],
                                               self.inputDict, nsxtObj, vcdObj.orgVdcInput["OrgVDCName"],
                                               self.vcenterObj,
                                               configureBridging=mainConstants.BRIDGING_KEYWORD in self.executeList,
                                               configureServices=mainConstants.SERVICES_KEYWORD in self.executeList)
                               )
            waitForThreadToComplete(futures)

    def runBridging(self):
        # Check if bridging is to be performed or not
        if mainConstants.BRIDGING_KEYWORD in self.executeList:
            orgVdcNetworkList = list()
            for orgVDCId, vcdObj in zip([data["id"] for data in self.orgVDCData.values()], self.vcdObjList):
                orgVdcNetworkList += vcdObj.retrieveNetworkListFromMetadata(orgVDCId, orgVDCType='source')
            # filtering the org vdc list as direct networks do not need to be bridged
            filteredList = copy.deepcopy(orgVdcNetworkList)
            filteredList = list(filter(lambda network: network['networkType'] != 'DIRECT', filteredList))

            # only if org vdc networks exist bridging will be configured
            if filteredList:
                # Configuring Bridging
                self.nsxtObjList[0].configureNSXTBridging(self.vcdObjList, self.vcenterObj)
                # verify bridge connectivity
                self.nsxtObjList[0].verifyBridgeConnectivity(self.vcdObjList, self.vcenterObj)
            elif orgVdcNetworkList:
                self.consoleLogger.warning('Skipping the NSXT Bridging configuration and connectivity verification check as the networks are type "Direct"')
            else:
                self.consoleLogger.warning('Skipping the NSXT Bridging configuration and connectivity verification check as no source Org VDC network exist')
        else:
            self.consoleLogger.warning('Skipping the NSXT Bridging configuration as per the input parameters provided')

    def runServices(self):
        # Check if services are to configured or not
        if mainConstants.SERVICES_KEYWORD in self.executeList:
            # Services configuration
            futures = list()
            with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                for vcdObj in self.vcdObjList:
                    # Configuring services
                    futures.append(executor.submit(vcdObj.configureServices, self.nsxvObj))
                waitForThreadToComplete(futures)

            # configuring target vdc i.e reconnecting target vdc networks and edge gateway
            futures = list()
            with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                for vcdObj in self.vcdObjList:
                    edgeGatewayDeploymentEdgeCluster = vcdObj.orgVdcInput.get('EdgeGatewayDeploymentEdgeCluster', None)
                    futures.append(executor.submit(vcdObj.configureTargetVDC, self.vcdObjList, edgeGatewayDeploymentEdgeCluster, self.nsxtObjList[0]))
                waitForThreadToComplete(futures)
        else:
            self.consoleLogger.warning(
                'Skipping the EdgeGateway Services configuration and Network Switchover as per the input parameters provided')

    def runWorkload(self):
        # Check if vApp migration is to be performed
        if mainConstants.MOVEVAPP_KEYWORD in self.executeList:
            # Save No of Source vApp to Metadata
            futures = list()
            with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                for vcdObj in self.vcdObjList:
                    futures.append(executor.submit(vcdObj.savevAppNoToMetadata))
                waitForThreadToComplete(futures)
            # Migrating IP/s from v-external network to NSX-T segment backed external network
            futures = list()
            with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                orgVDCIDList = [data["id"] for data in self.orgVDCData.values()]
                for vcdObj in self.vcdObjList:
                    futures.append(executor.submit(vcdObj.copyIPToSegmentBackedExtNet, orgVDCIDList=orgVDCIDList))
                waitForThreadToComplete(futures)

            # update network profile
            futures = list()
            with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                for vcdObj in self.vcdObjList:
                    edgeGatewayDeploymentEdgeCluster = vcdObj.orgVdcInput.get('EdgeGatewayDeploymentEdgeCluster', None)
                    sourceOrgVDCID = vcdObj.rollback.apiData['sourceOrgVDC']['@id']
                    targetOrgVDCID = vcdObj.rollback.apiData['targetOrgVDC']['@id']
                    futures.append(executor.submit(vcdObj.updateNetworkProfileOnTarget, sourceOrgVDCID,
                                                   targetOrgVDCID, edgeGatewayDeploymentEdgeCluster,
                                                   self.nsxtObjList[0]))
                waitForThreadToComplete(futures)

            # perform vApp Migration
            self.vcdObjList[0].migrateVapps(
                self.vcdObjList, self.inputDict, self.timeoutForVappMigration, threadCount=self.threadCount)
            self.vcdObjList[0].moveNamedDisks(
                self.vcdObjList, self.timeoutForVappMigration, threadCount=self.threadCount)

            # Enable target affinity rules
            futures = list()
            with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                for vcdObj in self.vcdObjList:
                    futures.append(executor.submit(vcdObj.enableTargetAffinityRules))
                waitForThreadToComplete(futures)

            # Removing IP/s from v-external network after vApp migration
            futures = list()
            with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
                for vcdObj in self.vcdObjList:
                    futures.append(executor.submit(vcdObj.directNetworkIpCleanup, source=True))
                waitForThreadToComplete(futures)
        else:
            self.consoleLogger.warning("Skipping vApp migration as the input parameters provided")

    def runPostMigrationSteps(self):
        # Copying source org vdc metadata to target org vdc
        futures = list()
        with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
            for vcdObj in self.vcdObjList:
                futures.append(executor.submit(vcdObj.copyMetadatatToTargetVDC))
            waitForThreadToComplete(futures)

        # Disabling target vdc only if source org vdc is disabled
        futures = list()
        with ThreadPoolExecutor(max_workers=self.numberOfParallelMigrations) as executor:
            for vcdObj in self.vcdObjList:
                futures.append(executor.submit(vcdObj.disableTargetOrgVDC))
            waitForThreadToComplete(futures)

        # Migration end state log.
        for vcdObj in self.vcdObjList:
            # Dump Migration end state log to file.
            vcdObj.dumpEndStateLog()

        self.consoleLogger.info(
            f'Successfully completed migration of NSX-V backed to NSX-T backed for Org VDC/s '
            f'{", ".join([vdc["OrgVDCName"] for vdc in self.inputDict["VCloudDirector"]["SourceOrgVDC"]])}.')

    def run(self):
        """
        Description : This method runs the migration process of VMware Cloud Director from V2T
        """
        try:
            # read release version
            self.releaseVersion()
            self.consoleLogger.warning("Log Filepath: {}".format(self.mainLogfile))

            # Execute v2tAssessment
            if self.v2tAssessment:
                self.runV2tAssessment()
                return

            self.getPassword()
            self.inputValidation()
            self.certificateValidation()
            self.initialization()
            self.loginToAllComponents()
            self.validateLogin()

            # Running migration script in assessment Mode
            if self.assessmentMode:
                self.runPrecheck()
                return

            self.runPreparation()

            # Perform rollback if rollback parameter is provided
            self.runRollback()

            # Running cleanup script if cleanup parameter is provided
            if self.cleanup:
                self.runCleanup()
                return

            self.runPreMigrationValidation()
            self.runPrepareTarget()
            self.runBridging()
            self.runServices()
            self.runWorkload()
            self.runPostMigrationSteps()

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
            logging.debug(traceback.format_exc())
            self.consoleLogger.exception(err)
            self.consoleLogger.critical("VCD V2T Migration Tool failed due to errors. For more details, please refer "
                                        "main log file {}".format(self.mainLogfile))
        finally:
            # Removing empty end state log file if exists.
            if logging.getLogger("endstateLogger").handlers:
                filePath = logging.getLogger("endstateLogger").handlers[0].baseFilename
                logging.getLogger("endstateLogger").handlers[0].close()
                if os.stat(filePath).st_size == 0:
                    os.remove(filePath)
            # logging out vcd user
            if getattr(self, 'vcdObjList', None):
                for vcdObject in self.vcdObjList:
                    vcdObject.deleteSession()
            # logging out the vcenter user
            if getattr(self, 'vcenterObj', None) and self.vcenterObj and self.vcenterObj.VCENTER_SESSION_CREATED:
                self.vcenterObj.deleteSession()
            # clear the requests certificates entries
            self.utils.clearRequestsPemCert()

    def signalHandler(self, sig, frame):
        """
        Description: Handling the Ctrl+C i.e abruptly closing the script
        """
        self.consoleLogger.warning('Aborting the VCD NSX Migrator tool execution due to keyboard interrupt.')
        try:
            # logging out vcd user
            if getattr(self, 'vcdObjList', None):
                for vcdObject in self.vcdObjList:
                    vcdObject.deleteSession()
            # logging out the vcenter user
            if getattr(self, 'vcenterObj', None) and self.vcenterObj and self.vcenterObj.VCENTER_SESSION_CREATED:
                self.vcenterObj.deleteSession()
            # clear the requests certificates entries
            self.utils.clearRequestsPemCert()
        except:
            pass
        os._exit(0)


if __name__ == '__main__':
    vcdMigrateObj = VMwareCloudDirectorNSXMigrator()
    vcdMigrateObj.run()
