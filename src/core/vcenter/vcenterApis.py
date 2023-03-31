# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description: Module which performs the vcenter API related Operations
"""

import atexit
import logging
import traceback

import pyVmomi
import requests
import ssl
from pyVmomi import vim, eam, VmomiSupport
from pyVim.connect import SmartConnect, Disconnect
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import src.core.vcenter.vcenterConstants as constants
from src.commonUtils.restClient import RestAPIClient

logger = logging.getLogger('mainLogger')


class VcenterApi():
    """
    Description : VCSAApis class provides methods to perform VCSA specific tasks
    """
    VCENTER_SESSION_CREATED = False

    def __init__(self, ipAddress, username, password, verify):
        """
        Description :   Initializer method of vcenter Operations
        Parameters  :   ipAddress   -   ipaddress of the vcenter (STRING)
                        username    -   Username of the vcenter (STRING)
                        password    -   Password of the vcenter (STRING)
                        verify      -   whether to verify the server's TLS certificate (BOOLEAN)
        """
        # Get VCSA Credentials from vcsaDict
        self.ipAddress = ipAddress
        self.username = username
        self.password = password
        self.verify = verify
        # Default header to be used for VCSA API calls
        self.headers = dict()
        self.headers.update({"Accept": constants.DEFAULT_ACCEPT_VALUE,
                             "Content-Type": constants.DEFAULT_ACCEPT_VALUE})
        self.headers.update({constants.SESSION_ID_KEY: ""})
        self._getRestClientObj()

    def _getRestClientObj(self):
        """
            Description :  Getting the rest client object
        """
        # Rest client API calls
        self.restClientObj = RestAPIClient(self.username, self.password, self.verify)

    def login(self):
        """
        Description : Method to log-in session for VCSA.
        Returns : sessionId - Session ID for the current VCSA session (STRING)
        """
        # Getting REST client object
        self._getRestClientObj()
        # URL for VCSA login
        url = constants.VCSA_LOGIN_API.format(hostname=self.ipAddress)
        response = self.restClientObj.get(url=url, headers=self.headers, auth=self.restClientObj.auth)
        if response.status_code == requests.codes.ok:
            # Check for session ID in response
            sessionId = response.json().get("value")
            if not sessionId:
                raise Exception("Failed to fetch vCenter Session ID ")
            self.VCENTER_SESSION_CREATED = True
            return sessionId
        raise Exception("Failed to login into Vcenter {} with the given credentials".format(self.ipAddress))

    def setSession(func):
        """
        Description : Decorator function that creates a login session for VCSA and sets the sessionId in headers
        Parameters : func - Function object which is decorated by setSession() (OBJECT)
        Returns : wrapperMethod - The decorated function object (OBJECT)
        """
        def wrapperMethod(self, *args, **kwargs):
            """
            Description : Decorator function
            """
            try:
                # get VCSA session ID
                sessionId = self.login()
                # set VCSA session ID
                self.headers[constants.SESSION_ID_KEY] = sessionId
                # execute the decorated function
                return func(self, *args, **kwargs)
            except Exception as e:
                raise e
        return wrapperMethod

    @setSession
    def getEdgeVmNetworkDetails(self, vmId):
        """
        Description : Method to get Edge Gateway VM network details
        Parameters : vmId - Edge Gateway VM ID (STRING)
        Returns : interfaceDetails - Edge Gateway VM network interfaces details (LIST)
        """
        try:
            # URL for getting VM details
            logger.debug('Getting interface details of Edge gateway')
            url = constants.VCSA_VM_DETAILS_API.format(hostname=self.ipAddress, id=vmId)
            response = self.restClientObj.get(url=url, headers=self.headers)
            if response.status_code == requests.codes.ok:
                # Get the VM NIC details
                nicDetails = response.json()[constants.VALUE_KEY][constants.NIC_DETAILS_KEY]
                # Convert the NIC details to List format if in Dict type
                # as for single NIC entries the details are in Dict format
                interfaceDetails = [nicDetails] if isinstance(nicDetails, dict) else nicDetails
                return interfaceDetails
            errorMessage = response.json()['value']['messages'][0]['default_message']
            raise Exception("Failed to fetch interface details for Edge VM Id - {}. Error - {}".format(vmId, errorMessage))
        except Exception:
            raise

    @setSession
    def getTimezone(self):
        """
        Description : Get vcenter timezone
        """
        # URL for getting timezone details
        logger.debug('Getting vcenter timezone')
        self._getRestClientObj()
        url = constants.VCSA_TIMEZONE_API.format(hostname=self.ipAddress)
        response = self.restClientObj.get(url=url, headers=self.headers)
        if response.status_code == requests.codes.ok:
            logger.debug('Successfully retrieved vcenter timezone')
        else:
            raise Exception("Failed to get vcenter timezone. Error - {}".format(response.json()['value']['messages'][0]['default_message']))

    def deleteSession(self):
        """
        Description :   Deletes the current VCSA session / log out the current VCSA user
        """
        try:
            logger.debug("Deleting the current user session of vcenter(Log out VCSA current user)")
            # url to delete the current user session of vcenter server
            url = constants.VCSA_DELETE_SESSION.format(hostname=self.ipAddress)
            # delete api call to delete the current user session of vcenter server
            response = self.restClientObj.delete(url=url, headers=self.headers, auth=(self.username, self.password))
            if response.status_code == requests.codes.ok:
                # successful log out of current vcenter user
                logger.debug("Successfully logged out vcenter user")
            elif response.status_code == requests.codes.unauthorized:
                logger.debug("vCenter user session already ended due to timeout")
            else:
                # failure in current vcenter user log out
                responseDict = response.json()
                raise Exception("Failed to log out the current vcenter user due to error: "
                                .format(responseDict['value']['messages'][0]['default_message']))
        except Exception:
            raise

    def fetchClusterResourcePoolMapping(self):
        """
            Description : This method creates mappings of cluster and resource pools
            Returns: Dictionary of mappings (DICT)
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Disabling the InsecureRequestWarning message
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            # connecting to vCenter
            si = SmartConnect(host=self.ipAddress,
                              user=self.username,
                              pwd=self.password,
                              sslContext=context)

            # If connection was not successful, raise an Exception
            if not si:
                raise Exception("Could not connect to the specified host using specified "
                                "username and password")

            atexit.register(Disconnect, si)
            content = si.RetrieveContent()

            # Cluster resource pool mapping
            clusterRpMapping = dict()

            # Iterating over datacenters
            for child in content.rootFolder.childEntity:
                if hasattr(child, 'hostFolder'):
                    # Iterating over all the cluster present in datacenter
                    for cluster in child.hostFolder.childEntity:
                        # Fetching cluster moref
                        clusterName = str(cluster).strip('\'').split(':')[-1]
                        resourcePoolList = []
                        # If resource pools are present iterate over them to get their names
                        if hasattr(cluster, 'resourcePool'):
                            # Fetch moref of parent resource pool
                            resourcePoolList.append(str(cluster.resourcePool).strip('\'').split(':')[-1])
                            if hasattr(cluster.resourcePool, 'resourcePool'):
                                for rPool in cluster.resourcePool.resourcePool:
                                    # Fetch moref of resource pool
                                    resourcePoolList.append(str(rPool).strip('\'').split(':')[-1])
                                    if hasattr(rPool, 'resourcePool'):
                                        for orgVdcRPool in rPool.resourcePool:
                                            # Fetch moref of resource pool
                                            resourcePoolList.append(str(orgVdcRPool).strip('\'').split(':')[-1])
                        # Create cluster and resource pool mapping
                        if clusterName in clusterRpMapping:
                            clusterRpMapping[clusterName].extend(resourcePoolList)
                        else:
                            clusterRpMapping[clusterName] = resourcePoolList

            return clusterRpMapping
        except Exception as err:
            logger.debug(traceback.format_exc())
            raise Exception(f"Failed to Resource Pool details from vCenter due to error - {str(err)}")

    def fetchAgencyClusterMapping(self):
        """
            Description : This method creates mappings of cluster and hosts as well as cluster and agents
            Returns: Dictionary of mappings (DICT)
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Disabling the InsecureRequestWarning message
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            # connecting to vCenter
            si = SmartConnect(host=self.ipAddress,
                              user=self.username,
                              pwd=self.password,
                              sslContext=context)
            # If connection was not successful, raise an Exception
            if not si:
                raise Exception(f"Could not connect to the vCenter-{self.ipAddress} using specified "
                                "username and password")

            # Defering disconnect method
            atexit.register(Disconnect, si)

            # Connect to EAM Endpoint
            hostname = si._stub.host.split(":")[0]
            eamStub = pyVmomi.SoapStubAdapter(host=hostname,
                                              version="eam.version.version1",
                                              path="/eam/sdk",
                                              poolSize=0,
                                              sslContext=context)
            eamStub.cookie = si._stub.cookie
            eamCx = eam.EsxAgentManager("EsxAgentManager", eamStub)
            eamAgencies = eamCx.QueryAgency()

            # List to store the mapping
            agencyClusterMapping = list()

            # Iterating over agencies
            for agency in eamAgencies:
                agentName = agency.QueryConfig().agentName
                for cluster in agency.QueryConfig().scope.computeResource:
                    clusterName = str(cluster).strip('\'').split(':')[-1]
                    agencyClusterMapping.append([clusterName, agentName])
            return agencyClusterMapping
        except Exception as err:
            logger.debug(traceback.format_exc())
            raise Exception(f"Failed to fetch agency details from EAM(EsxAgentManager) due to error - {str(err)}")

    def mobsApi(self, compute_id):
        """
        Description : This method sends response of MOBS API to updateEdgeTransportNodes in nsxtOperations
        compute_id : cluster name of Edge Transport Node
        """
        try:
            url = "{}{}".format(constants.MOBS_API.format(hostname=self.ipAddress), compute_id)
            response = self.restClientObj.get(url=url, headers=self.headers, auth=(self.username, self.password))
            if response.status_code == requests.codes.ok:
                logger.debug("Successfully fetched domain - '{}' information from vCenter".format(compute_id))
                return response
            else:
                raise Exception(response)
        except Exception as err:
            logger.debug(traceback.format_exc())
            raise Exception(f"Failed to get domain - '{compute_id}' information from vCenter due to error response- {str(err)}")