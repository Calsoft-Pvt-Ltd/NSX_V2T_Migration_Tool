# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which performs the vcenter API related Operations
"""

import logging
import requests

import src.core.vcenter.vcenterConstants as constants
from src.commonUtils.restClient import RestAPIClient

logger = logging.getLogger('mainLogger')


class VcenterApi():
    """
    Description : VCSAApis class provides methods to perform VCSA specific tasks
    """

    def __init__(self, vcenterDict):
        # Get VCSA Credentials from vcsaDict
        self.ipAddress = vcenterDict["ipAddress"]
        self.username = vcenterDict["username"]
        self.password = vcenterDict["password"]
        # Default header to be used for VCSA API calls
        self.headers = dict()
        self.headers.update({"Accept": constants.DEFAULT_ACCEPT_VALUE,
                             "Content-Type": constants.DEFAULT_ACCEPT_VALUE})
        self.headers.update({constants.SESSION_ID_KEY: ""})
        # Rest client API calls
        self.restClientObj = RestAPIClient()

    def login(self):
        """
        Description : Method to log-in session for VCSA.
        Returns : sessionId - Session ID for the current VCSA session (STRING)
        """
        # URL for VCSA login
        url = constants.VCSA_LOGIN_API.format(hostname=self.ipAddress)
        response = self.restClientObj.get(url=url, headers=self.headers, auth=(self.username, self.password))
        if response.status_code == requests.codes.ok:
            # Check for session ID in response
            sessionId = response.json().get("value")
            if not sessionId:
                raise Exception("Failed to fetch vCenter Session ID ")
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

    @setSession
    def getTimezone(self):
        """
        Description : Get vcenter timezone
        """
        # URL for getting timezone details
        logger.debug('Getting vcenter timezone')
        url = constants.VCSA_TIMEZONE_API.format(hostname=self.ipAddress)
        response = self.restClientObj.get(url=url, headers=self.headers)
        if response.status_code == requests.codes.ok:
            logger.debug('Successfully retrieved vcenter timezone')
        else:
            raise Exception("Failed to get vcenter timezone. Error - {}".format(response.json()['value']['messages'][0]['default_message']))
