# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which performs the REST Operations
"""

from requests.auth import HTTPBasicAuth

import requests
import urllib3


class RestAPIClient():
    """
    Description: Class that performs all REST CRUD Operations
    """

    def __init__(self, username=None, password=None):
        """
        Description: Initialization of RestAPIClient class
        Parameters: username - User name to use when connecting to host (STRING)
                    password - Password to use when connecting to host (STRING)
        """
        # setting the basic authentication
        self.auth = HTTPBasicAuth(username, password)
        self.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get(self, url, headers=None, auth=None, **kwargs):
        """
        Description: This method contains handler for RestAPIClient GET call.
        Parameters: url         - Complete location url path for running for REST call(STRING)
                    headers     - (OPTIONAL) Content-Type: application/(json/xml) (DICTIONARY)
                    kwargs      - (OPTIONAL) parameters used in REST request. (DICTIONARY)
        Returns: Response object
        """
        # get api call of requests module
        responseData = requests.get(url=url, headers=headers, auth=auth, verify=self.verify, **kwargs)
        return responseData

    def post(self, url, headers=None, auth=None, **kwargs):
        """
        Description : This method contains handler for RestAPIClient POST call.
        Parameters  : url         - Complete location url path for running for REST call (STRING)
                      headers     - (OPTIONAL) Content-Type: application/(json/xml) (DICTIONARY)
                      kwargs      - (OPTIONAL) parameters used in REST request. (DICTIONARY)
        Returns     : Response object
        """
        # post api call of requests module
        responseData = requests.post(url=url, headers=headers, auth=auth, verify=self.verify, **kwargs)
        return responseData

    def put(self, url, headers=None, **kwargs):
        """
        Description : This method contains handler for RestAPIClient PUT call.
        Parameters  : url         - Complete location url path for running for REST call (STRING)
                      headers     - (OPTIONAL) Content-Type: application/(json/xml) (DICTIONARY)
                      kwargs      - (OPTIONAL) parameters used in REST request. (DICTIONARY)
        Returns     : Response object
        """
        # put api call of requests module
        responseData = requests.put(url=url, headers=headers, verify=self.verify, **kwargs)
        return responseData

    def delete(self, url, headers=None, **kwargs):
        """
        Description : This method contains handler for RestAPIClient DELETE call.
        Parameters  : url       - Complete location url path for running for REST call (STRING)
                      headers   - (OPTIONAL) Content-Type: application/(json/xml) (DICTIONARY)
                      kwargs    - (OPTIONAL) parameters used in REST request. (DICTIONARY)
        Returns     : Response object
        """
        # delete api call of requests module
        responseData = requests.delete(url=url, headers=headers, verify=self.verify, **kwargs)
        return responseData
