# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: NSXT Module which performs the NSX-V related Operations
"""

import logging
import os
import re
import requests
import subprocess

from src.commonUtils.certUtils import generateRSAKey, decryptCertPrivateKey, decryptSessionKey
import src.core.nsxv.nsxvConstants as nsxvConstants

from src.commonUtils.restClient import RestAPIClient

logger = logging.getLogger('mainLogger')

class NSXVOperations():
    """
    Description: Class that performs the NSX-V related Operations
    """
    def __init__(self, ipAddress=None, username=None, password=None, verify=False):
        """
        Description :   Initializer method of NSXV Operations
        Parameters  :   ipAddress   -   ipaddress of the nsxv (STRING)
                        username    -   Username of the nsxv (STRING)
                        password    -   Password of the nsxv (STRING)
                        verify      -   whether to verify the server's TLS certificate (BOOLEAN)
        """
        self.ipAddress = ipAddress
        self.password = password
        self.username = username
        self.verify = verify
        self.pemFileName = 'privateKey.pem'

    def login(self):
        """
        Description : Check login to NSXV using a test access url
        """
        try:
            if not self.password:
                raise Exception('NSX-V password not present in password file, please enter a valid password file.')
            # getting the RestAPIClient object to call the REST apis
            self.restClientObj = RestAPIClient(self.username, self.password, self.verify)
            url = nsxvConstants.NSXV_HOST_API_URL.format(self.ipAddress, nsxvConstants.NSXV_ACCESS_TEST_URL)
            response = self.restClientObj.get(url, headers=nsxvConstants.NSXV_API_HEADER, auth=self.restClientObj.auth)
            if response.status_code == requests.codes.ok:
                logger.debug("Successfully logged into NSX-V {}".format(self.ipAddress))
            elif response.status_code == requests.codes.forbidden:
                errorMsg = re.findall('Message</b>(.*?)</p>', response.text)[0]
                if re.search(r'Bad Username or Credentials presented', errorMsg):
                    raise Exception('Failed to login to NSX-V {} with the given credentials.'.format(self.ipAddress))
                else:
                    raise Exception('Login failed to NSX-V due to error - {}'.format(errorMsg))
        except Exception:
            raise

    def postPublicKeyAndRetreiveCertNSXV(self, publicKey, objectId):
        """
            Description :   posts public to NSXV and retrieves certificate details
            Params      :   publicKey - public key that will be posted to NSXV (STRING)
                            objectId - Object ID of certificate that if required (STRING)
            Returns     :   certificate, certificate private key and session key (STRING)
        """
        try:
            logger.debug('Posting generated publickey to nsx-v')
            nsx_publickey_post_api_url = nsxvConstants.NSXV_HOST_API_URL.format(self.ipAddress,
                                                                                nsxvConstants.NSXV_PUBLICKEY_POST_API_URL)

            nsxv_retrieve_all_cert_api_url = nsxvConstants.NSXV_HOST_API_URL.format(self.ipAddress,
                                                                                nsxvConstants.NSXV_CERTIFICATE_RETRIEVAL_URL)

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

            payload = "<v2tpublickey><publickey>" + publicKey + "</publickey></v2tpublickey>"

            # posting public key api to nsxv
            apiPostResponse = self.restClientObj.post(nsx_publickey_post_api_url, data=payload, headers=nsxvConstants.NSXV_API_HEADER, auth=self.restClientObj.auth)
            if apiPostResponse.status_code == requests.codes.created:
                logger.debug('Successfully posted public key to nsx-v')
            else:
                raise Exception('Failed to post public key to nsx-v')

            # getting all cert details from nsxv
            certResponse = self.restClientObj.get(nsxv_retrieve_all_cert_api_url, headers=headers, auth=self.restClientObj.auth)
            if certResponse.status_code == requests.codes.ok:
                logger.debug('Successfully retrieved certificates from nsx-v')
            else:
                raise Exception('Failed to retrieve certificates from nsx-v')

            # Fetching JSON response from response
            respJson = certResponse.json()
            # Filtering the certificate required
            try:
                certificateJson = list(filter(lambda cert: cert['objectId'] == objectId, respJson['trustObjects']))[0]
            except IndexError:
                raise Exception("Certificate with object id - '{}' not found in nsx-v".format(objectId))
            # Getting certificate value from the certificate JSON
            certificate = certificateJson['pemEncoding']
            # Getting private key of ceritificate
            certPrivateKey = certificateJson['privateKey']
            # Getting session key from the response
            sessionKey = respJson['sessionKey']
            return certificate, certPrivateKey, sessionKey
        except:
            raise

    def certRetrieval(self, objectId):
        """
            Description :   Dedcrypts private key of certificate for futher usage
            Params      :   objectId - Object ID of certificate that if required (STRING)
            Returns     :   certificate from NSXV that will be uploaded on vCD(STRING)
        """
        try:
            # creating private and public RSA keys
            publicKey, privateKey = generateRSAKey()
            # posting the public key to nsx-v and fetching certificate details
            certificate, enc_private_key, session_key = self.postPublicKeyAndRetreiveCertNSXV(publicKey, objectId)
            logger.debug('Decrypting certificate session key using private key')
            secret = decryptSessionKey(privateKey, session_key)
            # decrypting cert private key using decrypted secret key
            logger.debug('Decrypting certificate private key using decrypted secret key')
            decryptedPrivateKey = decryptCertPrivateKey(enc_private_key, secret)

            # Writing decrypted private key to file
            logger.debug('Writing decrypted private key to {} file'.format(self.pemFileName))
            with open(self.pemFileName, 'w', encoding='utf-8') as private_file:
                private_file.write(decryptedPrivateKey)

            # file name to be used to convert pkcs1 pem file to pkcs8 file
            pkcs8PemFileName = 'privateKeyPKCS8.pem'
            list_files = subprocess.run(
                ["openssl", "pkcs8", "-topk8", "-inform", "PEM", "-outform", "PEM", "-in", self.pemFileName, "-out",
                 pkcs8PemFileName, "-nocrypt"])
            if list_files.returncode:
                raise Exception('Failed to convert pkcs1 private key to pkcs2 private key')
            os.remove(self.pemFileName)
            return certificate
        except:
            raise
        finally:
            if os.path.exists(self.pemFileName):
                os.remove(self.pemFileName)
