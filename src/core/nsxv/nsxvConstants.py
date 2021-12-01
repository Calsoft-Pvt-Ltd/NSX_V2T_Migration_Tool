# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which contains all the constants required for VMware Cloud Director Migration from NSX-V to NSX-T
"""


# NSXV HOST AND API URL FORMAT
NSXV_HOST_API_URL = "https://{}/{}"

# results key that exists in the successful response of getComponentData api
NSX_API_RESULTS_KEY = "results"

# display_name key that exists in the successful response of getComponentData api
NSX_API_DISPLAY_NAME_KEY = "display_name"

# default header required for nsx-v api
NSXV_API_HEADER = {'Content-Type': 'application/xml'}

# json headers for nsx-v api
NSXV_JSON_API_HEADER = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# nsx-v uri to check login
NSXV_ACCESS_TEST_URL = "/api/2.0/services/usermgmt/user/admin"

# url to post public key to nsx-v
NSXV_PUBLICKEY_POST_API_URL = "/api/2.0/services/truststore/v2tmigration/certificate/publickey"

# url to retrieve certificates from nsx-v
NSXV_CERTIFICATE_RETRIEVAL_URL = "/api/2.0/services/truststore/v2tmigration/certificate"

# nsx-v uri to fetch overlay pool ranges
NSXV_VNI_POOL_URL = "/api/2.0/vdn/config/segments"

# nsx-v url to fetch nsx-v manager version
NSXV_MANAGER_VERSION_URL = "api/1.0/appliance-management/global/info"
