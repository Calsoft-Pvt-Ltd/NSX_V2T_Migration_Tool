# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which has vcenter API related constants
"""


# APIs list
VCSA_LOGIN_API = "https://{hostname}/rest/com/vmware/cis/session?~method=post"
VCSA_VM_DETAILS_API = "https://{hostname}/rest/vcenter/vm/{id}"
VCSA_TIMEZONE_API = "https://{hostname}/rest/appliance/system/time/timezone"
VCSA_DELETE_SESSION = "https://{hostname}/rest/com/vmware/cis/session"
MOBS_API = "https://{hostname}/mob/?moid="

# Default accept value
DEFAULT_ACCEPT_VALUE = "application/json"
SESSION_ID_KEY = "vmware-api-session-id"

# value key
VALUE_KEY = "value"

# nics key
NIC_DETAILS_KEY = "nics"
