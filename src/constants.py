# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: This module holds the constants needed for the project to run
"""

import os
from pathlib import Path

rootDir = os.path.dirname(os.path.abspath(__file__))    # src

parentRootDir = Path(__file__).parent.parent            # vcd-migration

VALID_CLI_OPTIONS = ["--cleanup", "--help"]

# Regular expression for validation of FQDN
FQDN_REGEX = "(?!-)[A-Z\d-]{1,63}(?<!-)$"

# Regular Expression for validation of IP
VALID_IP_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
