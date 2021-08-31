# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************


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

# Regular Expression for validation of IP in CIDR format
VALID_IP_CIDR_FORMAT_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([0-9]|[1-2][0-9]|3[0-2])$"

# Valid skip values as input
VALID_SKIP_VALUES = ["bridging", "services", "movevapp"]

# Valid execute values as input
VALID_EXECUTE_VALUES = ["topology", "bridging", "services", "movevapp"]

# Replication Keyword
REPLICATION_KEYWORD = "topology"

# Bridging Keyword
BRIDGING_KEYWORD = "bridging"

# Services Keyword
SERVICES_KEYWORD = "services"

# MoveVapp Keyword
MOVEVAPP_KEYWORD = "movevapp"

# Description of the skip/execute values
DESCRIPTION_OF_WORKFLOWS = {REPLICATION_KEYWORD: "Topology Replication",
                            BRIDGING_KEYWORD: "L2 Bridging",
                            SERVICES_KEYWORD: "N/S Switchover and Services Config",
                            MOVEVAPP_KEYWORD: "Workload Migration"}