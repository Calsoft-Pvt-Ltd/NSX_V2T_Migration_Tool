# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which contains all the constants required for VMware Cloud Director Migration from NSX-V to NSX-T
"""

import os

# NSXT HOST AND API URL FORMAT
NSXT_HOST_API_URL = "https://{}/{}"

# results key that exists in the successful response of getComponentData api
NSX_API_RESULTS_KEY = "results"

# display_name key that exists in the successful response of getComponentData api
NSX_API_DISPLAY_NAME_KEY = "display_name"

# resource_type key
NSX_API_RES_TYPE_KEY = "resource_type"

# default header required for nsx-t api
NSXT_API_HEADER = {'Content-Type': 'application/json'}

# nsx-t edge cluster uri
CREATE_EDGE_CLUSTER_API = "api/v1/edge-clusters"

# nsx-t bridge endpoint profile uri
CREATE_BRIDGE_ENDPOINT_PROFILE = "api/v1/bridge-endpoint-profiles"

# root directory constant which fetches the absolute path of this module i.e D:/vcd-migration/src/core/nsxt
NSXT_ROOT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

# nsx-t create bridge endpoint profile template name
CREATE_BRIDGE_ENDPOINT_PROFILE_COMPONENT_NAME = 'createBridgeEndpointProfile'

# nsx-t component name used in the template.json
COMPONENT_NAME = 'NSXT'

# nsx-t transport node uri
TRANSPORT_NODE_API = "api/v1/transport-nodes"

# nsx-t host switch profile uri
HOST_SWITCH_PROFILE_API = "api/v1/host-switch-profiles"

# nsx-t create uplink profile template name used in template.json
CREATE_UPLINK_PROFILE = "createUplinkProfiles"

# nsx-t bridge uplink profile name
BRDIGE_UPLINK_PROFILE_NAME = "bridge-uplink-profile"

# nsx-t transport zone uri
TRANSPORT_ZONE_API = "api/v1/transport-zones"

# nsx-t transport node by id uri
UPDATE_TRANSPORT_NODE_API = "api/v1/transport-nodes/{}"

# nsx-t logical switch uri
CREATE_LOGICAL_SWITCH_API = "api/v1/logical-switches"

# nsx-t logical switch port uri
CREATE_LOGICAL_SWITCH_PORT_API = "api/v1/logical-ports"

# nsx-t create logical switch port template name used in template.json
CREATE_LOGICAL_SWITCH_PORT_TEMPLATE = "createLogicalPort"

# nsx-t create bridge endpoint template name used in template.json
CREATE_BRIDGE_ENDPOINT_TEMPLATE = "createBridgeEndpoint"

# nsx-t create bridge endpoint uri
CREATE_BRIDGE_ENDPOINT_API = "api/v1/bridge-endpoints"

# nsx-t pnic name for attaching vxlan logical switch to edge transport node
PNIC_NAME = 'fp-eth2'

# nsx-t bridge endpoint by id uri
GET_BRIDGE_ENDPOINT_BY_ID_API = "api/v1/bridge-endpoints/{}"

# nsx-t bridge endpoint profile by id uri
GET_BRIDGE_ENDPOINT_PROFILE_BY_ID_API = "api/v1/bridge-endpoint-profiles/{}"

# nsx-t logical switch port by id uri
DELETE_LOGICAL_SWITCH_PORT_API = "api/v1/logical-ports/{}?detach=True"

# nsx-t edge cluster by id uri
GET_EDGE_CLUSTER_API = "api/v1/edge-clusters/{}"

# nsx-t host swicth profile by id uri
DELETE_HOST_SWITCH_PROFILE_API = "api/v1/host-switch-profiles/{}"

# nsx-t uri to retrieve the list of compute-managers
LIST_COMPUTE_MANAGERS = "api/v1/fabric/compute-managers"
