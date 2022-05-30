# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description: Module which contains all the constants required for VMware Cloud Director Migration from NSX-V to NSX-T
"""

import os

# NSXT HOST AND API URL FORMAT
NSXT_HOST_API_URL = "https://{}/{}"
NSXT_HOST_POLICY_API = "https://{}/policy/api/v1"

# results key that exists in the successful response of getComponentData api
NSX_API_RESULTS_KEY = "results"

# display_name key that exists in the successful response of getComponentData api
NSX_API_DISPLAY_NAME_KEY = "display_name"

# default header required for nsx-t api
NSXT_API_HEADER = {'Content-Type': 'application/json'}

# nsx-t edge cluster uri
CREATE_EDGE_CLUSTER_API = "api/v1/edge-clusters"

# nsx-t logical routers uri
LOGICAL_ROUTER_API = "api/v1/logical-routers"

# max limit of bridge endpoint profiles in NSX-T
MAX_LIMIT_OF_BRIDGE_ENDPOINT_PROFILES = 128

# nsx-t bridge endpoint profile uri
CREATE_BRIDGE_ENDPOINT_PROFILE = "api/v1/bridge-endpoint-profiles"

# nsx-t Edeg bridge profile with policy API
BRIDGE_ENDPOINT_PROFILE_POLICY_PATH = "/infra/sites/default/enforcement-points/default/edge-bridge-profiles/Bridge-Edge-Profile{}"

# nsx-t edge profile details with Policy API.
BRIDGE_EDGE_PROFILE_DETAILS = "/infra/sites/default/enforcement-points/default/edge-bridge-profiles"

# NSX-T get edge clusters
GET_EDGE_CLUSTERS_API = "/infra/sites/default/enforcement-points/default/edge-clusters"

# nsx-r Edge Path for create Edge Bride Profile with policy API.
EDGE_PATH = "/edge-nodes"

# nsx-t API version
API_VERSION = "/spec/openapi/nsx_policy_api.json"

# root directory constant which fetches the absolute path of this module i.e D:/vcd-migration/src/core/nsxt
NSXT_ROOT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

# nsx-t create bridge endpoint profile template name
CREATE_BRIDGE_ENDPOINT_PROFILE_COMPONENT_NAME = 'createBridgeEndpointProfile'

# nsx-t create bridge edge profile(Policy API) template name.
CREATE_BRIDGE_EDGE_PROFILE_COMPONENT_NAME = 'createBridgeEdgeProfile'

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

# nsx-t bridge transport zone name
BRIDGE_TRANSPORT_ZONE_NAME = "Bridge-Migration-TZ"

# nsx-t bridge transport zone's host-switch-name
BRIDGE_TRANSPORT_ZONE_HOST_SWITCH_NAME = "Bridge-nvds-v2t"

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

# nsx-t host swicth profile by id uri
DELETE_HOST_SWITCH_PROFILE_API = "api/v1/host-switch-profiles/{}"

# nsx-t uri to retrieve the list of compute-managers
LIST_COMPUTE_MANAGERS = "api/v1/fabric/compute-managers"

# BGP ROUTING CONFIG uri
BGP_ROUTING_CONFIG_API = "/infra/tier-0s/{}/locale-services/{}/bgp"

# Tier0 locale serivces uri
GET_LOCALE_SERVICES_API = '/infra/tier-0s/{}/locale-services'

# Logical segment using policy API
LOGICAL_SEGMENTS_ENDPOINT = "/infra/segments/{}"
SEGMENT_DETAILS = "/infra/segments"

# policy API version startswith '3.' onwards.
API_VERSION_STARTWITH = "3."

# nsx-t openapi specs uri
OPENAPI_SPECS_API = "api/v1/spec/openapi/nsx_api.json"

# nsx-t vni pool uri
FETCH_VNI_POOL = "api/v1/pools/vni-pools"

# nsx-t Default transport zone path.
TRANSPORT_ZONE_PATH = "/infra/sites/default/enforcement-points/default/transport-zones/{}"

# Get transport zone details
TRANSPORT_ZONE_DETAILS_URL = "/infra/sites/default/enforcement-points/default/transport-zones/{}"

# Timeout to get Transport Zone details.
TRANSPORT_ZONE_DETAILS_TIMEOUT = 60 * 10

# API to check realization state after policy API is executed
REALIZED_STATE_API = "/infra/realized-state/status?intent_path={}"

# API to check NSX-T version
NSXT_VERSION = "api/v1/node"

# NSXT QOS profile
NSXT_QOS_PROFILE = "/infra/gateway-qos-profiles/{}_Mbps"

#NSXT GlobalConfig
NSXT_GLOBALCONFIG = "/infra/global-config"

#NSXT macaddressglobal
NSXT_MACGLOBAL = '02:50:56:56:44:52'