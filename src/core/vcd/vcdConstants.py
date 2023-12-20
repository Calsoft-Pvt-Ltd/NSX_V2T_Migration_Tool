# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************
"""
Description: Module which contains all the constants required for VMware Cloud Director Migration from NSX-V to NSX-T
"""

import os

# get supported api version url
GET_API_VERSION = 'https://{}/api/versions'

# api header used for legacy api and openapi's
VCD_API_HEADER = 'application/*;version={}'

# vcd admin operations legacy api url
XML_ADMIN_API_URL = "https://{}/api/admin/"

# API version for VCD builds
API_VERSION_PRE_ZEUS = "34.0"
API_VERSION_ZEUS = "35.0"
API_VERSION_ZEUS_10_2_2 = "35.2"
API_VERSION_ANDROMEDA = "36.0"
API_VERSION_ANDROMEDA_10_3_1 = "36.1"
API_VERSION_ANDROMEDA_10_3_2 = "36.2"
VCD_10_3_2_1_BUILD = '10.3.2.19442122'
API_VERSION_ANDROMEDA_10_3_3 = "36.3"
API_VERSION_BETELGEUSE_10_4 = "37.0"
API_VERSION_CASTOR_10_4_1 = "37.1"
API_10_4_2_BUILD = "37.2"

# vm Affinity rule url
AFFINITY_URL = "https://{}/api/vdc/{}/vmAffinityRules/"

# enable/disable affinity rules url
ENABLE_DISABLE_AFFINITY_RULES = "https://{}/api/vmAffinityRule/{}"

# vcd user operations legacy api url
XML_API_URL = "https://{}/api/"

# query to fetch org vdc data
ORG_VDC_QUERY = "query?type=adminOrgVdc&format=records"

# fetch all vdcs
FETCH_ALL_VDCS = "vdcs"

# create org vdc metadata entry template name used in template.yml
CREATE_ORG_VDC_METADATA_TEMPLATE = 'createOrgVDCMetadata'

# undeploy vApp template
UNDEPLOY_VAPP_TEMPLATE = 'undeployvApp'

# undeploy vApp api
UNDEPLOY_VAPP_API = 'vApp/{}/action/undeploy'

# create org vdc metadata template name used in template.yml
CREATE_ORG_VDC_METADATA_ENTRY_TEMPLATE = 'createOrgVDCMetadataEntry'

# create new metadata entry(key, value) in org vdc task name used to check if the task completed successfully
CREATE_METADATA_IN_ORG_VDC_TASK_NAME = 'metadataUpdate'

# vcd open api url
OPEN_API_URL = "https://{}/cloudapi/1.0.0/"

# current session uri
CURRENT_SESSION = 'sessions/current'

# delete current session uri
DELETE_CURRENT_SESSION = 'sessions/{}'

# vcd login url
LOGIN_URL = "https://{}/api/sessions"

# vcd nsv api url
XML_VCD_NSX_API = "https://{}/network/"

# external networks uri
ALL_EXTERNAL_NETWORKS = "externalNetworks"

# filter for external networks
EXTERNAL_NETWORK_FILTER = "filter=(name=={})"

# create IP Spaces
CREATE_IP_SPACES = "ipSpaces"

# update IP Spaces
UPDATE_IP_SPACES = "ipSpaces/{}"

# external network ip space uplinks
IP_SPACE_UPLINKS = "ipSpaceUplinks"

# allocate ip space entities
IP_SPACE_ALLOCATE = "allocate"

# IP Space allocations
IP_SPACE_ALLOCATIONS = "allocations"

# migration tag scope name
MIGRATION_UPLINK = 'V2T-Migration'

# direct network connected to (port group backed) external network backing type
DIRECT_NETWORK_CONNECTED_TO_PG_BACKED_EXT_NET = "DV_PORTGROUP"

# org vdc capabilities
ORG_VDC_CAPABILITIES = "vdcs/{}/capabilities"

# org vdc networks uri
ALL_ORG_VDC_NETWORKS = "orgVdcNetworks"

#org vdc network dhcp uri
ORG_VDC_NETWORK_DHCP = "orgVdcNetworks/{}/dhcp"

# org vdc network additional properties
ORG_VDC_NETWORK_ADDITIONAL_PROPERTIES = "orgVdcNetworks/{}/additionalProperties"

#nsx managers uri
NSX_MANAGERS = "extension/nsxtManagers"

# edge gateways uri
ALL_EDGE_GATEWAYS = "edgeGateways"

# openapi provider vdcs uri
PROVIDER_VDC = "providerVdcs"

# xml api provider vdc uri
PROVIDER_VDC_XML = "providervdc"

# org vdc network dhcp uri
DHCP_ENABLED_FOR_ORG_VDC_NETWORK_BY_ID = "{}/dhcp"

# disable org vdc uri
ORG_VDC_DISABLE = "vdc/{}/action/disable"

# org vdc affinity rules uri
ORG_VDC_AFFINITY_RULES = "vdc/{}/vmAffinityRules"

# vcd nsxv edge uri
NETWORK_EDGES = "edges"

# vcd cells information
VCD_CELLS = "cells"

# application Port Profile uri
APPLICATION_PORT_PROFILES = "applicationPortProfiles"

# org vdc edge gateway network services config uris:-
# dhcp config uri for edge gateway by id
EDGE_GATEWAY_DHCP_CONFIG_BY_ID = "/{}/dhcp/config"

# firewal config uri for edge gateway by id
EDGE_GATEWAY_FIREWALL_CONFIG_BY_ID = "/{}/firewall/config"

# nat config uri for edge gateway by id
EDGE_GATEWAY_NAT_CONFIG_BY_ID = "/{}/nat/config"

# ipsec config uri for edge gateway by id
EDGE_GATEWAY_IPSEC_CONFIG = "/{}/ipsec/config?showSensitiveData= true"

# sslvpn config uri for edge gateway by id
EDGE_GATEWAY_SSLVPN_CONFIG = "/{}/sslvpn/config"

# l2vpn config uri for edge gateway by id
EDGE_GATEWAY_L2VPN_CONFIG = "/{}/l2vpn/config"

# upload certificate in vcd
CERTIFICATE_URL = "ssl/certificateLibrary"

# load balancer config uri for edge gateway by id
EDGE_GATEWAY_LOADBALANCER_CONFIG = "/{}/loadbalancer/config"

# load balancer url to get virtual server using edge gateway id
EDGE_GATEWAY_VIRTUAL_SERVER_CONFIG = "edges/{}/loadbalancer/config/virtualservers"

# load balancer pool uri for edge gateway
EDGE_GATEWAY_LOADBALANCER_POOLS = "loadBalancer/pools"

# load balancer virtual server uri for edge gateway
EDGE_GATEWAY_LOADBALANCER_VIRTUAL_SERVER = 'loadBalancer/virtualServices'

# load balancer pool uri for edge gateway using edge gateway id
EDGE_GATEWAY_LOADBALANCER_POOLS_USING_ID = 'edgeGateways/{}/loadBalancer/poolSummaries'

# load balancer virtual service uri for edge gateway using edge gateway id
EDGE_GATEWAY_LOADBALANCER_VIRTUALSERVICE_USING_ID = 'edgeGateways/{}/loadBalancer/virtualServiceSummaries'

# load balancer clouds uri using cloud id
GET_LOADBALANCER_CLOUD_USING_ID = 'loadBalancer/clouds/{}'

# load balancer controller uri using controller id
GET_LOADBALANCER_CONTROLLER_USING_ID = 'loadBalancer/controllers/{}'

# routing config uri for edge gateway by id
EDGE_GATEWAY_ROUTING_CONFIG = "/{}/routing/config/"
EDGE_GATEWAY_DHCP_RELAY_CONFIG_BY_ID = "/relay"
EDGE_GATEWAY_BGP_CONFIG = "/{}/routing/config/bgp?showSensitiveData= true"

# t1 router service config uris:-
# ipsec config uri for t1 router by id
T1_ROUTER_IPSEC_CONFIG = "/{}/ipsec/tunnels"

# nat config uri for t1 router by id
T1_ROUTER_NAT_CONFIG = "/{}/nat/rules"

# ipsec config uri for t1 router by id
T1_ROUTER_FIREWALL_CONFIG = "/{}/firewall/rules"

# bgp config uri for t1 router by id
T1_ROUTER_BGP_CONFIG = "/{}/routing/bgp"

# create bgp neighbour uri for t1 router by id
CREATE_BGP_NEIGHBOR_CONFIG = "/{}/routing/bgp/neighbors"

# create prefixLists uri
CREATE_PREFIX_LISTS_BGP = '/{}/routing/bgp/prefixLists'

# config route advertisement
CONFIG_ROUTE_ADVERTISEMENT = '/{}/routing/advertisement'

# create org vdc uri for specific organization
CREATE_ORG_VDC = "org/{}/vdcsparams"

# create access control in org vdc uri
CREATE_ACCESS_CONTROL_IN_ORG_VDC = "vdc/{}/action/controlAccess"

# get access control info in org vdc uri
GET_ACCESS_CONTROL_IN_ORG_VDC = "vdc/{}/controlAccess"

# all org vdc compute policies uri
VDC_COMPUTE_POLICIES = "vdcComputePolicies"

# vdc compute policy by id uri
VDC_COMPUTE_POLICIES_BY_ID = "/{}/vdcs"

# org vdc metadata uri
META_DATA_IN_ORG_VDC_BY_ID = "vdc/{}/metadata"

# disk metadata uri
META_DATA_IN_DISK_BY_ID = "disk/{}/metadata"

#configure network profile
NETWORK_PROFILE = 'vdcs/{}/networkProfile'

# create edge gateway uri
CREATE_EDGE_GATEWAY = "vdc/{}/edgeGateways"

# get vApp network configuration
VAPP_NETWORK_CONFIGURATION = "vApp/vapp-{}/networkConfigSection"

# vcd task operations timeout
VCD_CREATION_TIMEOUT = 360.0

# vcd task operations interval
VCD_CREATION_INTERVAL = 10.0

# api template names:-
# create org vdc network template name used in template.json
CREATE_ORG_VDC_NETWORK_TEMPLATE = 'createOrgVDCNetwork'

# create ipsec template name used in template.json
CREATE_IPSEC_TEMPLATE = 'createIPSecServices'

# create dnat template name used in template.json
CREATE_DNAT_TEMPLATE = 'createDNATServices'

# create snat template name used in template.json
CREATE_SNAT_TEMPLATE = 'createSNATServices'

# create org vdc access control template name used in template.yml
CREATE_ORG_VDC_ACCESS_CONTROL_TEMPLATE = 'createOrgVDCAccessControl'

# create affinity template name used in template.yml
CREATE_AFFINITY_RULE_TEMPLATE = 'creatingAffinityRule'

# component name
COMPONENT_NAME = 'vCloudDirector'

# openapi content type for json
OPEN_API_CONTENT_TYPE = 'application/json;version={}'

# content type for json
GENERAL_JSON_ACCEPT_HEADER = 'application/*+json;version={}'
GENERAL_JSON_CONTENT_TYPE_HEADER = 'application/*+json'

# content type for xml
GENERAL_XML_CONTENT_TYPE = 'application/*+xml;charset=UTF-8'

# vapp type string
TYPE_VAPP = 'application/vnd.vmware.vcloud.vApp+xml'

# create vdc task name used to check if the task completed successfully
CREATE_VDC_TASK_NAME = 'vdcCreateVdc'

# create edge gateway task name used to check if the task completed successfully
CREATE_EDGE_GATEWAY_TASK_NAME = 'orgVdcGatewayCreate'

# create org vdc networks task name used to check if the task completed successfully
CREATE_ORG_VDC_NETWORK_TASK_NAME = 'orgVdcNetworkCreate'

# create ipsec vpn tunnel task name used to check if the task completed successfully
CREATE_IPSEC_VPN_TASK_NAME = 'createIpSecVpnTunnel'

# create affinity rule task name used to check if the task completed successfully
CREATE_AFFINITY_RULE_TASK_NAME = 'affinityRuleUpdate'

# create nat rule task name used to check if the task completed successfully
CREATE_NAT_RULE_TASK_NAME = 'createNatRule'

# delete org vdc task name used to check if the task completed successfully
DELETE_ORG_VDC_TASK_NAME = 'vdcDeleteVdc'

# delete org vdc network task name for isolated network used to check if the task completed successfully
DELETE_ORG_VDC_ISOLATED_NETWORK_TASK_NAME = 'networkDelete'

# delete org vdc network task name for routed network used to check if the task completed successfully
DELETE_ORG_VDC_ROUTED_NETWORK_TASK_NAME = 'orgVdcNetworkDelete'

# delete nsx-v backed org vdc edge gateway task name used to check if the task completed successfully
DELETE_NSX_V_BACKED_ORG_VDC_EDGE_GATEWAY_TASK_NAME = 'networkEdgeGatewayDelete'

# delete nsx-t backed org vdc edge gateway task name used to check if the task completed successfully
DELETE_NSX_T_BACKED_ORG_VDC_EDGE_GATEWAY_TASK_NAME = 'orgVdcGatewayDelete'

# update org vdc network task name used to check if the task completed successfully
UPDATE_ORG_VDC_NETWORK_TASK_NAME = 'orgVdcNetworkUpdate'

# update bgp configuration task name used to check if the task completed successfully
UPDATE_BGP_CONFIG_TASK_NAME = 'bgpConfigUpdate'

# update edge gateway task name used to check if the task completed successfully
UPDATE_EDGE_GATEWAY_TASK_NAME = 'edgeGatewayUpdate'

# update edge gateway openapi task name used to check if the task completed successfully
UPDATE_EDGE_GATEWAY_OPENAPI_TASK_NAME = 'orgVdcGatewayUpdate'

# xml content type for create org vdc
XML_CREATE_VDC_CONTENT_TYPE = 'application/vnd.vmware.admin.createVdcParams+xml'

# content type for access control
CONTROL_ACCESS_CONTENT_TYPE = "application/vnd.vmware.vcloud.controlAccess+json"

# xml content type to rename the catalog
RENAME_CATALOG_CONTENT_TYPE = 'application/vnd.vmware.admin.catalog+xml;charset=UTF-8'

# delete org vdc network by id uri
DELETE_ORG_VDC_NETWORK_BY_ID = "orgVdcNetworks/{}"

# org vdc by id uri
ORG_VDC_BY_ID = "vdc/{}"

# get distributed firewall uri
GET_DISTRIBUTED_FIREWALL = "firewall/globalroot-0/config?vdc={}"

# get application services
GET_APPLICATION_SERVICES = "services/application/scope/{}"

#get application service groups
GET_APPLICATION_SERVICE_GROUPS = "services/applicationgroup/scope/{}"

# update edge gateway by id xml api uri
UPDATE_EDGE_GATEWAY_BY_ID = "edgeGateway/{}"

# update edge gateway by id openapi uri
UPDATE_EDGE_GATEWAYS_BY_ID = "edgeGateways/{}"

# disable nsx-v backed edge gateway distributed routing uri
DISABLE_EDGE_GATEWAY_DISTRIBUTED_ROUTING = '/action/disableDistributedRouting'

# disable nsx-v backed edge gateway distributed routing task name
DISABLE_EDGE_GATEWAY_DISTRIBUTED_ROUTING_TASK_NAME = 'networkGatewayDisableDistributedRouting'

# xml content type for update edge gateway
XML_UPDATE_EDGE_GATEWAY = 'application/vnd.vmware.admin.edgeGateway+xml'

# get vsphere portgroup's api
GET_PORTGROUP_INFO = 'query?type=portgroup'

# root directory constant which fetches the absolute path of this module i.e D:/vcd-migration/src/core/vcd
VCD_ROOT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

# vmware cloud director storage profile by id uri
VCD_STORAGE_PROFILE_BY_ID = "vdcStorageProfile/{}"

# string to check if the independent key exist or not in source org vdc
XML_INDEPENDENT_DISK_TYPE = 'application/vnd.vmware.vcloud.disk+xml'

# compute policy of org vdc by id uri
ORG_VDC_COMPUTE_POLICY = "vdc/{}/computePolicies"

# rename org vdc task name used to check if the task completed successfully
RENAME_ORG_VDC = 'vdcUpdateVdc'

# page size for application port profiles
APPLICATION_PORT_PROFILES_PAGE_SIZE = 75

# create firewall group uri
CREATE_FIREWALL_GROUP = 'firewallGroups'

# ipset group by id uri
GET_IPSET_GROUP_BY_ID = 'services/ipset/{}'

# IPSET filter for firewall groups
FIREWALL_GROUP_IPSET_FILTER = 'filterEncoded=true&filter=((ownerRef.id=={};typeValue==IP_SET))'

# create firewall group task name used to check if the task completed successfully
CREATE_FIREWALL_GROUP_TASK_NAME = 'createFirewallGroup'

# create prefix list task name used to check if the task completed successfully
CREATE_PREFIX_LISTS_TASK_NAME = 'prefixListCreate'

# update firewall rules task name used to check if the task completed successfully
UPDATE_FIREWALL_RULES_TASK_NAME = 'updateFirewallRules'

# vapp startup section uri
VAPP_STARTUP_SECTION = '/startupSection'

# vapp startup section task name used to check if the task completed successfully
VAPP_STARTUP_TASK_NAME = 'vdcUpdateVapp'

# content-type for rename org vdc
VDC_RENAME_CONTENT_TYPE = 'application/vnd.vmware.admin.vdc+json'

# vm sizing policy by org vdc id uri
ORG_VDC_VM_SIZING_POLICY = 'vdcs/{}/computePolicies?filter=isSizingOnly==true&links=true'

# assign compute policy to org vdc by compute policy id uri
ASSIGN_COMPUTE_POLICY_TO_VDC = 'vdcComputePolicies/{}/vdcs'

# delete vapp in org vdc task name used to check if the task completed successfully
DELETE_VAPP_TASK_NAME = 'vdcDeleteVapp'

# page size for port group
PORT_GROUP_PAGE_SIZE = 50

# enable org vdc by id uri
ENABLE_ORG_VDC = 'vdc/{}/action/enable'

# create bgp neighbor task name used to check if the task completed successfully
CREATE_BGP_NEIGHBOR_TASK_NAME = 'bgpNeighborCreate'

# create catalog by organization id uri
CREATE_CATALOG = "org/{}/catalogs"

# create catalog template name used in template/yml
CREATE_CATALOG_TEMPLATE = 'createCatalog'

# xml content-type for create catalog
XML_CREATE_CATALOG = 'application/vnd.vmware.admin.catalog+xml'

# move vapp template name used in template.yml
MOVE_CATALOG_TEMPLATE = 'moveCatalogItem'

# move vapp by catalog id uri
MOVE_CATALOG = 'catalog/{}/action/move'

# Catalog VappVmTemplate storage policy
CATALOG_VAPP_VM_TEMP_STORAGE_POLICY = "catalogVAppTemplate"

# static routing config uri
STATIC_ROUTING_CONFIG = 'edges/{}/routing/config/static'

# static route create url
TARGET_STATIC_ROUTE = '/{}/routing/staticRoutes'

# target static route update url
TARGET_STATIC_ROUTE_BY_ID = '/{}/routing/staticRoutes/{}'

# external network of edges uri
EDGES_EXTERNAL_NETWORK = 'edges/{}/vdcNetworks?includeDistributed=false'

# move vdc template
MOVE_VDC_TEMPLATE_TASK = 'vdcCopyTemplate'

# delete catalog task name used to check if the task completed successfully
DELETE_CATALOG_TASK = 'catalogDelete'

# rename catalog url
RENAME_CATALOG = 'catalog/{}'

# create application port profile task name
CREATE_APPLICATION_PORT_PROFILE_TASK_NAME = 'createAppPortProfile'

# validate dedicated external network filter api uri
VALIDATE_DEDICATED_EXTERNAL_NETWORK_FILTER = '?filter=edgeGatewayUplinks.uplinkId=={}'

# validate external network ip space
VALIDATE_EXTERNAL_NETWORK_IP_SPACES = "?filter=externalNetworkRef.id=={}"

# icmptype if any
ICMP_ALL = 'ICMPv4-ALL'

# get icmp port profiles
GET_ICMP_PORT_PROFILES_FILTER = '?filter=(applicationPorts.protocol==ICMPv4;_context=={})'

# check string for vapps having no vms in it
CHECK_STRING_FOR_EMPTY_VAPPS = 'The requested operation could not be executed since vApp "{}" is not running.'

# source network pool type VXLAN
VXLAN_NETWORK_POOL_TYPE = 'VxlanPoolType'

# source network pool type VLAN
VLAN_NETWORK_POOL_TYPE = 'VlanPoolType'

# source network pool type PortGroup
PORTGROUP_NETWORK_POOL_TYPE = 'PortGroupPoolType'

# target network pool type
GENEVE_NETWORK_POOL_TYPE = 'GenevePoolType'

# edge gateway status keys
EDGE_GATEWAY_STATUS_KEY = "edgeStatus"
EDGE_GATEWAY_VM_STATUS_KEY = "edgeVmStatus"

# vcd network edges gateway status api
EDGE_GATEWAY_STATUS = "/{}/status"

CONNECT_ADDITIONAL_UPLINK_EDGE_GATEWAY_TEMPLATE = 'addUplinkEdgeGateway'

# json content type for update edge gateway
JSON_UPDATE_EDGE_GATEWAY = 'application/vnd.vmware.admin.edgeGateway+json'

# update external network task name
UPDATE_EXTERNAL_NETWORK_NAME = 'externalNetworkUpdate'

# update source external network task name
UPDATE_SOURCE_EXTERNAL_NETWORK_NAME = 'networkUpdateNetwork'

# rename catalog template
RENAME_CATALOG_TEMPLATE = 'renameCatalog'

# page size for org vdc compute policy
ORG_VDC_COMPUTE_POLICY_PAGE_SIZE = 25

# cidr dict constant
CIDR_DICT = {"1": "32", "2": "31", "4": "30", "8": "29", "16": "28", "32": "27", "64": "26", "128": "25", "256": "24"}

# dns config uri for edge gateway by id
EDGE_GATEWAY_DNS_CONFIG_BY_ID = "/{}/dns/config"

# dns  uri for t1 router by id
DNS_CONFIG = "/{}/dns"

# create dns task name used to check if the task completed successfully
CONFIGURE_DNS_TASK_NAME = 'orgVdcGatewayDnsUpdate'

# org vdc network portgroup properties uri
ORG_VDC_NETWORK_PORTGROUP_PROPERTIES_URI = 'dvpgProperties'

# org vdc network portgroup properties task name
ORG_VDC_NETWORK_PORTGROUP_PROPERTIES_TASK_NAME = 'networkUpdateDvpgProperties'

# configure target connection properties for ipsec vpn
CONNECTION_PROPERTIES_CONFIG = '/{}/connectionProperties'

# distributed firewall supported object
DISTRIBUTED_FIREWALL_OBJECT_LIST = ['IPSet', 'Network', 'Ipv4Address']
DISTRIBUTED_FIREWALL_OBJECT_LIST_ANDROMEDA = ['IPSet', 'Network', 'Ipv4Address', 'VirtualMachine', 'SecurityGroup']

# ike version dict
CONNECTION_PROPERTIES_IKE_VERSION = {"ikev1": "IKE_V1", "ikev2": "IKE_V2", "ike-flex": "IKE_FLEX"}

# dh group dict ipsec
CONNECTION_PROPERTIES_DH_GROUP = {"dh2": "GROUP2", "dh5": "GROUP5", "dh14": "GROUP14", "dh15": "GROUP15", "dh16": "GROUP16", "dh19": "GROUP19", "dh20": "GROUP20", "dh21": "GROUP21"}

# digest algorithm dict ipsec
CONNECTION_PROPERTIES_DIGEST_ALGORITHM = {"sha1": "SHA1", "sha-256": "SHA2_256"}

# encryption algorithm ipsec
CONNECTION_PROPERTIES_ENCRYPTION_ALGORITHM = {"aes256": "AES_256", "aes": "AES_128", "aes-gcm": "AES_GCM_128"}

# update connecton properties ipsec vpn
UPDATE_IPSEC_TUNNEL_PROPERTIES = 'updateIpSecVpnTunnelProperties'

# get org vcd network by id
GET_ORG_VDC_NETWORK_BY_ID = "orgVdcNetworks/{}"

# get org vcd network allocated IPs
GET_ORG_VDC_NETWORK_ALLOCATED_IP = "/allocatedIpAddresses"

#security_group_types
SECURITY_GROUP_IPSET = 'IP_SET'
SECURITY_GROUP = 'SECURITY_GROUP'

# move vapp template
MOVE_VAPP_TEMPLATE = 'moveVapp'

# move vapp with network config template
MOVE_VAPP_NETWORK_CONFIG_TEMPLATE = 'moveVappNetworkConfig'

# move vapp with vm template
MOVE_VAPP_VM_TEMPLATE = 'moveVappVm'

# move vapp with compute policy template i.e both placement and sizing
MOVE_VAPP_VM_COMPUTE_POLICY_TEMPLATE = 'moveVappVmWithComputePolicy'

# move vapp with vm placement policy
MOVE_VAPP_VM_PLACEMENT_POLICY_TEMPLATE = 'moveVappVmpWithPlacementPolicy'

# move vapp with vm sizing policy
MOVE_VAPP_VM_SIZING_POLICY_TEMPLATE = 'moveVappVmWithSizingPolicy'

# adding/removing static route interfaces
STATIC_ROUTE_INTERFACE_TEMPLATE = 'staticRouteInterfaceConfig'

# move vApp in specified org vdc uri
MOVE_VAPP_IN_ORG_VDC = "vdc/{}/action/moveVApp"

# move vapp task name used to check if the task completed successfully
MOVE_VAPP_TASK_NAME = 'vdcMoveVapp'

# xml content type for move vApp
XML_MOVE_VAPP = 'application/vnd.vmware.vcloud.moveVAppParams+xml'

# vapp template type string
TYPE_VAPP_TEMPLATE = 'application/vnd.vmware.vcloud.vAppTemplate+xml'

# vapp media type string
TYPE_VAPP_MEDIA = 'application/vnd.vmware.vcloud.media+xml'

# get vapp template info uri
GET_VAPP_TEMPLATE_INFO = 'query?type=vAppTemplate'

# page size for vapp template
VAPP_TEMPLATE_PAGE_SIZE = 50

# get media of organization uri
GET_MEDIA_INFO = 'query?type=media'

# page size for media
MEDIA_PAGE_SIZE = 50

# vm references from the affinity rules template names
VM_REFERENCES_TEMPLATE_NAME = 'vmReferenceAffinityRules'

# enable or disable affinity rules template name
ENABLE_DISABLE_AFFINITY_RULES_TEMPLATE_NAME = 'enableDisableAffinityRules'

# default compute policy template for creating target org vdc
COMPUTE_POLICY_TEMPLATE_NAME = 'defaultComputePolicyTargetOvdc'

# storage profile template name for creating target org vdc
STORAGE_PROFILE_TEMPLATE_NAME = 'vdcStorageProfileTargetOvdc'

# create org vdc template name
CREATE_ORG_VDC_TEMPLATE_NAME = 'createTargetOrgVDC'

# template for vApp startup section
TARGET_VAPP_STARTUP_SECTION = 'vAppStartupSection'

#template for vApp Items
VAPP_ITEM_LIST = 'vAppItems'

# changed vcd login url
OPEN_LOGIN_URL = "sessions/provider"

# vApp status
VAPP_STATUS = {
    'FAILED_CREATION': '-1',
    'UNRESOLVED': '0',
    'POWERED_ON': '4',
    'UNRECOGNIZED': '7',
    'POWERED_OFF': '8',
    'INCONSISTENT_STATE': '9'
}

#ipset scope url
IPSET_SCOPE_URL = 'scope/{}'

# firewall groups summary
FIREWALL_GROUPS_SUMMARY = "firewallGroups/summaries"

# specific firewall group
FIREWALL_GROUP = "firewallGroups/{}"

# page size for firewall summary page
FIREWALL_GROUPS_SUMMARY_PAGE_SIZE = 25

# vapp vm network connection template
VAPP_VM_NETWORK_CONNECTION_SECTION_TEMPLATE = 'vAppVMNetworkConnectionDetails'

# vapp vm disk storage policy template
VAPP_VM_DISK_STORAGE_POLICY_TEMPLATE = 'vAppVMDiskStoragePolicy'

#url for nsx jobs
NSX_JOBS = '/jobs/{}'

# content type to update the vapp network
VAPP_NETWORK_CONTENT_TYPE = 'application/vnd.vmware.vcloud.vAppNetwork+json'

# get service engine group uri
GET_SERVICE_ENGINE_GROUP_URI = 'loadBalancer/serviceEngineGroups'

# page size for service engine group
SERVICE_ENGINE_GROUP_PAGE_SIZE = 25

# loadbalancer enable uri
LOADBALANCER_ENABLE_URI = '{}/loadBalancer'

# DHCPV6 enable in SLACC Mode
DHCPV6_SLACC_ENABLE_URI = '{}/slaacProfile'

# enable loadbalancer task name
LOADBALANCER_ENABLE_TASK_NAME = 'gatewayLoadBalancerConfigUpdate'

# assign service engine group to edge gateway uri
ASSIGN_SERVICE_ENGINE_GROUP_URI = 'loadBalancer/serviceEngineGroups/assignments'

# assign service engine group task name
ASSIGN_SERVICE_ENGINE_GROUP_TASK_NAME = 'loadBalancerServiceEngineGroupAssignmentCreate'

# vCD groups
VDC_GROUPS = 'vdcGroups'

# get Vdc group by Id
GET_VDC_GROUP_BY_ID = 'vdcGroups/{}/'

# Vdc group sync keyword
VDC_GROUP_SYNC = 'sync'

# get or enable DFW policies
ENABLE_DFW_POLICY = 'dfwPolicies'

# get / put DFW policy rules
GET_DFW_RULES = '/{}/rules'

IPV6ICMP = 'ICMP ALL'

# update DFW rules task name used to check if the task completed successfully
UPDATE_DFW_RULES_TASK_NAME = 'vdcGroupDfwRulesUpdate'

# Applied to list for DFW
APPLIED_TO_LIST = ['VDC', 'Network']

# query to check parentnetwork
QUERY_EXTERNAL_NETWORK = '?filterEncoded=true&filter=((parentNetworkId.id=={}))'

# query to check the scope of external network
SCOPE_EXTERNAL_NETWORK_QUERY = 'filterEncoded=true&filter=(_context=={})'

# Qurey API tp get vlan id of the port groups

GET_PORTGROUP_VLAN_ID ='query?type=portgroup&filter=(moref=={})'

# Default page size for query APIs
DEFAULT_QUERY_PAGE_SIZE = 25

# Query API and Page size for named disk
GET_NAMED_DISK_BY_VDC = 'query?type=disk&filter=(((vdc=={})))'

# API to move Disk
DISK_MOVE = 'action/moveDisk'

# Task type for JSON requests
JSON_TASK_TYPE = 'application/vnd.vmware.vcloud.task+json'

# Constans used to Dump Migration State Log to logfile.
ORG = 'Organization'
SOURCE_ORG_VDC = 'sourceOrgVDC'
SOURCE_ORG_VDC_NW = 'sourceOrgVDCNetworks'
SOURCE_EDGE_GW = 'sourceEdgeGateway'
TARGET_ORG_VDC = 'targetOrgVDC'
TARGET_ORG_VDC_NW = 'targetOrgVDCNetworks'
TARGET_EDGE_GW = 'targetEdgeGateway'
SOURCE_VAPPS = 'SourcevApp'
TARGET_VAPPS = 'TargetvApp'

# vApp data url
VAPP_DATA_URL = 'https://{}/api/query?type=vApp&format=records'

# Query to get vApp data
VAPP_INFO_QUERY = 'query?type=vApp'

# max orgVdc count for shared network migration
MAX_ORGVDC_COUNT = 16

# query to get vAppNetwork
VAPP_NETWORK_QUERY = "query?type=vAppNetwork"

# get edgeCluster data
EDGE_CLUSTER_DATA = 'edgeClusters'

# get vNics details
VNIC = '/vnics'

# Update DHCP forwarder config on edge gateway services
DHCP_FORWARDER = "edgeGateways/{}/dhcpForwarder"

# Filter to get VNic details
VNIC_INDEX = "/vdcNetworks?includeDistributed=false&includeUdlrUplinks=true"
# syslog config uri for edge gateway by id
EDGE_GATEWAY_SYSLOG_CONFIG_BY_ID = "/{}/syslog/config"

# ssh settings ur for edge gateway by id
EDGE_GATEWAY_CLISETTINGS_CONFIG_BY_ID = "/{}/clisettings"

# DHCP Static Binding
DHCP_BINDINGS = "orgVdcNetworks/{}/dhcp/bindings"

# Get all vCenters registered with vCD
GET_VIRTUAL_CENTERS = "virtualCenters"

# Fetch NSXV settings of vCenter
FETCH_VC_NSXV_SETTINGS = "extension/vsm/{}"

# IP Prefix list name
TARGET_BGP_IP_PREFIX_NAME = "v-t migrated IP prefix list"

# Get NSX-T Manager QOS Profiles.
NSX_T_QOS_PROFILE = "nsxTResources/gatewayQoSProfiles?filter=nsxTManagerRef.id=={}"

# Configure Edge gateway QOS profile for rate limit
QOS_PROFILE = "edgeGateways/{}/qos"

# DNS for DLR interface of distributed network.
DLR_DNR_IFACE = "10.255.255.249"

# Get networkPool backing Details
NETWORK_POOL = "networkPools/{}"
VXLAN = "VXLAN"
VLAN = "VLAN"
PORT_GROUP = "PORTGROUP_BACKED"

# Advertised Tier-1 Subnets Connected Segment List
ADVERTISED_SUBNET_LIST = ["TIER1_LB_VIP", "TIER1_NAT", "TIER1_IPSEC_LOCAL_ENDPOINT", "TIER1_STATIC"]

# Admin user
ADMIN_USER = 'system'

# Get Share Permissions for catalog.
GET_CATALOG_SHARE_PERMISSIONS = 'catalog/{}/controlAccess'

# Set Share Permissions fot catalog.
SET_CATALOG_SHARE_PERMISSIONS = 'catalog/{}/action/controlAccess'

# Set Read-Only access of catalog to all ORGS
PUBLISH_CATALOG_READ_ACCESS_TO_ALL_ORG = 'action/publish'

# Catalog Read-Only acccess to all ORGs template
READ_ACCESS_CATALOG_TEMPLATE = 'catalogReadAccessToAllOrgs'