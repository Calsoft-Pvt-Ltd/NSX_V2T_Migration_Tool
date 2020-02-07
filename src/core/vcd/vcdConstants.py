# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which contains all the constants required for VMware Cloud Director Migration from NSX-V to NSX-T
"""

import os

# api header used for legacy api and openapi's
VCD_API_HEADER = 'application/*;version=34.0'

# vcd admin operations legacy api url
XML_ADMIN_API_URL = "https://{}/api/admin/"

# vm Affinity rule url
AFFINITY_URL = "https://{}/api/vdc/{}/vmAffinityRules/"

# eject media url
EJECT_MEDIA_URL = "https://{}/api/vApp/vm-{}/media/action/ejectMedia"

# vcd user operations legacy api url
XML_API_URL = "https://{}/api/"

# vcd open api url
OPEN_API_URL = "https://{}/cloudapi/1.0.0/"

# vcd login url
LOGIN_URL = "https://{}/api/sessions"

# vcd nsv api url
XML_VCD_NSX_API = "https://{}/network/"

# external networks uri
ALL_EXTERNAL_NETWORKS = "externalNetworks"

# org vdc networks uri
ALL_ORG_VDC_NETWORKS = "orgVdcNetworks"

# edge gateways uri
ALL_EDGE_GATEWAYS = "edgeGateways"

# openapi provider vdcs uri
PROVIDER_VDC = "providerVdcs"

# xml api provider vdc uri
PROVIDER_VDC_XML = "providervdc"

# provider vdc compute policies uri
PROVIDER_VDC_PLACEMENT_POLICIES = "pvdcComputePolicies"

# edge gateways URI for specific org vdc uri
EDGE_GATEWAYS_LIST_FOR_GIVEN_ORG_VDC = "edgeGateways?filter=(orgVdc.id=={})&page=1&pageSize=25"

# org vdc network dhcp uri
DHCP_ENABLED_FOR_ORG_VDC_NETWORK_BY_ID = "{}/dhcp"

# disable org vdc uri
ORG_VDC_DISABLE = "vdc/{}/action/disable"

# org vdc affinity rules uri
ORG_VDC_AFFINITY_RULES = "vdc/{}/vmAffinityRules"

# vcd nsxv edge uri
NETWORK_EDGES = "edges"

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

# load balancer config uri for edge gateway by id
EDGE_GATEWAY_LOADBALANCER_CONFIG = "/{}/loadbalancer/config"

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

# updating the exiting metadata key in org vdc by id
UPDATE_METADATA_IN_ORG_VDC_BY_ID_FOR_KEY = "vdc/{}/metadata/{}"

# add storage policy to org vdc by id uri
ADD_STORAGE_POLICY_TO_ORG_VDC_BY_ID = "vdc/{}/vdcStorageProfiles"

# create edge gateway uri
CREATE_EDGE_GATEWAY = "vdc/{}/edgeGateways"

# vcd task operations timeout
VCD_CREATION_TIMEOUT = 360.0

# vcd task operations interval
VCD_CREATION_INTERVAL = 10.0

# api template names:-
# create org vdc network template name used in template.json
CREATE_ORG_VDC_NETWORK_TEMPLATE = 'createOrgVDCNetwork'

# create org vdc edge gateway template name used in template.json
CREATE_ORG_VDC_EDGE_GATEWAY_TEMPLATE = 'createEdgeGateway'

# create org vdc template name used in template.json
CREATE_ORG_VDC_TEMPLATE = 'createOrgVDC'

# compose vapp template name used in template.yml
COMPOSE_VAPP_TEMPLATE = 'composeVapp'

# recompose vapp template name used in template.yml
RECOMPOSE_VAPP_TEMPLATE = 'recomposeVapp'

# undeploy vapp template name used in template.yml
UNDEPLOY_VAPP_TEMPLATE = 'undeployVapp'

# create ipsec template name used in template.json
CREATE_IPSEC_TEMPLATE = 'createIPSecServices'

# create dnat template name used in template.json
CREATE_DNAT_TEMPLATE = 'createDNATServices'

# create snat template name used in template.json
CREATE_SNAT_TEMPLATE = 'createSNATServices'

# create org vdc metadata template name used in template.yml
CREATE_ORG_VDC_METADATA_TEMPLATE = 'createOrgVDCMetadata'

# create org vdc access control template name used in template.yml
CREATE_ORG_VDC_ACCESS_CONTROL_TEMPLATE = 'createOrgVDCAccessControl'

# create affinity template name used in template.yml
CREATE_AFFINITY_RULE_TEMPLATE = 'creatingAffinityRule'

# eject media template name used in template.yml
EJECT_MEDIA_TEMPLATE = 'mediaInsertOrEject'

# recompose compute policy vapp template name used in template.yml
RECOMPOSE_COMPUTE_POLICY_VAPP_TEMPLATE = 'recomposeVappWithComputePolicy'

# recompose placement policy vapp template name used in template.yml
RECOMPOSE_PLACEMENT_POLICY_VAPP_TEMPLATE = 'recomposeVappWithPlacementPolicy'

# recompose sizing policy template name used in template.yml
RECOMPOSE_SIZING_POLICY_VAPP_TEMPLATE = 'recomposeVappWithSizingPolicy'

# compose vapp network template name used in template.yml
COMPOSE_VAPP_NETWORK_CONFIG_TEMPLATE = 'composeVappNetworkConfig'

# component name
COMPONENT_NAME = 'vCloudDirector'

# openapi content type for json
OPEN_API_CONTENT_TYPE = 'application/json'

# content type fro json
GENERAL_JSON_CONTENT_TYPE = 'application/*+json;version=34.0'

# content type for xml
GENERAL_XML_CONTENT_TYPE = 'application/*+xml;charset=UTF-8'

# vapp type string
TYPE_VAPP = 'application/vnd.vmware.vcloud.vApp+xml'

# vapp template type string
TYPE_VAPP_TEMPLATE = 'application/vnd.vmware.vcloud.vAppTemplate+xml'

# vapp media type string
TYPE_VAPP_MEDIA = 'application/vnd.vmware.vcloud.media+xml'

# create vdc task name used to check if the task completed successfully
CREATE_VDC_TASK_NAME = 'vdcCreateVdc'

# create edge gateway task name used to check if the task completed successfully
CREATE_EDGE_GATEWAY_TASK_NAME = 'orgVdcGatewayCreate'

# create org vdc networks task name used to check if the task completed successfully
CREATE_ORG_VDC_NETWORK_TASK_NAME = 'orgVdcNetworkCreate'

# create ipsec vpn tunnel task name used to check if the task completed successfully
CREATE_IPSEC_VPN_TASK_NAME = 'createIpSecVpnTunnel'

# eject media from vm task name used to check if the task completed successfully
EJECT_MEDIA_TASK_NAME = 'vappEjectCdFloppy'

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

# create new metadata entry(key, value) in org vdc task name used to check if the task completed successfully
CREATE_METADATA_IN_ORG_VDC_TASK_NAME = 'metadataUpdate'

# compose vapp task name used to check if the task completed successfully
COMPOSE_VAPP_TASK_NAME = 'vdcComposeVapp'

# xml content type for create org vdc
XML_CREATE_VDC_CONTENT_TYPE = 'application/vnd.vmware.admin.createVdcParams+xml'

# content type for access control
CONTROL_ACCESS_CONTENT_TYPE = "application/vnd.vmware.vcloud.controlAccess+json"

# delete org vdc network by id uri
DELETE_ORG_VDC_NETWORK_BY_ID = "orgVdcNetworks/{}"

# delete edge gateway by id uri
DELETE_EDGE_GATEWAY_BY_ID = "edgeGateways/{}"

# org vdc by id uri
ORG_VDC_BY_ID = "vdc/{}"

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

# compose vApp in specified org vdc uri
COMPOSE_VAPP_IN_ORG_VDC = "vdc/{}/action/composeVApp"

# xml content type for compose vApp
XML_COMPOSE_VAPP = 'application/vnd.vmware.vcloud.composeVAppParams+xml'

# power-off vapp uri
POWER_OFF_VAPP = 'action/undeploy'

# power of vapp task name used to check if the task completed successfully
POWER_OFF_VAPP_TASK = 'vappPowerOff'

# recompose vapp uri
RECOMPOSE_VAPP_API = 'action/recomposeVApp'

# content-type of recompose vapp
XML_RECOMPOSE_VAPP = 'application/vnd.vmware.vcloud.recomposeVAppParams+xml'

# recompose vapp task name used to check if the task completed successfully
RECOMPOSE_VAPP_TASK = 'vdcRecomposeVapp'

# xml content-type of indeploy vapp
XML_UNDEPLOY_VAPP = 'application/vnd.vmware.vcloud.undeployVAppParams+xml'

# undeploy vapp task name used to check if the task completed successfully
UNDEPLOY_VAPP_TASK = 'vappUndeployPowerOff'

# provider vdc storage profile details by id uri
PVDC_STORAGE_PROFILE_DETAILS_BY_ID = "pvdcStorageProfile/{}"

# vmware cloud director storage profile by id uri
VCD_STORAGE_PROFILE_BY_ID = "vdcStorageProfile/{}"

# string to check if the independent key exist or not in source org vdc
INDEPENDENT_DISKS_EXIST_IN_ORG_VDC_TYPE = 'application/vnd.vmware.vcloud.disk+xml'

# compute policy of org vdc by id uri
ORG_VDC_COMPUTE_POLICY = "vdc/{}/computePolicies"

# get vsphere resource pool uri
GET_RESOURCEPOOL_INFO = 'query?type=resourcePool'

# create vm groups by resource pool id uri
CREATE_VMGROUPS = 'extension/resourcePool/{}/vmGroups'

# xml create vmgroups content-type
XML_CREATE_VMGROUPS_CONTENT_TYPE = "application/vnd.vmware.admin.vmwVmGroupType+xml"

# create vm group task name used to check if the task completed successfully
CREATE_VMGROUP_TASK = 'createVmGroup'

# get vsphere vmgroup uri
GET_VMGROUP_INFO = 'query?type=vmGroups'

# create vm group template name used in template.yml
CREATE_VMGROUP_TEMPLATE = 'createVMGroup'

# compose vapp nonetwork template used in template.yml
COMPOSE_VAPP_NONETWORK_TEMPLATE = 'composeVappWithNoNetwork'

# vapp access control get uri
ACCESS_CONTROL = "/controlAccess"

# vapp access control put/post uri
VAPP_ACCESS_CONTROL_SETTINGS = "/action/controlAccess"

# change vapp onwer template name used in template.yml
CHANGE_VAPP_OWNER_TEMPLATE = 'changeVAppOwner'

# vapp owner uri
VAPP_OWNER = "/owner"

# vapp lease settings uri
VAPP_LEASE_SETTINGS = "/leaseSettingsSection"

# renew vapp lease settings template name used in template.yml
RENEW_VAPP_LEASE_SETTINGS_TEMPLATE = 'renewVappLeaseSettings'

# renew vapp lease settings task name used to check if the task completed successfully
RENEW_VAPP_LEASE_SETTINGS_TASK_NAME = 'vdcUpdateVapp'

# vapp metadata uri
METADATA_IN_VAPP = "/metadata"

# create vapp metadata template name used in template.yml
CREATE_VAPP_METADATA_TEMPLATE = 'createMetadataInVapp'

# create vapp metadata task name used to check if the task completed successfully
CREATE_METADATA_IN_VAPP_TASK_NAME = 'metadataUpdate'

# rename vapp template
RENAME_VAPP_TEMPLATE = 'renameVapp'

# rename org vdc template
RENAME_ORG_VDC_TEMPLATE = 'renameOrgVDC'

# rename org vdc task name used to check if the task completed successfully
RENAME_ORG_VDC = 'vdcUpdateVdc'

# page size for application port profiles
APPLICATION_PORT_PROFILES_PAGE_SIZE = 75

# page size for edge gateways
EDGE_GATEWAYS_PAGE_SIZE = 25

# create firewall group uri
CREATE_FIREWALL_GROUP = 'firewallGroups'

# ipset group by id uri
GET_IPSET_GROUP_BY_ID = 'services/ipset/{}'

# create firewall group task name used to check if the task completed successfully
CREATE_FIREWALL_GROUP_TASK_NAME = 'createFirewallGroup'

# create prefix list task name used to check if the task completed successfully
CREATE_PREFIX_LISTS_TASK_NAME = 'bgpConfigUpdate'

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

# get vapp template info uri
GET_VAPP_TEMPLATE_INFO = 'query?type=vAppTemplate'

# page size for vapp template
VAPP_TEMPLATE_PAGE_SIZE = 50

# get media of organization uri
GET_MEDIA_INFO = 'query?type=media'

# page size for media
MEDIA_PAGE_SIZE = 50

# create catalog by organization id uri
CREATE_CATALOG = "org/{}/catalogs"

# create catalog template name used in template/yml
CREATE_CATALOG_TEMPLATE = 'createCatalog'

# xml content-type for create catalog
XML_CREATE_CATALOG = 'application/vnd.vmware.admin.catalog+xml'

# move vapp template name used in template.yml
MOVE_VAPP_TEMPLATE = 'moveCatalogItem'

# move vapp by catalog id uri
MOVE_VAPP = 'catalog/{}/action/move'

# move vdc template
MOVE_VDC_TEMPLATE_TASK = 'vdcCopyTemplate'

# delete catalog task name used to check if the task completed successfully
DELETE_CATALOG_TASK = 'catalogDelete'

# create application port profile task name
CREATE_APPLICATION_PORT_PROFILE_TASK_NAME = 'createAppPortProfile'

# validate dedicated external network filter api uri
VALIDATE_DEDICATED_EXTERNAL_NETWORK_FILTER = '?filter=edgeGatewayUplinks.uplinkId=={}'

# icmptype if any
ICMP_ALL = 'ICMPv4-ALL'

# get icmp port profiles
GET_ICMP_PORT_PROFILES_FILTER = '?filter=(applicationPorts.protocol==ICMPv4)'

# check string for vapps having no vms in it
CHECK_STRING_FOR_EMPTY_VAPPS = 'The requested operation could not be executed since vApp "{}" is not running.'

# source network pool type
VXLAN_NETWORK_POOL_TYPE = 'vmext:VxlanPoolType'

# target network pool type
GENEVE_NETWORK_POOL_TYPE = 'vmext:GenevePoolType'

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

# page size for org vdc compute policy
ORG_VDC_COMPUTE_POLICY_PAGE_SIZE = 25
