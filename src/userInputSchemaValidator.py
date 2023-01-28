# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Yaml user Input file validation data for
    - Migration and
    - v2tAssessment
"""
import re
from schema import Optional
import src.constants as mainConstants


def validateIpAddress(host)-> str:
    '''
    Validate the Ipaddress for VDC, NSXT, NSXV and Vcenter for IP/FQDN
    '''
    isFqdn = not all(address.isdigit() for address in str(host).split("."))
    if isFqdn:
        if len(str(host)) > 255:
            raise Exception("Input IP/FQDN value is empty or has more than 255 characters")
        else:
            if "." in host:
                allowed = re.compile(mainConstants.FQDN_REGEX, re.IGNORECASE)
                if not all(allowed.match(address) for address in host.split(".")):
                    raise Exception("Input FQDN value is not in proper fqdn format")
    else:
        validIp = re.search(mainConstants.VALID_IP_REGEX, host) if host else None
        if not validIp:
            raise Exception("Input IP value is not in proper ip format")
    return host

# Schema for Common section og VDC,NSXT,NSXV,VCenter
componentCommonSchema = {
    "ipAddress": lambda host: validateIpAddress(host),
    "username": str,
    "verify": bool
}

# Schema for Edgegateways
edgeGatewaysSchema = {
    Optional("Tier0Gateways"): str,
    Optional("NoSnatDestinationSubnet"): [str],
    Optional("ServiceEngineGroupName"): str,
    Optional("LoadBalancerVIPSubnet"): str,
    Optional("LoadBalancerServiceNetwork"): str,
    Optional("LoadBalancerServiceNetworkIPv6"): str,
    Optional("AdvertiseRoutedNetworks"): bool,
    Optional("NonDistributedNetworks"): bool,
    Optional("serviceNetworkDefinition"): str,
}

# Migration User Input File Validation Data Schema
userInputValidationMigrationSchema = {
    "VCloudDirector": {
        "Common": componentCommonSchema,
        "Organization": {
            "OrgName": str
        },
        "SourceOrgVDC": [{
            "OrgVDCName": str,
            "NSXVProviderVDCName": str,
            "NSXTProviderVDCName": str,
            "Tier0Gateways": str,
            Optional("LegacyDirectNetwork"): bool,
            Optional("EmptyIPPoolOverride"): bool,
            "NSXTNetworkPoolName": str,
            Optional("NoSnatDestinationSubnet"): [str],
            Optional("ServiceEngineGroupName"): str,
            Optional("LoadBalancerVIPSubnet"): str,
            Optional("LoadBalancerServiceNetwork"): str,
            Optional("LoadBalancerServiceNetworkIPv6"): str,
            Optional("EdgeGatewayDeploymentEdgeCluster"): str,
            Optional("AdvertiseRoutedNetworks"): bool,
            Optional("NonDistributedNetworks"): bool,
            Optional("serviceNetworkDefinition"): str,
            Optional("SkipBGPMigration"): bool,
            Optional("EdgeGateways"): {
                Optional("EdgeGateway1Name"): edgeGatewaysSchema,
                Optional("EdgeGateway2Name"): edgeGatewaysSchema,
            }
        }],
        "ImportedNetworkTransportZone": str,
        "DummyExternalNetwork": str,
        Optional("CloneOverlayIds"): bool,
    },
    "NSXT": {
        "Common": componentCommonSchema,
        "EdgeClusterName": [str]
    },
    "NSXV": {
        "Common": componentCommonSchema
    },
    "Vcenter": {
        "Common": componentCommonSchema
    },
    "Common": {
        "CertificatePath": str,
        "MaxThreadCount": str,
        "TimeoutForVappMigration": str
    }
}


# V2TAssessment User Input File Data Scheam
userInputValidationv2tAssessmentSchema = {
    "VCloudDirector": {
        "ipAddress": lambda host: validateIpAddress(host),
        "username": str,
        "verify": bool
    },
    Optional("OrgVDC"): [
        str,
        {str: str}
    ],
    Optional("Organization"): [str],
    "Common": {
        "CertificatePath": str
    }
}


