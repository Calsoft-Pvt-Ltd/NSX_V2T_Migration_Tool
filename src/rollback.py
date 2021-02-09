# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description : Module performs all the rollback related operations during a failure
"""

import os
import copy

from src.commonUtils.utils import Utilities


class Rollback:
    """
        Description : Class performing rollback related operations during a failure
    """
    def __init__(self, logger):
        """
        Description :   Initializer method of rollback operations
        Parameters  :   logger - logger object for logging the messages (OBJECT)
        """
        # key that decides whick rollback tasks are to be performed
        self.key = None
        self.orgVDCNetworkList = None
        self.logger = logger
        self.utils = Utilities()
        self.executionResult = {}
        self.apiData = {}
        # initializing list of task to be performed for rollback
        self.rollbackTask = ['vcdObj.enableSourceOrgVdc(sourceOrgVDCId)']
        # function call creating all the key values required for rollback
        self._createRollbackKeyValues()
        self.vcdDict = None
        self.mainLogfile = ''
        self.metadata = {}

    def _createRollbackKeyValues(self):
        """
            Description :   Method that creates all the key value pair for rollback tasks
            Flow of rollback:
                1. Enabling the source org vdc
                2. Clearing NSX-T bridging
                3. Disabling the Promiscuous Mode and Forged Mode
                4. Deleting Target Org VDC Networks
                5. Deleting Target Edge Gateway
                6. Reset the target external network
                7. Deleting Target Org-Vdc
                8. Reconnecting Source Org VDC Network to Edge Gateway
                9. Configuring DHCP service in source Edge Gateway
                10. Configuring IPSEC VPN service in source Edge Gateway
                11. Disconnecting dummy-uplink from source Edge Gateway
                12. Deleting metadata from source org vdc
        """
        self.preMigrationValidation = copy.deepcopy(self.rollbackTask)

        self.rollbackTask.extend(['vcdObj.enableSourceAffinityRules()'])
        self.disableSourceAffinityRules = copy.deepcopy(self.rollbackTask)

        self.rollbackTask.extend(['vcdObj.deleteOrgVDC(targetOrgVDCId, rollback=True)'])
        self.createOrgVDC = copy.deepcopy(self.rollbackTask)
        self.applyVDCPlacementPolicy = copy.deepcopy(self.rollbackTask)
        self.applyVDCSizingPolicy = copy.deepcopy(self.rollbackTask)
        self.createACL = copy.deepcopy(self.rollbackTask)
        self.rollbackTask.insert(-1,'vcdObj.deleteOrgVDCGroup()')
        self.createOrgvDCGroup = copy.deepcopy(self.rollbackTask)

        self.rollbackTask.insert(1, 'vcdObj.deleteNsxTBackedOrgVDCEdgeGateways(targetOrgVDCId)', )
        self.rollbackTask.append('vcdObj.resetTargetExternalNetwork(self.vcdDict.NSXTProviderVDCExternalNetwork)')
        self.createEdgeGateway = copy.deepcopy(self.rollbackTask)

        self.rollbackTask.insert(1, 'vcdObj.deleteOrgVDCNetworks(targetOrgVDCId, source=False, rollback=True)')
        self.createOrgVDCNetwork = copy.deepcopy(self.rollbackTask)
        self.disconnectTargetOrgVDCNetwork = copy.deepcopy(self.rollbackTask)

        self.rollbackTask.insert(1, 'vcdObj.disablePromiscModeForgedTransmit()')
        self.enablePromiscModeForgedTransmit = copy.deepcopy(self.rollbackTask)
        self.getPortgroupInfo = copy.deepcopy(self.rollbackTask)
        self.migrateMetadata = copy.deepcopy(self.rollbackTask)

        self.rollbackTask.insert(1, 'nsxtObj.clearBridging(targetNetworkList, rollback=True)')
        self.createBridgeEndpointProfile = copy.deepcopy(self.rollbackTask)
        self.createUplinkProfile = copy.deepcopy(self.rollbackTask)
        self.updateEdgeTransportNodes = copy.deepcopy(self.rollbackTask)
        self.attachBridgeEndpointSegment = copy.deepcopy(self.rollbackTask)
        self.verifyBridgeConnectivity = copy.deepcopy(self.rollbackTask)

        self.configTargetIPSEC = copy.deepcopy(self.rollbackTask)
        self.configureTargetNAT = copy.deepcopy(self.rollbackTask)
        self.configureFirewall = copy.deepcopy(self.rollbackTask)
        self.createIPSET = copy.deepcopy(self.rollbackTask)
        self.configBGP = copy.deepcopy(self.rollbackTask)
        self.createBGPNeighbours = copy.deepcopy(self.rollbackTask)
        self.configureDNS = copy.deepcopy(self.rollbackTask)
        self.createBGPFilters = copy.deepcopy(self.rollbackTask)
        self.rollbackTask.insert(0, 'vcdObj.loadBalancerRollback()')
        self.configureLoadBalancer = copy.deepcopy(self.rollbackTask)

        self.rollbackTask.append('vcdObj.disconnectSourceOrgVDCNetwork(orgVDCNetworkList, rollback=True)')
        self.rollbackTask.append('vcdObj.dhcpRollBack()')
        self.rollbackTask.append('vcdObj.ipsecRollBack()')
        self.disconnectSourceOrgVDCNetwork = copy.deepcopy(self.rollbackTask)
        self.rollbackTask.append('vcdObj.reconnectOrDisconnectSourceEdgeGateway(sourceEdgeGatewayId, connect=True)')
        self.reconnectOrDisconnectSourceEdgeGateway = copy.deepcopy(self.rollbackTask)
        self.rollbackTask.append('vcdObj.connectUplinkSourceEdgeGateway(sourceEdgeGatewayId, rollback=True)')
        self.connectUplinkSourceEdgeGateway = copy.deepcopy(self.rollbackTask)
        self.reconnectOrgVDCNetworks = copy.deepcopy(self.rollbackTask)
        self.configureDHCP = copy.deepcopy(self.rollbackTask)
        self.rollbackTask.insert(0, 'vcdObj.increaseScopeOfEdgegateways(rollback=True)')
        self.rollbackTask.insert(0, 'vcdObj.dfwGroupsRollback()')
        self.rollbackTask.insert(0, 'vcdObj.firewallruleRollback()')
        self.increaseScopeOfEdgegateways = copy.deepcopy(self.rollbackTask)
        self.rollbackTask.insert(2, 'vcdObj.increaseScopeforNetworks(rollback=True)')
        self.increaseScopeforNetworks = copy.deepcopy(self.rollbackTask)
        self.rollbackTask.insert(0, 'vcdObj.enableDFWinOrgvdcGroup(rollback=True)')
        self.enableDFWinOrgvdcGroup = copy.deepcopy(self.rollbackTask)
        self.rollbackTask.insert(0, 'vcdObj.dfwRulesRollback(rollback=True)')
        self.configureDFW = copy.deepcopy(self.rollbackTask)
        self.reconnectTargetEdgeGateway = copy.deepcopy(self.rollbackTask)
        self.rollbackTask.insert(1, 'vcdObj.moveVapp(targetOrgVDCId, sourceOrgVDCId, orgVDCNetworkList, timeout, rollback=True)',)
        self.moveVapp = copy.deepcopy(self.rollbackTask)

    def perform(self, vcdObj, vcdValidationObj, nsxtObj, rollbackTasks=None):
        """
            Description : Method that performs the rollback of setup during a failure
            Parameters  : vcdObj - object of vcdOperations (object)
                          vcdValidationObj - object of vcdValidations (object)
                          nsxtObj - object of nsxtOperations (object)
                          rollbackTasks - List to tasks to be performed for rollback (LIST)
        """
        try:
            # getting the source org vdc urn
            sourceOrgVDCId = self.apiData.get('sourceOrgVDC', {}).get('@id')

            if sourceOrgVDCId:
                # getting source network list from metadata
                orgVDCNetworkList = vcdObj.retrieveNetworkListFromMetadata(sourceOrgVDCId, orgVDCType='source')

            # getting the target org vdc urn
            targetOrgVDCId = self.apiData.get('targetOrgVDC', {}).get('@id')

            if targetOrgVDCId:
                # allow rollback if there are no vapps on target Org VDC
                if self.key == 'moveVapp' and not vcdObj.getOrgVDCvAppsList(targetOrgVDCId):
                    self.moveVapp = copy.deepcopy(self.rollbackTask)

                # getting source edge gateway id from metadata
                sourceEdgeGatewayId = self.apiData.get('sourceEdgeGatewayId')
                # getting target network list from metadata
                dfwStatus = True if self.apiData.get('OrgVDCGroupID') else False
                targetNetworkList = vcdObj.retrieveNetworkListFromMetadata(targetOrgVDCId, orgVDCType='target', dfwStatus=dfwStatus)
                timeout = self.vcdDict.TimeoutForVappMigration
        except:
            pass

        try:
            # List of tasks to be performed as part of rollback
            listOfRollbackTasks = []
            if rollbackTasks:
                self.logger.info("Continuing rollback from its last failed state")
                listOfRollbackTasks = rollbackTasks
            # Checking if rollback key exists
            elif self.key:
                self.logger.info("Performing rollback")
                listOfRollbackTasks = getattr(self, self.key)
            if listOfRollbackTasks:
                # List of task left to pe performed as part of rollback
                rollbackTasksLeft = copy.deepcopy(listOfRollbackTasks)
                # Iterating over the list of rollback tasks corresponding the rollback key
                for rollbackTask in listOfRollbackTasks:
                    # Performing rollback task
                    eval(rollbackTask)
                    # Removing task from rollback tasks left list after the task has been performed successfully
                    rollbackTasksLeft.pop(0)
        except AttributeError:
            self.logger.error('Rollback is not supported in current state. Please perform manual rollback.')
            # Saving the list of tasks left as part of rollback in metadata to continue rollback from the same step
            vcdObj.createMetaDataInOrgVDC(sourceOrgVDCId,
                                          metadataDict={'rollbackTasks': rollbackTasksLeft}, domain='system')
        except Exception as error:
            self.logger.exception(error)
            # Saving the list of tasks left as part of rollback in metadata to continue rollback from the same step
            vcdObj.createMetaDataInOrgVDC(sourceOrgVDCId,
                                          metadataDict={'rollbackTasks': rollbackTasksLeft}, domain='system')
            self.logger.error("Rollback failed, manual rollback required or use --rollback parameter to retry rollback again.")
        else:
            # Deleting metadata created in the source org vdc after rollback
            vcdObj.deleteMetadata(sourceOrgVDCId)
            self.logger.info("Rollback completed successfully.")
        finally:
            # logging out vcd user
            vcdObj.deleteSession()
            # clear the requests certificates entries
            self.utils.clearRequestsPemCert()
            #self.logger.critical("VCD V2T Migration Tool failed due to errors. For more details, please refer "
            #                     "main log file {}".format(self.mainLogfile))
            # Exiting the migrator after rollback
            os._exit(0)
