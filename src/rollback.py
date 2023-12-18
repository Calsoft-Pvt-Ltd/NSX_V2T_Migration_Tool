# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description : Module performs all the rollback related operations during a failure
"""

import copy
import threading
import traceback

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
        # self.key = None
        self.orgVDCNetworkList = None
        self.logger = logger
        self.utils = Utilities()
        self.executionResult = {}
        self.apiData = {}
        # initializing list of task to be performed for rollback
        self.vcdDict = None
        self.timeoutForVappMigration = 3600
        self.mainLogfile = ''
        self.metadata = {}
        # function call creating all the key values required for rollback
        self._createRollbackKeyValues()

    def _createRollbackKeyValues(self):
        """
        Description :   Method that creates all the key value pair for rollback tasks
        """
        # All these tasks should be completed for all Org VDCs before deleting DC groups.
        # Hence task to delete DC groups is not included here.
        self.preRollbackTasks = [
            'vcdObj.setStaticRoutesScope(rollback=True)',
            'vcdObj.disconnectTargetOrgVDCNetwork(rollback=True)',
            'vcdObj.reconnectTargetEdgeGateway(reconnect=False)',
            'vcdObj.reconnectOrDisconnectSourceEdgeGateway(sourceEdgeGatewayId, connect=True)',
            'vcdObj.connectUplinkSourceEdgeGateway(sourceEdgeGatewayId, rollback=True)',
            'vcdObj.disconnectSourceOrgVDCNetwork(orgVDCNetworkList, sourceEdgeGatewayId, rollback=True)',
            'vcdObj.setStaticRoutesInterfaces(rollback=True)',
            'vcdObj.dhcpRollBack()',
            'vcdObj.ipsecRollBack()',
        ]

        self.rollbackTaskDfw = [
            'vcdObj.disableTargetOrgVDC(rollback=True)',
            'vcdObj.enableDFWinOrgvdcGroup(rollback=True)',
            'vcdObj.dfwGroupsRollback()',
            'vcdObj.securityTagsRollback()',
            'vcdObj.increaseScopeforNetworks(rollback=True)',
            'vcdObj.increaseScopeOfEdgegateways(rollback=True)',
        ]

        self.rollbackTask = [
            'vcdObj.loadBalancerRollback()',
            'vcdObj.enableSourceOrgVdc(sourceOrgVDCId)',
            'vcdObj.directNetworkIpCleanup()',
            'vcdObj.disablePromiscModeForgedTransmit()',
            'nsxtObj.deleteLogicalSegments()',
            'vcdObj.deleteOrgVDCGroup()',
            'vcdObj.deleteOrgVDCNetworks(targetOrgVDCId, rollback=True)',
            'vcdObj.deleteNsxTBackedOrgVDCEdgeGateways(targetOrgVDCId)',
            'vcdObj.releaseFloatingIps()',
            'vcdObj.releaseIpPrefixes()',
            'vcdObj.deleteIpPrefixAddedToIpSpaceUplinks()',
            'vcdObj.removeManuallyAddedUplinks()',
            'vcdObj.deletePrivateIpSpaces()',
            'vcdObj.directNetworkIpCleanup(key="segmentBackedNetworkIP")',
            'vcdObj.enableSourceAffinityRules()',
            'vcdObj.deleteOrgVDC(targetOrgVDCId, rollback=True)',
            'vcdObj.resetTargetExternalNetwork()',
        ]

    def perform(self, vcdObj, nsxtObj, vcdObjList, rollbackTasks=None, preRollback=False):
        """
            Description : Method that performs the rollback of setup during a failure
            Parameters  : vcdObj - object of vcdOperations (object)
                          nsxtObj - object of nsxtOperations (object)
                          rollbackTasks - List to tasks to be performed for rollback (LIST)
        """
        sourceOrgVDCId, orgVDCNetworkList, targetOrgVDCId, sourceEdgeGatewayId, targetNetworkList = str(), list(), str(), str(), list()
        if preRollback and vcdObj.rollback.metadata.get("preRollback"):
            return

        try:
            timeout = self.timeoutForVappMigration

            # Performing rollback task
            threading.current_thread().name = vcdObj.orgVdcInput["OrgVDCName"]
            # getting the source org vdc urn
            sourceOrgVDCId = self.apiData.get('sourceOrgVDC', {}).get('@id', str())

            if sourceOrgVDCId:
                # getting source network list from metadata
                orgVDCNetworkList = vcdObj.retrieveNetworkListFromMetadata(sourceOrgVDCId, orgVDCType='source')

            # getting the target org vdc urn
            targetOrgVDCId = self.apiData.get('targetOrgVDC', {}).get('@id')

            if targetOrgVDCId:
                # getting source edge gateway id from metadata
                sourceEdgeGatewayId = self.apiData.get('sourceEdgeGatewayId')
                # getting target network list from metadata
                dfwStatus = True if self.apiData.get('OrgVDCGroupID') else False
                targetNetworkList = vcdObj.retrieveNetworkListFromMetadata(targetOrgVDCId, orgVDCType='target', dfwStatus=dfwStatus)
        except:
            pass

        try:
            # List of tasks to be performed as part of rollback
            listOfRollbackTasks = []
            if rollbackTasks:
                self.logger.info("Continuing rollback from its last failed state")
                listOfRollbackTasks = rollbackTasks
            # Checking if rollback key exists
            else:
                listOfRollbackTasks = self.preRollbackTasks if preRollback else self.rollbackTask
            if listOfRollbackTasks:
                # List of task left to pe performed as part of rollback
                rollbackTasksLeft = copy.deepcopy(listOfRollbackTasks)
                # Iterating over the list of rollback tasks corresponding the rollback key
                for rollbackTask in listOfRollbackTasks:
                    # Performing rollback task
                    threading.current_thread().name = vcdObj.orgVdcInput["OrgVDCName"]

                    eval(rollbackTask)
                    # Removing task from rollback tasks left list after the task has been performed successfully
                    rollbackTasksLeft.pop(0)
                    # Saving the remaining rollback tasks in metadata
                    if preRollback:
                        vcdObj.createMetaDataInOrgVDC(sourceOrgVDCId, metadataDict={'preRollbackTasks': rollbackTasksLeft},
                                                      domain='system')
                    else:
                        vcdObj.createMetaDataInOrgVDC(sourceOrgVDCId, metadataDict={'rollbackTasks': rollbackTasksLeft},
                                                      domain='system')

        except AttributeError as err:
            self.logger.debug(traceback.format_exc())
            self.logger.error('Rollback is not supported in current state. Please perform manual rollback.')
            # Saving the list of tasks left as part of rollback in metadata to continue rollback from the same step
            if preRollback:
                vcdObj.createMetaDataInOrgVDC(sourceOrgVDCId, metadataDict={'preRollbackTasks': rollbackTasksLeft},
                                              domain='system')
            else:
                vcdObj.createMetaDataInOrgVDC(sourceOrgVDCId, metadataDict={'rollbackTasks': rollbackTasksLeft},
                                              domain='system')
            raise
        except Exception as error:
            self.logger.exception(error)
            self.logger.debug(traceback.format_exc())
            # Saving the list of tasks left as part of rollback in metadata to continue rollback from the same step
            if preRollback:
                vcdObj.createMetaDataInOrgVDC(sourceOrgVDCId, metadataDict={'preRollbackTasks': rollbackTasksLeft},
                                              domain='system')
            else:
                vcdObj.createMetaDataInOrgVDC(sourceOrgVDCId, metadataDict={'rollbackTasks': rollbackTasksLeft},
                                              domain='system')
            self.logger.error("Rollback failed, manual rollback required or use --rollback parameter to retry rollback again.")
            raise
        else:
            if not preRollback:
                # Deleting metadata created in the source org vdc after rollback
                vcdObj.deleteMetadata(sourceOrgVDCId)
                self.logger.info("Rollback completed successfully.")
            else:
                vcdObj.deleteMetadataApiCall(key='preRollbackTasks-system-v2t',
                                             orgVDCId=vcdObj.rollback.apiData.get('sourceOrgVDC', {}).get('@id'))
                vcdObj.createMetaDataInOrgVDC(sourceOrgVDCId, metadataDict={'preRollback': True}, domain='system')

    def performDfwRollback(self, vcdObj):
        """
            Description : Method that performs the rollback of setup during a failure
            Parameters  : vcdObj - object of vcdOperations (object)
        """
        threading.current_thread().name = vcdObj.orgVdcInput["OrgVDCName"]
        sourceOrgVDCId = self.apiData.get('sourceOrgVDC', {}).get('@id', str())
        # List of tasks to be performed as part of rollback
        rollbackTasksDfw = self.metadata.get('rollbackTasksDfw')
        if rollbackTasksDfw is not None:
            self.logger.info("Continuing rollback from its last failed state")
            listOfRollbackTasks = rollbackTasksDfw
        else:
            listOfRollbackTasks = self.rollbackTaskDfw

        # List of task left to pe performed as part of rollback
        rollbackTasksLeft = copy.deepcopy(listOfRollbackTasks)

        try:
            for rollbackTask in listOfRollbackTasks:
                # Performing rollback task
                threading.current_thread().name = vcdObj.orgVdcInput["OrgVDCName"]
                eval(rollbackTask)

                # Removing task from rollback tasks left list after the task has been performed successfully and
                # Saving the remaining rollback tasks in metadata
                rollbackTasksLeft.pop(0)
                vcdObj.createMetaDataInOrgVDC(
                    sourceOrgVDCId, metadataDict={'rollbackTasksDfw': rollbackTasksLeft}, domain='system')
        except AttributeError as err:
            self.logger.error('Rollback is not supported in current state. Please perform manual rollback.')
            # Saving the list of tasks left as part of rollback in metadata to continue rollback from the same step
            vcdObj.createMetaDataInOrgVDC(
                sourceOrgVDCId, metadataDict={'rollbackTasksDfw': rollbackTasksLeft}, domain='system')
            raise
        except Exception as error:
            self.logger.exception(error)
            self.logger.debug(traceback.format_exc())
            # Saving the list of tasks left as part of rollback in metadata to continue rollback from the same step
            vcdObj.createMetaDataInOrgVDC(
                sourceOrgVDCId, metadataDict={'rollbackTasksDfw': rollbackTasksLeft}, domain='system')
            self.logger.error(
                "Rollback failed, manual rollback required or use --rollback parameter to retry rollback again.")
            raise

