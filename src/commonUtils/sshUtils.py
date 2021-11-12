# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: This module performs ssh related operations using Paramiko
"""

import time
import socket
import paramiko

SSH_CONNECTION_TIMEOUT = 120
SSH_CONNECTION_CHECK_INTERVAL = 10


class SshUtils():
    """
    Description :
        This class provides commonly used ssh methods, it takes care of the open and close SSH session
        and any channels that tied to it.
    """
    # error strings(in lower case) that might contains in the command output.
    ERRORSTRs = ['invalid command', 'invalid parameter']

    def __init__(self, ip, username, password, port=22, retry=False):
        """
        Description : This function init a SshUtil object.
        Parameters  : ip        - IP of the target component t(STRING)
                      username  - Username of the target component(STRING)
                      password  - Password of the target component(STRING)
                      port      - ssh port(INTEGER)
        """
        # Initialize
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.ssh = None
        self.chan = None
        self.errorFlag = False
        self.retryConnection = retry

        # create a SSH session
        self.ssh = self.__sshConnect()

    def __sshConnect(self):
        """
        Description : This function creates a secure connection to a host.
        Return      : newly created SSH Client (OBJECT)
        """
        # Connect to an SSH server and authenticate to it.
        ssh = paramiko.SSHClient()

        # Set the policy to use when connecting to a server that does not have a host key in either the system or
        # local HostKeys objects.
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connectTime = 0.0
        status = False

        while connectTime < SSH_CONNECTION_TIMEOUT and not status:
            try:
                # Connect to the remote server, timeout default is none
                ssh.connect(self.ip, self.port, self.username, self.password)
                status = True
                break
            except (paramiko.AuthenticationException, paramiko.BadHostKeyException, paramiko.SSHException, socket.error):
                if self.retryConnection:
                    pass
                else:
                    break
            time.sleep(SSH_CONNECTION_CHECK_INTERVAL)
            connectTime += SSH_CONNECTION_CHECK_INTERVAL
        if status:
            pass
        else:
            msg = "Failed to create SSH connection to host {}".format(self.ip)
            raise Exception(msg)
        return ssh

    def runCmdOnSsh(self, cmd, timeout=None, reconnect=False, checkExitStatus=False):
        """
        Description :   This function run command on a given ssh client.
        Parameters  :   cmd             - command to be executed. (STRING)
                        timeout         - timeout value for execution. default to None(INT/FLOAT)
                        reconnect       - new connection regardless connection alive or not. default to True. (BOOL)
                        checkExitStatus - Check the exit status of command. If it's true raise exception for nonzero exit
                                          status. Default value is False (BOOL) (OPTIONAL)
        Return      :   output          - coutput from executing the command ( STRING )
        Raises      :   NonZeroExitCodeError if checkExitStatus is set to True and SSH command exited with Non Zero Status (EXCEPTION)
        """
        try:
            # New SSH connection if needed.
            if reconnect or not self.__checkAlive:
                self.sshConnectionReset()

            # Executing the commands given
            ssh_stdout = self.ssh.exec_command(cmd, timeout=timeout)[1]
            output = ssh_stdout.read().decode("utf-8")
            output = output.encode('ascii', 'ignore')

            # Check Exit Status of Executed Command if checkExitStatus flag is True
            if checkExitStatus:
                # Get exit Status of Executed Command. If SSH command is executed successfully, it's value will be 0.
                commandExitStatus = ssh_stdout.channel.recv_exit_status()
                if commandExitStatus:
                    raise Exception(f"Command failed with exit code {commandExitStatus} and with output '{output}'")
            return output
        except (paramiko.SSHException, socket.error) as e:
            msg = "Caught exception with type: {}, error: {}".format(type(e), str(e))
            raise Exception(msg)

    def __checkAlive(self):
        """
        Description : This function check whether SSH session is still alive
        Return      : True or False (BOOL)
        """
        transport = self.ssh.get_transport() if self.ssh else None
        return transport and transport.is_active()

    def sshConnectionReset(self):
        """
        Description : This function create a new SSH connection.
        Return      : True or False ( BOOL)
        """
        # close the existing connection if exist.
        if self.__checkAlive():
            self.ssh.close()
            self.ssh = None
            self.chan = None
        self.ssh = self.__sshConnect()
