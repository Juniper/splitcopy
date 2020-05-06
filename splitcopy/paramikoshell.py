# stdlib
import datetime
import os
import re
import socket
import getpass
import warnings
import logging
import time
import traceback
from select import select

# 3rd Party
import paramiko
from cryptography import utils
from paramiko.ssh_exception import (
    SSHException,
    ChannelException,
    BadHostKeyException,
    AuthenticationException,
    BadAuthenticationType,
    PasswordRequiredException,
)

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
warnings.simplefilter("ignore", utils.CryptographyDeprecationWarning)

_SHELL_PROMPT = re.compile("(% |# |\$ |> |%\t)$")
_SELECT_WAIT = 0.1
_RECVSZ = 1024

logger = logging.getLogger(__name__)


class SSHShell:
    """ class providing ssh connectivity using paramiko lib
    """

    def __init__(self, **kwargs):
        """ Initialise the SSHShell class
        """
        self.host = kwargs.get("host")
        self.user = kwargs.get("user")
        self.passwd = kwargs.get("passwd")
        self.key_filename = kwargs.get("ssh_key")
        self._sock = None
        self._chan = None
        self._session = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_ty, exc_val, exc_tb):
        self.close()

    def open(self):
        """
        This process opens a
        :class:`paramiko.SSHClient` instance.
        """
        self._session = self.session_open()

    def session_open(self):
        """ opens a paramiko.SSHClient instance
            handles both key and password based authentication
            :return: paramiko.SSHClient instance
        """
        logger.debug("entering session_open()")
        kwargs = {"hostname": self.host, "username": self.user}
        ssh_client = paramiko.SSHClient()
        ssh_client.load_system_host_keys()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_config = os.path.expanduser("~/.ssh/config")
        ask_pass = False
        key_found = False
        if (
            os.path.isfile(os.path.expanduser("~/.ssh/id_rsa"))
            or os.path.isfile(os.path.expanduser("~/.ssh/id_dsa"))
            or os.path.isfile(os.path.expanduser("~/.ssh/id_ecdsa"))
        ):
            key_found = True

        if os.path.isfile(ssh_config):
            config = paramiko.SSHConfig()
            with open(ssh_config) as open_ssh_config:
                config.parse(open_ssh_config)
            config = config.lookup(self.host)
            if config.get("proxycommand"):
                self._sock = paramiko.proxy.ProxyCommand(config.get("proxycommand"))
                kwargs.update({"sock": self._sock})

        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        logger.debug("ssh agent has {} keys".format(len(agent_keys)))

        if self.passwd is not None:
            kwargs.update(
                {"password": self.passwd, "allow_agent": False, "look_for_keys": False}
            )
        elif self.user != getpass.getuser():
            print(
                "skipping publickey ssh auth as {} != {}".format(
                    self.user, getpass.getuser()
                )
            )
            kwargs.update({"allow_agent": False, "look_for_keys": False})
            ask_pass = True
        elif self.key_filename is not None:
            kwargs.update(
                {
                    "key_filename": self.key_filename,
                    "allow_agent": False,
                    "look_for_keys": False,
                    "password": None,
                }
            )
            # paramiko is a little broken (see github issue #1664) 
            # work around by always asking for passphrase here
            # else "SSHException: encountered RSA key, expected OPENSSH key" error
            # when key has passphrase
            passphrase = getpass.getpass(
                prompt="ssh key passphrase (Enter for None): ", stream=None
            )
            if passphrase != "":
                kwargs.update({"passphrase": passphrase})
        elif len(agent_keys) == 0 and not key_found:
            print("no ssh keys found, nor ssh agent running, skipping publickey ssh auth")
            kwargs.update({"allow_agent": False, "look_for_keys": False})
            ask_pass = True

        if ask_pass:
            self.passwd = getpass.getpass(
                prompt="{}@{}'s password: ".format(self.user, self.host), stream=None
            )
            kwargs["password"] = self.passwd

        try:
            ssh_client.connect(**kwargs)
        except PasswordRequiredException:
            passphrase = getpass.getpass(
                prompt="ssh key passphrase (Enter for None): ", stream=None
            )
            if passphrase != "":
                kwargs.update({"passphrase": passphrase})
                ssh_client.connect(**kwargs)
        return ssh_client

    def get_transport(self, ssh_client):
        if ssh_client is None:
            raise SSHException("get_transport(), ssh_client was None")
        transport = ssh_client.get_transport()
        return transport

    def stdout_read(self, timeout):
        """ reads data off the socket
            :param timeout: amount of time before timeout is raised
            :type: int
            :returns output: stdout from the cmd
            :type: string
        """
        chan = self._chan
        now = datetime.datetime.now()
        timeout_time = now + datetime.timedelta(seconds=timeout)
        output = ""
        while not _SHELL_PROMPT.search(output):
            rd, wr, err = select([chan], [], [], _SELECT_WAIT)
            if rd:
                data = chan.recv(_RECVSZ)
                output += data.decode()
            if datetime.datetime.now() > timeout_time:
                raise TimeoutError
        return output

    def set_keepalive(self):
        """ ensures session stays up if inactive for long period
            not suitable for scp, will terminate session with BadUseError if enabled
            :return: None
        """
        self._session._transport.set_keepalive(60)

    def channel_open(self):
        """ opens an ssh channel on top of an ssh session
            :return: None
        """
        self._chan = self._session.invoke_shell()

    def write(self, cmd):
        """ Sends a cmd + newline char over the channel
            :param cmd: cmd to be sent over the channel
            :type: string
        """
        self._chan.send("{}\n".format(cmd))
        logger.debug("sent '{}'".format(cmd))

    def close(self):
        """ terminates both the channel (if present) and the underlying session
            :return: None
        """
        if self._chan is not None:
            self._chan.close()
        if self._session is not None:
            self._session.close()

    def run(self, cmd, timeout=30, exitcode=True):
        """ sends a cmd to remote host, if exitcode is True will check its exit status
            :param cmd: cmd to run on remote host
            :type: string
            :param timeout: amount of time before timeout is raised
            :type: float
            :param exitcode: toggles whether to check for exit status or not
            :type: bool
            :return result: whether successful or not
            :type: bool
            :return stdout: the output of the command
            :type: string
        """
        result = False
        self.write(cmd)
        stdout = self.stdout_read(timeout)

        if exitcode:
            self.write("echo $?".format(cmd))
            rc = self.stdout_read(timeout)
            if re.search(r"\r\n0\r\n", rc, re.MULTILINE):
                result = True
        elif stdout is not None and stdout != "":
            result = True
        return result, stdout
