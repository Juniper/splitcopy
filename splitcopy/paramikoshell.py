""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

# stdlib
import datetime
import os
import re
import socket
import getpass
import warnings
import logging
import traceback
import sys
from select import select

# 3rd Party
import paramiko
from cryptography import utils
from paramiko.ssh_exception import (
    SSHException,
    PasswordRequiredException,
    AuthenticationException,
    BadAuthenticationType,
)

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
warnings.simplefilter("ignore", utils.CryptographyDeprecationWarning)

_SHELL_PROMPT = re.compile(r"(% |# |\$ |> |%\t)$")
_SELECT_WAIT = 0.1
_RECVSZ = 1024

logger = logging.getLogger(__name__)


class SSHShell:
    """class providing ssh connectivity using paramiko lib"""

    def __init__(self, **kwargs):
        """Initialise the SSHShell class"""
        self.kwargs = kwargs
        logger.debug(self.kwargs)
        self.hostname = self.kwargs.get("hostname")
        self.username = self.kwargs.get("username")
        self.ssh_port = self.kwargs.get("ssh_port")
        self._chan = None
        self._transport = None

    def __enter__(self):
        return self

    def __exit__(self, exc_ty, exc_val, exc_tb):
        self.close()

    def socket_open(self):
        """
        wrapper around proxy or direct methods
        :returns: sock
        :type: object
        """
        logger.info("entering socket_open()")
        sock = self.socket_proxy()
        if not sock:
            sock = self.socket_direct()
        return sock

    def socket_proxy(self):
        """
        checks the .ssh/config file for any proxy commands to reach host
        :returns: sock
        :type: subprocess
        """
        logger.info("entering socket_proxy()")
        sock = None
        ssh_config = os.path.expanduser("~/.ssh/config")
        if os.path.isfile(ssh_config):
            config = paramiko.SSHConfig()
            with open(ssh_config) as open_ssh_config:
                config.parse(open_ssh_config)
            host_config = config.lookup(self.hostname)
            if host_config.get("proxycommand"):
                sock = paramiko.proxy.ProxyCommand(host_config.get("proxycommand"))
        return sock

    def socket_direct(self):
        """
        open a socket to remote host
        :returns: sock
        :type: socket object
        """
        logger.info("entering socket_direct()")
        try:
            sock = socket.create_connection((self.hostname, self.ssh_port), 10)
        except (socket.gaierror, socket.herror):
            raise ConnectionError("address or hostname not reachable")
        except (socket.timeout, ConnectionRefusedError, IOError, OSError):
            raise ConnectionError(f"error connecting to remote host on port {self.ssh_port}")
        return sock

    def get_pkey_from_file(self, pkey_type, pkey_path):
        """
        attempt to decode the private key
        :param pkey_type: key algorithm
        :type: string
        :param pkey_path: path to key file
        :type: string
        :returns: Pkey object
        :raises: PasswordRequiredException if key cannot be decoded
        """
        pkey = None
        try:
            if pkey_type == "RSA":
                pkey = paramiko.RSAKey.from_private_key_file(filename=pkey_path)
            elif pkey_type == "DSA":
                pkey = paramiko.DSSKey.from_private_key_file(filename=pkey_path)
            elif pkey_type == "EC":
                pkey = paramiko.ECDSAKey.from_private_key_file(filename=pkey_path)
            elif pkey_type == "OPENSSH":
                pkey = paramiko.Ed25519Key.from_private_key_file(filename=pkey_path)
        except PasswordRequiredException:
            raise
        except AttributeError:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            print(
                f"{pkey_type} key found, this paramiko version is missing support "
                f"for {pkey_type} keys"
            )
        return pkey

    def transport_open(self, sock):
        """
        opens a transport to the host
        :param: sock
        :type: either a socket object, or if a proxy is used, a subprocess
        :returns: paramiko Transport instance
        """
        self._transport = paramiko.Transport(sock)
        self._transport.start_client()
        return self._transport

    def worker_thread_auth(self):
        """
        authentication has succeeded previously, simplify nth time around
        :returns: bool
        """
        result = False
        auth_method = self.kwargs.get("auth_method")
        if auth_method == "agent":
            self.auth_using_agent()
        elif auth_method == "publickey":
            self.auth_using_provided_keyfile()
        elif auth_method == "keyboard-interactive":
            self.auth_using_keyb()
        else:
            self.password_auth()

        if self.is_authenticated():
            result = True
        return result

    def main_thread_auth(self):
        """
        determines what authentication methods the server supports
        attempts the available authentication methods in order:
        * publickey auth
        * keyboard-interactive auth
        * password auth
        :returns: bool
        """
        logger.info("entering main_thread_auth()")
        allowed_types = None
        result = False
        try:
            self._transport.auth_none(self.kwargs["username"])
        except BadAuthenticationType as e:
            allowed_types = e.allowed_types
        if allowed_types is None:
            raise SSHException("no authentication methods possible")
        logger.info(allowed_types)

        for auth_type in allowed_types:
            logger.info(f"trying auth method {auth_type}")
            if auth_type == "publickey" and self.kwargs["key_filename"] is None:
                if self.auth_using_agent():
                    self.kwargs["auth_method"] = "agent"
                    break
                if self.auth_using_keyfiles():
                    self.kwargs["auth_method"] = "publickey"
                    break
            elif auth_type == "publickey" and self.kwargs["key_filename"]:
                if self.auth_using_provided_keyfile():
                    self.kwargs["auth_method"] = "publickey"
                    break
            elif auth_type == "keyboard-interactive" and self.auth_using_keyb():
                self.kwargs["auth_method"] = "keyboard-interactive"
                break
            elif auth_type == "password" and self.password_auth():
                self.kwargs["auth_method"] = "password"
                break

        if self.is_authenticated():
            print("ssh authentication succeeded")
            result = True
        return result

    def ask_password(self):
        """
        obtains the password for PasswordAuthentication
        :returns: password
        :type: string
        :returns: None
        """
        logger.info("entering ask_password()")
        password = getpass.getpass(
            prompt=f"{self.username}@{self.hostname}'s password: ",
            stream=None,
        )
        return password

    def password_auth(self):
        """
        attempts Password Authentication
        :raises: AuthenticationException if auth fails
        :returns: bool
        """
        logger.info("entering password_auth()")
        result = False
        if not self.kwargs["password"]:
            self.kwargs["password"] = self.ask_password()
        try:
            self._transport.auth_password(
                username=self.kwargs["username"], password=self.kwargs["password"]
            )
            result = True
        except AuthenticationException:
            logger.info("password authentication failed")
        return result

    def auth_using_keyb(self):
        """
        Attempts keyboard-interactive authentication
        :returns: bool
        """
        logger.info("entering auth_using_keyb()")
        result = False
        if not self.kwargs["password"]:
            self.kwargs["password"] = self.ask_password()

        def handler(title, instructions, fields):
            logger.debug(fields)
            if len(fields) > 1:
                raise SSHException("keyboard-interactive authentication failed.")
            if len(fields) == 0:
                return []
            return [self.kwargs["password"]]

        try:
            username = self.kwargs["username"]
            self._transport.auth_interactive(username, handler)
            result = True
        except AuthenticationException:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            logger.info("keyboard-interactive authentication failed")
        return result

    def auth_using_agent(self):
        """
        Attempts publickey authentication using keys held by ssh-agent
        :returns: bool
        """
        logger.info("entering auth_using_agent()")
        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        logger.info(f"ssh agent has {len(agent_keys)} keys")
        result = False
        for pkey in agent_keys:
            pkey_type = pkey.get_name()
            logger.info(f"ssh agent has key type {pkey_type}")
            try:
                self._transport.auth_publickey(self.kwargs["username"], pkey)
                result = True
            except SSHException as err:
                logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                logger.info(f"{pkey_type} key authentication failed with error: {err}")
        return result

    def auth_using_keyfiles(self):
        """
        Attempts publickey authentication using keys found in ~/.ssh
        Iterates over any keys found
        :returns: bool
        """
        logger.info("entering auth_using_keyfiles()")
        pkey_types = {
            "RSA": "id_rsa",
            "DSA": "id_dsa",
            "EC": "id_ecdsa",
            "OPENSSH": "id_ed25519",
        }
        pkey_files = []
        result = False
        for pkey_type in pkey_types:
            path = os.path.expanduser(f"~/.ssh/{pkey_types[pkey_type]}")
            if os.path.isfile(path):
                pkey_files.append((pkey_type, path))
        logger.debug(f"key files found: {pkey_files}")
        for pkey_file in pkey_files:
            pkey_type, pkey_path = pkey_file[0], pkey_file[1]
            try:
                if self.key_auth_common(pkey_type, pkey_path):
                    self.kwargs.update({"key_filename": pkey_path})
                    result = True
                    break
            except PasswordRequiredException:
                continue
        return result

    def key_auth_common(self, pkey_type, pkey_path):
        """
        Attempts authentication using specified key and type
        :param pkey_type: key algorithm
        :type: string
        :param pkey_path: path to key file
        :type: string
        :returns: bool
        """
        result = False
        pkey = None
        try:
            pkey = self.get_pkey_from_file(pkey_type, pkey_path)
        except PasswordRequiredException:
            logger.info(f"key {pkey_path} has a passphrase")
            raise
        if pkey is not None:
            try:
                self._transport.auth_publickey(self.kwargs["username"], pkey)
                result = True
            except SSHException as err:
                self.kwargs.update({"key_filename": None})
                logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                print(f"{pkey_type} key authentication failed with error: {err}")
        return result

    def auth_using_provided_keyfile(self):
        """
        As key type is unknown, attempt publickey authentication
        using provided keyfile by looping through supported types
        :returns: bool
        """
        logger.info("entering auth_using_provided_keyfile()")
        pkey_path = self.kwargs["key_filename"]
        pkey_types = ["RSA", "DSA", "EC", "OPENSSH"]
        result = False
        for pkey_type in pkey_types:
            try:
                if self.key_auth_common(pkey_type, pkey_path):
                    result = True
                    break
            except PasswordRequiredException:
                break
        return result

    def is_authenticated(self):
        """
        verifies if authentication was successful
        :returns: bool
        """
        result = False
        logger.info("entering is_authenticated()")
        if self._transport.is_authenticated():
            result = True
        return result

    def channel_open(self):
        """
        opens a channel of type 'session' over existing transport
        :returns: None
        """
        logger.info("entering channel_open()")
        self._chan = self._transport.open_session()

    def invoke_shell(self):
        """
        opens a pty on remote host
        :returns: None
        """
        logger.info("entering invoke_shell()")
        self._chan.get_pty()
        self._chan.invoke_shell()

    def stdout_read(self, timeout):
        """
        reads data off the socket
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
        """
        ensures session stays up if inactive for long period
        not suitable for scp, will terminate session with BadUseError if enabled
        :returns: None
        """
        self._transport.set_keepalive(60)

    def write(self, cmd):
        """
        Sends a cmd + newline char over the channel
        :param cmd: cmd to be sent over the channel
        :type: string
        :returns: None
        """
        self._chan.send(f"{cmd}\n")
        logger.info(f"sent '{cmd}'")

    def close(self):
        """
        terminates both the channel (if present) and the underlying session
        :returns: None
        """
        if self._chan is not None:
            self._chan.close()
        if self._transport is not None:
            self._transport.close()

    def run(self, cmd, timeout=30, exitcode=True):
        """
        sends a cmd to remote host, if exitcode is True will check its exit status
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
        stdout = ""
        try:
            self.write(cmd)
            stdout = self.stdout_read(timeout)
            if exitcode:
                self.write("echo $?")
                rc = self.stdout_read(timeout)
                if re.search(r"\r\n0\r\n", rc, re.MULTILINE):
                    result = True
        except TimeoutError:
            logger.warning(f"timeout running '{cmd}'")
        return result, stdout
