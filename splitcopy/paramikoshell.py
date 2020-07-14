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
        self.kwargs = kwargs
        logger.debug(self.kwargs)
        self.hostname = self.kwargs.get("hostname")
        self.username = self.kwargs.get("username")
        self._chan = None
        self._transport = None

    def __enter__(self):
        return self

    def __exit__(self, exc_ty, exc_val, exc_tb):
        self.close()

    def socket_open(self):
        """ wrapper around proxy or direct methods
            :returns: sock
            :type: object
        """
        logger.info("entering socket_open()")
        sock = self.socket_proxy()
        if not sock:
            sock = self.socket_direct()
        return sock

    def socket_proxy(self):
        """ checks the .ssh/config file for any proxy commands to reach host
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
        """ open a socket to remote host
            :returns: sock
            :type: socket object
        """
        logger.info("entering socket_direct()")
        try:
            sock = socket.create_connection((self.hostname, 22), 10)
        except (socket.gaierror, socket.herror):
            raise ConnectionError("address or hostname not reachable")
        except (socket.timeout, ConnectionRefusedError, IOError, OSError):
            raise ConnectionError("error connecting to remote host on port 22")
        return sock

    def key_format(self, path):
        """ determines the key format
            :returns: result
            :type: string
            :raises: OSError upon file read errors
        """
        with open(path, "r") as private_key:
            # only read 1st line
            line = private_key.readline()
            regex = re.match(
                r"-{5}BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-{5}\s*$", line
            )
            result = str(regex.group(1))
        return result

    def ask_passphrase(self, key_type):
        """ obtain the passphrase for a private key
            :returns: passphrase
            :type: string
        """
        logger.info("entering ask_passphrase()")
        passphrase = getpass.getpass(
            prompt="{} key passphrase: ".format(key_type), stream=None
        )
        return passphrase

    def get_pkey_from_file(self, pkey_type, pkey_file, passphrase=None):
        """ attempt to decode the private key
            :param: pkey_type
            :type: string
            :param: pkey_file
            :type: string
            :passphrase:
            :type: string
            :returns: Pkey object
            :raises: PasswordRequiredException if key cannot be decoded
            :raises: AttributeError if key type isnt supported
        """
        pkey = None
        try:
            if pkey_type == "RSA":
                pkey = paramiko.RSAKey.from_private_key_file(
                    filename=pkey_file, password=passphrase
                )
            elif pkey_type == "DSA":
                pkey = paramiko.DSSKey.from_private_key_file(
                    filename=pkey_file, password=passphrase
                )
            elif pkey_type == "EC":
                pkey = paramiko.ECDSAKey.from_private_key_file(
                    filename=pkey_file, password=passphrase
                )
            elif pkey_type == "OPENSSH":
                pkey = paramiko.Ed25519Key.from_private_key_file(
                    filename=pkey_file, password=passphrase
                )
        except PasswordRequiredException:
            raise
        except AttributeError:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            print(
                "{} key found, this paramiko version is missing support for {} keys".format(
                    pkey_type, pkey_type
                )
            )
        return pkey

    def transport_open(self, sock):
        """ opens a transport to the host
            :param: sock
            :type: either a socket object, or if a proxy is used, a subprocess
            :returns: paramiko Transport instance
        """
        self._transport = paramiko.Transport(sock)
        self._transport.start_client()
        return self._transport

    def worker_thread_auth(self):
        """ authentication has succeeded previously, simplify nth time around
            :returns: bool
        """

        if self.kwargs.get("agent"):
            self.auth_using_agent()
        elif self.kwargs["key_filename"] is not None:
            self.auth_using_provided_keyfile()
        elif self.kwargs["password"] is not None:
            self.password_auth()

        if self.is_authenticated():
            return True

    def main_thread_auth(self):
        """ determines what authentication methods are available on the server
            by default will attempt publickey auth, and fall back to passwordauth
            :returns: bool
        """
        logger.info("entering auth_wrapper()")
        try:
            self._transport.auth_none(self.kwargs["username"])
        except BadAuthenticationType as e:
            self.kwargs["allowed_types"] = e.allowed_types
        if not self.kwargs["allowed_types"]:
            raise SSHException("no authentication methods possible")

        if self.kwargs["password"] is not None:
            self.password_auth()
        elif self.kwargs["username"] != getpass.getuser():
            print(
                "skipping publickey ssh auth as {} != {}".format(
                    self.username, getpass.getuser()
                )
            )
            if "password" in self.kwargs["allowed_types"]:
                self.password_auth()
        elif (
            "publickey" in self.kwargs["allowed_types"]
            and self.kwargs["key_filename"] is not None
        ):
            if not self.auth_using_provided_keyfile():
                self.password_auth()
        elif "publickey" in self.kwargs["allowed_types"]:
            if not self.auth_using_agent():
                if not self.auth_using_keyfiles():
                    self.password_auth()
        else:
            self.password_auth()

        if self.is_authenticated():
            print("ssh authentication succeeded")
            return True

    def ask_password(self):
        """ obtains the password for PasswordAuthentication
            :returns: password
            :type: string
            :returns: None
        """
        logger.info("entering ask_password()")
        password = getpass.getpass(
            prompt="{}@{}'s password: ".format(self.username, self.hostname),
            stream=None,
        )
        return password

    def password_auth(self):
        """ attempts Password Authentication
            :raises: AuthenticationException if auth fails
            :returns: None
        """
        if "password" not in self.kwargs["allowed_types"]:
            raise SSHException("password auth not allowed by server")

        if not self.kwargs["password"]:
            self.kwargs["password"] = self.ask_password()
        try:
            self._transport.auth_password(
                username=self.kwargs["username"], password=self.kwargs["password"]
            )
        except AuthenticationException:
            print("password authentication failed")
            raise

    def auth_using_agent(self):
        """ Attempts publickey authentication using keys held by ssh-agent
            :param: agent_keys
            :type: list
            :returns: bool
        """
        logger.info("entering auth_using_agent()")
        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        logger.info("ssh agent has {} keys".format(len(agent_keys)))
        result = False
        for pkey in agent_keys:
            pkey_type = pkey.get_name()
            logger.info("ssh agent has key type {}".format(pkey_type))
            try:
                self._transport.auth_publickey(self.kwargs["username"], pkey)
                result = True
                self.kwargs["agent"] = True
            except SSHException as err:
                logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                print(
                    "{} key authentication failed with error: {}".format(pkey_type, err)
                )
        return result

    def auth_using_keyfiles(self):
        """ Attempts publickey authentication using keys found in ~/.ssh
            Iterates over any keys found, stops if one is successful
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
            path = os.path.expanduser("~/.ssh/{}".format(pkey_types[pkey_type]))
            if os.path.isfile(path):
                pkey_files.append((pkey_type, path))

        for pkey_file in pkey_files:
            pkey_type, pkey_path = pkey_file[0], pkey_file[1]
            self.kwargs.update({"key_filename": pkey_path, "passphrase": None})
            try:
                pkey = self.get_pkey_from_file(pkey_type, pkey_path)
            except PasswordRequiredException:
                self.kwargs["passphrase"] = self.ask_passphrase(pkey_type)
                try:
                    pkey = self.get_pkey_from_file(
                        pkey_type, pkey_path, passphrase=self.kwargs["passphrase"]
                    )
                except SSHException as err:
                    self.kwargs.update({"key_filename": None, "passphrase": None})
                    logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                    print(
                        "{} key decryption failed with error: {}".format(pkey_type, err)
                    )
                    continue
            if pkey is not None:
                try:
                    self._transport.auth_publickey(self.kwargs["username"], pkey)
                    result = True
                    break
                except SSHException as err:
                    self.kwargs.update({"key_filename": None, "passphrase": None})
                    logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                    print(
                        "{} key authentication failed with error: {}".format(
                            pkey_type, err
                        )
                    )
                    continue
        return result

    def auth_using_provided_keyfile(self):
        """ Attempts publickey authentication using provided keyfile
            :returns: bool
        """
        logger.info("entering auth_using_provided_keyfile()")
        pkey_file = self.kwargs["key_filename"]
        pkey_type = self.key_format(pkey_file)
        pkey = None
        result = False
        try:
            pkey = self.get_pkey_from_file(
                pkey_type, pkey_file, passphrase=self.kwargs["passphrase"]
            )
        except PasswordRequiredException:
            self.kwargs["passphrase"] = self.ask_passphrase(pkey_type)
            try:
                pkey = self.get_pkey_from_file(
                    pkey_type, pkey_file, passphrase=self.kwargs["passphrase"]
                )
            except SSHException as err:
                self.kwargs.update({"key_filename": None, "passphrase": None})
                logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                print("{} key decryption failed with error: {}".format(pkey_type, err))
        if pkey is not None:
            try:
                self._transport.auth_publickey(self.kwargs["username"], pkey)
                result = True
            except SSHException as err:
                self.kwargs.update({"key_filename": None, "passphrase": None})
                logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                print(
                    "{} key authentication failed with error: {}".format(pkey_type, err)
                )
        return result

    def is_authenticated(self):
        """ verifies if authentication was successful
            :returns: bool
        """
        logger.info("entering is_authenticated()")
        if self._transport.is_authenticated():
            return True

    def channel_open(self):
        """ opens a channel of type 'session' over existing transport
            :returns: None
        """
        logger.info("entering channel_open()")
        self._chan = self._transport.open_session()

    def invoke_shell(self):
        """ opens a pty on remote host
            :returns: None
        """
        logger.info("entering invoke_shell()")
        self._chan.get_pty()
        self._chan.invoke_shell()

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
            :returns: None
        """
        self._transport.set_keepalive(60)

    def write(self, cmd):
        """ Sends a cmd + newline char over the channel
            :param cmd: cmd to be sent over the channel
            :type: string
            :returns: None
        """
        self._chan.send("{}\n".format(cmd))
        logger.info("sent '{}'".format(cmd))

    def close(self):
        """ terminates both the channel (if present) and the underlying session
            :returns: None
        """
        if self._chan is not None:
            self._chan.close()
        if self._transport is not None:
            self._transport.close()

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
        stdout = ""
        try:
            self.write(cmd)
            stdout = self.stdout_read(timeout)
            if exitcode:
                self.write("echo $?".format(cmd))
                rc = self.stdout_read(timeout)
                if re.search(r"\r\n0\r\n", rc, re.MULTILINE):
                    result = True
        except TimeoutError:
            logger.warning("timeout running '{}'".format(cmd))
            pass
        return result, stdout
