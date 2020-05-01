# stdlib
import datetime
import os
import re
import socket
import getpass
import logging
import sys
import time
import traceback
from select import select

# 3rd Party
from ssh2.session import Session
from ssh2.exceptions import *
from ssh2.error_codes import LIBSSH2_ERROR_EAGAIN

_SHELL_PROMPT = re.compile("(% |# |\$ |> |%\t)$")
_SELECT_WAIT = 0.1
_RECVSZ = 1024

logger = logging.getLogger(__name__)


class SSH2Shell:
    """ class providing ssh connectivity using ssh2-python lib
    """

    def __init__(self, **kwargs):
        """ Initialise the SSH2Shell class
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
        """ wrapper function for session_open() to handle exceptions
            :returns None:
            :raises OSError, EOFError, SSH2Error, Exception: upon failure
        """
        try:
            self.session_open()
        except OSError:
            raise
        except EOFError:
            raise
        except SSH2Error:
            raise
        except Exception as err:
            raise


    def socket_open(self):
        """ open a socket to remote host
            :return sock: socket object
            :raises SystemExit: if port isn't open
            :raises Exception: for other exceptions
        """
        try:
            sock = socket.create_connection((self.host, 22), 10)
        except ConnectionRefusedError:
            raise SystemExit(
                "port 22 isn't open on remote host, can't proceed"
            )
        except socket.timeout:
            raise Exception(
                "ssh port check timed out after 10 seconds, "
                "is the host reachable and ssh enabled?"
            )
        except socket.gaierror as err:
            raise Exception(
                "ip/ipv6 address supplied is invalid or unreachable. "
                "error was {}".format(str(err))
            )
        except socket.herror as err:
            raise Exception(
                "hostname supplied is invalid or unreachable. "
                "Error was: {}".format(str(err))
            )
        except Exception as err:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            raise Exception(
                "failed to connect to port 22 on remote host. error was {}".format(
                    str(err)
                )
            )
        return sock

    def session_open(self):
        """ opens an ssh2-python Session instance
            handles both key and password based authentication
            :return: None
        """
        logger.debug("entering session_open()")
        self._sock = self.socket_open()
        self._session = Session()
        self._session.handshake(self._sock)

        methods = self._session.userauth_list(self.user)
        if "publickey" in methods and self.key_filename is not None:
            if self.publickey_auth():
                return
        elif "publickey" in methods:
            if self.agent_auth():
                return
        if "password" in methods:
            self.password_auth()

    def password_auth(self):
        """ attempts ssh password authentication
            :return None:
            :raises SystemExit: upon 3 failed attempts
        """
        while not self._session.userauth_authenticated():
            if not self.passwd:
                self.passwd = getpass.getpass(
                    prompt="{}@{}'s password: ".format(self.user, self.host),
                    stream=None,
                )
            try:
                self._session.userauth_password(self.user, self.passwd)
            except AuthenticationError:
                print("Permission denied, please try again.")
                self.passwd = getpass.getpass(
                    prompt="{}@{}'s password: ".format(self.user, self.host),
                    stream=None,
                )
            except SocketDisconnectError:
                raise SystemExit("Permission denied")

    def publickey_auth(self):
        """ attempts publickey based authentication using specified key
            :returns result: success or failure
            :type: boolean
            :raises SystemExit: upon 3 failed attempts
        """
        result = False
        if self.user != getpass.getuser():
            return result
        priv_key = self.key_filename
        key_path = os.path.expanduser(priv_key)
        while not self._session.userauth_authenticated():
            passphrase = getpass.getpass(prompt="key passphrase (or Enter for None): ", stream=None)
            try:
                self._session.userauth_publickey_fromfile(
                    self.user, "{}".format(key_path), passphrase
                )
                result = True
            except AuthenticationError:
                logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            except SocketDisconnectError:
                raise SystemExit("Permission denied")

        return result

    def agent_auth(self):
        """ attempts authentication via ssh-agent, iterates over each key loaded
            :returns result: success or failure
            :type: boolean
        """
        result = False
        try:
            self._session.agent_auth(self.user)
            result = True
        except AgentAuthenticationError:
            pass

        return result

    def set_blocking(self, bool):
        """ toggles whether to enable blocking or not
            :param bool: True or False
            :type: boolean
            :return: None
        """
        self._session.set_blocking(bool)

    def set_keepalive(self):
        """ ensures session stays up if inactive for long period
            not suitable for scp, will terminate session with BadUseError if enabled
            :return: None
        """
        self._session.keepalive_config(True, 60)

    def channel_open(self):
        """ opens an ssh channel on top of an ssh session
            :return: None
        """
        self._chan = self._session.open_session()
        while self._chan == LIBSSH2_ERROR_EAGAIN:
            time.sleep(0.1)
            self._chan = self._session.open_session()
        self._chan.pty()
        self._chan.shell()

    def write(self, cmd):
        """ Sends a cmd + newline char over the channel
            :param cmd: cmd to be sent over the channel
            :type: string
        """
        while self._chan.write(cmd + "\n") == LIBSSH2_ERROR_EAGAIN:
            pass
        logger.debug("sent '{}'".format(cmd))

    def run(self, cmd, timeout=30.0, exitcode=True):
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

        try:
            self.write(cmd)
            stdout = self.stdout_read(timeout)
        except TimeoutError:
            raise
        except SSH2Error:
            raise

        if exitcode:
            try:
                self.write("echo $?".format(cmd))
                rc = self.stdout_read(timeout)
                if re.search(r"\r\n0\r\n", rc, re.MULTILINE):
                    result = True
            except TimeoutError:
                raise
            except SocketRecvError:
                raise
        elif stdout is not None and stdout != "":
            result = True
        return result, stdout

    def stdout_read(self, timeout):
        """ reads data off the socket
            :param timeout: amount of time before timeout is raised
            :type: int
            :returns output: stdout from the cmd
            :type: string
        """
        now = datetime.datetime.now()
        timeout_time = now + datetime.timedelta(seconds=timeout)
        output = ""
        while not _SHELL_PROMPT.search(output):
            try:
                rd, wr, err = select([self._sock], [], [], _SELECT_WAIT)
                if rd:
                    size, data = self._chan.read(_RECVSZ)
                    while size == LIBSSH2_ERROR_EAGAIN:
                        size, data = self._chan.read(_RECVSZ)
                    while size > 0:
                        output += data.decode()
                        size, data = self._chan.read()
            except SocketRecvError:
                raise
            if datetime.datetime.now() > timeout_time:
                raise TimeoutError
        return output

    def close(self):
        """ terminates both the channel and underlying session
            :return: None
        """
        if self._chan:
            self._chan.close()
            logger.info("SSH channel exit status: %s" % self._chan.get_exit_status())
        self._session.disconnect()

