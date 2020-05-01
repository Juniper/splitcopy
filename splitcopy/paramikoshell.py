# stdlib
import datetime
import os
import re
import socket
import getpass
import warnings
import logging
import time
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

_SHELL_PROMPT = re.compile("(% |# |\$ |%\t)$")
_SELECT_WAIT = 0.1
_RECVSZ = 1024


class SSHShell:
    """ class providing ssh connectivity """

    def __init__(self, **kwargs):
        """ Initialise the SSHShell class
        """
        self.host = kwargs.get("host")
        self.user = kwargs.get("user")
        self.passwd = kwargs.get("passwd")
        self.key_filename = kwargs.get("ssh_key")
        self.logger = kwargs.get("logger")
        self._sock = None
        self._chan = None
        self._client = None
        self.timeout = 30
        self.last_ok = None

    def open_socket(self, proxy=None):
        """ open a socket to remote host"""
        try:
            if proxy is not None:
                sock = socket.create_connection((self.host, 22), 10)
            else:
                sock = socket.create_connection((self.host, 22), 10)
        except ConnectionRefusedError:
            raise SystemExit("port 22 isn't open on remote host, can't proceed")
        except socket.timeout:
            raise SystemExit(
                "ssh port check timed out after 10 seconds, "
                "is the host reachable and ssh enabled?"
            )
        except (socket.gaierror, socket.herror) as err:
            raise SystemExit(
                "ip or hostname supplied is invalid or unreachable. "
                "error was {}".format(str(err))
            )
        except Exception as err:
            raise SystemExit(
                "failed to connect to port 22 on remote host. error was {}".format(
                    str(err)
                )
            )
        return sock

    def open_ssh_client(self):
        """
        :return: paramiko.SSHClient instance
        """
        self.logger.debug("entering open_ssh_client()")
        config = {}
        kwargs = {}
        ssh_client = paramiko.SSHClient()
        ssh_client.load_system_host_keys()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_config = os.path.expanduser("~/.ssh/config")

        if ssh_config:
            config = paramiko.SSHConfig()
            with open(ssh_config) as open_ssh_config:
                config.parse(open_ssh_config)
            config = config.lookup(self.host)

        if config.get("proxycommand"):
            proxy = paramiko.proxy.ProxyCommand(config.get("proxycommand"))
            self._sock = open_socket(proxy)
        elif config.get("proxyjump"):
            proxy = paramiko.proxy.ProxyJump(config.get("proxyjump"))
            self._sock = open_socket(proxy)
        else:
            self._sock = self.open_socket()

        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        self.logger.debug("ssh agent has {} keys".format(len(agent_keys)))
        ask = True

        if self.passwd is not None:
            kwargs.update(
                {"password": self.passwd, "allow_agent": False, "look_for_keys": False}
            )
            ask = False
        elif self.user != getpass.getuser():
            print(
                "skipping key based auth as {} != {}".format(
                    self.user, getpass.getuser()
                )
            )
            kwargs.update({"allow_agent": False, "look_for_keys": False})
        elif self.key_filename is not None:
            kwargs.update(
                {
                    "key_filename": self.key_filename,
                    "allow_agent": False,
                    "look_for_keys": False,
                    "password": None,
                    "passphrase": getpass.getpass(
                        prompt="ssh key passphrase (Enter for None): ", stream=None
                    ),
                }
            )
            ask = False
        elif len(agent_keys) == 0:
            kwargs.update({"allow_agent": False, "look_for_keys": False})
        elif len(agent_keys) > 0:
            ask = False

        if ask:
            self.passwd = getpass.getpass(
                prompt="{}@{}'s password: ".format(self.user, self.host), stream=None
            )
            kwargs["password"] = self.passwd

        kwargs.update(
            {"sock": self._sock, "hostname": self.host, "username": self.user}
        )
        try:
            ssh_client.connect(**kwargs)
        except Exception:
            raise

        # ensure session stays up
        ssh_client._transport.set_keepalive(60)
        return ssh_client

    def get_transport(self, ssh_client):
        if ssh_client is None:
            raise SSHException("get_transport(), ssh_client was None")
        transport = ssh_client.get_transport()
        return transport

    def wait_for(self, this=_SHELL_PROMPT, timeout=10):
        chan = self._chan
        now = datetime.datetime.now()
        timeout_time = now + datetime.timedelta(seconds=timeout)
        output = ""
        while not this.search(output):
            try:
                rd, wr, err = select([chan], [], [], _SELECT_WAIT)
                if rd:
                    data = chan.recv(_RECVSZ)
                    output += data.decode()
            except:
                raise
            if datetime.datetime.now() > timeout_time:
                raise TimeoutError
        return output



    def send(self, data):
        """
        Send the command **data** followed by a newline character.

        :param str data: the data to write out onto the shell.
        :returns: result of SSH channel send
        """
        self._chan.send(data)
        self._chan.send("\n")

    def open(self):
        """
        Open an ssh-client connection and issue the 'start shell' command to
        drop into the Junos shell (csh).  This process opens a
        :class:`paramiko.SSHClient` instance.
        """
        try:
            self._client = self.open_ssh_client()
            self._chan = self._client.invoke_shell()
        except BadAuthenticationType:
            raise SystemExit("ssh PasswordAuthentication method rejected")
        except BadHostKeyException:
            raise SystemExit(
                "ssh PasswordAuthentication failed. delete the hosts key in "
                "~/.ssh/known_hosts and retry"
            )
        except ChannelException:
            raise SystemExit(
                "ssh PasswordAuthentication failed while opening a channel"
            )
        except PasswordRequiredException:
            raise SystemExit("passphrase for key incorrect")
        except AuthenticationException as err:
            raise SystemExit(
                "ssh PasswordAuthentication failed, error was: {}".format(str(err))
            )
        except SSHException as err:
            raise SystemExit("ssh error occurred, the error was: {}".format(str(err)))
        except TimeoutError:
            raise SystemExit("ssh PasswordAuthentication timed out")
        except OSError as err:
            raise SystemExit("OSError returned, error was {}".format(str(err)))
        except EOFError:
            raise SystemExit("EOFError on socket")

        self.run("\n")
        self.run("start shell")

    def close(self):
        """ Close the SSH client channel """
        self._chan.close()
        self._client.close()

    def run(self, command, this=_SHELL_PROMPT, timeout=10):
        """
        Run a shell command and wait for the response.  The return is a
        tuple. The first item is True/False if exit-code is 0.  The second
        item is the output of the command.

        :param str command: the shell command to execute
        :param str this: the expected shell-prompt to wait for. If ``this`` is
          set to None, function will wait for all the output on the shell till
          timeout value.
        :param int timeout:
          Timeout value in seconds to wait for expected string/pattern (this).
          If not specified defaults to self.timeout. This timeout is specific
          to individual run call. If ``this`` is provided with None value,
          function will wait till timeout value to grab all the content from
          command output.

        :returns: (last_ok, result of the executed shell command (str) )

        .. code-block:: python

           with StartShell(dev) as ss:
               print ss.run('cprod -A fpc0 -c "show version"', timeout=10)

        .. note:: as a *side-effect* this method will set the ``self.last_ok``
                  property.  This property is set to ``True`` if ``$?`` is
                  "0"; indicating the last shell command was successful else
                  False. If ``this`` is set to None, last_ok will be set to
                  True if there is any content in result of the executed shell
                  command.
        """
        # run the command and capture the output
        self.send(command)
        got = self.wait_for(this=this, timeout=timeout)
        self.last_ok = False
        if this.search(got):
            # use $? to get the exit code of the command
            self.send("echo $?")
            rc = self.wait_for(this=this, timeout=timeout)
            self.last_ok = rc.find("\r\n0\r\n") > 0
        return got

    # -------------------------------------------------------------------------
    # CONTEXT MANAGER
    # -------------------------------------------------------------------------

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_ty, exc_val, exc_tb):
        self.close()
