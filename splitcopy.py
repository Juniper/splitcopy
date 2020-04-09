#!/usr/bin/env python3
""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

try:
    import asyncio
except ImportError:
    raise RuntimeError("This script requires Python 3.4+")
import argparse
import datetime
import fnmatch
import functools
import getpass
import glob
import hashlib
import logging
import multiprocessing
import os
import re
import signal
import shutil
import socket
import sys
import tempfile
import time
import warnings
from contextlib import contextmanager
from paramiko.ssh_exception import SSHException
from paramiko.ssh_exception import ChannelException
from paramiko.ssh_exception import BadHostKeyException
from paramiko.ssh_exception import AuthenticationException
from paramiko.ssh_exception import BadAuthenticationType
from paramiko.ssh_exception import PasswordRequiredException
from scp import SCPException
from jnpr.junos import Device
from jnpr.junos.utils.ftp import FTP
from jnpr.junos.utils.scp import SCP
from jnpr.junos.utils.start_shell import StartShell
from cryptography import utils

warnings.simplefilter("ignore", utils.CryptographyDeprecationWarning)


def main():
    """ body of script
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("filepath", help="Path to the file you want to copy")
    parser.add_argument(
        "userhost", help="username and remote host to connect to. e.g. user@host"
    )
    parser.add_argument(
        "--pwd", nargs=1, help="password to authenticate on remote host"
    )
    parser.add_argument(
        "--ssh_key",
        nargs=1,
        help="path to ssh private key (only if in non-default location)",
    )
    parser.add_argument("--dst", nargs=1, help="directory to put file")
    parser.add_argument(
        "--scp", action="store_true", help="use scp to copy files instead of ftp"
    )
    parser.add_argument(
        "--noverify",
        action="store_true",
        help="skip sha1 hash comparison of src and dst file",
    )
    parser.add_argument("--get", action="store_true", help="get file from remote host")
    parser.add_argument("--log", nargs=1, help="log level, eg DEBUG")
    args = parser.parse_args()

    if not args.userhost:
        parser.error(
            "must specify a username and remote host to connect to. e.g. user@host"
        )

    if not args.log:
        loglevel = "ERROR"
    else:
        loglevel = args.log[0]

    logger = logging.getLogger(__name__)
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: %s" % loglevel)
    logger.setLevel(numeric_level)
    handler = logging.StreamHandler()
    handler.setLevel(numeric_level)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    try:
        user = args.userhost.split("@")[0]
        host = args.userhost.split("@")[1]
    except IndexError:
        raise SystemExit("please specify user and host in the format user@host")

    get = args.get
    noverify = args.noverify

    if args.dst:
        if re.search(r"~$", args.dst[0]):
            dest_dir = os.path.expanduser(args.dst[0])
        else:
            dest_dir = os.path.abspath(args.dst[0])
    else:
        dest_dir = "/var/tmp"

    if get:
        # filepath is remote, must be posix path
        file_path = args.filepath
        file_name = os.path.basename(file_path)
        file_size = 0
        if not os.path.isdir(dest_dir):
            raise SystemExit(
                "destination directory {} does not exist on localhost. "
                "use the --dst flag to specify a valid directory".format(dest_dir)
            )
    else:
        # filepath is local path could be nt or posix
        file_path = os.path.abspath(args.filepath)
        if not os.path.isfile(file_path):
            raise SystemExit(
                "source file {} does not exist - cannot proceed".format(file_path)
            )
        try:
            open(file_path, "rb")
        except PermissionError:
            raise SystemExit(
                "source file {} exists but is not readable - cannot proceed".format(
                    file_path
                )
            )
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        logger.debug("src file size is {}".format(file_size))

    try:
        port_check(logger, host, 22)
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
            "error was {}".format(err)
        )
    except Exception as err:
        raise SystemExit(
            "failed to connect to port 22 on remote host. error was {}".format(str(err))
        )

    start_time = datetime.datetime.now()

    passwd = None
    if args.pwd:
        passwd = args.pwd[0]

    if args.scp:
        copy_proto = "scp"
    else:
        try:
            port_check(logger, host, 21)
            copy_proto = "ftp"
            passwd = getpass.getpass(prompt="Password: ", stream=None)
        except:
            copy_proto = "scp"

    ssh_auth = SshAuth(host, user, logger)

    def handlesigintssh(sigint, stack):
        raise SystemExit

    signal.signal(signal.SIGINT, handlesigintssh)

    if passwd:
        dev, ss = ssh_auth.ssh_passwd_auth(passwd)
    elif user != getpass.getuser():
        print(
            "skipping ssh key-based auth as user {} != {}".format(
                user, getpass.getuser()
            )
        )
        dev, ss = ssh_auth.ssh_passwd_auth()
    elif args.ssh_key:
        print("attempting ssh PubkeyAuthentication using specified key")
        dev, ss = ssh_auth.ssh_key_auth()
    else:
        print("attempting ssh PubkeyAuthentication method")
        dev, ss = ssh_auth.ssh_key_auth()

    print("ssh authentication succeeded")

    splitcopy = SplitCopy(
        dev,
        ss,
        host,
        dest_dir,
        file_name,
        file_path,
        file_size,
        copy_proto,
        get,
        logger,
        noverify,
    )

    def handlesigint(sigint, stack):
        splitcopy.close()

    signal.signal(signal.SIGINT, handlesigint)

    if get:
        loop_start, loop_end = splitcopy.get()
    else:
        loop_start, loop_end = splitcopy.put()

    # and we are done...
    end_time = datetime.datetime.now()
    time_delta = end_time - start_time
    transfer_delta = loop_end - loop_start
    print("data transfer = {}\ntotal runtime = {}".format(transfer_delta, time_delta))


def port_check(logger, host, port):
    """ checks if a port is open on remote host, emulates 'nc -z <host> <port>'
    Args:
        logger(obj) -
        host(str) - host to connect to
        port(int) - port to connect to
    Returns:
        None
    Raises:
        raises any exception
    """
    logger.debug("entering port_check()")
    try:
        socket.create_connection((host, port), 10)
    except:
        raise


class SshAuth:
    """ class providing ssh authentication
    """

    def __init__(self, host, user, logger):
        """ Initialise the SSH_AUTH class
        """
        self.host = host
        self.user = user
        self.logger = logger
        self.dev = None
        self.ss = None

    def ssh_passwd_auth(self, passwd=None):
        """ authenticate via ssh PasswordAuthentication
        Args:
            passwd(str) - password
        Returns:
            dev(object) -pyez Device object
            ss(object) - pyez StartShell object
        Raises:
            SystemExit - upon fatal exceptions
        """
        self.logger.debug("entering ssh_passwd_auth()")
        if not passwd:
            passwd = getpass.getpass(
                prompt="{}@{}'s password: ".format(self.user, self.host), stream=None
            )
        self.dev = Device(host=self.host, user=self.user, passwd=passwd)
        self.ss = StartShell(self.dev)
        try:
            self.ss.open()
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
        except AuthenticationException as err:
            raise SystemExit(
                "ssh PasswordAuthentication failed, error was: {}".format(str(err))
            )
        except SSHException as err:
            raise SystemExit("ssh error occurred, the error was: {}".format(str(err)))
        except TimeoutError:
            raise SystemExit("ssh PasswordAuthentication timed out")

        # ensure session stays up
        self.ss._chan.transport.set_keepalive(60)
        return self.dev, self.ss

    def ssh_key_auth(self, ssh_key=None, key_password=None):
        """ authenticate using ssh PubkeyAuthentication
        Args:
            ssh_key(str) - path to private ssh key
            key_password(str) - password for private ssh key
        Returns:
            dev(object) -pyez Device object
            ss(object) - pyez StartShell object
        Raises:
            SystemExit - upon fatal error
        """
        self.logger.debug("entering ssh_key_auth()")
        if key_password:
            self.dev = Device(
                host=self.host, ssh_private_key_file=ssh_key, passwd=key_password
            )
        elif ssh_key:
            self.dev = Device(host=self.host, ssh_private_key_file=ssh_key)
        else:
            self.dev = Device(host=self.host)
        self.ss = StartShell(self.dev)
        try:
            self.ss.open()
        except BadAuthenticationType:
            print("ssh PubkeyAuthentication method rejected")
            self.dev, self.ss = self.ssh_passwd_auth()
        except BadHostKeyException:
            raise SystemExit(
                "ssh PubkeyAuthentication failed. delete the hosts key in "
                "~/.ssh/known_hosts and retry"
            )
        except ChannelException:
            print("ssh PubkeyAuthentication failed while opening a channel")
            self.dev, self.ss = self.ssh_passwd_auth()
        except PasswordRequiredException:
            if ssh_key and key_password is None:
                key_password = getpass.getpass("Password for SSH private key file: ")
                self.ssh_key_auth(key_password)
            else:
                self.logger.info(
                    "ssh PubkeyAuthentication failed due to " "incorrect key password"
                )
                self.dev, self.ss = self.ssh_passwd_auth()
        except AuthenticationException as err:
            print(
                "ssh public-key authentication failed with error: {}".format(str(err))
            )
            self.dev, self.ss = self.ssh_passwd_auth()
        except SSHException as err:
            print("ssh public-key auth failed with error: {}".format(str(err)))
            self.dev, self.ss = self.ssh_passwd_auth()
        except TimeoutError:
            print("ssh public-key authentication timed out")
            self.dev, self.ss = self.ssh_passwd_auth()

        # ensure session stays up
        self.ss._chan.transport.set_keepalive(60)
        return self.dev, self.ss


class SplitCopy:
    """ class docstring
    """

    def __init__(
        self,
        dev,
        ss,
        host,
        dest_dir,
        file_name,
        file_path,
        file_size,
        copy_proto,
        get,
        logger,
        noverify,
    ):
        """ Initialise the SPLITCOPY class
        """
        self.dev = dev
        self.ss = ss
        self.host = host
        self.dest_dir = dest_dir
        self.file_name = file_name
        self.file_path = file_path
        self.file_size = file_size
        self.copy_proto = copy_proto
        self.command_list = []
        self.rm_remote_tmp = False
        self.config_rollback = True
        self.hard_close = False
        self.get_op = get
        self.logger = logger
        self.noverify = noverify
        self.local_sha1 = None
        self.local_tmpdir = None
        self.tasks = None
        self.split_size = None
        self.remote_tmpdir = None
        self.remote_sha1 = None
        self.host_os = None
        self.evo = False
        self.junos = False
        self.bsd_version = 0.0
        self.sshd_version = 0.0
        self.sha_bin = None
        self.mute = False

    def put(self):
        """ initiates the connection to the remote host
            uploads a file
            Args:
                self - class variables inherited from __init__
            Returns:
                loop_start(obj) - datetime
                loop_end(obj) - datetime
            Raises:
                None
        """
        # determine remote host os
        self.which_os()

        # check required binaries exist on remote host
        self.req_binaries()

        # evo doesn't support ftp
        if self.copy_proto == "ftp" and self.evo:
            print(
                "Switching to SCP to transfer files as "
                "EVO doesn't support ftp currently"
            )
            self.copy_proto = "scp"

        # cleanup previous remote tmp directory if found
        self.remote_cleanup(True)

        # confirm remote storage is sufficient
        self.storage_check_remote()

        # confirm local storage is sufficient
        self.storage_check_local()

        if not self.noverify:
            # get/create sha1 for local file
            self.local_sha1_put()

        # determine optimal size for chunks
        self.file_split_size()

        with self.tempdir():
            # split file into chunks
            self.split_file_local()

            # add chunk names to a list
            sfiles = []
            for sfile in os.listdir("."):
                if fnmatch.fnmatch(sfile, "{}*".format(self.file_name)):
                    sfiles.append(sfile)
            self.logger.debug("# of chunks = {}".format(len(sfiles)))

            # begin pre transfer checks, check if remote directory exists
            self.ss.run("test -d {}".format(self.dest_dir))
            if not self.ss.last_ok:
                self.close(err_str="remote directory specified does not exist")

            # end of pre transfer checks, create tmp directory
            self.mkdir_remote()

            # begin connection/rate limit check and transfer process
            if self.junos or self.evo:
                self.limit_check()

            if self.copy_proto == "ftp":
                kwargs = {"callback": FtpProgress(self.file_size).handle}
            else:
                kwargs = {
                    "progress": ScpProgress(self.file_size).handle,
                    "socket_timeout": 30.0,
                }

            # copy files to remote host
            self.hard_close = True
            loop_start = datetime.datetime.now()
            loop = asyncio.get_event_loop()
            self.tasks = []
            for sfile in sfiles:
                task = loop.run_in_executor(
                    None, functools.partial(self.put_files, sfile, **kwargs)
                )
                self.tasks.append(task)
            print("starting transfer...")
            try:
                loop.run_until_complete(asyncio.gather(*self.tasks))
            except KeyboardInterrupt:
                self.mute = True
                self.close()
            except TransferError:
                self.close(
                    err_str="an error occurred while copying the files to the "
                    "remote host"
                )
            finally:
                loop.close()
                self.hard_close = False

        print("transfer complete")
        loop_end = datetime.datetime.now()

        # combine chunks
        self.join_files_remote()

        # remove remote tmp dir
        self.remote_cleanup()

        # rollback any config changes made
        if self.command_list:
            self.limits_rollback()

        if self.noverify:
            print(
                "file has been successfully copied to {}:{}/{}".format(
                    self.host, self.dest_dir, self.file_name
                )
            )
        else:
            # generate a sha1 for the combined file, compare to sha1 of src
            self.remote_sha1_put()

        self.dev.close()
        return loop_start, loop_end

    def get(self):
        """ initiates the connection to the remote host
            downloads a file
            Args:
                self - class variables inherited from __init__
            Returns:
                loop_start(obj) - datetime
                loop_end(obj) - datetime
            Raises:
                None
        """

        # determine remote host os
        self.which_os()

        # check required binaries exist on remote host
        self.req_binaries()

        # evo doesn't support ftp
        if self.copy_proto == "ftp" and self.evo:
            print(
                "Switching to SCP to transfer files as "
                "EVO doesn't support ftp currently"
            )
            self.copy_proto = "scp"

        # cleanup previous remote tmp directory if found
        self.remote_cleanup(True)

        # begin pre transfer checks, check if remote file exists
        self.ss.run("test -r {}".format(self.file_path))
        if not self.ss.last_ok:
            self.close(err_str="file on remote host is not readable - does it exist?")

        # determine remote file size
        self.remote_filesize()

        # confirm remote storage is sufficient
        self.storage_check_remote()

        # confirm local storage is sufficient
        self.storage_check_local()

        if not self.noverify:
            # get/create sha1 for remote file
            self.remote_sha1_get()

        # determine optimal size for chunks
        self.file_split_size()

        # create tmp directory on remote host
        self.mkdir_remote()

        # split file into chunks
        self.split_file_remote()

        # add chunk names to a list
        remote_files = self.ss.run("ls -1 {}/".format(self.remote_tmpdir))
        if not self.ss.last_ok:
            self.close(err_str="couldn't get list of files from host")
        remote_files = remote_files[1].split("\r\n")
        sfiles = []
        for sfile in remote_files:
            if fnmatch.fnmatch(sfile, "{}*".format(self.file_name)):
                sfiles.append(sfile)
        self.logger.debug("# of chunks = {}".format(len(sfiles)))

        # begin connection/rate limit check and transfer process
        if self.junos or self.evo:
            self.limit_check()

        if self.copy_proto == "ftp":
            kwargs = {"callback": FtpProgress(self.file_size).handle}
        else:
            kwargs = {
                "progress": ScpProgress(self.file_size).handle,
                "socket_timeout": 30.0,
            }
        with self.tempdir():
            # copy files from remote host
            self.hard_close = True
            loop_start = datetime.datetime.now()
            loop = asyncio.get_event_loop()
            self.tasks = []
            for sfile in sfiles:
                task = loop.run_in_executor(
                    None, functools.partial(self.get_files, sfile, **kwargs)
                )
                self.tasks.append(task)
            print("starting transfer...")
            try:
                loop.run_until_complete(asyncio.gather(*self.tasks))
            except KeyboardInterrupt:
                self.mute = True
                self.close()
            except TransferError:
                self.close(
                    err_str="an error occurred while copying the files from "
                    "the remote host"
                )
            finally:
                loop.close()
                self.hard_close = False

            print("transfer complete")
            loop_end = datetime.datetime.now()

            # combine chunks
            self.join_files_local()

        # remove remote tmp dir
        self.remote_cleanup()

        # rollback any config changes made
        if self.command_list:
            self.limits_rollback()

        if self.noverify:
            print(
                "file has been successfully copied to {}/{}".format(
                    self.dest_dir, self.file_name
                )
            )
        else:
            # generate a sha1 for the combined file, compare to sha1 of src
            self.local_sha1_get()

        self.dev.close()
        return loop_start, loop_end

    def which_os(self):
        """ determine if host is JUNOS/EVO/*nix
            no support for Windows OS running OpenSSH
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering which_os()")
        host_os = self.ss.run("uname", timeout=30)
        if not self.ss.last_ok:
            err = "failed to determine remote host os, it must be *nix based"
            self.close(err_str=err)
        self.host_os = host_os[1].split("\n")[1].rstrip()
        if self.host_os == "Linux" and self.evo_os():
            self.evo = True
        else:
            self.junos_os()
        self.logger.debug(
            "evo = {}, junos = {}, bsd_version = {}, sshd_version = {}".format(
                self.evo, self.junos, self.bsd_version, self.sshd_version
            )
        )

    def evo_os(self):
        """ determines if host is EVO
        Args:
            self - class variables inherited from __init__
        Returns:
            bool
        Raises:
            None
        """
        self.logger.debug("entering evo_os()")
        self.ss.run("test -e /usr/sbin/evo-pfemand", timeout=30)
        return self.ss.last_ok

    def junos_os(self):
        """ determines if host is JUNOS
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering junos_os()")
        uname = self.ss.run("uname -i", timeout=30)
        if not self.ss.last_ok:
            self.close(err_str="failed to determine remote host os")
        uname = uname[1].split("\n")[1]
        if re.match(r"JUNIPER", uname):
            self.junos = True
            self.bsd_version = 6.0
            self.which_sshd()
        elif re.match(r"JNPR", uname):
            self.junos = True
            self.which_bsd()
            self.which_sshd()
        else:
            self.which_sshd()

    def which_bsd(self):
        """ determines the BSD version of JUNOS
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering which_bsd()")
        uname = self.ss.run("uname -r", timeout=30)
        if not self.ss.last_ok:
            self.close(err_str="failed to determine remote bsd version")
        uname = uname[1].split("\n")[1]
        self.bsd_version = float(uname.split("-")[1])

    def which_sshd(self):
        """ determines the OpenSSH daemon version
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering which_sshd()")
        output = self.ss.run("sshd -v", timeout=30)
        if not re.search(r"OpenSSH_", output[1]):
            self.close(err_str="failed to determine remote openssh version")
        output = output[1].split("\n")[2]
        version = re.sub(r"OpenSSH_", "", output)
        self.sshd_version = float(version[0:3])

    def req_binaries(self):
        """ ensures required binaries exist on remote host
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering req_binaries()")
        sha1_bins = ["sha1sum", "shasum", "sha1"]
        for req_bin in sha1_bins:
            if self.ss.run("which {}".format(req_bin))[0]:
                self.sha_bin = req_bin
                break
        if not self.sha_bin:
            self.close(
                err_str=(
                    "required binary 'sha1sum||shasum||sha1' used to "
                    "generate a sha1 on the remote host isn't found"
                )
            )
        if not self.junos and not self.evo:
            if self.get_op:
                req_bins = ["dd", "ls", "df", "rm"]
            else:
                req_bins = ["cat", "ls", "df", "rm"]
            for req_bin in req_bins:
                if not self.ss.run("which {}".format(req_bin))[0]:
                    self.close(
                        err_str=(
                            "required binary '{}' is missing from remote "
                            "host".format(req_bin)
                        )
                    )

    def close(self, err_str=None):
        """ Called when we want to exit the script
            attempts to delete the remote temp directory and close the TCP session
            If self.hard_close == False, contextmanager will rm the local temp dir
            If not, we must delete it manually
            Args:
                self - class variables inherited from __init__
                err_str(str) - error description
            Returns:
                None
            Raises either:
                SystemExit - terminates the script gracefully
                os._exit - terminates the script immediately (even asychio loop)
        """
        if self.rm_remote_tmp:
            self.remote_cleanup()
        if self.config_rollback and self.command_list:
            self.limits_rollback()
        print("closing device connection")
        self.dev.close()
        if err_str:
            print(err_str)
        if self.hard_close:
            try:
                shutil.rmtree(self.local_tmpdir)
            except PermissionError:
                # windows can throw this error, silence it for now
                print(
                    "{} may still exist, please delete manually if so".format(
                        self.local_tmpdir
                    )
                )
            raise os._exit(1)
        else:
            raise SystemExit(1)

    def join_files_remote(self):
        """ concatenates the file chunks into one file on remote host
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering join_files_remote()")
        print("joining files...")
        cmd_out = self.ss.run(
            "cat {}/* > {}/{}".format(
                self.remote_tmpdir, self.dest_dir, self.file_name
            ),
            timeout=600,
        )
        if not self.ss.last_ok:
            self.close(
                err_str=(
                    "failed to combine chunks on remote host. "
                    "error was:\n{}".format(cmd_out[1])
                )
            )

    def join_files_local(self):
        """ concatenates the file chunks into one file on local host
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering join_files_local()")
        print("joining files...")
        buf_size = 131072
        src_files = glob.glob(self.local_tmpdir + "/" + self.file_name + "*")
        dst_file = self.dest_dir + "/" + self.file_name
        with open(dst_file, "wb") as dst:
            for src in sorted(src_files):
                with open(src, "rb") as chunk:
                    data = chunk.read(buf_size)
                    while data:
                        dst.write(data)
                        data = chunk.read(buf_size)
        if not os.path.isfile(dst_file):
            err_str = "recombined file {} isn't found, exiting"
            self.close(err_str)

    def remote_sha1_put(self):
        """ creates a sha1 hash for the newly combined file on the remote host
            compares against local sha1
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering remote_sha1_put()")
        print("generating remote sha1...")
        self.ss.run("ls {}/{}".format(self.dest_dir, self.file_name))
        if not self.ss.last_ok:
            err = "file {}:{}/{} not found! please retry".format(
                self.host, self.dest_dir, self.file_name
            )
            self.config_rollback = False
            self.close(err_str=err)

        sha1_tuple = self.ss.run(
            "{} {}/{}".format(self.sha_bin, self.dest_dir, self.file_name), timeout=300
        )
        if not self.ss.last_ok:
            print(
                "remote sha1 generation failed or timed out, "
                'manually check the output of "sha1 <file>" and '
                "compare against {}".format(self.local_sha1)
            )
            return
        if self.sha_bin == "sha1sum" or self.sha_bin == "shasum":
            remote_sha1 = sha1_tuple[1].split("\n")[1].split()[0].rstrip()
        else:
            remote_sha1 = sha1_tuple[1].split("\n")[1].split()[3].rstrip()
        self.logger.debug("remote sha1 = {}".format(remote_sha1))
        if self.local_sha1 == remote_sha1:
            print(
                "local and remote sha1 match\nfile has been "
                "successfully copied to {}:{}/{}".format(
                    self.host, self.dest_dir, self.file_name
                )
            )
        else:
            err = (
                "file has been copied to {}:{}/{}, but the "
                "local and remote sha1 do not match - "
                "please retry".format(self.host, self.dest_dir, self.file_name)
            )
            self.config_rollback = False
            self.close(err_str=err)

    def file_split_size(self):
        """ The chunk size depends on the python version, cpu count,
            the protocol used to copy, FreeBSD and OpenSSH version
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering file_split_size()")
        if sys.version_info < (3, 6):
            # if using python < 3.6 the maximum number of simultaneous transfers is 5.
            self.split_size = int(divmod(self.file_size, 5)[0])
            return

        cpu_count = 1
        try:
            cpu_count = multiprocessing.cpu_count()
        except NotImplementedError:
            pass

        # python 3.6+ allows 5 simultaneous transfers per cpu
        if cpu_count <= 4:
            ftp_max, scp_max = cpu_count * 5, cpu_count * 5
        else:
            # ftp creates 1 user process per chunk
            # scp to FreeBSD 6 based junos creates 3 user processes per chunk
            # scp to FreeBSD 10+ based junos creates 2 user processes per chunk
            # +1 user process if openssh version is >= 7.4
            # each uid can have max of 64 processes
            # values here will leave min 19 processes headroom
            max_pids = 39
            ftp_max = max_pids
            if self.sshd_version >= 7.4 and self.bsd_version == 6.0:
                scp_pids = 4
            elif self.sshd_version >= 7.4 and self.bsd_version >= 11.0:
                scp_pids = 3
            elif self.bsd_version == 6.0:
                scp_pids = 3
            elif self.bsd_version >= 10.0:
                scp_pids = 2
            elif self.evo:
                scp_pids = 3
            else:
                # be conservative
                scp_pids = 4
            scp_max = round(max_pids / scp_pids)

        if self.copy_proto == "ftp":
            self.split_size = int(divmod(self.file_size, ftp_max)[0])
        else:
            self.split_size = int(divmod(self.file_size, scp_max)[0])
        self.logger.debug("file split size = {}".format(self.split_size))

    def split_file_local(self):
        """ splits file into chunks of size already determined in file_split_size()
            This function emulates GNU split.
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering split_file_local()")
        print("splitting file...")
        try:
            buf_size = 1024
            total_bytes = 0
            with open(self.file_path, "rb") as src:
                sfx_1 = "a"
                sfx_2 = "a"
                while total_bytes < self.file_size:
                    with open(
                        "{}{}{}".format(self.file_name, sfx_1, sfx_2), "wb"
                    ) as chunk:
                        chunk_bytes = 0
                        while chunk_bytes < self.split_size:
                            data = src.read(buf_size)
                            if data:
                                chunk.write(data)
                                chunk_bytes += buf_size
                                total_bytes += buf_size
                            else:
                                return
                    if sfx_2 == "z":
                        sfx_1 = "b"
                        sfx_2 = "a"
                    else:
                        sfx_2 = chr(ord(sfx_2) + 1)
        except Exception as err:
            err_str = (
                "an error occurred while splitting the file, "
                "the error was:\n{}".format(err)
            )
            self.close(err_str)

    def split_file_remote(self):
        """ splits file on remote host
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering split_file_remote()")
        total_blocks = int(self.file_size / 1024)
        block_size = int(self.split_size / 1024)
        cmd = (
            "size_b={}; size_tb={}; i=0; o=00; "
            "while [ $i -lt $size_tb ]; do "
            "dd if={} of={}/{}_$o bs=1024 count=$size_b skip=$i; "
            "i=`expr $i + $size_b`; o=`expr $o + 1`; "
            "if [ $o -lt 10 ]; then o=0$o; fi; done".format(
                block_size,
                total_blocks,
                self.file_path,
                self.remote_tmpdir,
                self.file_name,
            )
        )
        self.ss.run(
            "echo '{}' > {}/split.sh && sh {}/split.sh".format(
                cmd, self.remote_tmpdir, self.remote_tmpdir
            )
        )
        if not self.ss.last_ok:
            err_str = "couldn't split the remote file"
            self.close(err_str)

    def local_sha1_get(self):
        """ generates a sha1 for the combined file on the local host
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering local_sha1_get()")
        print("generating local sha1...")
        buf_size = 131072
        sha1 = hashlib.sha1()
        dst_file = self.dest_dir + "/" + self.file_name
        with open(dst_file, "rb") as dst:
            data = dst.read(buf_size)
            while data:
                sha1.update(data)
                data = dst.read(buf_size)
        local_sha1 = sha1.hexdigest()
        self.logger.debug("local sha1 = {}".format(local_sha1))
        if os.name == "nt":
            slash = "\\"
        else:
            slash = "/"
        if local_sha1 == self.remote_sha1:
            print(
                "local and remote sha1 match\nfile has been "
                "successfully copied to {}{}{}".format(
                    self.dest_dir, slash, self.file_name
                )
            )
        else:
            err = (
                "file has been copied to {}{}{}, but the "
                "local and remote sha1 do not match - "
                "please retry".format(self.dest_dir, slash, self.file_name)
            )
            self.config_rollback = False
            self.close(err_str=err)

    def local_sha1_put(self):
        """ checks whether a sha1 already exists for the file
            if not creates one
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering local_sha1_put()")
        if os.path.isfile(self.file_path + ".sha1"):
            sha1file = open(self.file_path + ".sha1", "r")
            self.local_sha1 = sha1file.read().split()[0].rstrip()
        else:
            print("sha1 not found, generating sha1...")
            buf_size = 131072
            sha1 = hashlib.sha1()
            with open(self.file_path, "rb") as original_file:
                data = original_file.read(buf_size)
                while data:
                    sha1.update(data)
                    data = original_file.read(buf_size)
            self.local_sha1 = sha1.hexdigest()
        self.logger.debug("local sha1 = {}".format(self.local_sha1))

    def mkdir_remote(self):
        """ creates a tmp directory on the remote host
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering mkdir_remote()")
        ts = time.strftime("%y%m%d%H%M%S")
        if self.get_op:
            self.remote_tmpdir = "/var/tmp/splitcopy_{}.{}".format(self.file_name, ts)
        else:
            self.remote_tmpdir = "{}/splitcopy_{}.{}".format(
                self.dest_dir, self.file_name, ts
            )
        cmd_out = self.ss.run("mkdir -p {}".format(self.remote_tmpdir))
        if not self.ss.last_ok:
            err = (
                "unable to create the tmp directory on remote host."
                "cmd output was:\n{}".format(cmd_out[1])
            )
            self.close(err_str=err)
        self.rm_remote_tmp = True

    def remote_sha1_get(self):
        """ generates a sha1 for the remote file to be copied
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering remote_sha1_get()")
        remote_sha1 = self.ss.run("cat {}.sha1".format(self.file_path))
        if self.ss.last_ok:
            self.logger.debug("sha1 file found")
            self.remote_sha1 = remote_sha1[1].split("\n")[1].rstrip()
        else:
            print("generating remote sha1...")
            remote_sha1 = self.ss.run(
                "{} {}".format(self.sha_bin, self.file_path), timeout=300
            )
            if not self.ss.last_ok:
                self.close(err_str="failed to generate remote sha1")

            if self.sha_bin == "sha1sum" or self.sha_bin == "shasum":
                self.remote_sha1 = remote_sha1[1].split("\n")[1].split()[0].rstrip()
            else:
                self.remote_sha1 = remote_sha1[1].split("\n")[1].split()[3].rstrip()
        self.logger.debug("remote sha1 = {}".format(self.remote_sha1))

    def remote_filesize(self):
        """  determines the remote file size in bytes
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering remote_filesize()")
        file_size = self.ss.run("ls -l {}".format(self.file_path))
        if self.ss.last_ok:
            self.file_size = int(file_size[1].split("\n")[1].split()[4])
        else:
            self.close(err_str="cannot determine remote file size")
        self.logger.debug("src file size is {}".format(self.file_size))

    def storage_check_remote(self):
        """ checks whether there is enough storage space on remote node
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering storage_check_remote()")
        avail_blocks = 0
        print("checking remote storage...")
        if self.get_op:
            multiplier = 1
            df_tuple = self.ss.run("df -k /var/tmp/")
        else:
            multiplier = 2
            df_tuple = self.ss.run("df -k {}".format(self.dest_dir))
        if not self.ss.last_ok:
            self.close(err_str="failed to determine remote disk space available")
        df_num = len(df_tuple[1].split("\n")) - 2
        if re.match(r"^ ", df_tuple[1].split("\n")[df_num]):
            split_num = 2
        else:
            split_num = 3
        try:
            avail_blocks = df_tuple[1].split("\n")[df_num].split()[split_num].rstrip()
        except:
            err_str = "unable to determine available blocks on remote host"
            self.close(err_str)

        avail_bytes = int(avail_blocks) * 1024
        self.logger.debug("remote filesystem available bytes is {}".format(avail_bytes))
        if self.file_size * multiplier > avail_bytes:
            if self.get_op:
                err_str = (
                    "not enough storage on remote host in /var/tmp.\nAvailable bytes "
                    "({}) must be > the original file size ({}) because it has to "
                    "store the file chunks".format(avail_bytes, self.file_size)
                )
            else:
                err_str = (
                    "not enough storage on remote host in {}.\nAvailable bytes ({}) "
                    "must be 2x the original file size ({}) because it has to "
                    "store the file chunks and the whole file at the "
                    "same time".format(self.dest_dir, avail_bytes, self.file_size)
                )
            self.close(err_str)

    def storage_check_local(self):
        """ checks whether there is enough storage space on local node
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering storage_check_local()")
        print("checking local storage...")
        local_tmpdir = tempfile.gettempdir()
        avail_bytes = shutil.disk_usage(local_tmpdir)[2]
        self.logger.debug(
            "local filesystem {} available bytes is {}".format(
                local_tmpdir, avail_bytes
            )
        )
        if self.file_size > avail_bytes:
            err_str = (
                "not enough storage on local host in temp dir {}.\nAvailable bytes "
                "({}) must be > the original file size ({}) because it has to "
                "store the file chunks".format(
                    local_tmpdir, avail_bytes, self.file_size
                )
            )
            self.close(err_str)

        if self.get_op:
            avail_bytes = shutil.disk_usage(self.dest_dir)[2]
            self.logger.debug(
                "local filesystem {} available bytes is {}".format(
                    self.dest_dir, avail_bytes
                )
            )
            if self.file_size > avail_bytes:
                err_str = (
                    "not enough storage on local host in {}.\nAvailable bytes ({}) "
                    "must be > the original file size ({}) because it has to "
                    "recombine the file chunks into a whole file".format(
                        self.dest_dir, avail_bytes, self.file_size
                    )
                )
                self.close(err_str)

    def put_files(self, sfile, **kwargs):
        """ copies files to remote host via ftp or scp
        Args:
            self - class variables inherited from __init__
            sfile(str) - name of the file to copy
            kwargs (dict) - named arguments
        Returns:
            None
        Raises:
            None
        """
        retry = 3
        success = False
        if self.copy_proto == "ftp":
            while retry:
                try:
                    with FTP(self.dev, **kwargs) as ftp_proto:
                        if ftp_proto.put(sfile, "{}/".format(self.remote_tmpdir)):
                            retry = 0
                            success = True
                        else:
                            if not self.mute:
                                print("retrying file {}".format(sfile))
                            retry -= 1
                except Exception as err:
                    if not self.mute:
                        print("retrying file {} due to error: {}".format(sfile, err))
                    retry -= 1
        else:
            while retry:
                try:
                    with SCP(self.dev, **kwargs) as scp_proto:
                        scp_proto.put(sfile, "{}/".format(self.remote_tmpdir))
                        retry = 0
                        success = True
                except SCPException as err:
                    err = str(err).split(":")[-1].rstrip().lstrip()
                    if not self.mute:
                        print(
                            "retrying file {} due to SCP error: {}".format(sfile, err)
                        )
                    retry -= 1
                except IOError:
                    if not self.mute:
                        print("retrying file {} due to IOError".format(sfile))
                    retry -= 1
                except SSHException as err:
                    if not self.mute:
                        print(
                            "retrying file {} due to SSH error: {}".format(sfile, err)
                        )
                    retry -= 1
                except Exception as err:
                    if not self.mute:
                        print("retrying file {} due to error: {}".format(sfile, err))
                    retry -= 1

        if not success:
            self.mute = True
            raise TransferError

    def get_files(self, sfile, **kwargs):
        """ copies files from remote host via ftp or scp
        Args:
            self - class variables inherited from __init__
            sfile(str) - name of the file to copy
            kwargs (dict) - named arguments
        Returns:
            None
        Raises:
            None
        """
        retry = 3
        success = False
        if self.copy_proto == "ftp":
            while retry:
                try:
                    with FTP(self.dev, **kwargs) as ftp_proto:
                        if ftp_proto.get(
                            "{}/{}".format(self.remote_tmpdir, sfile),
                            local_path="{}/{}".format(self.local_tmpdir, sfile),
                        ):
                            retry = 0
                            success = True
                        else:
                            if not self.mute:
                                print("retrying file {}".format(sfile))
                            retry -= 1
                except Exception as err:
                    if not self.mute:
                        print("retrying file {} due to error: {}".format(sfile, err))
                    retry -= 1
        else:
            while retry:
                try:
                    with SCP(self.dev, **kwargs) as scp_proto:
                        scp_proto.get(
                            "{}/{}".format(self.remote_tmpdir, sfile),
                            local_path="{}/{}".format(self.local_tmpdir, sfile),
                        )
                        retry = 0
                        success = True
                except SCPException as err:
                    err = str(err).split(":")[-1].rstrip().lstrip()
                    if not self.mute:
                        print(
                            "retrying file {} due to SCP error: {}".format(sfile, err)
                        )
                    retry -= 1
                except IOError:
                    if not self.mute:
                        print("retrying file {} due to IOError".format(sfile))
                    retry -= 1
                except SSHException as err:
                    if not self.mute:
                        print(
                            "retrying file {} due to SSH error: {}".format(sfile, err)
                        )
                    retry -= 1
                except Exception as err:
                    if not self.mute:
                        print("retrying file {} due to error: {}".format(sfile, err))
                    retry -= 1
        if not success:
            self.mute = True
            raise TransferError

    @contextmanager
    def change_dir(self, cleanup=lambda: True):
        """ cds into temp directory.
            Upon script exit, changes back to original directory
            and calls cleanup() to delete the temp directory
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        prevdir = os.getcwd()
        os.chdir(os.path.expanduser(self.local_tmpdir))
        try:
            yield
        finally:
            os.chdir(prevdir)
            cleanup()

    @contextmanager
    def tempdir(self):
        """
        creates a temp directory
        defines how to delete directory upon script exit
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.local_tmpdir = tempfile.mkdtemp()

        def cleanup():
            """ deletes temp dir
            """
            shutil.rmtree(self.local_tmpdir)

        with self.change_dir(cleanup):
            yield self.local_tmpdir

    def limit_check(self):
        """ Checks the remote hosts /etc/inetd file to determine whether there are any
        ftp or ssh connection/rate limits defined. If found, these configuration lines
        will be deactivated
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering limit_check()")
        config_stanzas = ["groups", "system services"]
        if self.copy_proto == "ftp":
            limits = [
                "ssh connection-limit",
                "ssh rate-limit",
                "ftp connection-limit",
                "ftp rate-limit",
            ]
        else:
            limits = ["ssh connection-limit", "ssh rate-limit"]

        # check for presence of rate/connection limits
        cli_config = ""
        conf_line = ""
        for stanza in config_stanzas:
            config = self.ss.run(
                'cli -c "show configuration {} | display set | no-more"'.format(stanza)
            )
            cli_config += config[1]
        for limit in limits:
            if (
                cli_config
                and re.search(r"{} [0-9]".format(limit), cli_config) is not None
            ):
                conf_list = cli_config.split("\r\n")
                for conf_statement in conf_list:
                    if re.search(r"set .* {} [0-9]".format(limit), conf_statement):
                        conf_line = re.sub(" [0-9]+$", "", conf_statement)
                        conf_line = re.sub("set", "deactivate", conf_line)
                        self.command_list.append("{};".format(conf_line))
                    if re.search(r"deactivate .* {}".format(limit), conf_statement):
                        self.command_list.remove("{};".format(conf_line))

        # if limits were configured, deactivate them
        if self.command_list:
            print("protocol rate-limit/connection-limit configuration found")
            self.ss.run(
                'cli -c "edit;{}commit and-quit"'.format("".join(self.command_list))
            )
            if self.ss.last_ok:
                print(
                    "the configuration has been modified. "
                    "deactivated the limit(s) found"
                )
            else:
                err = (
                    "Error: failed to deactivate {} connection-limit/rate-limit"
                    "configuration. Cannot proceed".format(self.copy_proto)
                )
                self.close(err_str=err)
        else:
            return

    def limits_rollback(self):
        """ revert config change made to remote host
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        self.logger.debug("entering limits_rollback()")
        rollback_cmds = "".join(self.command_list)
        rollback_cmds = re.sub("deactivate", "activate", rollback_cmds)
        self.ss.run('cli -c "edit;{}commit and-quit"'.format(rollback_cmds))
        if self.ss.last_ok:
            print("the configuration changes made have been reverted.")
        else:
            print(
                "Error: failed to revert the connection-limit/rate-limit"
                "configuration changes made"
            )

    def remote_cleanup(self, silent=False):
        """ delete tmp directory on remote host
        Args:
            self - class variables inherited from __init__
            silent (bool) - determines whether we announce the dir deletion
        Returns:
            None
        Raises:
            None
        """
        if not silent:
            print("deleting remote tmp directory...")
        self.ss.run("rm -rf {}".format(self.remote_tmpdir), timeout=30)
        if not self.ss.last_ok and not silent:
            print(
                "unable to delete the tmp directory {} on remote host, "
                "delete it manually".format(self.remote_tmpdir)
            )
        self.rm_remote_tmp = False


class TransferError(Exception):
    """ custom exception to indicate problem with file transfer
    """

    pass


class FtpProgress:
    """ class which jnpr.junos.utils.ftp calls back to
    """

    def __init__(self, file_size):
        """ Initialise the class
        """
        self.file_size = file_size
        self.last_percent = 0
        self.data_sum = 0
        self.header_bytes = 33

    def handle(self, data):
        """ For every 10% of data transferred, notifies the user
        Args:
            data(obj) - data being exchanged
        Returns:
            None
        Raises:
            None
        """
        size_data = sys.getsizeof(data) - self.header_bytes
        self.data_sum += size_data
        percent_done = int((100 / self.file_size) * self.data_sum)
        if self.last_percent != percent_done:
            self.last_percent = percent_done
            if percent_done % 10 == 0:
                print("{}% done".format(str(percent_done)))


class ScpProgress:
    """ class which jnpr.junos.utils.scp calls back to
    """

    def __init__(self, file_size):
        """ Initialise the class
        """
        self.file_size = file_size
        self.last_percent = 0
        self.sent_sum = 0
        self.last_sent = 0
        self.files_progress = {}

    def handle(self, file_name, size, sent):
        """ For every 10% of data transferred, notifies the user
        Args:
            file_name(str) - name of file
            size(int) - size of of file in bytes
            sent(int) - bytes transferred
        Returns:
            None
        Raises:
            None
        """
        try:
            file_name = file_name.decode()
        except AttributeError:
            pass
        self.files_progress["{}".format(file_name)] = sent
        sent_values = list(self.files_progress.values())
        self.sent_sum = sum(sent_values)
        percent_done = int((100 / self.file_size) * self.sent_sum)
        if self.last_percent != percent_done:
            self.last_percent = percent_done
            if percent_done % 10 == 0:
                print("{}% done".format(str(percent_done)))


if __name__ == "__main__":
    main()
