#!/usr/bin/env python3
""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

# stdlib
try:
    import asyncio
except ImportError:
    raise RuntimeError("Splitcopy requires Python 3.4+")
import argparse
import concurrent.futures
import datetime
import fnmatch
import functools
import getpass
import glob
import hashlib
import logging
import os
import re
import signal
import shutil
import socket
import sys
import tempfile
import time
import traceback
from contextlib import contextmanager
from math import ceil

# 3rd party
from scp import SCPClient
from paramiko.ssh_exception import SSHException

# local modules
from splitcopy.paramikoshell import SSHShell
from splitcopy.progress import Progress
from splitcopy.ftp import FTP

_BUF_SIZE_READ = 131072
_BUF_SIZE = 1024

logger = logging.getLogger(__name__)


def main():
    """ body of script
    """

    def handlesigint(sigint, stack):
        raise SystemExit

    signal.signal(signal.SIGINT, handlesigint)
    start_time = datetime.datetime.now()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "source", help="either <path> or user@<host>:<path> or <host>:<path>"
    )
    parser.add_argument(
        "target", help="either <path> or user@<host>:<path> or <host>:<path>"
    )
    parser.add_argument(
        "--pwd", nargs=1, help="password to authenticate on remote host"
    )
    parser.add_argument(
        "--ssh_key",
        nargs=1,
        help="path to ssh private key (only if in non-default location)",
    )
    parser.add_argument(
        "--scp", action="store_true", help="use scp to copy files instead of ftp"
    )
    parser.add_argument(
        "--noverify",
        action="store_true",
        help="skip sha hash comparison of src and dst file",
    )
    parser.add_argument("--log", nargs=1, help="log level, eg DEBUG")
    args = parser.parse_args()

    if not args.log:
        loglevel = "WARNING"
    else:
        loglevel = args.log[0]

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: {}".format(loglevel))
    logging.basicConfig(
        format="%(asctime)s %(name)s %(funcName)s %(levelname)s:%(message)s",
        level=numeric_level,
    )

    user = None
    user_specified = False
    host = None
    passwd = None
    ssh_key = None
    remote_dir = None
    remote_file = None
    remote_path = None
    local_dir = None
    local_name = None
    local_path = None
    file_size = 0
    copy_proto = None
    get = False
    noverify = args.noverify
    source = args.source
    target = args.target

    if re.search(r".*:", source):
        if re.search(r"@", source):
            user = source.split("@")[0]
            user_specified = True
            host = source.split("@")[1]
            host = host.split(":")[0]
        else:
            user = getpass.getuser()
            host = source.split(":")[0]
        remote_path = source.split(":")[1]
        remote_file = os.path.basename(remote_path)
        remote_dir = os.path.dirname(remote_path)
        if remote_dir == "" or remote_dir == ".":
            remote_dir = "~"
            remote_path = "{}/{}".format(remote_dir, remote_file)
        if not remote_file:
            raise SystemExit("src path doesn't specify a file name")
        get = True
    elif os.path.isfile(source):
        local_path = os.path.abspath(os.path.expanduser(source))
        try:
            open(local_path, "rb")
        except PermissionError:
            raise SystemExit(
                "source file {} exists but is not readable - cannot proceed".format(
                    local_path
                )
            )
        local_file = os.path.basename(local_path)
        local_dir = os.path.dirname(local_path)
        file_size = os.path.getsize(local_path)
        logger.info("src file size is {}".format(file_size))
    else:
        raise SystemExit(
            "specified source is not a valid path to a local "
            "file, or is not in the format <user>@<host>:<path> "
            "or <host>:<path>"
        )

    if re.search(r".*:", target):
        if re.search(r"@", target):
            user = target.split("@")[0]
            user_specified = True
            host = target.split("@")[1]
            host = host.split(":")[0]
        else:
            user = getpass.getuser()
            host = target.split(":")[0]
        remote_path = target.split(":")[1]
        if remote_path == "":
            remote_dir = "~"
            remote_file = local_file
            remote_path = "{}/{}".format(remote_dir, remote_file)
        elif os.path.dirname(remote_path) == "":
            remote_dir = "~"
            remote_file = remote_path
            remote_path = "{}/{}".format(remote_dir, remote_file)
    elif os.path.isdir(target):
        local_dir = os.path.abspath(os.path.expanduser(target))
        local_file = remote_file
    elif os.path.isdir(os.path.dirname(target)):
        # we've been passed in a filename, may not exist yet
        local_dir = os.path.dirname(os.path.abspath(os.path.expanduser(target)))
        if os.path.basename(target) != remote_file:
            # have to honour the change of name
            local_file = os.path.basename(target)
        else:
            local_file = remote_file
    else:
        raise SystemExit(
            "specified target is not a valid path to a local "
            "file or directory, or is not in the format <user>@<host>:<path> "
            "or <host>:<path>"
        )

    if args.pwd:
        passwd = args.pwd[0]

    if not args.scp:
        try:
            ftp_port_check(host)
            copy_proto = "ftp"
            if not user_specified:
                user_input = input("Username (or hit enter to use '{}'): ".format(user))
                if user_input != "":
                    user = user_input
            if passwd is None:
                passwd = getpass.getpass(prompt="Password: ", stream=None)
        except (socket.gaierror, socket.herror):
            raise SystemExit("address or hostname not reachable")
        except (socket.timeout, ConnectionRefusedError, IOError, OSError):
            copy_proto = "scp"
    else:
        copy_proto = "scp"
    logger.info("copy_proto == {}".format(copy_proto))

    if args.ssh_key is not None:
        ssh_key = os.path.abspath(args.ssh_key[0])
        if not os.path.isfile(ssh_key):
            raise SystemExit("specified ssh key not found")

    kwargs = {
        "user": user,
        "host": host,
        "passwd": passwd,
        "ssh_key": ssh_key,
        "remote_dir": remote_dir,
        "remote_file": remote_file,
        "remote_path": remote_path,
        "local_dir": local_dir,
        "local_file": local_file,
        "local_path": local_path,
        "file_size": file_size,
        "copy_proto": copy_proto,
        "get": get,
        "noverify": noverify,
    }
    logger.info(kwargs)

    splitcopy = SplitCopy(**kwargs)

    if get:
        loop_start, loop_end = splitcopy.get()
    else:
        loop_start, loop_end = splitcopy.put()

    # and we are done...
    end_time = datetime.datetime.now()
    time_delta = end_time - start_time
    transfer_delta = loop_end - loop_start
    print("data transfer = {}\ntotal runtime = {}".format(transfer_delta, time_delta))


def ftp_port_check(host):
    """ checks if ftp port is open on remote host, emulates 'nc -z <host> <port>'
        :param host: host to test
        :type: string
        :returns: None
        :raises: any exception
    """
    logger.info("entering ftp_port_check()")
    try:
        with socket.create_connection((host, 21), 10) as ftp_sock:
            pass
    except Exception:
        raise


class SplitCopy:
    """ copies a file between hosts
        speeds up the process by splitting/transferring/combining the file
        rate increases with number of ssh sessions (not channels) or ftp sessions
        ftp is slower to initialise, faster to transfer due to more sessions than scp
        scp is much faster to initialise, slower to transfer due to fewer sessions than ftp
    """

    def __init__(self, **kwargs):
        """ Initialise the SplitCopy class
        """
        self.user = kwargs.get("user")
        self.host = kwargs.get("host")
        self.passwd = kwargs.get("passwd")
        self.ssh_key = kwargs.get("ssh_key")
        self.remote_dir = kwargs.get("remote_dir")
        self.remote_file = kwargs.get("remote_file")
        self.remote_path = kwargs.get("remote_path")
        self.local_dir = kwargs.get("local_dir")
        self.local_file = kwargs.get("local_file")
        self.local_path = kwargs.get("local_path")
        self.file_size = kwargs.get("file_size")
        self.copy_proto = kwargs.get("copy_proto")
        self.get_op = kwargs.get("get")
        self.noverify = kwargs.get("noverify")
        self.command_list = []
        self.rm_remote_tmp = False
        self.config_rollback = True
        self.hard_close = False
        self.copy_kwargs = {}
        self.local_sha = None
        self.local_tmpdir = None
        self.tasks = []
        self.split_size = None
        self.remote_tmpdir = None
        self.remote_sha = None
        self.host_os = None
        self.evo = False
        self.junos = False
        self.bsd_version = 0.0
        self.sshd_version = 0.0
        self.sha_bin = None
        self.sha_len = None
        self.mute = False
        self.sha_hash = {}
        self.executor = None
        self.ssh_kwargs = {
            "username": self.user,
            "hostname": self.host,
            "password": self.passwd,
            "key_filename": self.ssh_key,
            "passphrase": None,
        }

    def handlesigint(self, sigint, stack):
        self.close()

    def connect(self):
        try:
            self.ss = SSHShell(**self.ssh_kwargs)
            sock = self.ss.socket_open()
            self.ss.transport_open(sock)
            if self.ss.main_thread_auth():
                self.ss.channel_open()
                self.ss.invoke_shell()
                self.ssh_kwargs = self.ss.kwargs
            else:
                raise SSHException("authentication failed")
            self.ss.set_keepalive()
            # remove the welcome message from the socket
            self.ss.stdout_read(timeout=30)
        except Exception as err:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            self.ss.close()
            raise SystemExit(
                "{} returned while connecting via ssh: {}".format(
                    err.__class__.__name__, str(err)
                )
            )

    def put(self):
        """ copies file from local host to remote host
            performs file split/transfer/join/verify functions
            :returns loop_start: time when transfers started
            :type: datetime object
            :returns loop_end: time when transfers ended
            :type: datetime object
        """
        # handle sigint gracefully on *nix, WIN32 is (of course) a basket case
        signal.signal(signal.SIGINT, self.handlesigint)

        # connect to host
        self.connect()

        # determine remote host os
        self.which_os()

        # ensure dest path is valid
        self.validate_remote_path_put()

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
            # get/create sha for local file
            self.local_sha_put()

        # determine optimal size for chunks
        self.file_split_size()

        with self.tempdir():
            # split file into chunks
            self.split_file_local()

            # add chunk names to a list
            sfiles = []
            for sfile in os.listdir("."):
                if fnmatch.fnmatch(sfile, "{}*".format(self.local_file)):
                    sfiles.append([sfile, os.stat(sfile).st_size])
            if not len(sfiles):
                self.close(err_str="file split operation failed")
            logger.info("# of chunks = {}".format(len(sfiles)))

            # end of pre transfer checks, create tmp directory
            self.mkdir_remote()

            # begin connection/rate limit check and transfer process
            if self.junos or self.evo:
                self.limit_check()

            if self.copy_proto == "ftp":
                self.copy_kwargs.update(
                    {
                        "progress": Progress(self.file_size).handle,
                        "host": self.host,
                        "user": self.user,
                        "passwd": self.passwd,
                    }
                )
            else:
                self.copy_kwargs.update({"progress": Progress(self.file_size).handle})

            # copy files to remote host
            self.hard_close = True
            loop_start = datetime.datetime.now()
            print("starting transfer...")
            loop = asyncio.get_event_loop()
            for sfile in sfiles:
                task = loop.run_in_executor(
                    self.executor, functools.partial(self.put_files, sfile)
                )
                self.tasks.append(task)
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

        print("\ntransfer complete")
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
                    self.host, self.remote_dir, self.remote_file
                )
            )
        else:
            # generate a sha hash for the combined file, compare to hash of src
            self.remote_sha_put()

        self.ss.close()
        return loop_start, loop_end

    def get(self):
        """ copies file from remote host to local host
            performs file split/transfer/join/verify functions
            :returns loop_start: time when transfers started
            :type: datetime object
            :returns loop_end: time when transfers ended
            :type: datetime object
        """
        # handle sigint gracefully on *nix, WIN32 is (of course) a basket case
        signal.signal(signal.SIGINT, self.handlesigint)

        # connect to host
        self.connect()

        # determine remote host os
        self.which_os()

        # ensure dest path is valid
        self.validate_remote_path_get()

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

        # determine remote file size
        self.remote_filesize()

        # confirm remote storage is sufficient
        self.storage_check_remote()

        # confirm local storage is sufficient
        self.storage_check_local()

        if not self.noverify:
            # get/create sha hash for remote file
            self.remote_sha_get()

        # determine optimal size for chunks
        self.file_split_size()

        # create tmp directory on remote host
        self.mkdir_remote()

        # split file into chunks
        self.split_file_remote()

        # add chunk names to a list
        result, stdout = self.ss.run("ls -l {}/".format(self.remote_tmpdir))
        if not result:
            self.close(err_str="couldn't get list of files from host")
        remote_files = stdout.split("\r\n")
        sfiles = []
        for sfile in remote_files:
            if fnmatch.fnmatch(sfile, "* {}*".format(self.remote_file)):
                sfile = sfile.split()
                sfiles.append([sfile[-1], sfile[-5]])
        if not len(sfiles):
            self.close(err_str="file split operation failed")
        logger.info("# of chunks = {}".format(len(sfiles)))

        # begin connection/rate limit check and transfer process
        if self.junos or self.evo:
            self.limit_check()

        if self.copy_proto == "ftp":
            self.copy_kwargs.update(
                {
                    "progress": Progress(self.file_size).handle,
                    "host": self.host,
                    "user": self.user,
                    "passwd": self.passwd,
                }
            )
        else:
            self.copy_kwargs.update({"progress": Progress(self.file_size).handle})

        with self.tempdir():
            # copy files from remote host
            self.hard_close = True
            loop_start = datetime.datetime.now()
            loop = asyncio.get_event_loop()
            self.tasks = []
            for sfile in sfiles:
                task = loop.run_in_executor(
                    self.executor, functools.partial(self.get_files, sfile)
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

            print("\ntransfer complete")
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
                    self.local_dir, self.local_file
                )
            )
        else:
            # generate a sha hash for the combined file, compare to hash of src
            self.local_sha_get()

        self.ss.close()
        return loop_start, loop_end

    def which_os(self):
        """ determine if host is JUNOS/EVO/*nix
            no support for Windows OS running OpenSSH
            :returns None:
        """
        logger.info("entering which_os()")
        self.ss.run("start shell", exitcode=False)
        result, stdout = self.ss.run("uname")
        if not result:
            err = "failed to determine remote host os, it must be *nix based"
            self.close(err_str=err)
        self.host_os = stdout[0].split("\n")[0].rstrip()
        if self.host_os == "Linux" and self.evo_os():
            self.evo = True
        else:
            self.junos_os()
        logger.info(
            "evo = {}, junos = {}, bsd_version = {}, sshd_version = {}".format(
                self.evo, self.junos, self.bsd_version, self.sshd_version
            )
        )

    def validate_remote_path_get(self):
        """ path must be a full path, expand as required
            :return: None
        """
        logger.info("entering validate_remote_path_get()")
        if re.match(r"~", self.remote_dir):
            result, stdout = self.ss.run("ls -d {}".format(self.remote_dir))
            if result:
                self.remote_dir = stdout.split("\n")[1].rstrip()
                self.remote_path = "{}/{}".format(self.remote_dir, self.remote_file)
                logger.info(
                    "remote_dir now = {}, remote_file now = {}".format(
                        self.remote_dir, self.remote_file
                    )
                )
            else:
                self.close(
                    err_str="unable to expand remote path {}".format(self.remote_path)
                )

        # bail if its a directory
        result, stdout = self.ss.run("test -d {}".format(self.remote_path))
        if result:
            self.close(err_str="src path is a directory, not a file")

        # begin pre transfer checks, check if remote file exists
        result, stdout = self.ss.run("test -r {}".format(self.remote_path))
        if not result:
            self.close(err_str="file on remote host is not readable")

        # is it a symlink? if so, rewrite remote_path with linked file path
        result, stdout = self.ss.run("test -L {}".format(self.remote_path))
        if result:
            logger.info("file is a symlink")
            result, stdout = self.ss.run("ls -l {}".format(self.remote_path))
            if result:
                self.remote_path = stdout.split()[-2].rstrip()
                self.remote_dir = os.path.dirname(self.remote_path)
                self.remote_file = os.path.basename(self.remote_path)
            else:
                self.close(
                    err_str="file on remote host is a symlink, failed to retrieve details"
                )

    def validate_remote_path_put(self):
        """ path provided can be a directory, a new or existing file
            :return: None
        """
        logger.info("entering validate_remote_path_put()")
        if self.ss.run("test -d {}".format(self.remote_path))[0]:
            # target path provided is a directory
            self.remote_file = self.local_file
            self.remote_dir = self.remote_path.rstrip("/")
        elif (
            self.ss.run("test -f {}".format(self.remote_path))[0]
            or self.ss.run("test -d {}".format(os.path.dirname(self.remote_path)))[0]
        ):
            if os.path.basename(self.remote_path) != self.local_file:
                # target path provided was a full path, file name does not match src
                # honour the change of file name
                self.remote_file = os.path.basename(self.remote_path)
            else:
                # target path provided was a full path, file name matches src
                self.remote_file = self.local_file
            self.remote_dir = os.path.dirname(self.remote_path)
            logger.info(
                "self.remote_path = {}, self.remote_dir = {}, self.remote_file = {}".format(
                    self.remote_path, self.remote_dir, self.remote_file
                )
            )
        else:
            self.close(
                err_str="target path {} on remote host isn't valid".format(
                    self.remote_path
                )
            )

    def evo_os(self):
        """ determines if host is EVO
            :returns result: True if OS is EVO
            :type: boolean
        """
        logger.info("entering evo_os()")
        result, stdout = self.ss.run("test -e /usr/sbin/evo-pfemand")
        return result

    def junos_os(self):
        """ determines if host is JUNOS
            :returns None:
        """
        logger.info("entering junos_os()")
        result, stdout = self.ss.run("uname -i")
        if not result:
            self.close(err_str="failed to determine remote host os")
        uname = stdout.split("\n")[1]
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
            :returns None:
        """
        logger.info("entering which_bsd()")
        result, stdout = self.ss.run("uname -r")
        if not result:
            self.close(err_str="failed to determine remote bsd version")
        uname = stdout.split("\n")[1]
        self.bsd_version = float(uname.split("-")[1])

    def which_sshd(self):
        """ determines the OpenSSH daemon version
            :returns None:
        """
        logger.info("entering which_sshd()")
        result, stdout = self.ss.run("sshd -v", exitcode=False)
        if not re.search(r"OpenSSH_", stdout):
            self.close(err_str="failed to determine remote openssh version")
        output = stdout.split("\n")[2]
        version = re.sub(r"OpenSSH_", "", output)
        self.sshd_version = float(version[0:3])

    def req_binaries(self):
        """ ensures required binaries exist on remote host
            :returns None:
        """
        logger.info("entering req_binaries()")
        if not self.junos and not self.evo:
            if self.get_op:
                req_bins = ["dd", "ls", "df", "rm"]
            else:
                req_bins = ["cat", "ls", "df", "rm"]
            for req_bin in req_bins:
                result, stdout = self.ss.run("which {}".format(req_bin))
                if not result:
                    self.close(
                        err_str=(
                            "required binary '{}' is missing from remote "
                            "host".format(req_bin)
                        )
                    )

    def second_elem(self, elem):
        """ used for key sort
            :returns: the 2nd part of an element
        """
        return elem[1]

    def req_sha_binaries(self):
        """ ensures required binaries for sha hash creation exist on remote host
        :returns None:
        """
        logger.info("entering req_sha_binaries()")
        sha_bins = []
        if self.sha_hash.get(512):
            bins = [("sha512sum", 512), ("sha512", 512), ("shasum", 512)]
            sha_bins.extend(bins)
        if self.sha_hash.get(384):
            bins = [("sha384sum", 384), ("sha384", 384), ("shasum", 384)]
            sha_bins.extend(bins)
        if self.sha_hash.get(256):
            bins = [("sha256sum", 256), ("sha256", 256), ("shasum", 256)]
            sha_bins.extend(bins)
        if self.sha_hash.get(224):
            bins = [("sha224sum", 224), ("sha224", 224), ("shasum", 224)]
            sha_bins.extend(bins)
        if self.sha_hash.get(1):
            bins = [("sha1sum", 1), ("sha1", 1), ("shasum", 1)]
            sha_bins.extend(bins)

        sha_bins = sorted(set(sha_bins), reverse=True, key=self.second_elem)
        logger.info(sha_bins)

        for req_bin in sha_bins:
            result, stdout = self.ss.run("which {}".format(req_bin[0]))
            if result:
                self.sha_bin = req_bin[0]
                self.sha_len = req_bin[1]
                break
        if not self.sha_bin:
            self.close(
                err_str=(
                    "required binary used to generate a sha "
                    "hash on the remote host isn't found"
                )
            )

    def close(self, err_str=None):
        """ Called when we want to exit the script
            attempts to delete the remote temp directory and close the TCP session
            If self.hard_close == False, contextmanager will rm the local temp dir
            If not, we must delete it manually
            :param err_str: error description
            :type: string
            :raises SystemExit: terminates the script gracefully
            :raises os._exit: terminates the script immediately (even asyncio loop)
        """
        if err_str:
            print(err_str)
        if self.rm_remote_tmp:
            self.remote_cleanup()
        if self.config_rollback and self.command_list:
            self.limits_rollback()
        print("closing device connection")
        self.ss.close()
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
            :returns None:
        """
        logger.info("entering join_files_remote()")
        print("joining files...")
        result = False
        try:
            # >{} because > {} could be matched as _SHELL_PROMPT
            result, stdout = self.ss.run(
                "cat {}/* >{}/{}".format(
                    self.remote_tmpdir, self.remote_dir, self.remote_file
                ),
                timeout=600,
            )
        except Exception as err:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            self.close(
                err_str="{} while combining file chunks on remote host: {}".format(
                    err.__class__.__name__, str(err)
                )
            )

        if not result:
            self.close(
                err_str=(
                    "failed to combine chunks on remote host. "
                    "error was:\n{}".format(stdout)
                )
            )

    def join_files_local(self):
        """ concatenates the file chunks into one file on local host
            :returns None:
        """
        logger.info("entering join_files_local()")
        print("joining files...")
        src_files = glob.glob(self.local_tmpdir + os.path.sep + self.remote_file + "*")
        dst_file = self.local_dir + os.path.sep + self.local_file
        with open(dst_file, "wb") as dst:
            for src in sorted(src_files):
                with open(src, "rb") as chunk:
                    data = chunk.read(_BUF_SIZE_READ)
                    while data:
                        dst.write(data)
                        data = chunk.read(_BUF_SIZE_READ)
        if not os.path.isfile(dst_file):
            err_str = "recombined file {} isn't found, exiting".format(dst_file)
            self.close(err_str)

    def remote_sha_put(self):
        """ creates a sha hash for the newly combined file on the remote host
            compares against local sha
            :returns None:
        """
        logger.info("entering remote_sha_put()")
        print("generating remote sha hash...")
        result, stdout = self.ss.run(
            "ls {}/{}".format(self.remote_dir, self.remote_file)
        )
        if not result:
            err = "file {}:{}/{} not found! please retry".format(
                self.host, self.remote_dir, self.remote_file
            )
            self.config_rollback = False
            self.close(err_str=err)

        if self.sha_bin == "shasum":
            cmd = "shasum -a {}".format(self.sha_len)
        else:
            cmd = "{}".format(self.sha_bin)

        result, stdout = self.ss.run(
            "{} {}/{}".format(cmd, self.remote_dir, self.remote_file), timeout=300
        )
        if not result:
            print(
                "remote sha hash generation failed or timed out, "
                'manually check the output of "{} {}/{}" and '
                "compare against {}".format(
                    cmd, self.remote_dir, self.remote_file, self.sha_hash[self.sha_len]
                )
            )
            return
        if re.match(r"sha.*sum", self.sha_bin):
            remote_sha = stdout.split("\n")[1].split()[0].rstrip()
        else:
            remote_sha = stdout.split("\n")[1].split()[3].rstrip()
        logger.info("remote sha = {}".format(remote_sha))
        if self.sha_hash[self.sha_len] == remote_sha:
            print(
                "local and remote sha hash match\nfile has been "
                "successfully copied to {}:{}/{}".format(
                    self.host, self.remote_dir, self.remote_file
                )
            )
        else:
            err = (
                "file has been copied to {}:{}/{}, but the "
                "local and remote sha do not match - "
                "please retry".format(self.host, self.remote_dir, self.remote_file)
            )
            self.config_rollback = False
            self.close(err_str=err)

    def file_split_size(self):
        """ The chunk size depends on the python version, cpu count,
            the protocol used to copy, FreeBSD and OpenSSH version
            :returns None:
        """
        logger.info("entering file_split_size()")

        try:
            cpu_count = os.cpu_count()
        except NotImplementedError:
            cpu_count = 1
        max_workers = min(32, cpu_count * 5)

        # each uid can have max of 64 processes
        # modulate worker count to consume no more than 40 pids
        if self.copy_proto == "ftp":
            # ftp creates 1 user process per chunk, no modulation required
            self.split_size = ceil(self.file_size / max_workers)
        elif max_workers <= 10:
            # 1 or 2 cpu cores, 5 or 10 workers will create 20-40 pids
            # no modulation required
            self.split_size = ceil(self.file_size / max_workers)
        else:
            # scp to FreeBSD 6 based junos creates 3 user processes per chunk
            # scp to FreeBSD 10+ based junos creates 2 user processes per chunk
            # +1 user process if openssh version is >= 7.4
            max_pids = 40
            if self.sshd_version >= 7.4 and self.bsd_version == 6.0:
                pid_count = 4
            elif self.sshd_version >= 7.4 and self.bsd_version >= 10.0:
                pid_count = 3
            elif self.bsd_version == 6.0:
                pid_count = 3
            elif self.bsd_version >= 10.0:
                pid_count = 2
            elif self.evo:
                pid_count = 3
            else:
                pid_count = 4
            max_workers = round(max_pids / pid_count)
            self.split_size = ceil(self.file_size / max_workers)

        # concurrent.futures.ThreadPoolExecutor can be a limiting factor
        # if using python < 3.5.3 the default max_workers is 5.
        # see https://github.com/python/cpython/blob/v3.5.2/Lib/asyncio/base_events.py
        # hence defining a custom executor to normalize max_workers across versions
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        logger.info(
            "max_workers = {}, cpu_count = {}, split_size = {}".format(
                max_workers, cpu_count, self.split_size
            )
        )

    def split_file_local(self):
        """ splits file into chunks of size already determined in file_split_size()
            This function emulates GNU split.
            :returns None:
        """
        logger.info("entering split_file_local()")
        print("splitting file...")
        try:
            total_bytes = 0
            with open(self.local_path, "rb") as src:
                sfx_1 = "a"
                sfx_2 = "a"
                while total_bytes < self.file_size:
                    with open(
                        "{}{}{}".format(self.local_file, sfx_1, sfx_2), "wb"
                    ) as chunk:
                        logger.info(
                            "writing data to {}{}{}".format(
                                self.local_file, sfx_1, sfx_2
                            )
                        )
                        src.seek(total_bytes)
                        data = src.read(self.split_size)
                        chunk.write(data)
                        total_bytes += self.split_size
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
            :returns None:
        """
        logger.info("entering split_file_remote()")
        total_blocks = ceil(self.file_size / _BUF_SIZE)
        block_size = ceil(self.split_size / _BUF_SIZE)
        logger.info(
            "total_blocks = {}, block_size = {}".format(total_blocks, block_size)
        )
        cmd = (
            "size_b={}; size_tb={}; i=0; o=00; "
            "while [ $i -lt $size_tb ]; do "
            "dd if={} of={}/{}_$o bs={} count=$size_b skip=$i; "
            "i=`expr $i + $size_b`; o=`expr $o + 1`; "
            "if [ $o -lt 10 ]; then o=0$o; fi; done".format(
                block_size,
                total_blocks,
                self.remote_path,
                self.remote_tmpdir,
                self.remote_file,
                _BUF_SIZE,
            )
        )

        # switched to file copy as the '> ' in 'echo cmd > file'
        # would sometimes be interpreted as shell prompt
        with self.tempdir():
            with open("split.sh", "w") as fd:
                fd.write(cmd)
            transport = self.ss._transport
            with SCPClient(transport, **self.copy_kwargs) as scpclient:
                scpclient.put("split.sh", "{}/split.sh".format(self.remote_tmpdir))

        self.ss.run("sh {}/split.sh".format(self.remote_tmpdir))

    def local_sha_get(self):
        """ generates a sha hash for the combined file on the local host
            :returns None:
        """
        logger.info("entering local_sha_get()")
        print("generating local sha hash...")
        if self.sha_hash.get(512):
            sha_idx = 512
            sha = hashlib.sha512()
        elif self.sha_hash.get(384):
            sha_idx = 384
            sha = hashlib.sha384()
        elif self.sha_hash.get(256):
            sha_idx = 256
            sha = hashlib.sha256()
        elif self.sha_hash.get(224):
            sha_idx = 224
            sha = hashlib.sha224()
        else:
            sha_idx = 1
            sha = hashlib.sha1()
        dst_file = self.local_dir + os.path.sep + self.local_file
        with open(dst_file, "rb") as dst:
            data = dst.read(_BUF_SIZE_READ)
            while data:
                sha.update(data)
                data = dst.read(_BUF_SIZE_READ)
        local_sha = sha.hexdigest()
        logger.info("local sha = {}".format(local_sha))
        if local_sha == self.sha_hash.get(sha_idx):
            print(
                "local and remote sha hash match\nfile has been "
                "successfully copied to {}{}{}".format(
                    self.local_dir, os.path.sep, self.local_file
                )
            )
        else:
            err = (
                "file has been copied to {}{}{}, but the "
                "local and remote sha hash do not match - "
                "please retry".format(self.local_dir, os.path.sep, self.local_file)
            )
            self.config_rollback = False
            self.close(err_str=err)

    def local_sha_put(self):
        """ checks whether a sha hash already exists for the file
            if not creates one
            :returns None:
        """
        file_path = self.local_path
        logger.info("entering local_sha_put()")
        if os.path.isfile("{}.sha512".format(file_path)):
            with open("{}.sha512".format(file_path), "r") as shafile:
                local_sha = shafile.read().split()[0].rstrip()
                self.sha_hash[512] = local_sha
        if os.path.isfile("{}.sha384".format(file_path)):
            with open("{}.sha384".format(file_path), "r") as shafile:
                local_sha = shafile.read().split()[0].rstrip()
                self.sha_hash[384] = local_sha
        if os.path.isfile("{}.sha256".format(file_path)):
            with open("{}.sha256".format(file_path), "r") as shafile:
                local_sha = shafile.read().split()[0].rstrip()
                self.sha_hash[256] = local_sha
        if os.path.isfile("{}.sha224".format(file_path)):
            with open("{}.sha224".format(file_path), "r") as shafile:
                local_sha = shafile.read().split()[0].rstrip()
                self.sha_hash[224] = local_sha
        if os.path.isfile("{}.sha1".format(file_path)):
            with open("{}.sha1".format(file_path), "r") as shafile:
                local_sha = shafile.read().split()[0].rstrip()
                self.sha_hash[1] = local_sha
        if not self.sha_hash:
            print("sha1 not found, generating sha1...")
            sha1 = hashlib.sha1()
            with open(file_path, "rb") as original_file:
                data = original_file.read(_BUF_SIZE_READ)
                while data:
                    sha1.update(data)
                    data = original_file.read(_BUF_SIZE_READ)
            local_sha = sha1.hexdigest()
            self.sha_hash[1] = local_sha
        logger.info("local sha hashes = {}".format(self.sha_hash))
        self.req_sha_binaries()

    def mkdir_remote(self):
        """ creates a tmp directory on the remote host
            :returns None:
        """
        logger.info("entering mkdir_remote()")
        ts = datetime.datetime.strftime(datetime.datetime.now(), "%y%m%d%H%M%S")
        if self.get_op:
            self.remote_tmpdir = "/var/tmp/splitcopy_{}.{}".format(self.remote_file, ts)
        else:
            self.remote_tmpdir = "{}/splitcopy_{}.{}".format(
                self.remote_dir, self.remote_file, ts
            )
        result, stdout = self.ss.run("mkdir -p {}".format(self.remote_tmpdir))
        if not result:
            err = (
                "unable to create the tmp directory on remote host."
                "cmd output was:\n{}".format(stdout)
            )
            self.close(err_str=err)
        self.rm_remote_tmp = True

    def remote_sha_get(self):
        """ checks for existence of a sha hash file
            if none found, generates a sha hash for the remote file to be copied
            :returns None:
        """
        logger.info("entering remote_sha_get()")
        result, stdout = self.ss.run("ls -1 {}.sha*".format(self.remote_path))
        if result:
            lines = stdout.split("\n")
            for line in lines:
                line = line.rstrip()
                match = re.search(r"\.sha([0-9]+)$", line)
                if match:
                    sha_num = int(match.group(1))
                    logger.info("{} file found".format(line))
                    result, stdout = self.ss.run("cat {}".format(line))
                    if result:
                        self.sha_hash[sha_num] = (
                            stdout.split("\n")[1].split()[0].rstrip()
                        )
                        logger.info("self.sha_hash[{}] added".format(sha_num))
                    else:
                        logger.info("unable to read remote sha file {}".format(line))

        if not self.sha_hash:
            self.sha_hash[1] = True
            self.req_sha_binaries()
            print("generating remote sha hash...")
            result, stdout = self.ss.run(
                "{} {}".format(self.sha_bin, self.remote_path), timeout=120
            )
            if not result:
                self.close(err_str="failed to generate remote sha1")

            if re.match(r"sha.*sum", self.sha_bin):
                self.sha_hash[1] = stdout.split("\n")[1].split()[0].rstrip()
            else:
                self.sha_hash[1] = stdout.split("\n")[1].split()[3].rstrip()
        logger.info("remote sha hashes = {}".format(self.sha_hash))

    def remote_filesize(self):
        """  determines the remote file size in bytes
            :returns None:
        """
        logger.info("entering remote_filesize()")
        result, stdout = self.ss.run("ls -l {}".format(self.remote_path))
        if result:
            self.file_size = int(stdout.split("\n")[1].split()[4])
        else:
            self.close(err_str="cannot determine remote file size")
        logger.info("src file size is {}".format(self.file_size))

    def storage_check_remote(self):
        """ checks whether there is enough storage space on remote node
            :returns None:
        """
        logger.info("entering storage_check_remote()")
        avail_blocks = 0
        print("checking remote storage...")
        if self.get_op:
            multiplier = 1
            result, stdout = self.ss.run("df -k {}".format(self.remote_dir))
        else:
            multiplier = 2
            result, stdout = self.ss.run("df -k {}".format(self.remote_dir))
        if not result:
            self.close(err_str="failed to determine remote disk space available")
        df_num = len(stdout.split("\n")) - 2
        if re.match(r"^ ", stdout.split("\n")[df_num]):
            split_num = 2
        else:
            split_num = 3
        try:
            avail_blocks = stdout.split("\n")[df_num].split()[split_num].rstrip()
        except Exception:
            err_str = "unable to determine available blocks on remote host"
            self.close(err_str)

        avail_bytes = int(avail_blocks) * 1024
        logger.info("remote filesystem available bytes is {}".format(avail_bytes))
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
                    "same time".format(self.remote_dir, avail_bytes, self.file_size)
                )
            self.close(err_str)

    def storage_check_local(self):
        """ checks whether there is enough storage space on local node
            :returns None:
        """
        logger.info("entering storage_check_local()")
        print("checking local storage...")
        local_tmpdir = tempfile.gettempdir()
        avail_bytes = shutil.disk_usage(local_tmpdir)[2]
        logger.info(
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
            avail_bytes = shutil.disk_usage(self.local_dir)[2]
            logger.info(
                "local filesystem {} available bytes is {}".format(
                    self.local_dir, avail_bytes
                )
            )
            if self.file_size > avail_bytes:
                err_str = (
                    "not enough storage on local host in {}.\nAvailable bytes ({}) "
                    "must be > the original file size ({}) because it has to "
                    "recombine the file chunks into a whole file".format(
                        self.local_dir, avail_bytes, self.file_size
                    )
                )
                self.close(err_str)

    def put_files(self, sfile):
        """ copies files to remote host via ftp or scp
            :param sfile: name and size of the file to copy
            :type: list
            :raises TransferError: if file transfer fails 3 times
            :returns None:
        """
        err_count = 0
        file_name = sfile[0]
        file_size = sfile[1]
        dstpath = "{}/{}".format(self.remote_tmpdir, file_name)
        logger.info("{}, size {}".format(file_name, file_size))
        if self.copy_proto == "ftp":
            while err_count < 3:
                try:
                    with FTP(**self.copy_kwargs) as ftp:
                        ftp.put(file_name, dstpath)
                        break
                except Exception as err:
                    logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                    if not self.mute:
                        logger.warning(
                            "retrying file {} due to {}: {}".format(
                                file_name, err.__class__.__name__, str(err)
                            )
                        )
                    err_count += 1
                    time.sleep(err_count)
        else:
            while err_count < 3:
                try:
                    with SSHShell(**self.ssh_kwargs) as ssh:
                        sock = ssh.socket_open()
                        transport = ssh.transport_open(sock)
                        if not ssh.worker_thread_auth():
                            ssh.close()
                            raise SSHException("authentication failed")
                        with SCPClient(transport, **self.copy_kwargs) as scpclient:
                            scpclient.put(file_name, dstpath)
                            break
                except Exception as err:
                    logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                    if not self.mute:
                        logger.warning(
                            "retrying file {} due to {}: {}".format(
                                file_name, err.__class__.__name__, str(err)
                            )
                        )
                    err_count += 1
                    time.sleep(err_count)

        if err_count == 3:
            self.mute = True
            raise TransferError

    def get_files(self, sfile):
        """ copies files from remote host via ftp or scp
            :param sfile: name and size of the file to copy
            :type: list
            :raises TransferError: if file transfer fails 3 times
            :returns None:
        """
        err_count = 0
        file_name = sfile[0]
        file_size = sfile[1]
        srcpath = "{}/{}".format(self.remote_tmpdir, file_name)
        logger.info("{}, size {}".format(file_name, file_size))
        if self.copy_proto == "ftp":
            while err_count < 3:
                try:
                    with FTP(**self.copy_kwargs) as ftp:
                        ftp.get(srcpath, file_name)
                        break
                except Exception as err:
                    logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                    if not self.mute:
                        logger.warning(
                            "retrying file {} due to {}: {}".format(
                                file_name, err.__class__.__name__, str(err)
                            )
                        )
                    err_count += 1
                    time.sleep(err_count)
        else:
            while err_count < 3:
                try:
                    with SSHShell(**self.ssh_kwargs) as ssh:
                        sock = ssh.socket_open()
                        transport = ssh.transport_open(sock)
                        if not ssh.worker_thread_auth():
                            ssh.close()
                            raise SSHException("authentication failed")
                        with SCPClient(transport, **self.copy_kwargs) as scpclient:
                            scpclient.get(srcpath, file_name)
                            break
                except Exception as err:
                    logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                    if not self.mute:
                        logger.warning(
                            "retrying file {} due to {}: {}".format(
                                file_name, err.__class__.__name__, str(err)
                            )
                        )
                    err_count += 1
                    time.sleep(err_count)

        if err_count == 3:
            self.mute = True
            raise TransferError

    @contextmanager
    def change_dir(self, cleanup=lambda: True):
        """ cds into temp directory.
            Upon script exit, changes back to original directory
            and calls cleanup() to delete the temp directory
            :returns None:
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
        """ creates a temp directory
            defines how to delete directory upon script exit
            :returns None:
        """
        self.local_tmpdir = tempfile.mkdtemp()
        logger.info(self.local_tmpdir)

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
            :returns None:
        """
        logger.info("entering limit_check()")
        config_stanzas = ["groups", "system services"]
        if self.copy_proto == "ftp":
            limits = [
                "services ssh connection-limit",
                "services ssh rate-limit",
                "services ftp connection-limit",
                "services ftp rate-limit",
            ]
        else:
            limits = ["services ssh connection-limit", "services ssh rate-limit"]

        # check for presence of rate/connection limits
        cli_config = ""
        conf_line = ""
        for stanza in config_stanzas:
            result, stdout = self.ss.run(
                'cli -c "show configuration {} | display set | no-more"'.format(stanza)
            )
            cli_config += stdout
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
            logger.info(self.command_list)
            result, stdout = self.ss.run(
                'cli -c "edit;{}commit and-quit"'.format("".join(self.command_list)),
                exitcode=False,
                timeout=60,
            )
            # cli always returns true so can't use exitcode
            if re.search(r"commit complete\r\nExiting configuration mode", stdout):
                print(
                    "the configuration has been modified. deactivated the limit(s) found"
                )
                self.ss.run(
                    "logger 'splitcopy has deactivated "
                    "ssh/ftp rate-limit/connection-limit "
                    "configuration'",
                    exitcode=False,
                )
            else:
                err = (
                    "Error: failed to deactivate {} connection-limit/rate-limit"
                    "configuration. output was:\n{}".format(self.copy_proto, stdout)
                )
                self.close(err_str=err)
        else:
            return

    def limits_rollback(self):
        """ revert config change made to remote host
            :returns None:
        """
        logger.info("entering limits_rollback()")
        rollback_cmds = "".join(self.command_list)
        rollback_cmds = re.sub("deactivate", "activate", rollback_cmds)
        result, stdout = self.ss.run(
            'cli -c "edit;{}commit and-quit"'.format(rollback_cmds),
            exitcode=False,
            timeout=60,
        )
        # cli always returns true so can't use exitcode
        if re.search(r"commit complete\r\nExiting configuration mode", stdout):
            print("the configuration changes made have been reverted.")
            self.ss.run(
                "logger 'splitcopy has activated "
                "ssh/ftp rate-limit/connection-limit "
                "configuration'",
                exitcode=False,
            )
        else:
            print(
                "Error: failed to revert the connection-limit/rate-limit"
                "configuration changes made. output was:\n{}".format(stdout)
            )

    def remote_cleanup(self, silent=False):
        """ delete tmp directory on remote host
            :param silent: determines whether we announce the dir deletion
            :type: bool
            :returns None:
        """
        if not silent:
            print("deleting remote tmp directory...")
        if self.remote_tmpdir is None:
            if self.get_op:
                self.ss.run("rm -rf /var/tmp/splitcopy_{}.*".format(self.remote_file))
            else:
                self.ss.run(
                    "rm -rf {}/splitcopy_{}.*".format(self.remote_dir, self.remote_file)
                )
        else:
            result, stdout = self.ss.run("rm -rf {}".format(self.remote_tmpdir))
            if not result and not silent:
                print(
                    "unable to delete the tmp directory {} on remote host, "
                    "delete it manually".format(self.remote_tmpdir)
                )
        self.rm_remote_tmp = False


class TransferError(Exception):
    """ custom exception to indicate problem with file transfer
    """

    pass


if __name__ == "__main__":
    main()
