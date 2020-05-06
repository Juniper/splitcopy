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
import traceback
from contextlib import contextmanager

# 3rd party
from scp import SCPClient

# local modules
from splitcopy.paramikoshell import SSHShell
from splitcopy.progress import Progress
from splitcopy.ftp import FTP

_BUF_SIZE_SPLIT = 10240
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
        loglevel = "ERROR"
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
    target_dir = None
    target_file = None
    target_path = None
    file_name = None
    file_path = None
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
        file_path = source.split(":")[1]
        file_name = os.path.basename(file_path)
        get = True
    elif os.path.isfile(source):
        file_path = source
        try:
            open(file_path, "rb")
        except PermissionError:
            raise SystemExit(
                "source file {} exists but is not readable - cannot proceed".format(
                    file_path
                )
            )
        file_name = os.path.basename(source)
        file_size = os.path.getsize(file_path)
        logger.debug("src file size is {}".format(file_size))
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
        target_path = target.split(":")[1]
        if target_path is None:
            target_dir = "."
            target_file = file_name
    elif os.path.isdir(target):
        target_dir = target.rstrip("/")
        target_file = file_name
    elif os.path.isdir(os.path.dirname(target)):
        # we've been passed in a filename, may not exist yet
        target_dir = os.path.dirname(target)
        if os.path.basename(target) != file_name:
            # have to honour the change of name
            target_file = os.path.basename(target)
        else:
            target_file = file_name
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
    logger.debug("copy_proto == {}".format(copy_proto))

    if args.ssh_key is not None:
        ssh_key = os.path.abspath(args.ssh_key[0])
        if not os.path.isfile(ssh_key):
            raise SystemExit("specified ssh key not found")

    kwargs = {
        "user": user,
        "host": host,
        "passwd": passwd,
        "ssh_key": ssh_key,
        "target_dir": target_dir,
        "target_file": target_file,
        "target_path": target_path,
        "file_name": file_name,
        "file_path": file_path,
        "file_size": file_size,
        "copy_proto": copy_proto,
        "get": get,
        "noverify": noverify,
    }

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
    logger.debug("entering ftp_port_check()")
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
        self.target_dir = kwargs.get("target_dir")
        self.target_file = kwargs.get("target_file")
        self.target_path = kwargs.get("target_path")
        self.file_name = kwargs.get("file_name")
        self.file_path = kwargs.get("file_path")
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
        self.mute = False
        self.sha_size = None
        self.ssh_kwargs = {
            "user": self.user,
            "host": self.host,
            "passwd": self.passwd,
            "ssh_key": self.ssh_key,
        }

    def handlesigint(self, sigint, stack):
        self.close()

    def connect(self):
        try:
            self.ss = SSHShell(**self.ssh_kwargs)
            self.ss.open()
            print("ssh auth succeeded")
            self.ssh_kwargs.update({"passwd": self.ss.passwd})
            self.ss.channel_open()
            self.ss.set_keepalive()
            # remove the welcome message from the socket
            self.ss.stdout_read(timeout=30)
        except Exception as err:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
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
        self.validate_remote_path()

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
                if fnmatch.fnmatch(sfile, "{}*".format(self.file_name)):
                    sfiles.append(sfile)
            logger.debug("# of chunks = {}".format(len(sfiles)))

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
                    None, functools.partial(self.put_files, sfile)
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
                    self.host, self.target_dir, self.target_file
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

        # begin pre transfer checks, check if remote file exists
        result, stdout = self.ss.run("test -r {}".format(self.file_path))
        if not result:
            self.close(err_str="file on remote host is not readable - does it exist?")

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
        result, stdout = self.ss.run("ls -1 {}/".format(self.remote_tmpdir))
        if not result:
            self.close(err_str="couldn't get list of files from host")
        remote_files = stdout.split("\r\n")
        sfiles = []
        for sfile in remote_files:
            if fnmatch.fnmatch(sfile, "{}*".format(self.file_name)):
                sfiles.append(sfile)
        logger.debug("# of chunks = {}".format(len(sfiles)))

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
                    None, functools.partial(self.get_files, sfile)
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
                    self.target_dir, self.target_file
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
        logger.debug("entering which_os()")
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
        logger.debug(
            "evo = {}, junos = {}, bsd_version = {}, sshd_version = {}".format(
                self.evo, self.junos, self.bsd_version, self.sshd_version
            )
        )

    def validate_remote_path(self):
        """ path provided can be a directory, a new or existing file
            :return: None
        """
        if self.ss.run("test -d {}".format(self.target_path))[0]:
            # target path provided is a directory
            self.target_file = self.file_name
            self.target_dir = self.target_path.rstrip("/")
        elif (
            self.ss.run("test -f {}".format(self.target_path))[0]
            or self.ss.run("test -d {}".format(os.path.dirname(self.target_path)))[0]
        ):
            # target path provided is a file that already exists
            if os.path.basename(self.target_path) != self.file_name:
                # target path provided was a full path, file name does not match src
                # honour the change of file name
                self.target_file = os.path.basename(self.target_path)
            else:
                # target path provided was a full path, file name matches src
                self.target_file = self.file_name
            self.target_dir = os.path.dirname(self.target_path)
        else:
            self.close(
                err_str="target path {} on remote host isn't valid".format(
                    self.target_path
                )
            )

    def evo_os(self):
        """ determines if host is EVO
            :returns result: True if OS is EVO
            :type: boolean
        """
        logger.debug("entering evo_os()")
        result, stdout = self.ss.run("test -e /usr/sbin/evo-pfemand")
        return result

    def junos_os(self):
        """ determines if host is JUNOS
            :returns None:
        """
        logger.debug("entering junos_os()")
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
        logger.debug("entering which_bsd()")
        result, stdout = self.ss.run("uname -r")
        if not result:
            self.close(err_str="failed to determine remote bsd version")
        uname = stdout.split("\n")[1]
        self.bsd_version = float(uname.split("-")[1])

    def which_sshd(self):
        """ determines the OpenSSH daemon version
            :returns None:
        """
        logger.debug("entering which_sshd()")
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
        logger.debug("entering req_binaries()")
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

    def req_sha_binaries(self):
        """ ensures required binaries for sha hash creation exist on remote host
        :returns None:
        """
        logger.debug("entering req_sha_binaries()")
        if self.sha_size == 512:
            sha_bins = ["sha512sum", "sha512", "shasum"]
        elif self.sha_size == 384:
            sha_bins = ["sha384sum", "sha384", "shasum"]
        elif self.sha_size == 256:
            sha_bins = ["sha256sum", "sha256", "shasum"]
        elif self.sha_size == 224:
            sha_bins = ["sha224sum", "sha224", "shasum"]
        else:
            sha_bins = ["sha1sum", "sha1", "shasum"]

        for req_bin in sha_bins:
            result, stdout = self.ss.run("which {}".format(req_bin))
            if result:
                self.sha_bin = req_bin
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
        logger.debug("entering join_files_remote()")
        print("joining files...")
        result = False
        try:
            # >{} because > {} could be matched as _SHELL_PROMPT
            result, stdout = self.ss.run(
                "cat {}/* >{}/{}".format(
                    self.remote_tmpdir, self.target_dir, self.target_file
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
        logger.debug("entering join_files_local()")
        print("joining files...")
        src_files = glob.glob(self.local_tmpdir + os.path.sep + self.file_name + "*")
        dst_file = self.target_dir + os.path.sep + self.target_file
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
        logger.debug("entering remote_sha_put()")
        print("generating remote sha hash...")
        result, stdout = self.ss.run(
            "ls {}/{}".format(self.target_dir, self.target_file)
        )
        if not result:
            err = "file {}:{}/{} not found! please retry".format(
                self.host, self.target_dir, self.target_file
            )
            self.config_rollback = False
            self.close(err_str=err)

        if self.sha_size == 512 and self.sha_bin == "shasum":
            cmd = "shasum -a 512"
        elif self.sha_size == 384 and self.sha_bin == "shasum":
            cmd = "shasum -a 384"
        elif self.sha_size == 256 and self.sha_bin == "shasum":
            cmd = "shasum -a 256"
        elif self.sha_size == 224 and self.sha_bin == "shasum":
            cmd = "shasum -a 224"
        else:
            cmd = "{}".format(self.sha_bin)

        result, stdout = self.ss.run(
            "{} {}/{}".format(cmd, self.target_dir, self.target_file), timeout=300
        )
        if not result:
            print(
                "remote sha hash generation failed or timed out, "
                'manually check the output of "{} <file>" and '
                "compare against {}".format(cmd, self.local_sha)
            )
            return
        if re.match(r"sha.*sum", self.sha_bin):
            remote_sha = stdout.split("\n")[1].split()[0].rstrip()
        else:
            remote_sha = stdout.split("\n")[1].split()[3].rstrip()
        logger.debug("remote sha = {}".format(remote_sha))
        if self.local_sha == remote_sha:
            print(
                "local and remote sha hash match\nfile has been "
                "successfully copied to {}:{}/{}".format(
                    self.host, self.target_dir, self.target_file
                )
            )
        else:
            err = (
                "file has been copied to {}:{}/{}, but the "
                "local and remote sha do not match - "
                "please retry".format(self.host, self.target_dir, self.target_file)
            )
            self.config_rollback = False
            self.close(err_str=err)

    def file_split_size(self):
        """ The chunk size depends on the python version, cpu count,
            the protocol used to copy, FreeBSD and OpenSSH version
            :returns None:
        """
        logger.debug("entering file_split_size()")
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
        logger.debug("file split size = {}".format(self.split_size))

    def split_file_local(self):
        """ splits file into chunks of size already determined in file_split_size()
            This function emulates GNU split.
            :returns None:
        """
        logger.debug("entering split_file_local()")
        print("splitting file...")
        try:
            total_bytes = 0
            with open(self.file_path, "rb") as src:
                sfx_1 = "a"
                sfx_2 = "a"
                while total_bytes < self.file_size:
                    with open(
                        "{}{}{}".format(self.file_name, sfx_1, sfx_2), "wb"
                    ) as chunk:
                        logger.debug(
                            "writing data to {}{}{}".format(
                                self.file_name, sfx_1, sfx_2
                            )
                        )
                        chunk_bytes = 0
                        while chunk_bytes < self.split_size:
                            data = src.read(_BUF_SIZE_SPLIT)
                            if data:
                                chunk.write(data)
                                chunk_bytes += _BUF_SIZE_SPLIT
                                total_bytes += _BUF_SIZE_SPLIT
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
            :returns None:
        """
        logger.debug("entering split_file_remote()")
        total_blocks = int(self.file_size / _BUF_SIZE)
        block_size = int(self.split_size / _BUF_SIZE)
        cmd = (
            "size_b={}; size_tb={}; i=0; o=00; "
            "while [ $i -lt $size_tb ]; do "
            "dd if={} of={}/{}_$o bs={} count=$size_b skip=$i; "
            "i=`expr $i + $size_b`; o=`expr $o + 1`; "
            "if [ $o -lt 10 ]; then o=0$o; fi; done".format(
                block_size,
                total_blocks,
                self.file_path,
                self.remote_tmpdir,
                self.file_name,
                _BUF_SIZE,
            )
        )

        # switched to file copy as the '> ' in 'echo cmd > file'
        # would sometimes be interpreted as shell prompt
        with self.tempdir():
            with open("split.sh", "w") as fd:
                fd.write(cmd)
            transport = self.ss.get_transport(self.ss._session)
            with SCPClient(transport, **self.copy_kwargs) as scpclient:
                scpclient.put("split.sh", "{}/split.sh".format(self.remote_tmpdir))

        result, stdout = self.ss.run(
            "sh {}/split.sh 2>&1".format(self.remote_tmpdir, self.remote_tmpdir)
        )
        if not result:
            err_str = "remote file split operation failed. cmd output was:\n{}".format(
                stdout
            )
            self.close(err_str)

    def local_sha_get(self):
        """ generates a sha hash for the combined file on the local host
            :returns None:
        """
        logger.debug("entering local_sha_get()")
        print("generating local sha hash...")
        if self.sha_size == 512:
            sha = hashlib.sha512()
        elif self.sha_size == 384:
            sha = hashlib.sha384()
        elif self.sha_size == 256:
            sha = hashlib.sha256()
        elif self.sha_size == 224:
            sha = hashlib.sha224()
        else:
            sha = hashlib.sha1()
        dst_file = self.target_dir + os.path.sep + self.target_file
        with open(dst_file, "rb") as dst:
            data = dst.read(_BUF_SIZE_READ)
            while data:
                sha.update(data)
                data = dst.read(_BUF_SIZE_READ)
        local_sha = sha.hexdigest()
        logger.debug("local sha = {}".format(local_sha))
        if local_sha == self.remote_sha:
            print(
                "local and remote sha hash match\nfile has been "
                "successfully copied to {}{}{}".format(
                    self.target_dir, os.path.sep, self.target_file
                )
            )
        else:
            err = (
                "file has been copied to {}{}{}, but the "
                "local and remote sha hash do not match - "
                "please retry".format(self.target_dir, os.path.sep, self.target_file)
            )
            self.config_rollback = False
            self.close(err_str=err)

    def local_sha_put(self):
        """ checks whether a sha hash already exists for the file
            if not creates one
            :returns None:
        """
        file_path = self.file_path
        logger.debug("entering local_sha_put()")
        if os.path.isfile(file_path + ".sha512"):
            with open(file_path + ".sha512", "r") as shafile:
                self.local_sha = shafile.read().split()[0].rstrip()
                self.sha_size = 512
        elif os.path.isfile(file_path + ".sha384"):
            with open(file_path + ".sha384", "r") as shafile:
                self.local_sha = shafile.read().split()[0].rstrip()
                self.sha_size = 384
        elif os.path.isfile(file_path + ".sha256"):
            with open(file_path + ".sha256", "r") as shafile:
                self.local_sha = shafile.read().split()[0].rstrip()
                self.sha_size = 256
        elif os.path.isfile(file_path + ".sha224"):
            with open(file_path + ".sha224", "r") as shafile:
                self.local_sha = shafile.read().split()[0].rstrip()
                self.sha_size = 224
        elif os.path.isfile(file_path + ".sha1"):
            with open(file_path + ".sha1", "r") as shafile:
                self.local_sha = shafile.read().split()[0].rstrip()
                self.sha_size = 1
        else:
            print("sha1 not found, generating sha1...")
            sha1 = hashlib.sha1()
            with open(file_path, "rb") as original_file:
                data = original_file.read(_BUF_SIZE_READ)
                while data:
                    sha1.update(data)
                    data = original_file.read(_BUF_SIZE_READ)
            self.local_sha = sha1.hexdigest()
            self.sha_size = 1
        logger.debug("local sha hash = {}".format(self.local_sha))
        self.req_sha_binaries()

    def mkdir_remote(self):
        """ creates a tmp directory on the remote host
            :returns None:
        """
        logger.debug("entering mkdir_remote()")
        ts = datetime.datetime.strftime(datetime.datetime.now(), "%y%m%d%H%M%S")
        if self.get_op:
            self.remote_tmpdir = "/var/tmp/splitcopy_{}.{}".format(self.file_name, ts)
        else:
            self.remote_tmpdir = "{}/splitcopy_{}.{}".format(
                self.target_dir, self.target_file, ts
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
        """ generates a sha hash for the remote file to be copied
            :returns None:
        """
        logger.debug("entering remote_sha_get()")
        file_path = self.file_path
        cmds = [
            (512, "cat {}.sha512".format(file_path)),
            (384, "cat {}.sha384".format(file_path)),
            (256, "cat {}.sha256".format(file_path)),
            (224, "cat {}.sha224".format(file_path)),
            (1, "cat {}.sha1".format(file_path)),
        ]
        for cmd in cmds:
            result, stdout = self.ss.run(cmd[1])
            if result:
                logger.debug("sha{} file found".format(cmd[0]))
                self.remote_sha = stdout.split("\n")[1].rstrip()
                self.sha_size = cmd[0]
                break
        if not self.sha_size:
            self.sha_size = 1
            self.req_sha_binaries()
            print("generating remote sha hash...")
            result, stdout = self.ss.run("{} {}".format(self.sha_bin, file_path))
            if not result:
                self.close(err_str="failed to generate remote sha1")

            if re.match(r"sha.*sum", self.sha_bin):
                self.remote_sha = stdout.split("\n")[1].split()[0].rstrip()
            else:
                self.remote_sha = stdout.split("\n")[1].split()[3].rstrip()
        logger.debug("remote sha = {}".format(self.remote_sha))

    def remote_filesize(self):
        """  determines the remote file size in bytes
            :returns None:
        """
        logger.debug("entering remote_filesize()")
        result, stdout = self.ss.run("ls -l {}".format(self.file_path))
        if result:
            self.file_size = int(stdout.split("\n")[1].split()[4])
        else:
            self.close(err_str="cannot determine remote file size")
        logger.debug("src file size is {}".format(self.file_size))

    def storage_check_remote(self):
        """ checks whether there is enough storage space on remote node
            :returns None:
        """
        logger.debug("entering storage_check_remote()")
        avail_blocks = 0
        print("checking remote storage...")
        if self.get_op:
            multiplier = 1
            result, stdout = self.ss.run("df -k {}".format(self.target_dir))
        else:
            multiplier = 2
            result, stdout = self.ss.run("df -k {}".format(self.target_dir))
        if not result:
            self.close(err_str="failed to determine remote disk space available")
        df_num = len(stdout.split("\n")) - 2
        if re.match(r"^ ", stdout.split("\n")[df_num]):
            split_num = 2
        else:
            split_num = 3
        try:
            avail_blocks = stdout.split("\n")[df_num].split()[split_num].rstrip()
        except:
            err_str = "unable to determine available blocks on remote host"
            self.close(err_str)

        avail_bytes = int(avail_blocks) * 1024
        logger.debug("remote filesystem available bytes is {}".format(avail_bytes))
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
                    "same time".format(self.target_dir, avail_bytes, self.file_size)
                )
            self.close(err_str)

    def storage_check_local(self):
        """ checks whether there is enough storage space on local node
            :returns None:
        """
        logger.debug("entering storage_check_local()")
        print("checking local storage...")
        local_tmpdir = tempfile.gettempdir()
        avail_bytes = shutil.disk_usage(local_tmpdir)[2]
        logger.debug(
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
            avail_bytes = shutil.disk_usage(self.target_dir)[2]
            logger.debug(
                "local filesystem {} available bytes is {}".format(
                    self.target_dir, avail_bytes
                )
            )
            if self.file_size > avail_bytes:
                err_str = (
                    "not enough storage on local host in {}.\nAvailable bytes ({}) "
                    "must be > the original file size ({}) because it has to "
                    "recombine the file chunks into a whole file".format(
                        self.target_dir, avail_bytes, self.file_size
                    )
                )
                self.close(err_str)

    def put_files(self, file_name):
        """ copies files to remote host via ftp or scp
            :param file_name: name of the file to copy
            :type: string
            :raises TransferError: if file transfer fails 3 times
            :returns None:
        """
        err_count = 0
        dstpath = "{}/{}".format(self.remote_tmpdir, file_name)
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
                        transport = ssh.get_transport(ssh._session)
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

    def get_files(self, file_name):
        """ copies files from remote host via ftp or scp
            :param file_name: name of the file to copy
            :type: string
            :raises TransferError: if file transfer fails 3 times
            :returns None:
        """
        err_count = 0
        srcpath = "{}/{}".format(self.remote_tmpdir, file_name)
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
                        transport = ssh.get_transport(ssh._session)
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
        logger.debug(self.local_tmpdir)

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
        logger.debug("entering limit_check()")
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
            result, stdout = self.ss.run(
                'cli -c "edit;{}commit and-quit"'.format("".join(self.command_list)),
                exitcode=False,
            )
            if re.search(r"commit complete\nExiting configuration mode$", stdout):
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
            :returns None:
        """
        logger.debug("entering limits_rollback()")
        rollback_cmds = "".join(self.command_list)
        rollback_cmds = re.sub("deactivate", "activate", rollback_cmds)
        result, stdout = self.ss.run(
            'cli -c "edit;{}commit and-quit"'.format(rollback_cmds), exitcode=False
        )
        # cli always returns true so can't use exitcode
        if re.search(r"commit complete\nExiting configuration mode$", stdout):
            print("the configuration changes made have been reverted.")
        else:
            print(
                "Error: failed to revert the connection-limit/rate-limit"
                "configuration changes made"
            )

    def remote_cleanup(self, silent=False):
        """ delete tmp directory on remote host
            :param silent: determines whether we announce the dir deletion
            :type bool:
            :returns None:
        """
        if not silent:
            print("deleting remote tmp directory...")
        if self.remote_tmpdir is None:
            if self.get_op:
                self.ss.run("rm -rf /var/tmp/splitcopy_{}.*".format(self.file_name))
            else:
                self.ss.run(
                    "rm -rf {}/splitcopy_{}.*".format(self.target_dir, self.target_file)
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
