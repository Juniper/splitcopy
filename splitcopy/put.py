""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

# stdlib
import asyncio
import datetime
import fnmatch
import functools
import hashlib
import logging
import os
import re
import signal
import sys
import time
import traceback

# 3rd party
from scp import SCPClient
from paramiko.ssh_exception import SSHException

# local modules
from splitcopy.paramikoshell import SSHShell
from splitcopy.progress import Progress
from splitcopy.ftp import FTP
from splitcopy.shared import SplitCopyShared

logger = logging.getLogger(__name__)

_BUF_SIZE_READ = 131072
_BUF_SIZE = 1024


class SplitCopyPut:
    def __init__(self, **kwargs):
        """
        Initialize the SplitCopyPut class
        """
        self.user = kwargs.get("user")
        self.host = kwargs.get("host")
        self.passwd = kwargs.get("passwd")
        self.ssh_key = kwargs.get("ssh_key")
        self.ssh_port = kwargs.get("ssh_port")
        self.remote_dir = kwargs.get("remote_dir")
        self.remote_file = kwargs.get("remote_file")
        self.remote_path = kwargs.get("remote_path")
        self.local_dir = kwargs.get("local_dir")
        self.local_file = kwargs.get("local_file")
        self.local_path = kwargs.get("local_path")
        self.copy_proto = kwargs.get("copy_proto")
        self.get_op = kwargs.get("get")
        self.noverify = kwargs.get("noverify")
        self.split_timeout = kwargs.get("split_timeout")
        self.scs = SplitCopyShared(**kwargs)
        self.mute = False
        self.hard_close = False
        self.ss = None

    def handlesigint(self, sigint, stack):
        logger.debug(f"signal {sigint} received, stack:\n{stack}")
        self.mute = True
        self.scs.close(hard_close=self.hard_close)

    def put(self):
        """
        copies file from local host to remote host
        performs file split/transfer/join/verify functions
        :returns loop_start: time when transfers started
        :type: datetime object
        :returns loop_end: time when transfers ended
        :type: datetime object
        """
        ssh_kwargs = {
            "username": self.user,
            "hostname": self.host,
            "password": self.passwd,
            "key_filename": self.ssh_key,
            "ssh_port": self.ssh_port,
        }

        # handle sigint gracefully on *nix, WIN32 is (of course) a basket case
        signal.signal(signal.SIGINT, self.handlesigint)

        # connect to host
        self.ss, ssh_kwargs = self.scs.connect(**ssh_kwargs)

        # determine remote host os
        junos, evo, bsd_version, sshd_version = self.scs.which_os()

        # verify which protocol to use
        self.copy_proto, self.passwd = self.scs.which_proto(
            self.copy_proto
        )

        # ensure dest path is valid
        self.validate_remote_path_put()

        # check required binaries exist on remote host
        self.scs.req_binaries(junos=junos, evo=evo)

        # cleanup previous remote tmp directory if found
        self.scs.remote_cleanup(
            remote_dir=self.remote_dir, remote_file=self.remote_file, silent=True
        )

        # delete target file if it already exists
        self.delete_target_remote()

        # determine local file size
        file_size = self.determine_local_filesize()

        # determine optimal size for chunks
        split_size, executor = self.scs.file_split_size(
            file_size, sshd_version, bsd_version, evo
        )

        # confirm remote storage is sufficient
        self.scs.storage_check_remote(file_size, split_size)

        # confirm local storage is sufficient
        self.scs.storage_check_local(file_size)

        if not self.noverify:
            # get/create sha for local file
            sha_bin, sha_len, sha_hash = self.local_sha_put()

        with self.scs.tempdir():
            # split file into chunks
            self.split_file_local(file_size, split_size)

            # add chunk names to a list
            sfiles = []
            for sfile in os.listdir("."):
                if fnmatch.fnmatch(sfile, f"{self.local_file}*"):
                    sfiles.append([sfile, os.stat(sfile).st_size])
            if not sfiles:
                self.scs.close(
                    err_str="file split operation failed", hard_close=self.hard_close
                )
            # sort chunks alphabetically
            sfiles = sorted(sfiles)
            logger.info(f"# of chunks = {len(sfiles)}")

            # create tmp directory
            remote_tmpdir = self.scs.mkdir_remote()

            # begin connection/rate limit check and transfer process
            command_list = []
            if junos or evo:
                command_list = self.scs.limit_check()

            if self.copy_proto == "ftp":
                copy_kwargs = {
                    "progress": Progress(file_size).handle,
                    "host": self.host,
                    "user": self.user,
                    "passwd": self.passwd,
                }
            else:
                copy_kwargs = {"progress": Progress(file_size).handle}

            # copy files to remote host
            self.hard_close = True
            loop_start = datetime.datetime.now()
            print("starting transfer...")
            loop = asyncio.get_event_loop()
            tasks = []
            for sfile in sfiles:
                task = loop.run_in_executor(
                    executor,
                    functools.partial(
                        self.put_files, sfile, remote_tmpdir, copy_kwargs, ssh_kwargs
                    ),
                )
                tasks.append(task)
            try:
                loop.run_until_complete(asyncio.gather(*tasks))
            except TransferError:
                self.scs.close(
                    err_str="an error occurred while copying the files to the remote host",
                    hard_close=self.hard_close,
                )
            finally:
                loop.close()
                self.hard_close = False

        print("\ntransfer complete")
        loop_end = datetime.datetime.now()

        # combine chunks
        self.join_files_remote(sfiles, remote_tmpdir)

        # remove remote tmp dir
        self.scs.remote_cleanup()

        # rollback any config changes made
        if command_list:
            self.scs.limits_rollback()

        if self.noverify:
            print(
                f"file has been successfully copied to {self.host}:"
                f"{self.remote_dir}/{self.remote_file}"
            )
        else:
            # generate a sha hash for the combined file, compare to hash of src
            self.remote_sha_put(sha_bin, sha_len, sha_hash)

        self.ss.close()
        return loop_start, loop_end

    def validate_remote_path_put(self):
        """
        path provided can be a directory, a new or existing file
        :return: None
        """
        logger.info("entering validate_remote_path_put()")
        if self.ss.run(f"test -d {self.remote_path}")[0]:
            # target path provided is a directory
            self.remote_file = self.local_file
            self.remote_dir = self.remote_path.rstrip("/")
        elif (
            self.ss.run(f"test -f {self.remote_path}")[0]
            or self.ss.run(f"test -d {os.path.dirname(self.remote_path)}")[0]
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
                f"self.remote_path = {self.remote_path}, self.remote_dir = "
                f"{self.remote_dir}, self.remote_file = {self.remote_file}"
            )
        else:
            self.scs.close(
                err_str=f"target path {self.remote_path} on remote host isn't valid",
                hard_close=self.hard_close,
            )

    def delete_target_remote(self):
        """
        deletes the target file if it already exists
        """
        logger.info("entering delete_target_remote()")
        result, stdout = self.ss.run(f"test -w {self.remote_dir}/{self.remote_file}")
        if result:
            result, stdout = self.ss.run(f"rm {self.remote_dir}/{self.remote_file}")

    def determine_local_filesize(self):
        """
        determines the local files size in bytes
        """
        logger.info("entering determine_local_filesize()")
        file_size = os.path.getsize(self.local_path)
        logger.info(f"src file size is {file_size}")
        return file_size

    def local_sha_put(self):
        """
        checks whether a sha hash already exists for the file
        if not creates one
        :returns None:
        """
        file_path = self.local_path
        sha_hash = {}
        logger.info("entering local_sha_put()")
        if os.path.isfile(f"{file_path}.sha512"):
            with open(f"{file_path}.sha512", "r") as shafile:
                local_sha = shafile.read().split()[0].rstrip()
                sha_hash[512] = local_sha
        if os.path.isfile(f"{file_path}.sha384"):
            with open(f"{file_path}.sha384", "r") as shafile:
                local_sha = shafile.read().split()[0].rstrip()
                sha_hash[384] = local_sha
        if os.path.isfile(f"{file_path}.sha256"):
            with open(f"{file_path}.sha256", "r") as shafile:
                local_sha = shafile.read().split()[0].rstrip()
                sha_hash[256] = local_sha
        if os.path.isfile(f"{file_path}.sha224"):
            with open(f"{file_path}.sha224", "r") as shafile:
                local_sha = shafile.read().split()[0].rstrip()
                sha_hash[224] = local_sha
        if os.path.isfile(f"{file_path}.sha1"):
            with open(f"{file_path}.sha1", "r") as shafile:
                local_sha = shafile.read().split()[0].rstrip()
                sha_hash[1] = local_sha
        if not sha_hash:
            print("sha1 not found, generating sha1...")
            sha1 = hashlib.sha1()
            with open(file_path, "rb") as original_file:
                data = original_file.read(_BUF_SIZE_READ)
                while data:
                    sha1.update(data)
                    data = original_file.read(_BUF_SIZE_READ)
            local_sha = sha1.hexdigest()
            sha_hash[1] = local_sha
        logger.info(f"local sha hashes = {sha_hash}")
        sha_bin, sha_len = self.scs.req_sha_binaries(sha_hash)
        return sha_bin, sha_len, sha_hash

    def split_file_local(self, file_size, split_size):
        """
        splits file into chunks of size already determined in file_split_size()
        This function emulates GNU split.
        :returns None:
        """
        print("splitting file...")
        try:
            total_bytes = 0
            with open(self.local_path, "rb") as src:
                sfx_1 = "a"
                sfx_2 = "a"
                while total_bytes < file_size:
                    with open(f"{self.local_file}{sfx_1}{sfx_2}", "wb") as chunk:
                        logger.info(f"writing data to {self.local_file}{sfx_1}{sfx_2}")
                        src.seek(total_bytes)
                        data = src.read(split_size)
                        chunk.write(data)
                        total_bytes += split_size
                    if sfx_2 == "z":
                        sfx_1 = "b"
                        sfx_2 = "a"
                    else:
                        sfx_2 = chr(ord(sfx_2) + 1)
        except Exception as err:
            err_str = (
                "an error occurred while splitting the file, " f"the error was:\n{err}"
            )
            self.scs.close(err_str, hard_close=self.hard_close)

    def join_files_remote(self, sfiles, remote_tmpdir):
        """
        concatenates the file chunks into one file on remote host
        :returns None:
        """
        logger.info("entering join_files_remote()")
        print("joining files...")
        result = False
        cmd = ""
        try:
            for sfile in sfiles:
                cmd += (
                    f"cat {remote_tmpdir}/{sfile[0]} "
                    f">>{self.remote_dir}/{self.remote_file}\n"
                    "if [ $? -gt 0 ]; then exit 1; fi\n"
                    f"rm {remote_tmpdir}/{sfile[0]}\n"
                    "if [ $? -gt 0 ]; then exit 1; fi\n"
                )
            with self.scs.tempdir():
                with open("join.sh", "w") as fd:
                    fd.write(cmd)
                transport = self.ss._transport
                with SCPClient(transport) as scpclient:
                    scpclient.put("join.sh", f"{remote_tmpdir}/join.sh")
            result, stdout = self.ss.run(f"sh {remote_tmpdir}/join.sh", timeout=600)
        except Exception as err:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            self.scs.close(
                err_str=(
                    f"{err.__class__.__name__} while combining file chunks on "
                    f"remote host: {str(err)}"
                ),
                hard_close=self.hard_close,
            )

        if not result:
            self.scs.close(
                err_str=(
                    "failed to combine chunks on remote host. " f"error was:\n{stdout}"
                ),
                hard_close=self.hard_close,
            )

    def remote_sha_put(self, sha_bin, sha_len, sha_hash):
        """
        creates a sha hash for the newly combined file on the remote host
        compares against local sha
        :returns None:
        """
        logger.info("entering remote_sha_put()")
        print("generating remote sha hash...")
        result, stdout = self.ss.run(f"ls {self.remote_dir}/{self.remote_file}")
        if not result:
            err = f"file {self.host}:{self.remote_dir}/{self.remote_file} not found! please retry"
            self.scs.close(
                err_str=err,
                config_rollback=False,
                hard_close=self.hard_close,
            )

        if sha_bin == "shasum":
            cmd = f"shasum -a {sha_len}"
        else:
            cmd = f"{sha_bin}"

        result, stdout = self.ss.run(
            f"{cmd} {self.remote_dir}/{self.remote_file}", timeout=300
        )
        if not result:
            print(
                "remote sha hash generation failed or timed out, "
                f'manually check the output of "{cmd} {self.remote_dir}/{self.remote_file}" and '
                f"compare against {sha_hash[sha_len]}"
            )
            return
        if re.match(r"sha.*sum", sha_bin):
            remote_sha = stdout.split("\n")[1].split()[0].rstrip()
        else:
            remote_sha = stdout.split("\n")[1].split()[3].rstrip()
        logger.info(f"remote sha = {remote_sha}")
        if sha_hash[sha_len] == remote_sha:
            print(
                f"local and remote sha hash match\nfile has been "
                f"successfully copied to {self.host}:{self.remote_dir}/{self.remote_file}"
            )
        else:
            err = (
                f"file has been copied to {self.host}:{self.remote_dir}/{self.remote_file}"
                ", but the local and remote sha do not match - please retry"
            )
            self.scs.close(
                err_str=err,
                config_rollback=False,
                hard_close=self.hard_close,
            )

    def put_files(self, sfile, remote_tmpdir, copy_kwargs, ssh_kwargs):
        """
        copies files to remote host via ftp or scp
        :param sfile: name and size of the file to copy
        :type: list
        :raises TransferError: if file transfer fails 3 times
        :returns None:
        """
        err_count = 0
        file_name = sfile[0]
        file_size = sfile[1]
        dstpath = f"{remote_tmpdir}/{file_name}"
        logger.info(f"{file_name}, size {file_size}")

        if self.copy_proto == "ftp":
            while err_count < 3:
                try:
                    with FTP(**copy_kwargs) as ftp:
                        ftp.put(file_name, dstpath)
                        break
                except Exception as err:
                    logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                    if not self.mute:
                        logger.warning(
                            f"retrying file {file_name} due to {err.__class__.__name__}"
                            f": {str(err)}"
                        )
                    err_count += 1
                    time.sleep(err_count)
        else:
            while err_count < 3:
                try:
                    with SSHShell(**ssh_kwargs) as ssh:
                        sock = ssh.socket_open()
                        transport = ssh.transport_open(sock)
                        if not ssh.worker_thread_auth():
                            ssh.close()
                            raise SSHException("authentication failed")
                        with SCPClient(transport, **copy_kwargs) as scpclient:
                            scpclient.put(file_name, dstpath)
                            break
                except Exception as err:
                    logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                    if not self.mute:
                        logger.warning(
                            f"retrying file {file_name} due to {err.__class__.__name__}"
                            f": {str(err)}"
                        )
                    err_count += 1
                    time.sleep(err_count)

        if err_count == 3:
            self.mute = True
            raise TransferError


class TransferError(Exception):
    """
    custom exception to indicate problem with file transfer
    """

    pass
