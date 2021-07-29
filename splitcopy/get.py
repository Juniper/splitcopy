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
import glob
import hashlib
import logging
import os
import re
import signal
import sys
import time
import traceback
from math import ceil

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


class SplitCopyGet:
    def __init__(self, **kwargs):
        """
        Initialise the SplitCopyGet class
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
        self.ss = None
        self.scs = SplitCopyShared(**kwargs)
        self.mute = False
        self.hard_close = False

    def handlesigint(self, sigint, stack):
        logger.debug(f"signal {sigint} received, stack:\n{stack}")
        self.mute = True
        self.scs.close(hard_close=self.hard_close)

    def get(self):
        """
        copies file from remote host to local host
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
        self.validate_remote_path_get()

        # check required binaries exist on remote host
        self.scs.req_binaries(junos=junos, evo=evo)

        # cleanup previous remote tmp directory if found
        self.scs.remote_cleanup(
            remote_dir=self.remote_dir, remote_file=self.remote_file, silent=True
        )

        # delete target file if it already exists
        self.delete_target_local()

        # determine remote file size
        file_size = self.remote_filesize()

        # determine optimal size for chunks
        split_size, executor = self.scs.file_split_size(
            file_size, sshd_version, bsd_version, evo
        )

        # confirm remote storage is sufficient
        self.scs.storage_check_remote(file_size, split_size)

        # confirm local storage is sufficient
        self.scs.storage_check_local(file_size)

        if not self.noverify:
            # get/create sha hash for remote file
            sha_bin, sha_len, sha_hash = self.remote_sha_get()

        # create tmp directory on remote host
        remote_tmpdir = self.scs.mkdir_remote()

        # split file into chunks
        self.split_file_remote(file_size, split_size, remote_tmpdir)

        # add chunk names to a list
        result, stdout = self.ss.run(f"ls -l {remote_tmpdir}/")
        if not result:
            self.scs.close(
                err_str="couldn't get list of files from host",
                hard_close=self.hard_close,
            )
        remote_files = stdout.split("\r\n")
        sfiles = []
        for sfile in remote_files:
            if fnmatch.fnmatch(sfile, f"* {self.remote_file}*"):
                sfile = sfile.split()
                sfiles.append([sfile[-1], sfile[-5]])
        if not sfiles:
            self.scs.close(
                err_str="file split operation failed",
                hard_close=self.hard_close,
            )
        logger.info(f"# of chunks = {len(sfiles)}")

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

        with self.scs.tempdir():
            # copy files from remote host
            self.hard_close = True
            loop_start = datetime.datetime.now()
            loop = asyncio.get_event_loop()
            tasks = []
            for sfile in sfiles:
                task = loop.run_in_executor(
                    executor,
                    functools.partial(
                        self.get_files,
                        sfile,
                        remote_tmpdir,
                        copy_kwargs,
                        ssh_kwargs,
                    ),
                )
                tasks.append(task)
            print("starting transfer...")
            try:
                loop.run_until_complete(asyncio.gather(*tasks))
            except TransferError:
                self.scs.close(
                    err_str="an error occurred while copying the files from the remote host",
                    hard_close=self.hard_close,
                )
            finally:
                loop.close()
                self.hard_close = False

            print("\ntransfer complete")
            loop_end = datetime.datetime.now()

            # combine chunks
            self.join_files_local()

        # remove remote tmp dir
        self.scs.remote_cleanup()

        # rollback any config changes made
        if command_list:
            self.scs.limits_rollback()

        if self.noverify:
            print(
                f"file has been successfully copied to {self.local_dir}/{self.local_file}"
            )
        else:
            # generate a sha hash for the combined file, compare to hash of src
            self.local_sha_get(sha_hash)

        self.ss.close()
        return loop_start, loop_end

    def validate_remote_path_get(self):
        """
        path must be a full path, expand as required
        :return: None
        """
        logger.info("entering validate_remote_path_get()")
        if re.match(r"~", self.remote_dir):
            result, stdout = self.ss.run(f"ls -d {self.remote_dir}")
            if result:
                self.remote_dir = stdout.split("\n")[1].rstrip()
                self.remote_path = f"{self.remote_dir}/{self.remote_file}"
                logger.info(
                    f"remote_dir now = {self.remote_dir}, remote_file now = {self.remote_file}"
                )
            else:
                self.scs.close(
                    err_str=f"unable to expand remote path {self.remote_path}",
                    hard_close=self.hard_close,
                )

        # bail if its a directory
        result, stdout = self.ss.run(f"test -d {self.remote_path}")
        if result:
            self.scs.close(
                err_str="src path is a directory, not a file",
                hard_close=self.hard_close,
            )

        # check if remote file exists
        result, stdout = self.ss.run(f"test -r {self.remote_path}")
        if not result:
            self.scs.close(
                err_str="file on remote host is not readable",
                hard_close=self.hard_close,
            )

        # is it a symlink? if so, rewrite remote_path with linked file path
        result, stdout = self.ss.run(f"test -L {self.remote_path}")
        if result:
            logger.info("file is a symlink")
            result, stdout = self.ss.run(f"ls -l {self.remote_path}")
            if result:
                self.remote_path = stdout.split()[-2].rstrip()
                self.remote_dir = os.path.dirname(self.remote_path)
                self.remote_file = os.path.basename(self.remote_path)
            else:
                self.scs.close(
                    err_str="file on remote host is a symlink, failed to retrieve details",
                    hard_close=self.hard_close,
                )

    def delete_target_local(self):
        """
        deletes the target file if it already exists
        """
        file_path = self.local_dir + os.path.sep + self.local_file
        if os.path.exists(file_path):
            os.remove(file_path)

    def remote_filesize(self):
        """
        determines the remote file size in bytes
        :returns None:
        """
        logger.info("entering remote_filesize()")
        result, stdout = self.ss.run(f"ls -l {self.remote_path}")
        if result:
            file_size = int(stdout.split("\n")[1].split()[4])
        else:
            self.scs.close(
                err_str="cannot determine remote file size",
                hard_close=self.hard_close,
            )
        logger.info(f"src file size is {file_size}")
        return file_size

    def remote_sha_get(self):
        """
        checks for existence of a sha hash file
        if none found, generates a sha hash for the remote file to be copied
        :returns None:
        """
        logger.info("entering remote_sha_get()")
        sha_hash = {}
        result, stdout = self.ss.run(f"ls -1 {self.remote_path}.sha*")
        if result:
            lines = stdout.split("\n")
            for line in lines:
                line = line.rstrip()
                match = re.search(r"\.sha([0-9]+)$", line)
                if match:
                    sha_num = int(match.group(1))
                    logger.info(f"{line} file found")
                    result, stdout = self.ss.run(f"cat {line}")
                    if result:
                        sha_hash[sha_num] = stdout.split("\n")[1].split()[0].rstrip()
                        logger.info(f"sha_hash[{sha_num}] added")
                    else:
                        logger.info(f"unable to read remote sha file {line}")

        if not sha_hash:
            sha_hash[1] = True
            sha_bin, sha_len = self.scs.req_sha_binaries(sha_hash)
            print("generating remote sha hash...")
            result, stdout = self.ss.run(f"{sha_bin} {self.remote_path}", timeout=120)
            if not result:
                self.scs.close(
                    err_str="failed to generate remote sha1",
                    hard_close=self.hard_close,
                )

            if re.match(r"sha.*sum", sha_bin):
                sha_hash[1] = stdout.split("\n")[1].split()[0].rstrip()
            else:
                sha_hash[1] = stdout.split("\n")[1].split()[3].rstrip()
        logger.info(f"remote sha hashes = {sha_hash}")
        return sha_bin, sha_len, sha_hash

    def split_file_remote(self, file_size, split_size, remote_tmpdir):
        """
        splits file on remote host
        :returns None:
        """
        logger.info("entering split_file_remote()")
        result = False
        total_blocks = ceil(file_size / _BUF_SIZE)
        block_size = ceil(split_size / _BUF_SIZE)
        logger.info(f"total_blocks = {total_blocks}, block_size = {block_size}")
        cmd = (
            f"size_b={block_size}; size_tb={total_blocks}; i=0; o=00; "
            "while [ $i -lt $size_tb ]; do "
            f"dd if={self.remote_path} of={remote_tmpdir}/{self.remote_file}_$o "
            f"bs={_BUF_SIZE} count=$size_b skip=$i; "
            "i=`expr $i + $size_b`; o=`expr $o + 1`; "
            "if [ $o -lt 10 ]; then o=0$o; fi; done"
        )

        # switched to file copy as the '> ' in 'echo cmd > file'
        # would sometimes be interpreted as shell prompt
        with self.scs.tempdir():
            with open("split.sh", "w") as fd:
                fd.write(cmd)
            transport = self.ss._transport
            with SCPClient(transport) as scpclient:
                scpclient.put("split.sh", f"{remote_tmpdir}/split.sh")

        print("splitting remote file...")
        result, stdout = self.ss.run(
            f"sh {remote_tmpdir}/split.sh",
            timeout=self.split_timeout,
        )
        if not result:
            self.scs.close(
                err_str=(
                    "failed to split file on remote host. " f"error was:\n{stdout}"
                ),
                hard_close=self.hard_close,
            )

    def get_files(self, sfile, remote_tmpdir, copy_kwargs, ssh_kwargs):
        """
        copies files from remote host via ftp or scp
        :param sfile: name and size of the file to copy
        :type: list
        :raises TransferError: if file transfer fails 3 times
        :returns None:
        """
        err_count = 0
        file_name = sfile[0]
        file_size = sfile[1]
        srcpath = f"{remote_tmpdir}/{file_name}"
        logger.info(f"{file_name}, size {file_size}")
        if self.copy_proto == "ftp":
            while err_count < 3:
                try:
                    with FTP(**copy_kwargs) as ftp:
                        ftp.get(srcpath, file_name)
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
                            scpclient.get(srcpath, file_name)
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

    def join_files_local(self):
        """
        concatenates the file chunks into one file on local host
        :returns None:
        """
        logger.info("entering join_files_local()")
        print("joining files...")
        local_tmpdir = self.scs.return_tmpdir()
        src_files = glob.glob(local_tmpdir + os.path.sep + self.remote_file + "*")
        dst_file = self.local_dir + os.path.sep + self.local_file
        with open(dst_file, "wb") as dst:
            for src in sorted(src_files):
                with open(src, "rb") as chunk:
                    data = chunk.read(_BUF_SIZE_READ)
                    while data:
                        dst.write(data)
                        data = chunk.read(_BUF_SIZE_READ)
        if not os.path.isfile(dst_file):
            err_str = f"recombined file {dst_file} isn't found, exiting"
            self.scs.close(
                err_str,
                hard_close=self.hard_close,
            )

    def local_sha_get(self, sha_hash):
        """
        generates a sha hash for the combined file on the local host
        :returns None:
        """
        logger.info("entering local_sha_get()")
        print("generating local sha hash...")
        if sha_hash.get(512):
            sha_idx = 512
            sha = hashlib.sha512()
        elif sha_hash.get(384):
            sha_idx = 384
            sha = hashlib.sha384()
        elif sha_hash.get(256):
            sha_idx = 256
            sha = hashlib.sha256()
        elif sha_hash.get(224):
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
        logger.info(f"local sha = {local_sha}")
        if local_sha == sha_hash.get(sha_idx):
            print(
                "local and remote sha hash match\nfile has been "
                f"successfully copied to {self.local_dir}{os.path.sep}{self.local_file}"
            )
        else:
            err = (
                f"file has been copied to {self.local_dir}{os.path.sep}{self.local_file}"
                ", but the local and remote sha hash do not match - please retry"
            )
            self.scs.close(
                err_str=err,
                config_rollback=False,
                hard_close=self.hard_close,
            )


class TransferError(Exception):
    """
    custom exception to indicate problem with file transfer
    """

    pass
