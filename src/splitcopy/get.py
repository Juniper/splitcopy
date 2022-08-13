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
from paramiko.ssh_exception import SSHException
from scp import SCPClient

# local modules
from splitcopy.ftp import FTP
from splitcopy.paramikoshell import SSHShell
from splitcopy.progress import Progress
from splitcopy.shared import SplitCopyShared

logger = logging.getLogger(__name__)

# use st_blksize
_BUF_SIZE_READ = 1024 * 8
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
        self.remote_path = kwargs.get("remote_path")
        self.copy_proto = kwargs.get("copy_proto")
        self.target = kwargs.get("target")
        self.noverify = kwargs.get("noverify")
        self.split_timeout = kwargs.get("split_timeout")
        self.use_curses = kwargs.get("use_curses")
        self.sshshell = None
        self.scs = SplitCopyShared(**kwargs)
        self.mute = False
        self.hard_close = False
        self.local_dir = ""
        self.local_file = ""
        self.local_path = ""
        self.remote_dir = ""
        self.remote_file = ""
        self.filesize_path = self.remote_path
        self.progress = Progress()

    def handlesigint(self, sigint, stack):
        """function called when SigInt is received
        :param sigint:
        :type int:
        :param stack:
        :type frame:
        """
        logger.debug(f"signal {sigint} received, stack:\n{stack}")
        self.mute = True
        self.progress.stop_progress()
        self.scs.close(hard_close=self.hard_close)

    def get(self):
        """copies file from remote host to local host
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

        # handle sigint gracefully on *nix
        signal.signal(signal.SIGINT, self.handlesigint)

        # connect to host
        self.sshshell, ssh_kwargs = self.scs.connect(SSHShell, **ssh_kwargs)

        # determine remote host os
        junos, evo, bsd_version, sshd_version = self.scs.which_os()

        # verify which protocol to use
        self.copy_proto, self.passwd = self.scs.which_proto(self.copy_proto)

        # ensure source path is valid
        self.validate_remote_path_get()

        # ensure dest path is valid
        self.local_dir, self.local_file, self.local_path = self.parse_target_arg()

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
            file_size, sshd_version, bsd_version, evo, self.copy_proto
        )

        # confirm remote storage is sufficient
        self.scs.storage_check_remote(file_size, split_size)

        # confirm local storage is sufficient
        self.scs.storage_check_local(file_size)

        if not self.noverify:
            # get/create sha hash for remote file
            sha_hash = self.remote_sha_get()

        # create tmp directory on remote host
        remote_tmpdir = self.scs.mkdir_remote()

        # split file into chunks
        self.split_file_remote(SCPClient, file_size, split_size, remote_tmpdir)

        # add chunk names to a list, pass this info to Progress
        chunks = self.get_chunk_info(remote_tmpdir)
        self.progress.add_chunks(file_size, chunks)

        # begin connection/rate limit check and transfer process
        command_list = []
        if junos or evo:
            command_list = self.scs.limit_check(self.copy_proto)
        print("starting transfer...")
        self.progress.start_progress(self.use_curses)
        with self.scs.tempdir():
            # copy files from remote host
            self.hard_close = True
            loop_start = datetime.datetime.now()
            loop = asyncio.new_event_loop()
            tasks = []
            for chunk in chunks:
                task = loop.run_in_executor(
                    executor,
                    functools.partial(
                        self.get_files,
                        FTP,
                        SSHShell,
                        SCPClient,
                        chunk,
                        remote_tmpdir,
                        ssh_kwargs,
                    ),
                )
                tasks.append(task)
            try:
                loop.run_until_complete(asyncio.gather(*tasks))
            except TransferError:
                self.progress.stop_progress()
                self.scs.close(
                    err_str="an error occurred while copying the files from the remote host",
                    hard_close=self.hard_close,
                )
            finally:
                loop.close()

            self.hard_close = False
            while self.progress.totals["percent_done"] != 100:
                time.sleep(0.1)
            self.progress.stop_progress()

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

        self.sshshell.close()
        return loop_start, loop_end

    def get_chunk_info(self, remote_tmpdir):
        """obtains the remote chunk file size and names
        :param remote_tmpdir:
        :type string:
        :return chunks:
        :type list:
        """
        logger.info("entering get_chunk_info()")
        result, stdout = self.sshshell.run(f"ls -l {remote_tmpdir}/")
        if not result:
            self.scs.close(
                err_str="couldn't get list of files from host",
                hard_close=self.hard_close,
            )
        lines = stdout.splitlines()
        chunks = []
        for line in lines:
            if fnmatch.fnmatch(line, f"* {self.remote_file}*"):
                chunk = line.split()
                chunks.append([chunk[-1], int(chunk[-5])])
        if not chunks:
            self.scs.close(
                err_str="failed to retreive chunk names and sizes",
                hard_close=self.hard_close,
            )
        logger.debug(chunks)
        return chunks

    def validate_remote_path_get(self):
        """path must be a full path, expand as required
        :return: None
        """
        logger.info("entering validate_remote_path_get()")
        self.remote_dir = os.path.dirname(self.remote_path)
        self.remote_file = os.path.basename(self.remote_path)
        try:
            self.expand_remote_dir()
            self.path_startswith_tilda()
            self.verify_path_is_not_directory()
            self.verify_file_exists()
            self.verify_file_is_readable()
            self.check_if_symlink()
        except ValueError as err:
            self.scs.close(
                err_str=err,
                hard_close=self.hard_close,
            )
        # update SplitCopyShared with these values
        self.scs.remote_file = self.remote_file
        self.scs.remote_dir = self.remote_dir

    def parse_target_arg(self):
        """determines the local file/dir/path based on the target arg
        :return local_dir:
        :type string:
        :return local_file:
        :type string:
        :return local_path:
        :type string:
        """
        logger.info("entering parse_target_arg()")
        local_dir = None
        local_file = None
        local_path = None
        target = self.target
        remote_file = self.remote_file
        if os.path.isdir(target):
            # target is a <path>/
            local_dir = os.path.abspath(os.path.expanduser(target))
            local_file = remote_file
        elif os.path.isdir(os.path.dirname(target)):
            # target is a <path>/<filename>
            local_dir = os.path.dirname(os.path.abspath(os.path.expanduser(target)))
            if os.path.basename(target) != remote_file:
                # have to honour the change of name
                local_file = os.path.basename(target)
            else:
                local_file = remote_file
        else:
            # target is <filename> only
            local_dir = os.getcwd()
            if os.path.basename(target) != remote_file:
                # have to honour the change of name
                local_file = os.path.basename(target)
            else:
                local_file = remote_file

        local_path = f"{local_dir}{os.path.sep}{local_file}"
        return local_dir, local_file, local_path

    def expand_remote_dir(self):
        """expands the remote directory to its absolute path
        :return None:
        :raises ValueError: if remote cmd fails
        """
        logger.info("entering expand_remote_dir()")
        if not self.remote_dir or re.match(r"\.", self.remote_dir):
            result, stdout = self.sshshell.run("pwd")
            if result:
                pwd = stdout.split("\n")[1].rstrip()
                self.remote_dir = f"{pwd}{self.remote_dir.lstrip('.')}"
                self.remote_path = f"{self.remote_dir}/{self.remote_file}"
                logger.debug(
                    f"remote_dir now = {self.remote_dir}, remote_path now = {self.remote_path}"
                )
            else:
                raise ValueError("Cannot determine the directory on the remote host")

    def path_startswith_tilda(self):
        """expands ~ based path to absolute path
        :return None:
        :raises ValueError: if remote cmd fails
        """
        logger.info("entering path_startswith_tilda()")
        if re.match(r"~", self.remote_dir):
            result, stdout = self.sshshell.run(f"ls -d {self.remote_dir}")
            if result:
                self.remote_dir = stdout.split("\n")[1].rstrip()
                self.remote_path = f"{self.remote_dir}/{self.remote_file}"
                logger.debug(
                    f"remote_dir now = {self.remote_dir}, remote_path now = {self.remote_path}"
                )
            else:
                raise ValueError(f"unable to expand remote path {self.remote_path}")

    def verify_path_is_not_directory(self):
        """verifies remote path is not a directory
        :return None:
        :raises ValueError: if path is a directory
        """
        logger.info("entering verify_path_is_not_directory()")
        result, stdout = self.sshshell.run(f"test -d {self.remote_path}")
        if result:
            raise ValueError("src path is a directory, not a file")

    def verify_file_exists(self):
        """verifies remote path exists
        :return None:
        :raises ValueError: if test fails
        """
        logger.info("entering verify_file_exists()")
        result, stdout = self.sshshell.run(f"test -e {self.remote_path}")
        if not result:
            raise ValueError("file on remote host doesn't exist")

    def verify_file_is_readable(self):
        """verifies the remote file is readable
        :return None
        :raises ValueError: if test fails
        """
        logger.info("entering verify_file_is_readable()")
        result, stdout = self.sshshell.run(f"test -r {self.remote_path}")
        if not result:
            raise ValueError("file on remote host is not readable")

    def check_if_symlink(self):
        """if remote_path is a symlink, determine the link dst path
        this is required to determine the files size
        :return None
        :raises ValueError: if test fails
        """
        logger.info("entering check_if_symlink()")
        result, stdout = self.sshshell.run(f"test -L {self.remote_path}")
        if result:
            logger.info("file is a symlink")
            result, stdout = self.sshshell.run(f"ls -l {self.remote_path}")
            if result:
                linked_path = stdout.split()[-2].rstrip()
                linked_dir = os.path.dirname(linked_path)
                linked_file = os.path.basename(linked_path)
            else:
                raise ValueError(
                    "file on remote host is a symlink, failed to retrieve details"
                )
            if not linked_dir:
                # symlink is in the same directory as source file use self.remote_dir
                self.filesize_path = f"{self.remote_dir}/{linked_file}"
            else:
                self.filesize_path = f"{linked_dir}/{linked_file}"
            logger.debug(
                f"filesize_path updated from {self.remote_path} to {self.filesize_path}"
            )

    def delete_target_local(self):
        """deletes the target file if it already exists
        :return None:
        """
        logger.info("entering delete_target_local()")
        file_path = self.local_dir + os.path.sep + self.local_file
        if os.path.exists(file_path):
            os.remove(file_path)

    def remote_filesize(self):
        """determines the remote file size in bytes
        :return file_size:
        :type int:
        """
        logger.info("entering remote_filesize()")
        result, stdout = self.sshshell.run(f"ls -l {self.filesize_path}")
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
        """checks for existence of a sha hash file
        if none found, generates a sha hash for the remote file to be copied
        :return sha_bin:
        :type string:
        :return sha_len:
        :type int:
        :return sha_hash:
        """
        logger.info("entering remote_sha_get()")
        sha_hash = {}
        result, stdout = self.find_existing_sha_files()
        if result:
            sha_hash = self.process_existing_sha_files(stdout)
        if not sha_hash:
            sha_hash[1] = True
            sha_bin, sha_len = self.scs.req_sha_binaries(sha_hash)
            print("generating remote sha hash...")
            if sha_bin == "shasum":
                result, stdout = self.sshshell.run(
                    f"{sha_bin} -a {sha_len} {self.remote_path}", timeout=120
                )
            else:
                result, stdout = self.sshshell.run(
                    f"{sha_bin} {self.remote_path}", timeout=120
                )
            if not result:
                self.scs.close(
                    err_str="failed to generate remote sha1",
                    hard_close=self.hard_close,
                )
            for line in stdout.splitlines():
                try:
                    sha_hash[1] = re.search(r"([0-9a-f]{40})", line).group(1)
                    break
                except AttributeError:
                    pass
            if not isinstance(sha_hash[1], str):
                self.scs.close(
                    err_str="failed to obtain remote sha1",
                    hard_close=self.hard_close,
                )

        logger.info(f"remote sha hashes = {sha_hash}")
        return sha_hash

    def find_existing_sha_files(self):
        """checks for presence of existing sha* files
        :return result:
        :type bool:
        :return stdout:
        :type string:
        """
        logger.info("entering find_existing_sha_files()")
        result, stdout = self.sshshell.run(f"ls -1 {self.remote_path}.sha*")
        return result, stdout

    def process_existing_sha_files(self, output):
        """reads existing sha files, puts the hash and sha length info a dict()
        :param output:
        :type string:
        :returns sha_hash:
        :type dict:
        """
        logger.info("entering process_existing_sha_files()")
        sha_hash = {}
        for line in output.splitlines():
            line = line.rstrip()
            match = re.search(r"\.sha([0-9]+)$", line)
            try:
                sha_num = int(match.group(1))
            except AttributeError:
                continue
            logger.info(f"{line} file found")
            result, stdout = self.sshshell.run(f"cat {line}")
            if result:
                sha_hash[sha_num] = stdout.split("\n")[1].split()[0].rstrip()
                logger.info(f"sha_hash[{sha_num}] added")
            else:
                logger.info(f"unable to read remote sha file {line}")
        return sha_hash

    def split_file_remote(self, scp_lib, file_size, split_size, remote_tmpdir):
        """writes a script into a file, copies it to the remote host then executes it.
        the source file is split into multiple smaller chunks ready to be copied
        :param scp_lib:
        :type class:
        :param file_size:
        :type int:
        :param split_size:
        :type int:
        :param remote_tmpdir:
        :type string:
        :return None:
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
            transport = self.sshshell._transport
            with scp_lib(transport) as scpclient:
                scpclient.put("split.sh", f"{remote_tmpdir}/split.sh")
        print("splitting remote file...")
        result, stdout = self.sshshell.run(
            f"sh {remote_tmpdir}/split.sh",
            timeout=self.split_timeout,
        )
        if not result:
            err_str = f"failed to split file on remote host, due to error:\n{stdout}"
            self.scs.close(err_str, hard_close=self.hard_close)

    def get_files(self, ftp_lib, ssh_lib, scp_lib, chunk, remote_tmpdir, ssh_kwargs):
        """copies files from remote host via ftp or scp
        :param ftp_lib:
        :type class:
        :param ssh_lib:
        :type class:
        :param scp_lib:
        :type class:
        :param chunk: name and size of the file to copy
        :type: list
        :param remote_tmpdir: path of the tmp directory on remote host
        :type: str
        :param ssh_kwargs: keyword arguments
        :type dict:
        :raises TransferError: if file transfer fails 3 times
        :returns None:
        """
        logger.info("entering get_files()")
        err_count = 0
        file_name = chunk[0]
        file_size = chunk[1]
        srcpath = f"{remote_tmpdir}/{file_name}"
        logger.info(f"{file_name}, size {file_size}")
        while err_count < 3:
            try:
                if self.copy_proto == "ftp":
                    with ftp_lib(
                        file_size=file_size,
                        progress=self.progress,
                        host=self.host,
                        user=self.user,
                        passwd=self.passwd,
                    ) as ftp:
                        restart_marker = None
                        if err_count:
                            try:
                                restart_marker = os.stat(file_name).st_size
                            except FileNotFoundError:
                                pass
                            self.progress.zero_file_stats(file_name)
                        if restart_marker is not None:
                            self.progress.print_error(
                                f"resuming {file_name} from byte {restart_marker}"
                            )
                        ftp.get(srcpath, file_name, restart_marker)
                    break
                else:
                    with ssh_lib(**ssh_kwargs) as ssh:
                        ssh.socket_open()
                        ssh.transport_open()
                        if not ssh.worker_thread_auth():
                            ssh.close()
                            raise SSHException("authentication failed")
                        with scp_lib(
                            ssh._transport, progress=self.progress.report_progress
                        ) as scpclient:
                            if err_count:
                                self.progress.zero_file_stats(file_name)
                            scpclient.get(srcpath, file_name)
                        # hack. at times, a FIN wasn't being sent resulting in sshd (notty)
                        # processes being left in ESTABLISHED state on server.
                        # adding sleep here appears to prevent this
                        time.sleep(1)
                    break
            except Exception as err:
                err_count += 1
                logger.debug("".join(traceback.format_exception(*sys.exc_info())))
                if not self.mute:
                    if err_count < 3:
                        self.progress.print_error(
                            f"chunk {file_name} transfer failed due to "
                            f"{err.__class__.__name__} {str(err)}, retrying"
                        )
                    else:
                        self.progress.print_error(
                            f"chunk {file_name} transfer failed due to "
                            f"{err.__class__.__name__} {str(err)}"
                        )
                time.sleep(err_count)

        if err_count == 3:
            self.mute = True
            raise TransferError

    def join_files_local(self):
        """concatenates the file chunks into one file on local host
        :returns None:
        """
        logger.info("entering join_files_local()")
        print("joining chunks...")
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
                err_str=err_str,
                hard_close=self.hard_close,
            )

    def local_sha_get(self, sha_hash):
        """generates a sha hash for the combined file on the local host
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
