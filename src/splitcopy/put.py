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
from ftplib import error_perm, error_proto, error_reply, error_temp

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
        self.remote_path = kwargs.get("remote_path")
        self.local_dir = kwargs.get("local_dir")
        self.local_file = kwargs.get("local_file")
        self.local_path = kwargs.get("local_path")
        self.copy_proto = kwargs.get("copy_proto")
        self.noverify = kwargs.get("noverify")
        self.use_curses = kwargs.get("use_curses")
        self.scs = SplitCopyShared(**kwargs)
        self.mute = False
        self.hard_close = False
        self.sshshell = None
        self.remote_dir = ""
        self.remote_file = ""
        self.progress = Progress()

    def handlesigint(self, sigint, stack):
        logger.debug(f"signal {sigint} received, stack:\n{stack}")
        self.mute = True
        self.progress.stop_progress()
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
        self.sshshell, ssh_kwargs = self.scs.connect(SSHShell, **ssh_kwargs)

        # determine remote host os
        junos, evo, bsd_version, sshd_version = self.scs.which_os()

        # verify which protocol to use
        self.copy_proto, self.passwd = self.scs.which_proto(self.copy_proto)

        # ensure dest path is valid
        self.validate_remote_path_put()

        # delete target file if it already exists
        if self.check_target_exists():
            self.delete_target_remote()

        # check required binaries exist on remote host
        self.scs.req_binaries(junos=junos, evo=evo)

        # cleanup previous remote tmp directory if found
        self.scs.remote_cleanup(
            remote_dir=self.remote_dir, remote_file=self.remote_file, silent=True
        )

        # determine local file size
        file_size = self.determine_local_filesize()

        # determine optimal size for chunks
        split_size, executor = self.scs.file_split_size(
            file_size, sshd_version, bsd_version, evo, self.copy_proto
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

            # add chunk names to a list, pass this info to Progress
            chunks = self.get_chunk_info()
            self.progress.add_chunks(file_size, chunks)

            # create tmp directory
            remote_tmpdir = self.scs.mkdir_remote()

            # begin connection/rate limit check and transfer process
            command_list = []
            if junos or evo:
                command_list = self.scs.limit_check(self.copy_proto)
            print("starting transfer...")
            self.progress.start_progress(self.use_curses)
            # copy files to remote host
            self.hard_close = True
            loop_start = datetime.datetime.now()
            loop = asyncio.new_event_loop()
            tasks = []
            for chunk in chunks:
                task = loop.run_in_executor(
                    executor,
                    functools.partial(
                        self.put_files,
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
                    err_str="\nan error occurred while copying the files to the remote host",
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
        self.join_files_remote(SCPClient, chunks, remote_tmpdir)

        # remove remote tmp dir
        self.scs.remote_cleanup()

        # rollback any config changes made
        if command_list:
            self.scs.limits_rollback()

        # check remote file size is correct
        self.compare_file_sizes(file_size)

        if self.noverify:
            print(
                f"file has been successfully copied to {self.host}:"
                f"{self.remote_dir}/{self.remote_file}"
            )
        else:
            # generate a sha hash for the combined file, compare to hash of src
            self.remote_sha_put(sha_bin, sha_len, sha_hash)

        self.sshshell.close()
        return loop_start, loop_end

    def get_chunk_info(self):
        chunks = []
        for chunk in os.listdir("."):
            if fnmatch.fnmatch(chunk, f"{self.local_file}*"):
                chunks.append([chunk, os.stat(chunk).st_size])
        if not chunks:
            self.scs.close(
                err_str="file split operation failed", hard_close=self.hard_close
            )
        # sort alphabetically
        chunks = sorted(chunks)
        logger.info(f"# of chunks = {len(chunks)}")
        logger.debug(chunks)
        return chunks

    def validate_remote_path_put(self):
        """
        path provided can be a directory, a new or existing file
        :return: None
        """
        logger.info("entering validate_remote_path_put()")
        if self.sshshell.run(f"test -d {self.remote_path}")[0]:
            # target path provided is a directory
            self.remote_file = self.local_file
            self.remote_dir = self.remote_path.rstrip("/")
        elif (
            self.sshshell.run(f"test -f {self.remote_path}")[0]
            or self.sshshell.run(f"test -d {os.path.dirname(self.remote_path)}")[0]
        ):
            if os.path.basename(self.remote_path) != self.local_file:
                # target path provided was a full path, file name does not match src
                # honour the change of file name
                self.remote_file = os.path.basename(self.remote_path)
            else:
                # target path provided was a full path, file name matches src
                self.remote_file = self.local_file
            self.remote_dir = os.path.dirname(self.remote_path)
        else:
            self.scs.close(
                err_str=f"target path {self.remote_path} on remote host isn't valid",
                hard_close=self.hard_close,
            )
        logger.info(
            f"self.remote_path = {self.remote_path}, self.remote_dir = "
            f"{self.remote_dir}, self.remote_file = {self.remote_file}"
        )

    def check_target_exists(self):
        """Function that checks if the target file already exists
        :return result:
        :type bool:
        """
        logger.info("entering check_target_exists()")
        result, stdout = self.sshshell.run(
            f"test -e {self.remote_dir}/{self.remote_file}"
        )
        return result

    def delete_target_remote(self):
        """Function that attempts to delete the target file
        :return None:
        """
        logger.info("entering delete_target_remote()")
        result, stdout = self.sshshell.run(
            f"rm -f {self.remote_dir}/{self.remote_file}"
        )
        if not result:
            err = "remote file already exists, and could not be deleted"
            self.scs.close(err_str=err)

    def determine_local_filesize(self):
        """Function that determines the local files size in bytes
        :return file_size:
        :type int:
        """
        logger.info("entering determine_local_filesize()")
        file_size = os.path.getsize(self.local_path)
        logger.info(f"src file size is {file_size}")
        return file_size

    def local_sha_put(self):
        """Function that checks whether a sha hash already exists for the file
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
        except Exception as error:
            err = f"an error occurred while splitting the file, the error was:\n{error}"
            self.scs.close(err_str=err, hard_close=self.hard_close)

    def join_files_remote(self, scp_lib, chunks, remote_tmpdir):
        """Function that concatenates the files chunks into one file on remote host
        :returns None:
        """
        logger.info("entering join_files_remote()")
        print("joining chunks...")
        result = False
        cmd = ""
        try:
            for chunk in chunks:
                cmd += (
                    f"cat {remote_tmpdir}/{chunk[0]} "
                    f">>{self.remote_dir}/{self.remote_file}\n"
                    "if [ $? -gt 0 ]; then exit 1; fi\n"
                    f"rm {remote_tmpdir}/{chunk[0]}\n"
                    "if [ $? -gt 0 ]; then exit 1; fi\n"
                )
            with self.scs.tempdir():
                with open("join.sh", "w", newline="\n") as fd:
                    fd.write(cmd)
                transport = self.sshshell._transport
                with scp_lib(transport) as scpclient:
                    scpclient.put("join.sh", f"{remote_tmpdir}/join.sh")
            result, stdout = self.sshshell.run(
                f"sh {remote_tmpdir}/join.sh", timeout=600
            )
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

    def compare_file_sizes(self, file_size):
        """Function that obtains the newly combined file size
        and compares it to the source files size
        :param file_size:
        :type int:
        :return None:
        """
        logger.info("entering compare_file_sizes()")
        result, stdout = self.sshshell.run(
            f"ls -l {self.remote_dir}/{self.remote_file}"
        )
        if not result:
            self.scs.close(
                err_str=(
                    f"file {self.host}:{self.remote_dir}/{self.remote_file} "
                    "not found! please retry"
                ),
                config_rollback=False,
                hard_close=self.hard_close,
            )
        combined_file_size = int(stdout.split("\r\n")[1].split()[4])
        if combined_file_size != file_size:
            self.scs.close(
                err_str=(
                    f"combined file size is {combined_file_size}, file "
                    f"{self.host}:{self.remote_dir}/{self.remote_file} size "
                    f"is {file_size}. Unexpected mismatch in file size. Please retry"
                ),
                config_rollback=False,
                hard_close=self.hard_close,
            )
        print("local and remote file sizes match")

    def remote_sha_put(self, sha_bin, sha_len, sha_hash):
        """Function that creates a sha hash for the newly combined file
        on the remote host compares against local sha
        :param sha_bin:
        :type string:
        :param sha_len:
        :type int:
        :param sha_hash:
        :type hash:
        :returns None:
        """
        print("generating remote sha hash...")
        remote_sha = ""
        if sha_bin == "shasum":
            cmd = f"shasum -a {sha_len}"
        else:
            cmd = f"{sha_bin}"

        result, stdout = self.sshshell.run(
            f"{cmd} {self.remote_dir}/{self.remote_file}", timeout=300
        )
        if not result:
            print(
                "remote sha hash generation failed or timed out, "
                f'manually check the output of "{cmd} {self.remote_dir}/{self.remote_file}" and '
                f"compare against {sha_hash[sha_len]}"
            )
            return
        for line in stdout.splitlines():
            try:
                remote_sha = re.search(r"([0-9a-f]{40,})", line).group(1)
                break
            except AttributeError:
                pass
        if not remote_sha:
            self.scs.close(
                err_str="failed to obtain remote sha hash to compare against",
                config_rollback=False,
                hard_close=self.hard_close,
            )
        logger.info(f"remote sha = {remote_sha}")
        if sha_hash[sha_len] == remote_sha:
            print(
                f"local and remote sha hash match\nfile has been "
                f"successfully copied to {self.host}:{self.remote_dir}/{self.remote_file}"
            )
        else:
            self.scs.close(
                err_str=(
                    f"file has been copied to {self.host}:{self.remote_dir}/{self.remote_file}"
                    ", but the local and remote sha do not match - please retry"
                ),
                config_rollback=False,
                hard_close=self.hard_close,
            )

    def put_files(self, ftp_lib, ssh_lib, scp_lib, chunk, remote_tmpdir, ssh_kwargs):
        """
        copies files to remote host via ftp or scp
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
        err_count = 0
        file_name = chunk[0]
        file_size = chunk[1]
        dstpath = f"{remote_tmpdir}/{file_name}"
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
                                ftp.sendcmd("TYPE I")
                                restart_marker = ftp.size(dstpath)
                            except (error_perm, error_proto, error_reply, error_temp):
                                pass
                        if restart_marker is not None:
                            self.progress.print_error(
                                f"resuming {file_name} from byte {restart_marker}"
                            )
                        else:
                            self.progress.zero_file_stats(file_name)
                        ftp.put(file_name, dstpath, restart_marker)
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
                            scpclient.put(file_name, dstpath)
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


class TransferError(Exception):
    """Custom exception to indicate problem with file transfer"""

    pass