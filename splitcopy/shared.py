""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

# stdlib
import concurrent.futures
import datetime
from ftplib import error_reply, error_temp, error_perm, error_proto
import getpass
import logging
import os
import re
import shutil
from socket import timeout as socket_timeout
from socket import create_connection
import sys
import tempfile
import traceback
from contextlib import contextmanager
from math import ceil

# 3rd party
from paramiko.ssh_exception import SSHException

# local modules
from splitcopy.paramikoshell import SSHShell
from splitcopy.ftp import FTP

logger = logging.getLogger(__name__)


class SplitCopyShared:
    """
    functions shared by both SplitCopyGet and SplitCopyPut classes
    """

    def __init__(self, **kwargs):
        """
        Initialise the SplitCopyShared class
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
        self.copy_proto = kwargs.get("copy_proto")
        self.get_op = kwargs.get("get")
        self.split_timeout = kwargs.get("split_timeout")
        self.command_list = []
        self.rm_remote_tmp = False
        self.local_tmpdir = None
        self.remote_tmpdir = None
        self.ss = None

    def connect(self, **ssh_kwargs):
        try:
            self.ss = SSHShell(**ssh_kwargs)
            sock = self.ss.socket_open()
            self.ss.transport_open(sock)
            if self.ss.main_thread_auth():
                self.ss.channel_open()
                self.ss.invoke_shell()
                ssh_kwargs = self.ss.kwargs
                logger.debug(f"ssh_kwargs returned are: {ssh_kwargs}")
            else:
                raise SSHException("authentication failed")
            self.ss.set_keepalive()
            # remove the welcome message from the socket
            self.ss.stdout_read(timeout=30)
        except Exception as err:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            self.ss.close()
            raise SystemExit(
                f"{err.__class__.__name__} returned while connecting via ssh: {str(err)}"
            )
        return self.ss, ssh_kwargs

    def which_proto(self, copy_proto):
        """
        verify that if FTP is selected as protocol, that authentication works
        """
        passwd = self.ss.kwargs["password"]
        result = None
        if copy_proto == "ftp" and self.ftp_port_check():
            if passwd is None:
                passwd = getpass.getpass(
                    prompt=f"{self.user}'s password: ", stream=None
                )
            try:
                result = self.ftp_login_check(passwd)
            except (error_reply, error_temp, error_perm, error_proto) as err:
                print(
                    f"ftp login failed, switching to scp for transfer. Error was: {err}"
                )
            except socket_timeout:
                print(f"ftp auth timed out, switching to scp for transfer")

            if not result:
                copy_proto = "scp"
        else:
            copy_proto = "scp"

        logger.info(f"copy_proto == {copy_proto}")
        return copy_proto, passwd

    def ftp_port_check(self):
        """
        checks ftp port is open
        :returns: bool
        """
        result = False
        print("attempting FTP authentication...")
        try:
            with create_connection((self.host, 21), 10) as ftp_sock:
                logger.info("ftp port is open")
                result = True
        except socket_timeout:
            print(f"ftp socket timed out, switching to scp for transfer")
        except ConnectionRefusedError:
            print("ftp connection refused, switching to scp for transfer")

        return result

    def ftp_login_check(self, passwd):
        """
        checks ftp login works on remote host
        :param passwd: password
        :type: string
        :returns: bool
        """
        result = False
        kwargs = {
            "host": self.host,
            "user": self.user,
            "passwd": passwd,
            "timeout": 10,
        }
        with FTP(**kwargs) as ftp:
            result = True
        return result

    def which_os(self):
        """
        determine if host is JUNOS/EVO/*nix
        no support for Windows OS running OpenSSH
        :returns None:
        """
        logger.info("entering which_os()")
        evo = False
        bsd_version = float()
        sshd_version = float()
        self.ss.run("start shell", exitcode=False)
        result, stdout = self.ss.run("uname")
        if not result:
            err = "failed to determine remote host os, it must be *nix based"
            self.close(err_str=err)
        host_os = stdout[0].split("\n")[0].rstrip()
        if host_os == "Linux" and self.evo_os():
            evo = True
        else:
            junos, bsd_version, sshd_version = self.junos_os()
        logger.info(
            f"evo = {evo}, junos = {junos}, bsd_version = {bsd_version}, "
            f"sshd_version = {sshd_version}"
        )
        return junos, evo, bsd_version, sshd_version

    def evo_os(self):
        """
        determines if host is EVO
        :returns result: True if OS is EVO
        :type: boolean
        """
        logger.info("entering evo_os()")
        result, stdout = self.ss.run("test -e /usr/sbin/evo-pfemand")
        return result

    def junos_os(self):
        """
        determines if host is JUNOS
        :returns None:
        """
        logger.info("entering junos_os()")
        junos = False
        bsd_version = float()
        sshd_version = float()
        result, stdout = self.ss.run("uname -i")
        if not result:
            self.close(err_str="failed to determine remote host os")
        uname = stdout.split("\n")[1]
        if re.match(r"JUNIPER", uname):
            junos = True
            bsd_version = 6.0
            sshd_version = self.which_sshd()
        elif re.match(r"JNPR", uname):
            junos = True
            bsd_version = self.which_bsd()
            sshd_version = self.which_sshd()
        else:
            sshd_version = self.which_sshd()
        return junos, bsd_version, sshd_version

    def which_bsd(self):
        """
        determines the BSD version of JUNOS
        :returns None:
        """
        logger.info("entering which_bsd()")
        result, stdout = self.ss.run("uname -r")
        if not result:
            self.close(err_str="failed to determine remote bsd version")
        uname = stdout.split("\n")[1]
        bsd_version = float(uname.split("-")[1])
        return bsd_version

    def which_sshd(self):
        """
        determines the OpenSSH daemon version
        :returns None:
        """
        logger.info("entering which_sshd()")
        result, stdout = self.ss.run("sshd -v", exitcode=False)
        if not re.search(r"OpenSSH_", stdout):
            self.close(err_str="failed to determine remote openssh version")
        output = stdout.split("\n")[2]
        version = re.sub(r"OpenSSH_", "", output)
        sshd_version = float(version[0:3])
        return sshd_version

    def req_binaries(self, get_op=False, junos=False, evo=False):
        """
        ensures required binaries exist on remote host
        :returns None:
        """
        logger.info("entering req_binaries()")
        if not junos and not evo:
            if get_op:
                req_bins = ["dd", "ls", "df", "rm"]
            else:
                req_bins = ["cat", "ls", "df", "rm"]
            for req_bin in req_bins:
                result, stdout = self.ss.run(f"which {req_bin}")
                if not result:
                    self.close(
                        err_str=(
                            f"required binary '{req_bin}' is missing from remote host"
                        )
                    )

    def second_elem(self, elem):
        """
        used for key sort
        :returns: the 2nd part of an element
        """
        return elem[1]

    def req_sha_binaries(self, sha_hash):
        """
        ensures required binaries for sha hash creation exist on remote host
        :returns None:
        """
        logger.info("entering req_sha_binaries()")
        sha_bins = []
        sha_bin = None
        sha_len = None
        if sha_hash.get(512):
            bins = [("sha512sum", 512), ("sha512", 512), ("shasum", 512)]
            sha_bins.extend(bins)
        if sha_hash.get(384):
            bins = [("sha384sum", 384), ("sha384", 384), ("shasum", 384)]
            sha_bins.extend(bins)
        if sha_hash.get(256):
            bins = [("sha256sum", 256), ("sha256", 256), ("shasum", 256)]
            sha_bins.extend(bins)
        if sha_hash.get(224):
            bins = [("sha224sum", 224), ("sha224", 224), ("shasum", 224)]
            sha_bins.extend(bins)
        if sha_hash.get(1):
            bins = [("sha1sum", 1), ("sha1", 1), ("shasum", 1)]
            sha_bins.extend(bins)

        sha_bins = sorted(set(sha_bins), reverse=True, key=self.second_elem)
        logger.info(sha_bins)

        for req_bin in sha_bins:
            result, stdout = self.ss.run(f"which {req_bin[0]}")
            if result:
                sha_bin = req_bin[0]
                sha_len = req_bin[1]
                break
        if not sha_bin:
            self.close(
                err_str=(
                    "required binary used to generate a sha "
                    "hash on the remote host isn't found"
                )
            )
        return sha_bin, sha_len

    def close(self, err_str=None, config_rollback=True, hard_close=False):
        """
        Called when we want to exit the script
        attempts to delete the remote temp directory and close the TCP session
        If hard_close == False, contextmanager will rm the local temp dir
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
        if config_rollback and self.command_list:
            self.limits_rollback()
        print("closing device connection")
        self.ss.close()
        if hard_close:
            try:
                shutil.rmtree(self.local_tmpdir)
            except PermissionError:
                # windows can throw this error, silence it for now
                print(
                    f"{self.local_tmpdir} may still exist, please delete manually if so"
                )
            raise os._exit(1)
        else:
            raise SystemExit(1)

    def file_split_size(self, file_size, sshd_version, bsd_version, evo):
        """
        The chunk size depends on the python version, cpu count,
        the protocol used to copy, FreeBSD and OpenSSH version
        :returns split_size:
        :type int:
        :returns executor:
        :type concurrent.futures object:
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
            split_size = ceil(file_size / max_workers)
        elif max_workers <= 10:
            # 1 or 2 cpu cores, 5 or 10 workers will create 20-40 pids
            # no modulation required
            split_size = ceil(file_size / max_workers)
        else:
            # scp to FreeBSD 6 based junos creates 3 user processes per chunk
            # scp to FreeBSD 10+ based junos creates 2 user processes per chunk
            # +1 user process if openssh version is >= 7.4
            max_pids = 40
            if sshd_version >= 7.4 and bsd_version == 6.0:
                pid_count = 4
            elif sshd_version >= 7.4 and bsd_version >= 10.0:
                pid_count = 3
            elif bsd_version == 6.0:
                pid_count = 3
            elif bsd_version >= 10.0:
                pid_count = 2
            elif evo:
                pid_count = 3
            else:
                pid_count = 4
            max_workers = round(max_pids / pid_count)
            split_size = ceil(file_size / max_workers)

        # concurrent.futures.ThreadPoolExecutor can be a limiting factor
        # if using python < 3.5.3 the default max_workers is 5.
        # see https://github.com/python/cpython/blob/v3.5.2/Lib/asyncio/base_events.py
        # hence defining a custom executor to normalize max_workers across versions
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        logger.info(
            f"max_workers = {max_workers}, cpu_count = {cpu_count}, split_size = {split_size}"
        )
        return split_size, executor

    def mkdir_remote(self):
        """
        creates a tmp directory on the remote host
        :returns self.remote_tmpdir:
        :type string:
        """
        logger.info("entering mkdir_remote()")
        time_stamp = datetime.datetime.strftime(datetime.datetime.now(), "%y%m%d%H%M%S")
        if self.get_op:
            remote_tmpdir = f"/var/tmp/splitcopy_{self.remote_file}.{time_stamp}"
        else:
            remote_tmpdir = f"{self.remote_dir}/splitcopy_{self.remote_file}.{time_stamp}"
        result, stdout = self.ss.run(f"mkdir -p {remote_tmpdir}")
        if not result:
            err = (
                "unable to create the tmp directory on remote host."
                f"cmd output was:\n{stdout}"
            )
            self.close(err_str=err)
        self.rm_remote_tmp = True
        return remote_tmpdir

    def storage_check_remote(self, file_size, split_size):
        """
        checks whether there is enough storage space on remote node
        :returns None:
        """
        logger.info("entering storage_check_remote()")
        avail_blocks = 0
        print("checking remote storage...")
        result, stdout = self.ss.run(f"df -k {self.remote_dir}")
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
            err = "unable to determine available blocks on remote host"
            self.close(err_str=err)

        avail_bytes = int(avail_blocks) * 1024
        logger.info(f"remote filesystem available bytes is {avail_bytes}")
        if self.get_op:
            if file_size > avail_bytes:
                err = (
                    "not enough storage on remote host in /var/tmp.\nAvailable bytes "
                    f"({avail_bytes}) must be > the original file size "
                    f"({file_size}) because it has to store the file chunks"
                )
                self.close(err_str=err)
        else:
            if file_size + split_size > avail_bytes:
                err = (
                    f"not enough storage on remote host in {self.remote_dir}.\n"
                    f"Available bytes ({avail_bytes}) must be > "
                    f"the original file size ({file_size}) + largest chunk size "
                    f"({split_size})"
                )
                self.close(err_str=err)

    def storage_check_local(self, file_size):
        """
        checks whether there is enough storage space on local node
        :returns None:
        """
        logger.info("entering storage_check_local()")
        print("checking local storage...")
        local_tmpdir = tempfile.gettempdir()
        avail_bytes = shutil.disk_usage(local_tmpdir)[2]
        logger.info(f"local filesystem {local_tmpdir} available bytes is {avail_bytes}")
        if file_size > avail_bytes:
            err = (
                f"not enough storage on local host in temp dir {local_tmpdir}.\n"
                f"Available bytes ({avail_bytes}) must be > the original file size "
                f"({file_size}) because it has to store the file chunks"
            )
            self.close(err_str=err)

        if self.get_op:
            avail_bytes = shutil.disk_usage(self.local_dir)[2]
            logger.info(
                f"local filesystem {self.local_dir} available bytes is {avail_bytes}"
            )
            if file_size > avail_bytes:
                err = (
                    f"not enough storage on local host in {self.local_dir}.\n"
                    f"Available bytes ({avail_bytes}) must be > the "
                    f"original file size ({file_size}) because it has to "
                    "recombine the file chunks into a whole file"
                )
                self.close(err_str=err)

    @contextmanager
    def change_dir(self, cleanup=lambda: True):
        """
        cds into temp directory.
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
        """
        creates a temp directory
        defines how to delete directory upon script exit
        :returns None:
        """
        self.local_tmpdir = tempfile.mkdtemp()
        logger.info(self.local_tmpdir)

        def cleanup():
            """deletes temp dir"""
            shutil.rmtree(self.local_tmpdir)

        with self.change_dir(cleanup):
            yield self.local_tmpdir

    def return_tmpdir(self):
        return self.local_tmpdir

    def limit_check(self):
        """
        Checks the remote hosts /etc/inetd file to determine whether there are any
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
                f'cli -c "show configuration {stanza} | display set | no-more"'
            )
            cli_config += stdout
        for limit in limits:
            if cli_config and re.search(rf"{limit} [0-9]", cli_config) is not None:
                conf_list = cli_config.split("\r\n")
                for conf_statement in conf_list:
                    if re.search(rf"set .* {limit} [0-9]", conf_statement):
                        conf_line = re.sub(" [0-9]+$", "", conf_statement)
                        conf_line = re.sub("set", "deactivate", conf_line)
                        self.command_list.append(f"{conf_line};")
                    if re.search(rf"deactivate .* {limit}", conf_statement):
                        self.command_list.remove(f"{conf_line};")

        # if limits were configured, deactivate them
        if self.command_list:
            print("protocol rate-limit/connection-limit configuration found")
            logger.info(self.command_list)
            result, stdout = self.ss.run(
                f'cli -c "edit;{"".join(self.command_list)}commit and-quit"',
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
                    f"Error: failed to deactivate {self.copy_proto} connection-limit/rate-limit"
                    f"configuration. output was:\n{stdout}"
                )
                self.close(err_str=err)
            return self.command_list
        else:
            return None

    def limits_rollback(self):
        """
        revert config change made to remote host
        :returns None:
        """
        logger.info("entering limits_rollback()")
        rollback_cmds = "".join(self.command_list)
        rollback_cmds = re.sub("deactivate", "activate", rollback_cmds)
        result, stdout = self.ss.run(
            f'cli -c "edit;{rollback_cmds}commit and-quit"',
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
                f"configuration changes made. output was:\n{stdout}"
            )

    def remote_cleanup(self, remote_dir=None, remote_file=None, silent=False):
        """
        delete tmp directory on remote host
        :param silent: determines whether we announce the dir deletion
        :type: bool
        :returns None:
        """
        if remote_dir:
            self.remote_dir = remote_dir
        if remote_file:
            self.remote_file = remote_file
        if not silent:
            print("deleting remote tmp directory...")
        if self.remote_tmpdir is None:
            if self.get_op:
                self.ss.run(f"rm -rf /var/tmp/splitcopy_{self.remote_file}.*")
            else:
                self.ss.run(f"rm -rf {self.remote_dir}/splitcopy_{self.remote_file}.*")
        else:
            result, stdout = self.ss.run(f"rm -rf {self.remote_tmpdir}")
            if not result and not silent:
                print(
                    f"unable to delete the tmp directory {self.remote_tmpdir} on remote host, "
                    "delete it manually"
                )
        self.rm_remote_tmp = False
