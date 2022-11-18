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
import getpass
import logging
import os
import re
import shutil
import socket
import sys
import tempfile
import traceback
from contextlib import contextmanager
from ftplib import error_perm, error_proto, error_reply, error_temp
from math import ceil
from socket import timeout as socket_timeout

# 3rd party
from paramiko.ssh_exception import SSHException

# local modules
from splitcopy.ftp import FTP

logger = logging.getLogger(__name__)


def pad_string(text):
    """pads a given string to the terminal width
    :param text:
    :type string:
    :return padded_string:
    :type string
    """
    term_width = shutil.get_terminal_size()[0]
    padding = " " * (term_width - len(text))
    padded_string = f"{text}{padding}"
    return padded_string


class SplitCopyShared:
    """class containing functions used by both SplitCopyGet
    and SplitCopyPut classes
    """

    def __init__(self, **kwargs):
        """Initialise the class"""
        self.user = kwargs.get("user")
        self.host = kwargs.get("host")
        self.passwd = kwargs.get("passwd")
        self.ssh_key = kwargs.get("ssh_key")
        self.ssh_port = kwargs.get("ssh_port")
        self.local_dir = kwargs.get("local_dir")
        self.copy_op = kwargs.get("copy_op")
        self.remote_dir = ""
        self.remote_file = ""
        self.command_list = []
        self.rm_remote_tmp = False
        self.local_tmpdir = None
        self.remote_tmpdir = None
        self.sshshell = None
        self.use_shell = False
        self.hard_close = False

    def connect(self, ssh_lib, **ssh_kwargs):
        """open an ssh session to a remote host
        :param ssh_lib:
        :type class:
        :param ssh_kwargs:
        :type dict:
        :return self.sshshell:
        :type paramiko.SSHShell object:
        :returm ssh_kwargs:
        :type dict:
        """
        logger.info("entering connect()")
        try:
            self.sshshell = ssh_lib(**ssh_kwargs)
            self.sshshell.socket_open()
            self.sshshell.transport_open()
            self.sshshell.set_transport_keepalive()
            if self.sshshell.main_thread_auth():
                ssh_kwargs = self.sshshell.kwargs
                logger.debug(f"ssh_kwargs returned are: {ssh_kwargs}")
            else:
                raise SSHException("authentication failed")
        except Exception as err:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            if self.sshshell is not None:
                self.sshshell.close()
            raise SystemExit(
                f"{err.__class__.__name__} returned while connecting via ssh: {str(err)}"
            )
        return self.sshshell, ssh_kwargs

    def which_proto(self, copy_proto):
        """determines which protocol will be used for the transfer.
        If FTP is selected as protocol, verify that authentication works
        :param copy_proto:
        :type string:
        :return copy_proto:
        :type string:
        :return passwd:
        :type string:
        """
        logger.info("entering which_proto()")
        passwd = self.sshshell.kwargs["password"]
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
                print("ftp auth timed out, switching to scp for transfer")

            if not result:
                copy_proto = "scp"
        else:
            copy_proto = "scp"

        logger.info(f"copy_proto == {copy_proto}")
        return copy_proto, passwd

    def ftp_port_check(self, socket_lib=socket):
        """checks whether the ftp port is open
        :return result:
        :type bool:
        """
        logger.info("entering ftp_port_check()")
        result = False
        print("attempting FTP authentication...")
        try:
            socket_lib.create_connection((self.host, 21), 10)
            logger.info("ftp port is open")
            result = True
        except socket_timeout:
            print("ftp socket timed out, switching to scp for transfer")
        except ConnectionRefusedError:
            print("ftp connection refused, switching to scp for transfer")

        return result

    def ftp_login_check(self, passwd, ftp_lib=FTP):
        """verifies ftp authentication on remote host
        :param passwd:
        :type string:
        :return result:
        :type bool:
        """
        logger.info("entering ftp_login_check()")
        result = False
        kwargs = {
            "host": self.host,
            "user": self.user,
            "passwd": passwd,
            "timeout": 10,
        }
        with ftp_lib(**kwargs) as ftp:
            result = True
        return result

    def juniper_cli_check(self):
        """determines whether exec cmd is run on a juniper cli
        :returns bool:
        """
        logger.info("entering juniper_cli_check()")
        result, stdout = self.ssh_cmd("uname")
        if result and stdout == "\nerror: unknown command: uname":
            # this is junos or evo CLI. exit code is always 0.
            self.use_shell = True
        elif result:
            pass
        else:
            err = "cmd 'uname' failed on remote host, it must be *nix based"
            self.close(err_str=err)
        return self.use_shell

    def which_os(self):
        """determines if host is JUNOS or EVO
        no support for remote Windows OS running OpenSSH
        :return junos:
        :type bool:
        :return evo:
        :type bool:
        :return bsd_version:
        :type float:
        :return sshd_version:
        :type float:
        """
        logger.info("entering which_os()")
        junos = False
        evo = False
        bsd_version = float()
        sshd_version = float()
        result, stdout = self.ssh_cmd("uname")
        if not result:
            err = "cmd 'uname' failed on remote host, it must be *nix based"
            self.close(err_str=err)
        if self.use_shell:
            host_os = stdout.split("\n")[1].rstrip()
        else:
            host_os = stdout
        if host_os == "Linux" and self.evo_os():
            evo = True
        elif host_os == "JUNOS":
            junos = True
            bsd_version = 6.3
            sshd_version = self.which_sshd()
        elif host_os == "FreeBSD" and self.junos_os():
            junos = True
            bsd_version = self.which_bsd()
            sshd_version = self.which_sshd()
        logger.info(
            f"evo = {evo}, "
            f"junos = {junos}, "
            f"bsd_version = {bsd_version}, "
            f"sshd_version = {sshd_version}"
        )
        return junos, evo, bsd_version, sshd_version

    def evo_os(self):
        """determines if host is running EVO
        :return result:
        :type bool:
        """
        logger.info("entering evo_os()")
        result, stdout = self.ssh_cmd("test -e /usr/sbin/evo-pfemand")
        return result

    def junos_os(self):
        """determines if host is running JUNOS
        :return result:
        :type bool:
        """
        logger.info("entering junos_os()")
        result, stdout = self.ssh_cmd("uname -i | egrep 'JUNIPER|JNPR'")
        return result

    def which_bsd(self):
        """determines the BSD version of JUNOS
        :return bsd_version:
        :type float:
        """
        logger.info("entering which_bsd()")
        result, stdout = self.ssh_cmd("uname -r")
        if not result:
            self.close(err_str="failed to determine remote bsd version")
        if self.use_shell:
            uname = stdout.split("\n")[1]
        else:
            uname = stdout
        bsd_version = float(uname.split("-")[1])
        return bsd_version

    def which_sshd(self):
        """determines the OpenSSH daemon version
        :return sshd_version:
        :type float
        """
        logger.info("entering which_sshd()")
        result, stdout = self.ssh_cmd("sshd -v", exitcode=False, combine=True)
        if self.use_shell:
            if not re.search(r"OpenSSH_", stdout):
                self.close(err_str="failed to determine remote openssh version")
            output = stdout.split("\n")[2]
        else:
            if not re.search(r"OpenSSH_", stdout):
                self.close(err_str="failed to determine remote openssh version")
            output = stdout.split("\n")[1]
        version = re.sub(r"OpenSSH_", "", output)
        sshd_version = float(version[0:3])
        return sshd_version

    def req_binaries(self, junos=False, evo=False):
        """ensures required binaries exist on remote host
        :param junos:
        :type bool:
        :param evo:
        :type bool:
        :returns None:
        """
        logger.info("entering req_binaries()")
        if not junos and not evo:
            if self.copy_op == "get":
                req_bins = "dd ls df rm"
            else:
                req_bins = "cat ls df rm"
            result, stdout = self.ssh_cmd(f"which {req_bins}")
            if not result:
                self.close(
                    err_str=(
                        f"one or more required binaries [{req_bins}] is missing from remote host"
                    )
                )

    def req_sha_binaries(self, sha_hash):
        """ensures required binaries for sha hash creation exist on remote host
        :param sha_hash:
        :type hash:
        :return sha_bin:
        :type string:
        :return sha_len:
        :type int:
        """
        logger.info("entering req_sha_binaries()")
        sha_bins = []
        sha_bin = ""
        sha_len = 0
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

        sha_bins = sorted(set(sha_bins), reverse=True, key=lambda x: (x[1], x[0]))
        logger.info(sha_bins)

        for req_bin in sha_bins:
            result, stdout = self.ssh_cmd(f"which {req_bin[0]}")
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

    def close(self, err_str=None, config_rollback=True):
        """called when we want to exit the script
        attempts to delete the remote temp directory and close the TCP session
        If hard_close == False, contextmanager will rm the local temp dir
        If not, we must delete it manually
        :param err_str:
        :type: string:
        :param config_rollback:
        :type bool:
        :raises SystemExit: terminates the script gracefully
        :raises os._exit: terminates the script immediately (even asyncio loop)
        """
        logger.info("entering close()")
        if err_str:
            print(err_str)
        if (
            self.use_shell
            and self.sshshell._chan is not None
            and not self.sshshell._chan.closed
            or not self.use_shell
            and self.sshshell._transport is not None
            and self.sshshell._transport.active
        ):
            if self.rm_remote_tmp:
                self.remote_cleanup()
            if config_rollback and self.command_list:
                self.limits_rollback()
            print(f"\r{pad_string('closing device connection')}")
            self.sshshell.close()
        if self.hard_close:
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

    def file_split_size(self, file_size, sshd_version, bsd_version, evo, copy_proto):
        """determines the optimal chunk size. This depends on the python
        version, cpu count, the protocol used and the FreeBSD/OpenSSH versions
        :returns split_size:
        :type int:
        :returns executor:
        :type concurrent.futures object:
        """
        logger.info("entering file_split_size()")

        cpu_count = 1
        try:
            cpu_count = os.cpu_count()
        except NotImplementedError:
            pass
        max_workers = min(32, cpu_count * 5)

        # each uid can have max of 64 processes
        # modulate worker count to consume no more than 40 pids
        if copy_proto == "ftp":
            # ftp creates 1 user process per chunk, no modulation required
            split_size = ceil(file_size / max_workers)
        elif max_workers == 5:
            # 1 cpu core, 5 workers will create <= 20 pids
            # no modulation required
            split_size = ceil(file_size / max_workers)
        else:
            # scp to FreeBSD 6 based junos creates 3 user processes per chunk
            # scp to FreeBSD 10+ based junos creates 2 user processes per chunk
            # +1 user process if openssh version is >= 7.4
            pid_count = 0
            max_pids = 40
            if sshd_version >= 7.4 and bsd_version == 6.3:
                pid_count = 4
            elif sshd_version >= 7.4 and bsd_version >= 10.0:
                pid_count = 3
            elif bsd_version == 6.3:
                pid_count = 3
            elif bsd_version >= 10.0:
                pid_count = 2
            elif evo:
                pid_count = 3

            if pid_count:
                max_workers = round(max_pids / pid_count)
            else:
                # sshd config defaults
                # Maxsessions = 10, MaxStartups = 10:30:100
                # value here should not hit these limits
                max_workers = 5

            split_size = ceil(file_size / max_workers)

        # concurrent.futures.ThreadPoolExecutor can be a limiting factor
        # if using python < 3.5.3 the default max_workers is 5.
        # see https://github.com/python/cpython/blob/v3.5.2/Lib/asyncio/base_events.py
        # hence defining a custom executor to normalize max_workers across versions
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="ThreadPoolWorker"
        )
        logger.info(
            f"max_workers = {max_workers}, cpu_count = {cpu_count}, split_size = {split_size}"
        )
        return split_size, executor

    def mkdir_remote(self, remote_dir, remote_file):
        """creates a tmp directory on the remote host
        :param remote_dir:
        :type string:
        :param remote_file:
        :type string:
        :returns remote_tmpdir:
        :type string:
        """
        logger.info("entering mkdir_remote()")
        time_stamp = datetime.datetime.strftime(datetime.datetime.now(), "%y%m%d%H%M%S")
        self.remote_tmpdir = f"{remote_dir}/splitcopy_{remote_file}.{time_stamp}"
        result, stdout = self.ssh_cmd(f"mkdir -p {self.remote_tmpdir}")
        if not result:
            err = f"unable to create the tmp directory {self.remote_tmpdir} on remote host"
            self.close(err_str=err)
        self.rm_remote_tmp = True
        return self.remote_tmpdir

    def storage_check_remote(self, file_size, split_size, remote_dir):
        """checks whether there is enough storage space on remote node
        :param file_size:
        :type int:
        :param split_size:
        :type int:
        :param remote_dir:
        :type string:
        :returns None:
        """
        logger.info("entering storage_check_remote()")
        avail_blocks = 0
        print("checking remote storage...")
        result, stdout = self.ssh_cmd(f"df -k {remote_dir}")
        if not result:
            self.close(err_str="failed to determine remote disk space available")
        try:
            fs_blocks = re.search(r" ([0-9]+) +([0-9]+) +(-?[0-9]+) +", stdout)
            total_blocks = int(fs_blocks.group(1))
            used_blocks = int(fs_blocks.group(2))
            avail_blocks = int(fs_blocks.group(3))
        except AttributeError:
            err = "unable to determine available storage on remote host"
            self.close(err_str=err)

        if avail_blocks < 0:
            reserved_blocks_percent = 100 - round(
                100 / total_blocks * (used_blocks + avail_blocks)
            )
            reserved_blocks_threshold = used_blocks + avail_blocks
            reserved_blocks_count = total_blocks - (used_blocks + avail_blocks)
            err = (
                f"not enough available storage on remote host in {remote_dir}\n"
                f"{reserved_blocks_count} / {reserved_blocks_percent}% of 1024-byte blocks "
                "are reserved and may only be allocated by privileged processes\n"
                f"used blocks: {used_blocks} is > than the threshold for reserved blocks: {reserved_blocks_threshold}"
            )
            self.close(err_str=err)

        avail_bytes = avail_blocks * 1024
        logger.info(f"remote filesystem available bytes is {avail_bytes}")
        if self.copy_op == "get":
            if file_size > avail_bytes:
                err = (
                    f"not enough storage on remote host in {remote_dir}\n"
                    f"available bytes ({avail_bytes}) must be >= the original file size "
                    f"({file_size}) because it has to store the file chunks"
                )
                self.close(err_str=err)
        else:
            if file_size + split_size > avail_bytes:
                err = (
                    f"not enough storage on remote host in {remote_dir}\n"
                    f"available bytes ({avail_bytes}) must be > "
                    f"the original file size ({file_size}) + largest chunk size "
                    f"({split_size})"
                )
                self.close(err_str=err)

    def storage_check_local(self, file_size):
        """checks whether there is enough storage space on local node
        :param file_size:
        :type int:
        :return None:
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

        if self.copy_op == "get":
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
        """cds into temp directory.
        Upon script exit, changes back to original directory
        and calls cleanup() to delete the temp directory
        :param cleanup:
        :type function:
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
        """creates a temp directory, defines how to delete directory upon script exit
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
        """Function to return class variable
        :return self.local_tmpdir:
        :type string:
        """
        return self.local_tmpdir

    def find_configured_limits(self, config_stanzas, limits):
        """Function that retrieves any configuration stazas that implement
        rate/connection limits.
        It is faster to perform grep on the router, than to transfer
        potentially huge amounts of text and do it locally
        :param config_stanzas:
        :type list:
        :param limits:
        :type list:
        :return cli_config:
        :type string:
        """
        logger.info("entering find_configured_limits()")
        cli_config = ""
        limits_str = "|".join(limits)
        for stanza in config_stanzas:
            result, stdout = self.ssh_cmd(
                f"cli -c 'show configuration {stanza} | display set | "
                f'grep "{limits_str}" | no-more\'',
            )
            cli_config += stdout
        return cli_config

    def limit_check(self, copy_proto):
        """Function that checks the remote junos/evo hosts configuration to
        determine whether there are any ftp or ssh connection/rate limits defined.
        If found, these configuration lines will be deactivated
        :param copy_proto:
        :type string:
        :return self.command_list:
        :type list:
        """
        logger.info("entering limit_check()")
        config_stanzas = ["groups", "system services", "system login"]
        retry_options = "system login retry-options"
        limits = ["services ssh connection-limit", "services ssh rate-limit"]
        if copy_proto == "ftp":
            limits.append("services ftp connection-limit")
            limits.append("services ftp rate-limit")
        print("checking router configuration... ")
        cli_config = self.find_configured_limits(config_stanzas, limits)

        for limit in limits:
            re_limit_multiline = re.compile(rf"^set .*{limit} [0-9]", re.MULTILINE)
            conf_list_limits = re.findall(re_limit_multiline, cli_config)
            for conf_statement in conf_list_limits:
                conf_line = re.sub(" [0-9]+$", "", conf_statement)
                conf_line = re.sub(r"^set", "deactivate", conf_line)
                self.command_list.append(f"{conf_line};")
        re_retry_multiline = re.compile(rf"^set .*{retry_options}", re.MULTILINE)
        conf_list_retry_options = re.findall(re_retry_multiline, cli_config)
        for conf_statement in conf_list_retry_options:
            conf_line = re.match(rf"(set .*{retry_options})", conf_statement).group(1)
            conf_line = re.sub(r"^set", "deactivate", conf_line)
            self.command_list.append(f"{conf_line};")

        # if limits were configured, deactivate them
        if self.command_list:
            print("rate-limit/connection-limit/login retry-options configuration found")
            logger.info(self.command_list)
            result, stdout = self.ssh_cmd(
                f'cli -c "edit;{"".join(self.command_list)}commit and-quit"',
                exitcode=False,
                timeout=60,
            )
            # cli always returns true so can't use exitcode
            if re.search(r"commit complete\r\nExiting configuration mode", stdout):
                print("configuration has been modified. deactivated the relevant lines")
                self.ssh_cmd(
                    "logger 'splitcopy has made the following config changes: "
                    f"{''.join(self.command_list)}'",
                    exitcode=False,
                )
            else:
                err = (
                    "Error: failed to deactivate connection-limit/rate-limit/login retry-options"
                    f"configuration. output was:\n{stdout}"
                )
                self.close(err_str=err)
        return self.command_list

    def limits_rollback(self):
        """Function to revert config changes made to remote host
        :returns None:
        """
        logger.info("entering limits_rollback()")
        rollback_cmds = "".join(self.command_list)
        rollback_cmds = re.sub("deactivate", "activate", rollback_cmds)
        result, stdout = self.ssh_cmd(
            f'cli -c "edit;{rollback_cmds}commit and-quit"',
            exitcode=False,
            timeout=60,
        )
        # cli always returns true so can't use exitcode
        if re.search(r"commit complete\r\nExiting configuration mode", stdout):
            print("configuration changes made have been reverted")
            self.ssh_cmd(
                "logger 'splitcopy has reverted config changes'",
                exitcode=False,
            )
        else:
            print(
                "Error: failed to revert the configuration changes. "
                f"output was:\n{stdout}"
            )

    def remote_cleanup(self, remote_dir=None, remote_file=None, silent=False):
        """Function that deletes the tmp directory on remote host
        :param remote_dir:
        :type string:
        :param remote_file:
        :type string:
        :param silent: determines whether we announce the dir deletion
        :type: bool
        :return None:
        """
        logger.info("entering remote_cleanup()")
        result = False
        if remote_dir:
            self.remote_dir = remote_dir
        if remote_file:
            self.remote_file = remote_file
        if not silent:
            print(f"\r{pad_string('deleting remote tmp directory...')}")
        if self.remote_tmpdir is None:
            if self.copy_op == "get":
                result, stdout = self.ssh_cmd(
                    f"rm -rf /var/tmp/splitcopy_{self.remote_file}.*"
                )
            else:
                result, stdout = self.ssh_cmd(
                    f"rm -rf {self.remote_dir}/splitcopy_{self.remote_file}.*"
                )
        else:
            result, stdout = self.ssh_cmd(f"rm -rf {self.remote_tmpdir}")
            if not result and not silent:
                print(
                    f"unable to delete the tmp directory {self.remote_tmpdir} on remote host, "
                    "delete it manually"
                )
        self.rm_remote_tmp = False
        return result

    def enter_shell(self):
        """in order to drop into shell from cli mode, a pty and interactive shell are required
        :return result:
        :type bool:
        """
        try:
            # request a channel
            self.sshshell.channel_open()
            # request a pty and an interactive shell session
            self.sshshell.invoke_shell()
            # remove the welcome message from the socket
            self.sshshell.stdout_read(timeout=30)
        except SSHException as err:
            self.close(err_str=err)
        # enter shell mode
        result, stdout = self.ssh_cmd("start shell", exitcode=False)
        return result

    def ssh_cmd(
        self, cmd, timeout=30, exitcode=True, combine=False, retry=True, count=0
    ):
        """wrapper around functions that send a cmd to a remote host.
        which function gets called depends on whether an interactive shell is in use.
        if exitcode is True will check its exit status
        :param cmd: cmd to run on remote host
        :type string:
        :param timeout: amount of time before timeout is raised
        :type float:
        :param exitcode: toggles whether to check for exit status or not
        :type bool:
        :return result: whether successful or not
        :type bool:
        :return stdout: the output of the command
        :type string:
        """
        result = False
        stdout = ""
        logger.debug(cmd)
        try:
            if self.use_shell:
                result, stdout = self.sshshell.shell_cmd(cmd, timeout, exitcode)
            else:
                result, stdout = self.sshshell.exec_cmd(cmd, timeout, combine)
            logger.debug(result)
        except TimeoutError:
            count += 1
            timeout = timeout * 2
            if self.use_shell:
                # channel is now unusable, close it and open a new channel
                self.sshshell.close_channel()
                self.enter_shell()
            if retry:
                if count == 3:
                    self.close(err_str="cmd timed out")
                print(
                    f"cmd '{cmd}' timed out, retrying with a timeout of {timeout} secs"
                )
                result, stdout = self.ssh_cmd(
                    cmd,
                    timeout=timeout,
                    exitcode=exitcode,
                    combine=combine,
                    count=count,
                )
        except SSHException as err:
            self.close(err_str=f"ssh exception '{err}' raised while running '{cmd}'")
        except OSError as err:
            self.close(err_str=f"OSError exception raised while running '{cmd}'")
        return result, stdout
