#!/usr/bin/env python3
""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.

    Splits a given file into chunks in a tmp directory,
    copies these chunks to a junos host and recombines them.

    Requires 'system services ssh' configuration on remote host.
    If using ftp to copy files (default) then 'system services ftp' is also
    required.

    Requires python 3.4 to run, 3.5 is faster, 3.6 is faster again

    install required module via:
        pip3 install junos-eznc

    Script overhead includes authentication, sha1 generation/comparison,
    disk space check, file split and join.
    It will be slower than normal ftp/scp for small files as a result.

    Because it opens a number of simultaneous connections,
    if the router has connection/rate limits configured like this:

    system {
        services {
            ssh { # or ftp
                connection-limit 10;
                rate-limit 10;
            }
        }
    }

    The script will deactivate these limits so it can proceed
"""

import sys

if sys.version_info < (3, 4):
    raise RuntimeError("This package requires Python 3.4+")
import asyncio
import argparse
import os
import datetime
import fnmatch
import functools
import getpass
import re
import shutil
import tempfile
import signal
import subprocess
import warnings
import scp
from contextlib import contextmanager
from paramiko.ssh_exception import SSHException
from paramiko.ssh_exception import ChannelException
from paramiko.ssh_exception import BadHostKeyException
from paramiko.ssh_exception import AuthenticationException
from paramiko.ssh_exception import BadAuthenticationType
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
    parser.add_argument("filepath", help="Path to filename to work on")
    parser.add_argument("host", help="remote host to connect to")
    parser.add_argument("user", help="user to authenticate on remote host")
    parser.add_argument(
        "-p", "--password", nargs=1, help="password to authenticate on remote host"
    )
    parser.add_argument(
        "-d", "--remotedir", nargs=1, help="remote host directory to put file"
    )
    parser.add_argument(
        "-s",
        "--scp",
        action="store_const",
        const="scp",
        help="use scp to copy files instead of ftp",
    )
    args = parser.parse_args()

    if not args.user:
        parser.error("must specify a username")

    if not args.host:
        parser.error("must specify a remote host")

    host = args.host
    user = args.user

    if not os.path.isfile(args.filepath):
        raise SystemExit(
            "source file {} does not exist - cannot proceed".format(args.filepath)
        )

    if not args.password:
        password = getpass.getpass(prompt="Password: ", stream=None)
    else:
        password = args.password[0]

    if args.remotedir:
        remote_dir = args.remotedir[0]
    else:
        remote_dir = "/var/tmp"

    if re.search("/", args.filepath):
        file_name = args.filepath.rsplit("/", 1)[1]
    else:
        file_name = args.filepath

    file_path = os.path.abspath(args.filepath)
    file_size = os.path.getsize(file_path)
    start_time = datetime.datetime.now()

    print("checking remote port(s) are open...")
    try:
        if not port_check(host, "22"):
            raise SystemExit("port 22 isn't open on remote host, can't proceed")
    except subprocess.TimeoutExpired:
        raise SystemExit(
            "ssh port check timed out after 10 seconds, "
            "is the host reachable and ssh enabled?"
        )
    except subprocess.SubprocessError as err:
        raise SystemExit(
            "an error occurred during remote ssh port check, "
            "the error was:\n{}".format(err)
        )

    if args.scp:
        copy_proto = "scp"
        print("using SCP for file transfer")
    else:
        try:
            if port_check(host, "21"):
                copy_proto = "ftp"
                print("using FTP for file transfer")
            else:
                copy_proto = "scp"
                print("using SCP for file transfer")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            copy_proto = "scp"
            print("using SCP for file transfer")
            pass

    splitcopy = SPLITCOPY(
        host, user, password, remote_dir, file_name, file_path, file_size, copy_proto
    )

    # connect to host
    loop_start, loop_end = splitcopy.connect()

    # and we are done...
    end_time = datetime.datetime.now()
    time_delta = end_time - start_time
    transfer_delta = loop_end - loop_start
    print("data transfer = {}\ntotal runtime = {}".format(transfer_delta, time_delta))


def port_check(host, port):
    """ checks if a port is open on remote host
    Args:
        host(str) - host to connect to
        port(str) - port to connect to
    Returns:
        (bool) True if port is open, False if port is closed
    Raises:
        subprocess.TimeoutExpired - the subprocess timed out
        subprocess.SubprocessError - the subprocess returned an error
    """
    try:
        if subprocess.call(
            ["nc", "-z", host, port],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        ):
            return False
        else:
            return True
    except subprocess.TimeoutExpired:
        raise
    except subprocess.SubprocessError:
        raise


class SPLITCOPY(object):
    """ class docstring
    """

    def __init__(
        self,
        host,
        user,
        password,
        remote_dir,
        file_name,
        file_path,
        file_size,
        copy_proto,
    ):
        """ Initialise the SPLITCOPY class
        """
        self.host = host
        self.user = user
        self.password = password
        self.remote_dir = remote_dir
        self.file_name = file_name
        self.file_path = file_path
        self.file_size = file_size
        self.copy_proto = copy_proto

    def connect(self):
        """ initiates the connection to the remote host
            Args:
                self - class variables inherited from __init__
            Returns:
                loop_start(obj) - datetime
                loop_end(obj) - datetime
            Raises:
                SystemExit upon connection errors
        """
        try:
            self.dev = Device(host=self.host, user=self.user, passwd=self.password)
            with StartShell(self.dev) as self.start_shell:
                # cleanup previous remote tmp directory if found
                self.remote_cleanup(True)

                # confirm remote storage is sufficient
                self.storage_check()

                # get/create sha1 for local file
                self.sha1_check()

                with self.tempdir():
                    # split file into chunks
                    self.split_file()

                    # add chunk names to a list
                    sfiles = []
                    for sfile in os.listdir("."):
                        if fnmatch.fnmatch(sfile, "{}*".format(self.file_name)):
                            sfiles.append(sfile)

                    # begin pre transfer checks, check if remote directory exists
                    self.start_shell.run("test -d {}".format(self.remote_dir))
                    if not self.start_shell.last_ok:
                        self.close(
                            err_str="remote directory specified does not exist",
                            not_remote=True,
                        )

                    # end of pre transfer checks, create tmp directory
                    self.start_shell.run(
                        "mkdir {}/splitcopy_{}".format(self.remote_dir, self.file_name)
                    )
                    if not self.start_shell.last_ok:
                        self.close(
                            err_str="unable to create the tmp directory on remote host",
                            not_remote=True,
                        )

                    # begin connection/rate limit check and transfer process
                    try:
                        self.limit_check()
                    except StartShellFail as err:
                        self.close(err_str=err)

                    if self.copy_proto == "ftp":
                        kwargs = {"callback": UploadProgress(self.file_size).handle}
                    else:
                        kwargs = {"progress": True, "socket_timeout": 30.0}

                    # copy files to remote host
                    loop_start = datetime.datetime.now()
                    loop = asyncio.get_event_loop()
                    self.tasks = []
                    for sfile in sfiles:
                        task = loop.run_in_executor(
                            None, functools.partial(self.put_files, sfile, **kwargs)
                        )
                        self.tasks.append(task)
                    loop.add_signal_handler(signal.SIGPIPE, self.signal_bail)
                    print("starting transfer...")
                    try:
                        loop.run_until_complete(asyncio.gather(*self.tasks))
                    except scp.SCPException as err:
                        self.close(
                            err_str="an scp error occurred, the error was {}".format(
                                err
                            ),
                            hard=True,
                        )
                    except KeyboardInterrupt:
                        self.close(hard=True)
                    except:
                        self.close(
                            err_str="an error occurred while copying the files to the "
                            "remote host, please retry",
                            hard=True,
                        )
                    finally:
                        loop.close()

                print("transfer complete")
                loop_end = datetime.datetime.now()

                # combine chunks
                try:
                    self.join_files()
                except StartShellFail as err:
                    self.close(err_str=err)

                # remove remote tmp dir
                self.remote_cleanup()

                # generate a sha1 for the combined file, compare to sha1 of src
                self.remote_sha1()

        except TimeoutError:
            raise SystemExit("ssh connection attempt timed out")
        except BadAuthenticationType:
            raise SystemExit("authentication type used isn't allowed by the host")
        except AuthenticationException:
            raise SystemExit("ssh authentication failed")
        except BadHostKeyException:
            raise SystemExit(
                "host key verification failed. delete the host key in "
                "~/.ssh/known_hosts and retry"
            )
        except ChannelException as err:
            raise SystemExit(
                "an attempt to open a new ssh channel failed. "
                " error code returned was:\n{}".format(err)
            )
        except SSHException as err:
            raise SystemExit("an ssh error occurred, the error was {}".format(err))
        except KeyboardInterrupt:
            raise SystemExit(1)

        self.dev.close()
        return loop_start, loop_end

    def signal_bail(self):
        """ if a signal is recevied while copying files to host we must quit
            as file cannot be recombined.
            Would be better if we could retry the failed chunk... WIP
            Args:
                self - class variables inherited from __init__
            Returns:
                None
            Raises:
                None
        """
        err = "signal received, transfer has failed - please retry"
        self.close(err_str=err, hard=True)


    def close(self, err_str=None, hard=False, not_remote=False, not_local=False):
        """ Called when we want to exit the script
            attempts to delete the remote temp directory and close the TCP session
            If hard == False, contextmanager will delete the local temp directory
            If not, we must delete it manually
            Args:
                self - class variables inherited from __init__
                err_str(str) - error description
                hard(bool) - determines whether we exit gracefully or not
                not_remote(bool) - skip remote tmp directory deletion or not
                not_local(boot) - skip local tmp directory deletion or not
            Returns:
                None
            Raises either:
                SystemExit - terminates the script gracefully
                os._exit - terminates the script immediately (even asychio loop)
        """
        if err_str:
            print(err_str)
        if not not_remote:
            self.remote_cleanup()
        print("closing device connection")
        self.dev.close()
        if hard and not_local:
            raise os._exit(1)
        elif hard:
            shutil.rmtree(self.local_tmpdir)
            raise os._exit(1)
        else:
            raise SystemExit(1)


    def join_files(self):
        """ concatenates the file chunks into one file
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            StartShellFail - remote shell cmd failed or timed out
        """
        print("joining files...")
        self.start_shell.run(
            "cat {}/splitcopy_{}/* > {}/{}".format(
                self.remote_dir, self.file_name, self.remote_dir, self.file_name
            ),
            timeout=600,
        )
        if not self.start_shell.last_ok:
            raise StartShellFail("failed to combine chunks on remote host")


    def remote_sha1(self):
        """ creates a sha1 hash for the newly combined file on the remote host
            compares against local sha1
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        print("generating remote sha1...")
        self.start_shell.run("ls {}/{}".format(self.remote_dir, self.file_name))
        if not self.start_shell.last_ok:
            err=(
                "file {}:{}/{} not found! please retry".format(
                    self.host, self.remote_dir, self.file_name
                )
            )
            self.close(err_str=err, not_remote=True)
        sha1_tuple = self.start_shell.run(
            "sha1 {}/{}".format(self.remote_dir, self.file_name), timeout=300
        )
        if not self.start_shell.last_ok:
            print(
                "remote sha1 generation failed or timed out, "
                'manually check the output of "sha1 <file>" and '
                "compare against {}".format(self.orig_sha1)
            )
            return
        new_sha1 = sha1_tuple[1].split("\n")[1].split()[3].rstrip()
        if self.orig_sha1 == new_sha1:
            print(
                "local and remote sha1 match\nfile has been "
                "successfully copied to {}:{}/{}".format(
                    self.host, self.remote_dir, self.file_name
                )
            )
        else:
            err=("file has been copied to {}:{}/{}, but the "
                "local and remote sha1 do not match - "
                "please retry".format(self.host, self.remote_dir, self.file_name)
            )
            self.close(err_str=err, not_remote=True)


    def split_file(self):
        """ splits file into chunks. The chunk size varies depending on the
            protocol used to copy, and the FreeBSD version
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        verstring = None
        if self.copy_proto == "ftp":
            split_size = str(divmod(self.file_size, 40)[0])
        else:
            # check if JUNOS running BSD10+
            # scp to FreeBSD 6 based junos creates 3 processes per chunk
            # scp to FreeBSD 10+ based junos creates 2 processes per chunk
            # each uid can have max of 64 processes
            # values here should leave ~24 processes headroom
            ver = self.start_shell.run("uname -i")
            if self.start_shell.last_ok:
                verstring = ver[1].split("\n")[1].rstrip()

            if re.match(r"JNPR", verstring):
                split_size = str(divmod(self.file_size, 20)[0])
            else:
                split_size = str(divmod(self.file_size, 13)[0])
        print("splitting file...")
        try:
            subprocess.call(
                ["split", "-b", split_size, self.file_path, self.file_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            self.close(
                err_str="local file splitting operation timed out after 10 mins",
                not_remote=True,
            )
        except subprocess.SubprocessError as err:
            err_str=(
                "an error occurred while splitting the file, "
                "the error was:\n{}".format(err)
            )
            self.close(err_str, not_remote=True)


    def sha1_check(self):
        """ checks whether a sha1 already exists for the file
            if not creates one
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        if os.path.isfile(self.file_path + ".sha1"):
            sha1file = open(file_path + ".sha1", "r")
            self.orig_sha1 = sha1file.read().rstrip()
        else:
            print("sha1 not found, generating sha1...")
            try:
                sha1_str = subprocess.check_output(["shasum", self.file_path]).decode()
            except subprocess.SubprocessError as err:
                err=(
                    "an error occurred generating a local sha1, "
                    "the error was:\n{}".format(err)
                )
                self.close(err_str=err, not_remote=True, not_local=True)
            finally:
                self.orig_sha1 = sha1_str.split()[0]


    def storage_check(self):
        """ checks whether there is enough space on remote node to
            store both the original file and the chunks
        Args:
            self - class variables inherited from __init__
        Returns:
            None
        Raises:
            None
        """
        print("checking remote storage...")
        df_tuple = self.start_shell.run("df {}".format(self.remote_dir))
        if not self.start_shell.last_ok:
            self.close(
                err_str="failed to determine remote disk space available",
                not_remote=True,
                not_local=True,
            )
        avail_blocks = df_tuple[1].split("\n")[2].split()[3].rstrip()
        avail_bytes = int(avail_blocks) * 512
        if self.file_size * 2 > avail_bytes:
            self.close(
                err_str=(
                    "not enough space on remote host. Available space "
                    "must be 2x the original file size because it has to "
                    "store the file chunks and the whole file at the "
                    "same time"
                ),
                not_remote=True,
                not_local=True,
            )

    def put_files(self, sfile, **kwargs):
        """ copies files to remote host via ftp or scp
        Args:
            self - class variables inherited from __init__
            sfile(str) - name of the file to copy
            kwargs (dict) - named arguments
        Returns:
            None
        Raises:
            re-raises any exception
        """
        if self.copy_proto == "ftp":
            with FTP(self.dev, **kwargs) as ftp_proto:
                try:
                    ftp_proto.put(
                        sfile,
                        "{}/splitcopy_{}/".format(self.remote_dir, self.file_name),
                    )
                except:
                    raise
        else:
            with SCP(self.dev, **kwargs) as scp_proto:
                try:
                    scp_proto.put(
                        sfile,
                        "{}/splitcopy_{}/".format(self.remote_dir, self.file_name),
                    )
                except:
                    raise


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
            StartShellFail - if any of the start_shell commands fail or time out
        """

        inetd = self.start_shell.run("cat /etc/inetd.conf", timeout=300)
        if not self.start_shell.last_ok:
            raise StartShellFail(
                "Error: failed to read /etc/inetd.conf, "
                "can't determine whether ssh or ftp connection limits are configured"
            )

        port_conf = []
        if self.copy_proto == "ftp":
            port_conf.append(re.search(r"ftp stream tcp/.*", inetd[1]).group(0))
            port_conf.append(re.search(r"ssh stream tcp/.*", inetd[1]).group(0))
        else:
            port_conf.append(re.search(r"ssh stream tcp/.*", inetd[1]).group(0))

        command_list = []
        for port in port_conf:
            config = re.split("[/ ]", port)
            p_name = config[0]
            con_lim = int(config[5])
            rate_lim = int(config[6])

            # check for presence of rate/connection limits
            if con_lim < 25:
                print(
                    "{} configured connection-limit is under 25".format(p_name.upper())
                )
                d_config = self.start_shell.run(
                    'cli -c "show configuration | display set '
                    '| grep {} | grep connection-limit"'.format(p_name)
                )
                if (
                    self.start_shell.last_ok
                    and re.search(r"connection-limit", d_config[1]) is not None
                ):
                    d_config = d_config[1].split("\r\n")[1]
                    d_config = re.sub(" [0-9]+$", "", d_config)
                    d_config = re.sub("set", "deactivate", d_config)
                    command_list.append("{};".format(d_config))
                else:
                    raise StartShellFail(
                        "Error: failed to determine configured limits, cannot proceed"
                    )

            if rate_lim < 100:
                print("{} configured rate limit is under 100".format(p_name.upper()))
                d_config = self.start_shell.run(
                    'cli -c "show configuration | display set '
                    '| grep {} | grep rate-limit"'.format(p_name)
                )
                if (
                    self.start_shell.last_ok
                    and re.search(r"rate-limit", d_config[1]) is not None
                ):
                    d_config = d_config[1].split("\r\n")[1]
                    d_config = re.sub(" [0-9]+$", "", d_config)
                    d_config = re.sub("set", "deactivate", d_config)
                    command_list.append("{};".format(d_config))
                else:
                    raise StartShellFail(
                        "Error: failed to determine configured limits, cannot proceed"
                    )

        # if limits were configured, deactivate them
        if command_list:
            self.start_shell.run(
                'cli -c "edit;{}commit and-quit"'.format("".join(command_list))
            )

            if self.start_shell.last_ok:
                print(
                    "NOTICE: the configuration has been modified. "
                    "deactivated the limit(s) found"
                )
            else:
                raise StartShellFail(
                    "Error: failed to deactivate {} connection-limit/rate-limit"
                    "configuration. Cannot proceed".format(self.copy_proto)
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
        self.start_shell.run(
            "rm -rf {}/splitcopy_{}".format(self.remote_dir, self.file_name), timeout=10
        )
        if not self.start_shell.last_ok:
            print(
                "unable to delete the tmp directory {}/splitcopy_{} on remote host, "
                "delete it manually".format(self.remote_dir, self.file_name)
            )


class StartShellFail(Exception):
    """ custom exception class
    """
    pass


class UploadProgress:
    """ class which ftp module calls back to after each block has been sent
    """

    def __init__(self, file_size):
        """ Initialise the class
        """
        self.block_size = 0
        self.file_size = file_size
        self.last_percent = 0


    def handle(self, arg=None):
        """ For every 10% of data transferred, notifies the user
        Args:
            arg -  used to keep python3.4 from complaining about number of args
        Returns:
            None, just prints progress
        Raises:
            None
        """
        self.block_size += 8192
        percent_done = round((self.block_size / self.file_size) * 100)
        if self.last_percent != percent_done:
            self.last_percent = percent_done
            if percent_done % 10 == 0:
                print("{}% done".format(str(percent_done)))


if __name__ == "__main__":
    main()
