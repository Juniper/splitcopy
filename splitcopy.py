#!/usr/bin/env python3
""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.

    splits a given file into pieces in a tmp directory, copies these to a junos
    host then reassembles them. Tested to be 15x faster to transfer an 845MB
    file than regular ftp/scp.

    Requires 'system services ssh' configuration on remote host.
    If using ftp to copy files (default) then 'system services ftp' is also
    required.

    Requires python 3.4+ to run.

    install required module via:
        pip3 install junos-eznc

    Script overhead is 5-10 seconds on 64bit RE's, longer on RE2000's
    and PPC based models like MX80.
    This includes authentication, sha1 generation/comparison,
    disk space check, file split and join.
    It will be slower than ftp/scp for small files as a result.

    Because it opens many simultaneous connections
    if the router has limits set like this:

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
    raise RuntimeError("This package requres Python 3.4+")

import asyncio
import argparse
import os
import contextlib
import datetime
import fnmatch
import functools
import getpass
import re
import shutil
import tempfile
import subprocess
import paramiko
import scp
from jnpr.junos import Device
from jnpr.junos.utils.ftp import FTP
from jnpr.junos.utils.scp import SCP
from jnpr.junos.utils.start_shell import StartShell


def main():
    """
    Generic main() statement
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

    if not args.password:
        password = getpass.getpass(prompt="Password: ", stream=None)
    else:
        password = args.password[0]

    if args.remotedir:
        remote_dir = args.remotedir[0]
    else:
        remote_dir = "/var/tmp"

    if not os.path.isfile(args.filepath):
        print("source file {} does not exist - cannot proceed".format(args.filepath))
        sys.exit(1)

    if re.search("/", args.filepath):
        file_name = args.filepath.rsplit("/", 1)[1]
    else:
        file_name = args.filepath

    file_path = os.path.abspath(args.filepath)
    file_size = os.path.getsize(file_path)
    start_time = datetime.datetime.now()

    print("checking remote port(s) are open...")
    if not port_check(host, "ssh", "22"):
        sys.exit(1)
    if args.scp:
        copy_proto = "scp"
    else:
        if port_check(host, "ftp", "21"):
            copy_proto = "ftp"
        else:
            copy_proto = "scp"

    with tempdir():
        # connect to host
        dev = Device(host=host, user=user, passwd=password)
        try:
            with StartShell(dev) as start_shell:
                # cleanup previous tmp directory if found
                if not remote_cleanup(start_shell, remote_dir, file_name, False):
                    sys.exit(1)

                # confirm remote storage is sufficient
                storage_check(start_shell, file_size, remote_dir)

                # get/create sha1 for local file
                orig_sha1 = sha1_check(file_path)

                # split file into chunks
                split_file(start_shell, copy_proto, file_size, file_path, file_name)

                sfiles = []
                for sfile in os.listdir("."):
                    if fnmatch.fnmatch(sfile, "{}*".format(file_name)):
                        sfiles.append(sfile)

                # begin pre transfer checks, check if remote directory exists
                start_shell.run("test -d {}".format(remote_dir))
                if not start_shell.last_ok:
                    print("remote directory specified does not exist")
                    sys.exit(1)

                # end of pre transfer checks, create tmp directory
                start_shell.run("mkdir {}/splitcopy_{}".format(remote_dir, file_name))
                if not start_shell.last_ok:
                    print("unable to create the tmp directory on remote host")
                    sys.exit(1)

                # begin connection/rate limit check and transfer process
                limit_check(start_shell, copy_proto)
                if copy_proto == "ftp":
                    kwargs = {"callback": UploadProgress(file_size).handle}
                else:
                    kwargs = {"progress": True, "socket_timeout": 30.0}

                # copy files to remote host
                loop_start = datetime.datetime.now()
                async_transfer(
                    start_shell, dev, copy_proto, remote_dir, file_name, sfiles, kwargs
                )
                loop_end = datetime.datetime.now()

                # end transfer, combine chunks
                join_files(start_shell, remote_dir, file_name)

                # remove remote tmp dir
                remote_cleanup(start_shell, remote_dir, file_name)

                # generate a sha1 for the combined file, compare to sha1 of src
                remote_sha1(start_shell, orig_sha1, remote_dir, file_name, host)

        except paramiko.ssh_exception.BadAuthenticationType:
            print("authentication type used isnt allowed by the host")
            sys.exit(1)

        except paramiko.ssh_exception.AuthenticationException:
            print("ssh authentication failed")
            sys.exit(1)

        except paramiko.ssh_exception.BadHostKeyException:
            print(
                "host key verification failed. delete the host key in "
                "~/.ssh/known_hosts and retry"
            )
            sys.exit(1)

        except paramiko.ssh_exception.ChannelException as err:
            print(
                "an attempt to open a new ssh channel failed. "
                " error code returned was:\n{}".format(err)
            )
            sys.exit(1)

        except paramiko.ssh_exception.SSHException as err:
            print("an ssh error occurred")
            sys.exit(1)

        except KeyboardInterrupt:
            remote_cleanup(start_shell, remote_dir, file_name)
            sys.exit(1)

        # and.... we are done
        dev.close()
        end_time = datetime.datetime.now()
        time_delta = end_time - start_time
        transfer_delta = loop_end - loop_start
        print(
            "data transfer = {}\ntotal runtime = {}".format(transfer_delta, time_delta)
        )


def join_files(start_shell, remote_dir, file_name):
    """ concatenates the file chunks into one file
    Args:
        start_shell - the StartShell object handle
        remote_dir (str) - path to file on remote host (excluding file_name)
        file_name (str) - name of the file
    Returns:
        None
    Raises:
        None
    """
    print("joining files...")
    start_shell.run(
        "cat {}/splitcopy_{}/* > {}/{}".format(
            remote_dir, file_name, remote_dir, file_name
        ),
        timeout=600,
    )
    if not start_shell.last_ok:
        print("failed to combine chunks on remote host")
        sys.exit(1)


def async_transfer(start_shell, dev, copy_proto, remote_dir, file_name, sfiles, kwargs):
    """ asychronously copies the file chunks to the remote host
    Args:
        start_shell - the StartShell object handle
        dev - the device handle
        copy_proto (str) - protocol to be used for file transfer
        remote_dir (str) - path to file on remote host (excluding file_name)
        file_name (str) - name of the file
        sfiles (list) - list of file chunks to transfer
        kwargs (dict) - named arguments
    Returns:
        None
    Raises:
        None
    """
    print("starting transfer...")
    loop = asyncio.get_event_loop()
    tasks = []
    for sfile in sfiles:
        task = loop.run_in_executor(
            None,
            functools.partial(
                put_files, dev, sfile, file_name, remote_dir, copy_proto, **kwargs
            ),
        )
        tasks.append(task)
    try:
        loop.run_until_complete(asyncio.gather(*tasks))
    except scp.SCPException as err:
        print("scp returned the following error:\n{}".format(err))
        remote_cleanup(start_shell, remote_dir, file_name)
        sys.exit(1)
    except KeyboardInterrupt:
        remote_cleanup(start_shell, remote_dir, file_name)
        sys.exit(1)
    loop.close()


def remote_sha1(start_shell, orig_sha1, remote_dir, file_name, host):
    """ creates a sha1 hash for the newly combined file on the remote host
        compares against local sha1
    Args:
        start_shell - the StartShell object handle
        orig_sha1 (str) - sha1 hash of the local file
        remote_dir (str) - path to file on remote host (excluding file_name)
        file_name (str) - name of the file
        host (str) - the remote host
    Returns:
        None
    Raises:
        None
    """
    print("generating remote sha1...")
    start_shell.run("ls {}/{}".format(remote_dir, file_name))
    if start_shell.last_ok:
        sha1_tuple = start_shell.run(
            "sha1 {}/{}".format(remote_dir, file_name), timeout=300
        )
        if start_shell.last_ok:
            new_sha1 = sha1_tuple[1].split("\n")[1].split()[3].rstrip()
            if orig_sha1 == new_sha1:
                print(
                    "local and remote sha1 match\nfile has been "
                    "successfully copied to {}:{}/{}".format(
                        host, remote_dir, file_name
                    )
                )
            else:
                print(
                    "file has been copied to {}:{}/{}, but the "
                    "local and remote sha1 do not match - "
                    "please retry".format(host, remote_dir, file_name)
                )
                remote_cleanup(start_shell, remote_dir, file_name)
                sys.exit(1)
        else:
            print(
                "remote sha1 verification didnt complete, "
                'manually check the output of "sha1 <file>" and '
                "compare against {}".format(orig_sha1)
            )
    else:
        print(
            "file {}:{}/{} not found! please retry".format(host, remote_dir, file_name)
        )
        remote_cleanup(start_shell, remote_dir, file_name)
        sys.exit(1)


def split_file(start_shell, copy_proto, file_size, file_path, file_name):
    """ splits file into chunks. The chunk size varies depending on the
        protocol used to copy, and the FreeBSD version
    Args:
        start_shell - the StartShell object handle
        copy_proto (str) - name of protocol used to copy files with
        file_size(int) - size of the file to copy
        file_path(str) - full file path
        file_name(str) - name of the file to copy
    Returns:
        None
    Raises:
        None
    """
    if copy_proto == "ftp":
        split_size = str(divmod(file_size, 40)[0])
    else:
        # check if JUNOS running BSD10+
        # scp to FreeBSD 6 based junoscreates 3 pids per chunk
        # scp to FreeBSD 10+ based junos creates 2 pids per chunk
        # each uid can have max of 64 processes
        # values here should leave ~24 pid headroom
        ver = start_shell.run("uname -i")
        if start_shell.last_ok:
            verstring = ver[1].split("\n")[1].rstrip()
            if re.match(r"JNPR", verstring):
                split_size = str(divmod(file_size, 20)[0])
            else:
                split_size = str(divmod(file_size, 13)[0])
        else:
            # fallback to lower values
            split_size = str(divmod(file_size, 13)[0])

    print("splitting file...")
    try:
        subprocess.call(
            ["split", "-b", split_size, file_path, file_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        print("splitting the file timed out after 10 mins")
        sys.exit(1)
    except subprocess.SubprocessError as err:
        print(
            "an error occurred while splitting the file, "
            "the error was:\n{}".format(err)
        )
        sys.exit(1)


def sha1_check(file_path):
    """ checks whether a sha1 already exists for the file
        if not creates one
    Args:
        file_path(str) - full file path
    Returns:
        orig_sha1(str) - sha1 hash of the file
    Raises:
        None
    """
    if os.path.isfile(file_path + ".sha1"):
        sha1file = open(file_path + ".sha1", "r")
        orig_sha1 = sha1file.read().rstrip()
    else:
        print("sha1 not found, generating sha1...")
        try:
            sha1_str = subprocess.check_output(["shasum", file_path]).decode()
        except subprocess.SubprocessError as err:
            print(
                "an error occurred generating a local sha1, "
                "the error was:\n{}".format(err)
            )
            sys.exit(1)
        orig_sha1 = sha1_str.split()[0]
    return orig_sha1


def storage_check(start_shell, file_size, remote_dir):
    """ checks whether there is enough space on remote node to
        store both the original file and the chunks
    Args:
        start_shell - the StartShell object handle
        file_size(int) - size of the file to copy
        remote_dir(str) - directory path on remote node
    Returns:
        None
    Raises:
        None
    """
    print("checking remote storage...")
    df_tuple = start_shell.run("df {}".format(remote_dir))
    if not start_shell.last_ok:
        print("failed to determine remote disk space available")
        sys.exit(1)
    avail_blocks = df_tuple[1].split("\n")[2].split()[3].rstrip()
    avail_bytes = int(avail_blocks) * 512
    if file_size * 2 > avail_bytes:
        print(
            "not enough space on remote host. Available space "
            "must be 2x the original file size because it has to "
            "store the file chunks and the whole file at the "
            "same time"
        )
        sys.exit(1)


def put_files(dev, sfile, file_name, remote_dir, copy_proto, **kwargs):
    """ copies files to remote host via ftp or scp
    Args:
        dev - the ssh connection handle
        sfile(str) - name of the file to copy
        file_name(str) - part of directory name
        remote_dir (str) - path to file on remote host (excluding file_name)
        copy_proto (str) - name of protocol used to copy files with
        kwargs (dict) - named arguments
    Returns:
        None
    Raises:
        None
    """
    if copy_proto == "ftp":
        with FTP(dev, **kwargs) as ftp:
            ftp.put(sfile, "{}/splitcopy_{}/".format(remote_dir, file_name))
    else:
        with SCP(dev, **kwargs) as scp:
            scp.put(sfile, "{}/splitcopy_{}/".format(remote_dir, file_name))


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
        'arg' is used to keep python3.4 from complaining about number of args
        Args:
            self
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


@contextlib.contextmanager
def change_dir(newdir, cleanup=lambda: True):
    """ cds into temp directory.
        Upon script exit, changes back to original directory
        and calls cleanup() to delete the temp directory
    Args:
        newdir(str) - path to temp directory
        cleanup(?) - pointer to cleanup function ?
    Returns:
        None
    Raises:
        None
    """
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)
        cleanup()


@contextlib.contextmanager
def tempdir():
    """
    creates a temp directory
    defines how to delete directory upon script exit
    Args:
        None
    Returns:
        dirpath(str): path to temp directory
    Raises:
        None
    """
    dirpath = tempfile.mkdtemp()

    def cleanup():
        """ deletes temp dir
        """
        shutil.rmtree(dirpath)

    with change_dir(dirpath, cleanup):
        yield dirpath


def port_check(host, proto, port):
    """ checks if a port is open on remote host
    Args:
        host(str) - host to connect to
        proto(str) - protocol to connect with
        port(str) - port to connect to
    Returns:
        True if port is open
        False if port is closed
    Raises:
        subprocess.TimeoutExpired if timeout occurs
        subprocess.SubprocessError for generic subprocess errors
    """
    success = True
    try:
        if subprocess.call(
            ["nc", "-z", host, port],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        ):
            print("remote {} port {} isnt open".format(proto, port))
            success = False
    except subprocess.TimeoutExpired:
        print(
            "{} port check timed out after 10 seconds"
            ", is the host reacheable and {} enabled?".format(proto, proto)
        )
        success = False
    except subprocess.SubprocessError as err:
        print(
            "an error occurred during remote {} port check, "
            "the error was:\n{}".format(proto, err)
        )
        success = False

    return success


def limit_check(start_shell, copy_proto):
    """ Checks the remote hosts /etc/inetd file to determine whether there are any
    ftp or ssh connection/rate limits defined. If found, these configuration lines
    will be deactivated
    Args:
        start_shell - the StartShell object handle
        copy_proto (str) - protocol to be used for file transfer
    Returns:
        None
    Raises:
        A general exception if shell commands fail to execute correctly or if
        a real exception is thrown due to some unknown error.
    """

    inetd = start_shell.run("cat /etc/inetd.conf", timeout=300)
    if not start_shell.last_ok:
        print(
            "Error: failed to read /etc/inetd.conf, "
            "can't determine whether ssh or ftp connection limits are configured"
        )
        sys.exit(1)

    port_conf = []
    if copy_proto == "ftp":
        port_conf.append(re.search(r"ftp stream tcp\/.*", inetd[1]).group(0))
        port_conf.append(re.search(r"ssh stream tcp\/.*", inetd[1]).group(0))
    else:
        port_conf.append(re.search(r"ssh stream tcp\/.*", inetd[1]).group(0))

    command_list = []
    for port in port_conf:
        config = re.split("/| ", port)
        p_name = config[0]
        con_lim = int(config[5])
        rate_lim = int(config[6])

        # check for presence of rate/connection limits
        try:
            if con_lim < 25:
                print(
                    "{} configured connection-limit is under 25".format(p_name.upper())
                )
                d_config = start_shell.run(
                    'cli -c "show configuration | display set '
                    '| grep {} | grep connection-limit"'.format(p_name)
                )
                if (
                    start_shell.last_ok
                    and re.search(r"connection-limit", d_config[1]) is not None
                ):
                    d_config = d_config[1].split("\r\n")[1]
                    d_config = re.sub(" [0-9]+$", "", d_config)
                    d_config = re.sub("set", "deactivate", d_config)
                    command_list.append("{};".format(d_config))
                else:
                    raise Exception

            if rate_lim < 100:
                print("{} configured rate limit is under 100".format(p_name.upper()))
                d_config = start_shell.run(
                    'cli -c "show configuration | display set '
                    '| grep {} | grep rate-limit"'.format(p_name)
                )
                if (
                    start_shell.last_ok
                    and re.search(r"rate-limit", d_config[1]) is not None
                ):
                    d_config = d_config[1].split("\r\n")[1]
                    d_config = re.sub(" [0-9]+$", "", d_config)
                    d_config = re.sub("set", "deactivate", d_config)
                    command_list.append("{};".format(d_config))
                else:
                    raise Exception

        except Exception:
            print("Error: failed to determine configured limits, cannot proceed")
            sys.exit(1)

    try:
        # if limits were configured, deactivate them
        if command_list:
            start_shell.run(
                'cli -c "edit;{}commit and-quit"'.format("".join(command_list))
            )

            if start_shell.last_ok:
                print(
                    "NOTICE: the configuration has been modified. "
                    "deactivated the limit(s) found"
                )
            else:
                raise Exception

    except Exception:
        print("Error: failed to deactivate limits. Cannot proceed")
        sys.exit(1)


def remote_cleanup(start_shell, remote_dir, file_name, announce=True):
    """ delete tmp directory on remote host
    Args:
        dir(str) - remote directory to remove
    Returns:
        True if directory deletion was successful
        False if directory deletion was unsuccessful
    Raises:
        none
    """
    if announce:
        print("deleting remote tmp directory...")
    start_shell.run("rm -rf {}/splitcopy_{}".format(remote_dir, file_name), timeout=300)
    if not start_shell.last_ok:
        print(
            "unable to delete the tmp directory on remote host," " delete it manually"
        )
        return False
    return True


if __name__ == "__main__":
    main()
