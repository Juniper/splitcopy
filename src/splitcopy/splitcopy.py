#!/usr/bin/env python3
""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

# stdlib
import argparse
import datetime
import getpass
import logging
import os
import re
import signal
import socket

from splitcopy.get import SplitCopyGet
from splitcopy.put import SplitCopyPut

logger = logging.getLogger(__name__)


def parse_args():
    """parses arguments
    :return args:
    :type Namespace:
    """
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
    parser.add_argument(
        "--split_timeout",
        nargs=1,
        help="time to wait for remote file split operation to complete, default 120s",
    )
    parser.add_argument(
        "--ssh_port",
        nargs=1,
        help="ssh port number to connect to",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="if target file already exists, delete it prior to transfer",
    )
    parser.add_argument("--nocurses", action="store_true", help="disable curses output")
    parser.add_argument("--log", nargs=1, help="log level, eg DEBUG")
    args = parser.parse_args()
    return args


def windows_path(arg_name):
    """determine if argument is a windows/UNC path
    :param arg_name:
    :type string:
    :return bool:
    """
    result = False
    if os.path.splitdrive(arg_name)[0]:
        # arg is a windows drive/UNC sharepoint
        # splitdrive() only returns a value at index 0 on windows systems
        logger.debug(f"'{arg_name}' is a windows path")
        result = True
    return result


def parse_src_arg_as_local(source):
    """attempts to open path provided on local filesystem
    :param arg_name:
    :type string:
    :return local_file:
    :type string:
    :return local_dir:
    :type string:
    :return local_path:
    :type string:
    """
    local_file = ""
    local_dir = ""
    local_path = os.path.abspath(os.path.expanduser(source))
    with open(local_path, "rb"):
        local_file = os.path.basename(local_path)
        local_dir = os.path.dirname(local_path)
    return local_file, local_dir, local_path


def parse_arg_as_remote(arg_name):
    """parses argument to determine if it's on a remote host.
    If successful, returns the user, host and remote path.
    :param arg_name:
    :type string:
    :return user:
    :type string:
    :return host:
    :type string:
    :return remote_path:
    :type string:
    """
    user = ""
    host = ""
    remote_path = ""
    # greedy match for @ and :
    user_at_host = re.compile(r"(.+)@(.+):(.+)*")
    # greedy match for :
    host_only = re.compile(r"(.+):(.+)*")
    # not impossible that remote_path could contain ':' or '@' char
    # or username could contain '@' char
    # above is too simplistic to deal with these edge use cases
    if re.match(user_at_host, arg_name):
        # usernames ought to consist of [a-z_][a-z0-9_-]*[$]?
        # according to useradd man page, but the use of chars such as '@'
        # are not enforced which affects the pattern match
        # hostname does thankfully enforce '@' and ':' as invalid
        regex = re.match(user_at_host, arg_name)
        user = regex.group(1)
        host = regex.group(2)
        remote_path = regex.group(3) or ""
    elif re.match(host_only, arg_name):
        user = getpass.getuser()
        regex = re.match(host_only, arg_name)
        host = regex.group(1)
        remote_path = regex.group(2) or ""
    else:
        raise ValueError(
            f"'{arg_name}' is not in the correct format "
            "<user>@<host>:<path> or <host>:<path>"
        )
    return user, host, remote_path


def open_ssh_keyfile(path):
    """tests whether the provided ssh keyfile can be read
    :param path:
    :type string:
    :return bool:
    """
    result = False
    ssh_key = os.path.abspath(os.path.expanduser(path))
    with open(ssh_key, "r") as key:
        result = True
    return result


def handlesigint(sigint, stack):
    """called upon sigINT, effectively suppresses KeyboardInterrupt
    :param sigint:
    :type int:
    :param stack:
    :type frame object:
    :raises SystemExit:
    :return None:
    """
    raise SystemExit


def process_args(source, target):
    """determines the copy operation to perform, paths, username and host
    :param source:
    :type string:
    :param target:
    :type string:
    :returns result:
    :type dict:
    :raises SystemExit:
    """
    user = ""
    host = ""
    remote_path = ""
    local_dir = ""
    local_file = ""
    local_path = ""
    copy_op = ""
    source_in_remote_format = False
    target_in_remote_format = False

    try:
        local_file, local_dir, local_path = parse_src_arg_as_local(source)
    except FileNotFoundError:
        # expected if this is a remote path
        pass
    except PermissionError:
        raise SystemExit(
            f"'{source}' exists, but file cannot be read due to a permissions error"
        )
    except IsADirectoryError:
        raise SystemExit(f"'{source}' is a directory, not a file")

    try:
        user, host, remote_path = parse_arg_as_remote(source)
        if not windows_path(source):
            source_in_remote_format = True
    except ValueError as err:
        pass

    try:
        user, host, remote_path = parse_arg_as_remote(target)
        if not windows_path(target):
            target_in_remote_format = True
    except ValueError as err:
        pass

    if source_in_remote_format and target_in_remote_format:
        raise SystemExit(
            f"both '{source}' and '{target}' are remote paths - "
            "one path must be local, the other remote"
        )
    elif local_file and target_in_remote_format:
        copy_op = "put"
    elif local_file and not target_in_remote_format:
        raise SystemExit(
            f"file '{source}' found, remote path '{target}' is not in the correct format [user@]host:path"
        )
    elif not local_file and target_in_remote_format:
        raise SystemExit(f"'{source}' file not found")
    elif not local_file and not source_in_remote_format:
        raise SystemExit(f"'{source}' file not found")
    elif not local_file and source_in_remote_format and not remote_path:
        raise SystemExit(f"'{source}' does not specify a filepath")
    elif not local_file and source_in_remote_format and not target_in_remote_format:
        copy_op = "get"

    try:
        host = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise SystemExit(
            f"Could not resolve hostname '{host}', resolution failed"
        ) from exc

    result = {
        "user": user,
        "host": host,
        "remote_path": remote_path,
        "local_dir": local_dir,
        "local_file": local_file,
        "local_path": local_path,
        "copy_op": copy_op,
        "target": target,
    }
    return result


def main(get_class=SplitCopyGet, put_class=SplitCopyPut):
    """body of script
    :param get_class:
    :type class:
    :param put_class:
    :type class:
    :return bool:
    """
    signal.signal(signal.SIGINT, handlesigint)
    start_time = datetime.datetime.now()

    args = parse_args()
    if not args.log:
        loglevel = "WARNING"
    else:
        loglevel = args.log[0]

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {loglevel}")
    logging.basicConfig(
        format="%(asctime)s %(name)s %(lineno)s %(funcName)s %(levelname)s:%(message)s",
        level=numeric_level,
    )

    passwd = ""
    ssh_key = ""
    ssh_port = 22
    copy_proto = ""
    noverify = args.noverify
    use_curses = True
    overwrite = args.overwrite

    if args.nocurses:
        use_curses = False

    if args.pwd is not None:
        passwd = args.pwd[0]

    if not args.scp:
        copy_proto = "ftp"
    else:
        copy_proto = "scp"

    if args.ssh_key is not None:
        ssh_key = args.ssh_key[0]
        try:
            open_ssh_keyfile(ssh_key)
        except FileNotFoundError as exc:
            raise SystemExit(f"'{ssh_key}' file does not exist") from exc
        except PermissionError as exc:
            raise SystemExit(
                f"'{ssh_key}' exists, but file cannot be read due to a permissions error"
            ) from exc
        except IsADirectoryError as exc:
            raise SystemExit(f"'{ssh_key}' is a directory, not a file") from exc

    if args.ssh_port is not None:
        try:
            ssh_port = int(args.ssh_port[0])
        except ValueError as exc:
            raise SystemExit("ssh_port must be an integer") from exc

    split_timeout = 120
    if args.split_timeout is not None:
        try:
            split_timeout = int(args.split_timeout[0])
        except ValueError as exc:
            raise SystemExit("split_timeout must be an integer") from exc

    kwargs = process_args(args.source, args.target)
    kwargs["passwd"] = passwd
    kwargs["ssh_key"] = ssh_key
    kwargs["ssh_port"] = ssh_port
    kwargs["copy_proto"] = copy_proto
    kwargs["noverify"] = noverify
    kwargs["split_timeout"] = split_timeout
    kwargs["use_curses"] = use_curses
    kwargs["overwrite"] = overwrite
    logger.info(kwargs)

    if kwargs["copy_op"] == "get":
        splitcopyget = get_class(**kwargs)
        loop_start, loop_end = splitcopyget.get()
    else:
        splitcopyput = put_class(**kwargs)
        loop_start, loop_end = splitcopyput.put()

    # and we are done...
    end_time = datetime.datetime.now()
    time_delta = end_time - start_time
    transfer_delta = loop_end - loop_start
    print(f"data transfer = {transfer_delta}\ntotal runtime = {time_delta}")
    return True
