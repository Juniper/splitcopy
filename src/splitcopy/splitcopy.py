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


def parse_arg_as_local(arg_name):
    local_file = None
    local_dir = None
    local_path = os.path.abspath(os.path.expanduser(arg_name))
    with open(local_path, "rb"):
        local_file = os.path.basename(local_path)
        local_dir = os.path.dirname(local_path)
    return local_file, local_dir, local_path


def parse_arg_as_remote(arg_name):
    user = None
    host = None
    remote_path = None
    if os.path.splitdrive(arg_name)[0]:
        # arg is a windows drive/UNC sharepoint
        # splitdrive() only returns a value at index 0 on windows systems
        raise ValueError("local windows path")
    elif re.match(r".+@.+:", arg_name):
        # usernames ought to consist of [a-z_][a-z0-9_-]*[$]?
        # according to useradd man page, but the use of chars such as '@'
        # are not enforced which affects the pattern match
        # hostname does thankfully enforce '@' and ':' as invalid
        split_str = arg_name.split("@")
        user = "@".join(split_str[:-1])
        host = split_str[-1].split(":")[0]
        remote_path = split_str[-1].split(":")[-1]
    elif re.match(r".+:", arg_name):
        user = getpass.getuser()
        host = arg_name.split(":")[0]
        remote_path = arg_name.split(":")[1]
    else:
        raise ValueError
    return user, host, remote_path


def open_ssh_keyfile(path):
    result = False
    ssh_key = os.path.abspath(os.path.expanduser(path))
    with open(ssh_key, "r") as key:
        result = True
    return result


def handlesigint(sigint, stack):
    raise SystemExit


def main(get_class=SplitCopyGet, put_class=SplitCopyPut):
    """body of script"""
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

    user = None
    host = None
    passwd = None
    ssh_key = None
    ssh_port = 22
    remote_path = None
    local_dir = None
    local_file = None
    local_path = None
    copy_proto = None
    copy_op = ""
    noverify = args.noverify
    source = args.source
    target = args.target
    use_curses = True
    overwrite = args.overwrite
    target_remote = False
    source_remote = False
    if args.nocurses:
        use_curses = False

    # test whether source or target is a correctly formatted remote path

    try:
        user, host, remote_path = parse_arg_as_remote(target)
        target_remote = True
    except ValueError:
        pass

    try:
        user, host, remote_path = parse_arg_as_remote(source)
        source_remote = True
    except ValueError:
        pass

    if target_remote and source_remote:
        raise SystemExit(
            "only one of the source or target arguments can "
            "be a remote path using the format "
            "<user>@<host>:<path> or <host>:<path>"
        )
    elif not target_remote and not source_remote:
        raise SystemExit(
            "neither of the source or target arguments "
            "specify a remote path in the correct format "
            "<user>@<host>:<path> or <host>:<path>"
        )
    elif target_remote:
        try:
            local_file, local_dir, local_path = parse_arg_as_local(source)
        except FileNotFoundError:
            raise SystemExit(f"'{source}' file does not exist")
        except PermissionError:
            raise SystemExit(
                f"'{source}' exists, but file cannot be read due to a permissions error"
            )
        except IsADirectoryError:
            raise SystemExit(f"'{source}' is a directory, not a file")
        copy_op = "put"
    else:
        if not remote_path:
            raise SystemExit(f"source argument '{source}' doesn't specify a file")
        copy_op = "get"

    try:
        host = socket.gethostbyname(host)
    except socket.gaierror:
        raise SystemExit("hostname resolution failed")

    if args.pwd:
        passwd = args.pwd[0]

    if not args.scp:
        copy_proto = "ftp"
    else:
        copy_proto = "scp"

    if args.ssh_key is not None:
        ssh_key = args.ssh_key[0]
        try:
            open_ssh_keyfile(ssh_key)
        except FileNotFoundError:
            raise SystemExit(f"'{ssh_key}' file does not exist")
        except PermissionError:
            raise SystemExit(
                f"'{ssh_key}' exists, but file cannot be read due to a permissions error"
            )
        except IsADirectoryError:
            raise SystemExit(f"'{ssh_key}' is a directory, not a file")

    if args.ssh_port is not None:
        try:
            ssh_port = int(args.ssh_port[0])
        except ValueError:
            raise SystemExit("ssh_port must be an integer")

    split_timeout = 120
    if args.split_timeout is not None:
        try:
            split_timeout = int(args.split_timeout[0])
        except ValueError:
            raise SystemExit("split_timeout must be an integer")

    kwargs = {
        "user": user,
        "host": host,
        "passwd": passwd,
        "ssh_key": ssh_key,
        "ssh_port": ssh_port,
        "remote_path": remote_path,
        "local_dir": local_dir,
        "local_file": local_file,
        "local_path": local_path,
        "copy_proto": copy_proto,
        "copy_op": copy_op,
        "noverify": noverify,
        "split_timeout": split_timeout,
        "use_curses": use_curses,
        "target": target,
        "overwrite": overwrite,
    }
    logger.info(kwargs)

    if copy_op == "get":
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


if __name__ == "__main__":
    main()
