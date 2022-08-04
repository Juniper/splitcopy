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
import sys
import traceback

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
    parser.add_argument("--nocurses", action="store_true", help="disable curses output")
    parser.add_argument("--log", nargs=1, help="log level, eg DEBUG")
    args = parser.parse_args()
    return args


def parse_source_arg_as_local(source):
    local_file = None
    local_dir = None
    local_path = os.path.abspath(os.path.expanduser(source))
    with open(local_path, "rb"):
        local_file = os.path.basename(local_path)
        local_dir = os.path.dirname(local_path)
    return local_file, local_dir, local_path


def parse_arg_as_remote(arg_name, arg_str):
    user = None
    host = None
    if re.search(r".*@.*:", arg_name):
        user = arg_name.split("@")[0]
        host = re.search(r"@(.*):", arg_name).group(1)
    elif re.search(r".*:", arg_name):
        user = getpass.getuser()
        host = arg_name.split(":")[0]
    else:
        raise ValueError(
            f"{arg_str} argument path is not in the correct format "
            "<user>@<host>:<path> or <host>:<path>"
        )
    remote_path = arg_name.split(":")[1]
    return user, host, remote_path


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
    remote_dir = None
    remote_file = None
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
    if args.nocurses:
        use_curses = False

    try:
        local_file, local_dir, local_path = parse_source_arg_as_local(source)
    except FileNotFoundError:
        pass
    except PermissionError:
        raise SystemExit(
            f"source file '{source}' exists, but cannot be read due to a permissions error"
        )
    except IsADirectoryError:
        raise SystemExit("source arg is a directory, not a file")

    if not local_file and os.path.splitdrive(source)[0]:
        # source arg is a windows drive/UNC sharepoint
        # splitdrive will only return a value on windows systems
        raise SystemExit(f"source arg file at path {source} cannot be found")

    if local_file is not None:
        copy_op = "put"
        try:
            user, host, remote_path = parse_arg_as_remote(target, "target")
        except ValueError as err:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            raise SystemExit(err)
    else:
        copy_op = "get"
        try:
            user, host, remote_path = parse_arg_as_remote(source, "source")
        except ValueError as err:
            logger.debug("".join(traceback.format_exception(*sys.exc_info())))
            raise SystemExit(err)

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
        ssh_key = os.path.abspath(args.ssh_key[0])
        if not os.path.isfile(ssh_key):
            raise SystemExit("specified ssh key not found")

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
        "remote_dir": remote_dir,
        "remote_file": remote_file,
        "remote_path": remote_path,
        "local_dir": local_dir,
        "local_file": local_file,
        "local_path": local_path,
        "copy_proto": copy_proto,
        "noverify": noverify,
        "split_timeout": split_timeout,
        "use_curses": use_curses,
        "target": target,
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
