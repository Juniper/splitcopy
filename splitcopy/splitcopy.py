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
from socket import gethostbyname, gaierror, herror

# local modules
from splitcopy.put import SplitCopyPut
from splitcopy.get import SplitCopyGet

logger = logging.getLogger(__name__)


def main():
    """body of script"""

    def handlesigint(sigint, stack):
        raise SystemExit

    signal.signal(signal.SIGINT, handlesigint)
    start_time = datetime.datetime.now()

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
        help="time to wait for file split operation to complete, default 120",
    )
    parser.add_argument(
        "--ssh_port",
        nargs=1,
        help="ssh port number to connect to",
    )
    parser.add_argument("--log", nargs=1, help="log level, eg DEBUG")
    args = parser.parse_args()

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
    local_path = None
    copy_proto = None
    get = False
    noverify = args.noverify
    source = args.source
    target = args.target

    if re.search(r".*:", source):
        if re.search(r"@", source):
            user = source.split("@")[0]
            host = source.split("@")[1]
            host = host.split(":")[0]
        else:
            user = getpass.getuser()
            host = source.split(":")[0]
        remote_path = source.split(":")[1]
        remote_file = os.path.basename(remote_path)
        remote_dir = os.path.dirname(remote_path)
        if remote_dir == "" or remote_dir == ".":
            remote_dir = "~"
            remote_path = f"{remote_dir}/{remote_file}"
        if not remote_file:
            raise SystemExit("src path doesn't specify a file name")
        get = True
    elif os.path.isfile(source):
        local_path = os.path.abspath(os.path.expanduser(source))
        try:
            with open(local_path, "rb"):
                pass
        except PermissionError:
            raise SystemExit(
                f"source file {local_path} exists but is not readable - cannot proceed"
            )
        local_file = os.path.basename(local_path)
        local_dir = os.path.dirname(local_path)
    else:
        raise SystemExit(
            "specified source is not a valid path to a local "
            "file, or is not in the format <user>@<host>:<path> "
            "or <host>:<path>"
        )

    if re.search(r".*:", target):
        if re.search(r"@", target):
            user = target.split("@")[0]
            host = target.split("@")[1]
            host = host.split(":")[0]
        else:
            user = getpass.getuser()
            host = target.split(":")[0]
        remote_path = target.split(":")[1]
        if remote_path == "":
            remote_dir = "~"
            remote_file = local_file
            remote_path = f"{remote_dir}/{remote_file}"
        elif os.path.dirname(remote_path) == "":
            remote_dir = "~"
            remote_file = remote_path
            remote_path = f"{remote_dir}/{remote_file}"
    elif os.path.isdir(target):
        local_dir = os.path.abspath(os.path.expanduser(target))
        local_file = remote_file
    elif os.path.isdir(os.path.dirname(target)):
        # we've been passed in a filename, may not exist yet
        local_dir = os.path.dirname(os.path.abspath(os.path.expanduser(target)))
        if os.path.basename(target) != remote_file:
            # have to honour the change of name
            local_file = os.path.basename(target)
        else:
            local_file = remote_file
    else:
        raise SystemExit(
            "specified target is not a valid path to a local "
            "file or directory, or is not in the format <user>@<host>:<path> "
            "or <host>:<path>"
        )

    try:
        host = gethostbyname(host)
    except (gaierror, herror):
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
        if split_timeout < 120:
            split_timeout = 120
            print("split_timeout value is < default of 120. setting it to 120")

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
        "get": get,
        "noverify": noverify,
        "split_timeout": split_timeout,
    }
    logger.info(kwargs)

    if get:
        splitcopyget = SplitCopyGet(**kwargs)
        loop_start, loop_end = splitcopyget.get()
    else:
        splitcopyput = SplitCopyPut(**kwargs)
        loop_start, loop_end = splitcopyput.put()

    # and we are done...
    end_time = datetime.datetime.now()
    time_delta = end_time - start_time
    transfer_delta = loop_end - loop_start
    print(f"data transfer = {transfer_delta}\ntotal runtime = {time_delta}")


if __name__ == "__main__":
    main()
