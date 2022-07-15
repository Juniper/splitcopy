""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

# stdlib
import ftplib
import logging
import os
import sys


class FTP(ftplib.FTP):
    """FTP utility used to transfer files to and from hosts
    mostly ripped from py-junos-eznc (with permission)
    """

    def __init__(self, file_size=None, progress=None, **kwargs):
        """initialize the FTP class
        :param file_size: size of file to transfer
        :type int:
        :param progress: Progress (from progress.py)
        :type object:
        :param kwargs: named arguments
        :type dict:
        """
        host = kwargs.get("host")
        user = kwargs.get("user")
        passwd = kwargs.get("passwd")
        timeout = kwargs.get("timeout")
        if not timeout:
            timeout = 30
        logger = logging.getLogger(__name__)
        if logger.getEffectiveLevel() == 10:
            self.set_debuglevel(level=1)
        ftplib.FTP.__init__(self, host=host, user=user, passwd=passwd, timeout=timeout)
        self.file_size = file_size
        self.progress = progress
        self.header_bytes = 33
        self.sent = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_ty, exc_val, exc_tb):
        self.quit()

    def put(self, local_file, remote_file, restart_marker):
        """copies file from local host to remote host
        :param local_file: path to local file
        :type string:
        :param remote_file: full path on server
        :type string:
        :return None:
        """
        with open(local_file, "rb") as open_local_file:
            if restart_marker is not None:
                self.sent = restart_marker
                open_local_file.seek(restart_marker, 0)

            def callback(data):
                size_data = sys.getsizeof(data) - self.header_bytes
                self.sent += size_data
                self.progress.report_progress(
                    file_name=os.path.basename(local_file),
                    file_size=self.file_size,
                    sent=self.sent,
                )

            self.storbinary(
                cmd="STOR " + remote_file,
                fp=open_local_file,
                callback=callback,
                rest=restart_marker,
            )

    def get(self, remote_file, local_file, restart_marker=None):
        """copies file from remote host to local host
        :param remote_file: full path on server
        :type string:
        :param local_file:  path to local file
        :type string:
        :return None:
        """
        if restart_marker is not None:
            self.sent = restart_marker
        with open(local_file, "ab") as open_local_file:

            def callback(data):
                open_local_file.write(data)
                size_data = sys.getsizeof(data) - self.header_bytes
                self.sent += size_data
                self.progress.report_progress(
                    file_name=os.path.basename(local_file),
                    file_size=self.file_size,
                    sent=self.sent,
                )

            self.retrbinary("RETR " + remote_file, callback, rest=restart_marker)
