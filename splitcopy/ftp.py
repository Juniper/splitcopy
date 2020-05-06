# stdlib
import ftplib
import logging
import os
import re
import sys

logger = logging.getLogger(__name__)


class FTP(ftplib.FTP):
    """ FTP utility used to transfer files to and from hosts
        mostly ripped from py-junos-eznc (with permission)
    """

    def __init__(self, **kwargs):
        """ initialize the FTP class
            :param kwargs: named arguments
            :type dict:
        """
        self.host = kwargs.get("host")
        self.user = kwargs.get("user")
        self.passwd = kwargs.get("passwd")
        self.callback = kwargs.get("progress")
        self.header_bytes = 33
        self.sent = 0
        self.file_size = 0
        ftplib.FTP.__init__(self, self.host, self.user, self.passwd)

    def put(self, local_file, remote_file):
        """ copies file from local host to remote host
            :param local_file: path to local file
            :type: string
            :param remote_file: full path on server
            :type: string
        """
        fileinfo = os.stat(local_file)
        self.file_size = fileinfo.st_size
        logger.debug("{}, size {}".format(local_file, self.file_size))

        with open(local_file, "rb") as open_local_file:
            def callback(data):
                if self.callback:
                    size_data = sys.getsizeof(data) - self.header_bytes
                    self.sent += size_data
                    self.callback(
                        file_name=os.path.basename(local_file),
                        file_size=self.file_size,
                        sent=self.sent,
                    )
            self.storbinary(
                cmd="STOR " + remote_file, fp=open_local_file, callback=callback
            )

    def get(self, remote_file, local_file):
        """ copies file from remote host to local host
            :param remote_file: full path on server
            :type: string
            :param local_file:  path to local file
            :type: string
        """
        self.voidcmd("TYPE I")
        self.file_size = self.size(remote_file)
        logger.debug("{}, size {}".format(remote_file, self.file_size))

        with open(local_file, "wb") as local_fh:
            def callback(data):
                local_fh.write(data)
                if self.callback:
                    size_data = sys.getsizeof(data) - self.header_bytes
                    self.sent += size_data
                    self.callback(
                        file_name=os.path.basename(local_file),
                        file_size=self.file_size,
                        sent=self.sent,
                    )
            self.retrbinary("RETR " + remote_file, callback)
