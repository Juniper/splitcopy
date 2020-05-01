# stdlib
import os
import logging

_RECVSZ = 1024

logger = logging.getLogger(__name__)

class SSH2ScpClient:
    """ class providing scp client functionality using ssh2-python lib
    """

    def __init__(self, **kwargs):
        """ Initialise the SSH2ScpClient class
        """
        self._ssh2 = kwargs.get("ssh2")
        self._callback = kwargs.get("callback")
        self.chan = None

    def __enter__(self):
        return self

    def __exit__(self, exc_ty, exc_val, exc_tb):
        self.close()

    def scp_send(self, file, srcpath, dstpath, timeout=30000):
        """ copies a file from local to remote host
            :param file: file name of file to be copied
            :type: string
            :param srcpath: full path of file to be copied
            :type: string
            :param dstpath: full path of destination
            :type: string
            :param timeout: value in ms
            :type: int
        """
        session = self._ssh2._session
        session.set_timeout(timeout)
        fileinfo = os.stat(srcpath)
        file_size = fileinfo.st_size
        self.chan = session.scp_send64(
            dstpath,
            fileinfo.st_mode & 0o777,
            fileinfo.st_size,
            fileinfo.st_mtime,
            fileinfo.st_atime,
        )
        total_bytes_written = 0
        logger.debug("{}, size {}".format(file, file_size))
        with open(srcpath, "rb") as local_fh:
            while total_bytes_written < file_size:
                data = local_fh.read(_RECVSZ)
                rc, bytes_written = self.chan.write(data)
                total_bytes_written += bytes_written
                if self._callback:
                    self._callback(file, file_size, total_bytes_written)
            logger.debug("file {} completed".format(file))

    def scp_recv(self, file, srcpath, dstpath, timeout=30000):
        """ copies a file from remote to local host
            :param file: file name of file to be copied
            :type: string
            :param srcpath: full path of file to be copied
            :type: string
            :param dstpath: full path of destination
            :type: string
            :param timeout: value in ms
            :type: int
        """
        session = self._ssh2._session
        session.set_timeout(timeout)
        chan = session.scp_recv2(srcpath)
        self.chan = chan[0]
        total_bytes_written = 0
        file_size = chan[1].st_size
        logger.debug("{}, size {}".format(file, file_size))
        with open(dstpath, "ab") as local_fh:
            while total_bytes_written < file_size:
                rc, data = self.chan.read(_RECVSZ)
                if file_size - total_bytes_written < _RECVSZ:
                    # remove EOF from end of byte stream
                    data = data.rstrip(b"\0")
                    rc -= 1
                local_fh.write(data)
                total_bytes_written += rc
                if self._callback:
                    self._callback(file, file_size, total_bytes_written)
            logger.debug("file {} completed".format(file))

    def close(self):
        """ terminates the channel
            :returns None:
        """
        if self.chan is None:
            return
        self.chan.send_eof()
        self.chan.wait_eof()
        self.chan.wait_closed()

