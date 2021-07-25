""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

# stdlib
import logging

logger = logging.getLogger(__name__)


class Progress:
    """ class which both FTP and SCPClient calls back to.
        provides a progress meter to the user
        TODO, provide per file values as well as total value.
            issue is using the below method will not overwrite
            correctly if line length > tty columns.
            NCURSES is an option, but not cross-platform
    """

    def __init__(self, total_file_size):
        """ Initialise the Progress class
        """
        self.total_file_size = total_file_size
        self.last_percent = 0
        self.sent_sum = 0
        self.files_bytes = {}

    def handle(self, file_name, file_size, sent):
        """ For every % of data transferred, notifies the user
            :param file_name: name of file
            :type: string
            :param size: file size in bytes
            :type: int
            :param sent: bytes transferred
            :type: int
        """
        self.files_bytes[file_name] = sent
        logger.debug(self.files_bytes)
        sent_values = list(self.files_bytes.values())
        self.sent_sum = sum(sent_values)
        total_percent_done = int((100 / self.total_file_size) * self.sent_sum)
        if self.last_percent != total_percent_done:
            self.last_percent = total_percent_done
            print("\r{}% done".format(str(total_percent_done)), end="")
