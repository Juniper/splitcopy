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
    """class which both FTP and SCPClient calls back to.
    provides a progress meter to the user
    TODO, provide per file values as well as total value.
        issue is using the below method will not overwrite
        correctly if line length > tty columns.
        NCURSES is an option, but not cross-platform
    """

    def __init__(self, total_file_size, num_chunks):
        """Initialise the Progress class"""
        self.total_file_size = total_file_size
        self.num_chunks = num_chunks
        self.chunks_complete = {}
        self.last_percent = 0
        self.files_bytes = {}

    def report_progress(self, file_name, file_size, sent):
        """For every % of data transferred, notifies the user
        :param file_name: name of file
        :type: string
        :param size: file size in bytes
        :type: int
        :param sent: bytes transferred
        :type: int
        """
        self.files_bytes[file_name] = sent
        logger.debug(self.files_bytes)
        if file_size == sent:
            self.chunks_complete[file_name] = 1
        else:
            self.chunks_complete[file_name] = 0
        sent_values = list(self.files_bytes.values())
        sent_sum = sum(sent_values)
        sum_completed = sum(self.chunks_complete.values())
        total_percent_done = int((100 / self.total_file_size) * sent_sum)
        if self.last_percent != total_percent_done:
            self.last_percent = total_percent_done
            print(
                f"\r{str(total_percent_done)}% done "
                f"({sum_completed}/{self.num_chunks} chunks completed)",
                end="",
            )