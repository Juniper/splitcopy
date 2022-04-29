""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

# stdlib
import logging
import os
import time

try:
    import curses
except:
    pass

logger = logging.getLogger(__name__)


class Progress:
    """class which both FTP and SCPClient calls back to.
    provides a progress meter to the user
    TODO, provide per file values as well as total value.
        issue is using the below method will not overwrite
        correctly if line length > tty columns.
        NCURSES is an option, but not cross-platform
    """

    def __init__(self, total_file_size, chunks, nocurses):
        """Initialise the Progress class"""
        self.total_file_size = total_file_size
        self.chunks = chunks
        self.nocurses = nocurses
        self.chunks_complete = {}
        self.last_percent = 0
        self.sent_bytes = {}
        self.ts_bytes = {}
        self.percent_done = {}
        self.stdscr = None
        self.ts = time.time()
        self.chunk_size = len(str(chunks[0][1]))
        self.no_refresh = False
        for chunk in chunks:
            file_name = chunk[0]
            self.sent_bytes[file_name] = 0
            self.ts_bytes[file_name] = {}
            self.ts_bytes[file_name]["last_ts"] = time.time()
            self.ts_bytes[file_name]["last_kb"] = 0
            self.ts_bytes[file_name]["kb_rate"] = 0
            self.percent_done[file_name] = 0
        if not self.nocurses:
            self.prepare_curses()

    def percent_val(self, total_amount, partial_amount):
        return int((100 / total_amount) * partial_amount)

    def progress_bar(self, file_name, percent_done):
        return f"[{'#' * int(percent_done/2)}{(50 - int(percent_done/2)) * ' '}]"

    def report_progress(self, file_name, file_size, sent):
        """For every % of data transferred, notifies the user
        :param file_name: name of file
        :type: string(from FTP lib) or bytes(from SCP lib)
        :param size: file size in bytes
        :type: int
        :param sent: bytes transferred
        :type: int
        """
        try:
            file_name = file_name.decode()
        except AttributeError:
            pass
        self.sent_bytes[file_name] = sent
        logger.debug(self.sent_bytes)
        if file_size == sent:
            self.chunks_complete[file_name] = 1
        else:
            self.chunks_complete[file_name] = 0
        sent_values = list(self.sent_bytes.values())
        sent_sum = sum(sent_values)
        sum_completed = sum(self.chunks_complete.values())
        total_percent_done = self.percent_val(self.total_file_size, sent_sum)

        if os.name == "nt" or self.nocurses:
            self.windows_progress(sent_sum, sum_completed, total_percent_done)
        else:
            self.unix_progress(
                sent_sum, sum_completed, total_percent_done, file_name, file_size, sent
            )

    def windows_progress(self, sent_sum, sum_completed, total_percent_done):
        if self.last_percent != total_percent_done:
            self.last_percent = total_percent_done
            print(
                f"\r{str(total_percent_done)}% done {int(sent_sum/1024)}/{int(self.total_file_size/1024)}KB "
                f"({sum_completed}/{len(self.chunks)} chunks completed)",
                end="",
            )

    def unix_progress(
        self, sent_sum, sum_completed, total_percent_done, file_name, file_size, sent
    ):
        percent_done = self.percent_val(file_size, sent)
        if self.percent_done[file_name] == percent_done:
            return
        else:
            self.percent_done[file_name] = percent_done
        if self.last_percent != total_percent_done:
            self.last_percent = total_percent_done
        if time.time() > self.ts + 0.05:
            self.ts = time.time()
            txt_lines = []
            txt_lines.append(
                f"{str(total_percent_done)}% done {int(sent_sum/1024)}/{int(self.total_file_size/1024)}KB "
                f"({sum_completed}/{len(self.chunks)} chunks completed)"
            )
            for file in self.chunks:
                file_name = file[0]
                percent_done = self.percent_done[file_name]
                sent_kbytes = int(self.sent_bytes[file_name] / 1024)
                last_ts = self.ts_bytes[file_name]["last_ts"]
                last_kb = self.ts_bytes[file_name]["last_kb"]
                kb_rate = self.ts_bytes[file_name]["kb_rate"]
                current_ts = time.time()
                if current_ts >= last_ts + 1:
                    kb_rate = float(sent_kbytes - last_kb)
                    self.ts_bytes[file_name]["last_ts"] = current_ts
                    self.ts_bytes[file_name]["last_kb"] = sent_kbytes
                    self.ts_bytes[file_name]["kb_rate"] = kb_rate
                txt_lines.append(
                    f"{file_name} {self.progress_bar(file_name, percent_done)} {percent_done:>3}% {sent_kbytes:>{self.chunk_size}}KB {kb_rate:>6.1f}KB/s"
                )
            txt_lines.append("")
            if not self.no_refresh:
                self.redraw_screen(txt_lines)

    def prepare_curses(self):
        """
        Function to do some prep work to use curses.
        """
        if os.name == "nt":
            return
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()

    def abandon_curses(self):
        """
        Function to restore terminal once curses exits.
        """
        if os.name == "nt":
            return
        self.no_refresh = True
        try:
            curses.nocbreak()
            curses.echo()
            curses.endwin()
        except curses.error:
            pass

    def redraw_screen(self, txt_lines):
        """
        Method to redraw the screen using CURSES library.

        Inputs:
            - txt_lines: list of lines
            - stdscr: curses.cursew window object
        """
        lines = len(txt_lines)
        for line in range(lines):
            self.stdscr.addstr(line, 0, txt_lines[line])
        self.stdscr.refresh()
