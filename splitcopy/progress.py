""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

# stdlib
from decimal import DivisionByZero
import logging
import time
import os
from threading import Thread

# stdlib on *nix, 3rd party on win32
import curses

logger = logging.getLogger(__name__)


class Progress:
    """class which both FTP and SCPClient calls back to.
    provides a progress meter to the user
    """

    def __init__(self, total_file_size, chunks, use_curses):
        """Initialize the class
        :param total_file_size:
        :type int:
        :param chunks:
        :type list:
        :param curses:
        :type bool:
        :return None:
        """
        self.chunks = chunks
        self.ts = time.time()
        self.chunk_size = str(chunks[0][1])
        self.totals = {}
        self.totals["sum_sent"] = 0
        self.totals["sum_completed"] = 0
        self.totals["sum_kbps"] = 0.0
        self.totals["percent_done"] = 0
        self.totals["total_file_size"] = total_file_size
        self.files = {}
        for chunk in chunks:
            file_name = chunk[0]
            self.files[file_name] = {}
            self.files[file_name]["last_kb"] = 0.0
            self.files[file_name]["kb_rate"] = 0.0
            self.files[file_name]["percent_done"] = 0
            self.files[file_name]["sent_bytes"] = 0
            self.files[file_name]["complete"] = 0
        self.curses = self.check_term_size(use_curses)
        if self.curses:
            self.stdscr = self.prepare_curses()
        self.timer = None
        self.stop_timer = False
        self.initiate_timer_thread()

    def check_term_size(self, result):
        """function that checks whether curses can be supported or not
        preferable to do this prior to initiating a curses window
        :param result:
        :type bool:
        :return result:
        :type bool:
        """
        if result:
            term_width, term_height = os.get_terminal_size()
            req_height = len(self.chunks) + 4
            if term_height < req_height:
                result = False
            if term_width < 100:
                result = False
            if not result:
                print("terminal window is too small to display per-chunk statistics")
        return result

    def initiate_timer_thread(self):
        """Function that starts a single thread
        :return None:
        """
        self.timer = Thread(
            name="one_sec_timer",
            target=self.one_sec_timer,
            args=(1, lambda: self.stop_timer),
        )
        self.timer.start()

    def one_sec_timer(self, thread_id, stop):
        """Function that calls other functions to update data that is then displayed
        to the user once a second
        :param thread_id:
        :type int: # required for Thread(), otherwise unused
        :param stop:
        :type bool: # allows loop to be exited gracefully
        :return None:
        """
        while True:
            if stop():
                break
            self.kbps_update()
            self.totals_update()
            if self.curses:
                self.update_screen_contents()
            else:
                self.disp_total_progress()
            time.sleep(1)

    def stop_timer_thread(self):
        """function that causes the timer thread to exit
        :returns None:
        """
        self.stop_timer = True
        try:
            self.timer.join()
        except (AttributeError, RuntimeError):
            pass

    def report_progress(self, file_name, file_size, sent):
        """For every % of data transferred, notifies the user
        :param file_name: name of file
        :type string: (from FTP lib) or bytes(from SCP lib)
        :param file_size: file size in bytes
        :type int:
        :param sent: bytes transferred
        :type int:
        :return None:
        """
        try:
            file_name = file_name.decode()
        except AttributeError:
            # FTP lib uses string already
            pass
        if file_size == sent:
            self.files[file_name]["complete"] = 1
        else:
            self.files[file_name]["complete"] = 0
        self.files[file_name]["sent_bytes"] = sent
        self.file_percentage_update(file_name, file_size, sent)

    def disp_total_progress(self):
        """Function that outputs progress string when curses is not used
        :return None:
        """
        print(f"\r{self.total_progress_str()}", end="")

    def file_percentage_update(self, file_name, file_size, sent):
        """Function to update the percent complete for a given file
        :param file_name:
        :type string:
        :param file_size:
        :type int:
        :param sent:
        :type int:
        :return None:
        """
        percent_done = self.percent_val(file_size, sent)
        if self.files[file_name]["percent_done"] != percent_done:
            self.files[file_name]["percent_done"] = percent_done

    def totals_update(self):
        """Function that determines the total number of bytes sent,
        the total percentage of bytes transferred and how many of
        the chunks are completed
        :return None:
        """
        sum_sent = 0
        sum_completed = 0
        for file in self.files:
            sum_sent += self.files[file]["sent_bytes"]
            sum_completed += self.files[file]["complete"]
        self.totals["sum_sent"] = sum_sent
        self.totals["sum_completed"] = sum_completed
        total_file_size = self.totals["total_file_size"]
        percent_done = self.percent_val(total_file_size, sum_sent)
        self.totals["percent_done"] = percent_done

    def total_progress_str(self):
        """returns a single line with progress info such as:
            % done, number of bytes transferred etc
        :return output:
        :type string:
        """
        percent_done = self.totals["percent_done"]
        sum_completed = self.totals["sum_completed"]
        sum_kbps = self.totals["sum_kbps"]
        sum_sent = self.totals["sum_sent"]
        total_file_size = self.totals["total_file_size"]

        sum_sent_kb = 0
        try:
            sum_sent_kb = int(sum_sent / 1024)
        except DivisionByZero:
            pass
        output = (
            f"{str(percent_done)}% done {sum_sent_kb}"
            f"/{int(total_file_size/1024)} KB "
            f"{sum_kbps:>6.1f} KB/s "
            f"({sum_completed}/{len(self.chunks)} chunks completed)"
        )
        return output

    def percent_val(self, total_amount, partial_amount):
        """returns a percentage
        :param total_amount:
        :type int:
        :param partial_amount:
        :type int:
        :return int:
        """
        return int((100 / total_amount) * partial_amount)

    def progress_bar(self, percent_done):
        """returns a graphical progress bar as a string
        :param percent_done:
        :type int:
        :return string:
        """
        return f"[{'#' * int(percent_done/2)}{(50 - int(percent_done/2)) * ' '}]"

    def kbps_update(self):
        """updates the KBps per chunk and total. Called on a 1sec periodic
        :return None:
        """
        sum_kbps = 0.0
        for file in self.chunks:
            file_name = file[0]
            try:
                sent_kbytes = self.files[file_name]["sent_bytes"] / 1024
            except DivisionByZero:
                sent_kbytes = 0
            last_kb = self.files[file_name]["last_kb"]
            kb_rate = float(sent_kbytes - last_kb)
            self.files[file_name]["last_kb"] = int(sent_kbytes)
            self.files[file_name]["kb_rate"] = kb_rate
            sum_kbps += kb_rate
        self.totals["sum_kbps"] = sum_kbps

    def zero_file_stats(self, file_name):
        """Function that resets a files stats if transfer is restarted
        :param file_name:
        :type string:
        :return None:
        """
        self.files[file_name]["last_kb"] = 0
        self.files[file_name]["kb_rate"] = 0
        self.files[file_name]["percent_done"] = 0
        self.files[file_name]["sent_bytes"] = 0
        self.files[file_name]["complete"] = 0

    def update_screen_contents(self):
        """Function collates the information to be drawn by curses
        :return None:
        """
        txt_lines = []
        for file in self.chunks:
            file_name = file[0]
            last_kb = self.files[file_name]["last_kb"]
            kb_rate = self.files[file_name]["kb_rate"]
            percent_done = self.files[file_name]["percent_done"]
            txt_lines.append(
                f"{file_name} {self.progress_bar(percent_done)} "
                f"{percent_done:>3}% {last_kb:>6}KB {kb_rate:>6.1f}KB/s"
            )
        txt_lines.append("")
        txt_lines.append(f"{self.total_progress_str()}\n")
        try:
            self.redraw_screen(txt_lines)
        except curses.error:
            self.abandon_curses()
            self.curses = False

    def print_error(self, error):
        """correctly output errors when curses window is active or not
        :param error:
        :type string:
        :return None:
        """
        if not self.curses:
            print(f"\n{error}")
        else:
            # when using curses window, \n results in broken output
            term_width = os.get_terminal_size()[0]
            padding = " " * (term_width - len(error))
            print(f"\r{error}{padding}")

    def stop_progress(self):
        """Function that stops the timer thread (and thus progress output)
        Then shuts down the curses window (if applicable)
        :return None:
        """
        self.stop_timer_thread()
        self.abandon_curses()

    def prepare_curses(self):
        """Function to do some prep work to use curses.
        :return stdscr:
        :type _curses.window object:
        """
        stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        return stdscr

    def abandon_curses(self):
        """Function to exit curses and restore terminal to prior state.
        :return None:
        """
        try:
            curses.nocbreak()
            curses.echo()
            curses.endwin()
        except (curses.error, AttributeError):
            pass

    def redraw_screen(self, txt_lines):
        """Method to redraw the screen using curses library.
        :param txt_lines:
        :type list:
        :return None:
        """
        lines = len(txt_lines)
        for line in range(lines):
            # using format 'y-axis, x-axis, string'
            self.stdscr.addstr(line, 0, txt_lines[line])
        self.stdscr.refresh()
