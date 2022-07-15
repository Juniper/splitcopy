""" Copyright (c) 2018, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""

# stdlib on *nix, 3rd party on win32
import curses

# stdlib
import logging
import time
from shutil import get_terminal_size
from threading import Thread

# local modules
from splitcopy.shared import pad_string

logger = logging.getLogger(__name__)


def percent_val(total_amount, partial_amount):
    """returns a percentage
    :param total_amount:
    :type int:
    :param partial_amount:
    :type int:
    :return int:
    """
    return int(round(100 / total_amount * partial_amount, 2))


def progress_bar(percent_done):
    """returns a graphical progress bar as a string
    :param percent_done:
    :type int:
    :return string:
    """
    return f"[{'#' * int(percent_done/2)}{(50 - int(percent_done/2)) * ' '}]"


def bytes_display(num_bytes):
    """Function that returns a string identifying the size of the number
    :param num_bytes:
    :type int:
    :return amount:
    :type float:
    :return unit:
    :type string:
    """
    amount = 0.0
    unit = ""
    if num_bytes < 1024**2:
        amount = num_bytes / 1024
        unit = "KB"
    elif num_bytes < 1024**3:
        amount = num_bytes / 1024**2
        unit = "MB"
    elif num_bytes < 1024**4:
        amount = num_bytes / 1024**3
        unit = "GB"
    return amount, unit


def prepare_curses():
    """Function to do some prep work to use curses.
    :return stdscr:
    :type _curses.window object:
    """
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    return stdscr


def abandon_curses():
    """Function to exit curses and restore terminal to prior state.
    :return None:
    """
    try:
        curses.nocbreak()
        curses.echo()
        curses.endwin()
    except (curses.error, AttributeError):
        pass


class Progress:
    """class which both FTP and SCPClient calls back to.
    provides a progress meter to the user
    """

    def __init__(self):
        """Initialize the class"""
        self.chunks = []
        self.chunk_size = ""
        self.totals = {}
        self.error_list = ["", "", ""]
        self.files = {}
        self.curses = False
        self.stdscr = None
        self.timer = None
        self.stop_timer = False

    def add_chunks(self, total_file_size, chunks):
        """Function that creates required data structures
        :param chunks:
        :type list:
        :return None:
        """
        self.chunks = chunks
        self.chunk_size = str(chunks[0][1])
        for chunk in chunks:
            file_name = chunk[0]
            self.files[file_name] = {}
            self.files[file_name]["sent_bytes"] = 0
            self.files[file_name]["last_sent_bytes"] = 0
            self.files[file_name]["bytes_per_sec"] = 0.0
            self.files[file_name]["percent_done"] = 0
            self.files[file_name]["complete"] = 0
        self.totals["sum_bytes_sent"] = 0
        self.totals["sum_completed"] = 0
        self.totals["sum_bytes_per_sec"] = 0.0
        self.totals["percent_done"] = 0
        self.totals["total_file_size"] = total_file_size

    def check_term_size(self, result):
        """function that checks whether curses can be supported or not
        preferable to do this prior to initiating a curses window
        :param result:
        :type bool:
        :return result:
        :type bool:
        """
        if result:
            term_width, term_height = get_terminal_size()
            req_height = len(self.chunks) + 4
            if term_height < req_height:
                result = False
            if not result:
                print("terminal window is too small to display per-chunk statistics")
        return result

    def initiate_timer_thread(self):
        """Function that starts a single thread
        :return None:
        """
        self.timer = Thread(
            name="refresh_timer",
            target=self.refresh_timer,
            args=(1, lambda: self.stop_timer),
        )
        self.timer.start()

    def refresh_timer(self, thread_id, stop):
        """Function that calls other functions to update data that is then displayed
        to the user once a second
        :param thread_id:
        :type int: # required for Thread(), otherwise unused
        :param stop:
        :type function: # allows loop to be exited gracefully
        :return None:
        """
        while True:
            if stop():
                break
            self.rates_update()
            self.totals_update()
            if self.curses:
                self.update_screen_contents()
                # add a newline to the end of the error list
                # pushing older errors out of the curses display
                self.print_error("")
                # remove the 1st element from the error_list
                # effectively making it a circular buffer
                del self.error_list[0]
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
        percent_done = percent_val(file_size, sent)
        if self.files[file_name]["percent_done"] != percent_done:
            self.files[file_name]["percent_done"] = percent_done

    def totals_update(self):
        """Function that determines the total number of bytes sent,
        the total percentage of bytes transferred and how many of
        the chunks are completed
        :return None:
        """
        sum_bytes_sent = 0
        sum_completed = 0
        total_file_size = self.totals["total_file_size"]
        for file in self.files.values():
            sum_bytes_sent += file["sent_bytes"]
            sum_completed += file["complete"]
        self.totals["sum_bytes_sent"] = sum_bytes_sent
        self.totals["sum_completed"] = sum_completed
        percent_done = percent_val(total_file_size, sum_bytes_sent)
        self.totals["percent_done"] = percent_done
        logger.debug(self.totals)

    def total_progress_str(self):
        """returns a single line with progress info such as:
            % done, number of bytes transferred etc
        :return output:
        :type string:
        """
        percent_done = self.totals["percent_done"]
        sum_completed = self.totals["sum_completed"]
        sum_bytes_per_sec = self.totals["sum_bytes_per_sec"]
        sum_bytes_sent = self.totals["sum_bytes_sent"]
        total_file_size = self.totals["total_file_size"]
        sum_bytes, sum_bytes_unit = bytes_display(sum_bytes_sent)
        total_bytes, total_bytes_unit = bytes_display(total_file_size)
        rate_per_sec, rate_unit = bytes_display(sum_bytes_per_sec)
        output = (
            f"{str(percent_done)}% done {sum_bytes:.1f}{sum_bytes_unit}"
            f"/{total_bytes:.1f}{total_bytes_unit} "
            f"{rate_per_sec:>6.1f}{rate_unit}/s "
            f"({sum_completed}/{len(self.chunks)} chunks completed)"
        )
        return output

    def rates_update(self):
        """updates the transfer rates per chunk and total. Called on a 1sec periodic
        :return None:
        """
        sum_bytes_per_sec = 0.0
        for file in self.chunks:
            file_name = file[0]
            sent_bytes = self.files[file_name]["sent_bytes"]
            last_sent_bytes = self.files[file_name]["last_sent_bytes"]
            bytes_per_sec = sent_bytes - last_sent_bytes
            self.files[file_name]["last_sent_bytes"] = sent_bytes
            self.files[file_name]["bytes_per_sec"] = bytes_per_sec
            sum_bytes_per_sec += bytes_per_sec
        self.totals["sum_bytes_per_sec"] = sum_bytes_per_sec

    def zero_file_stats(self, file_name):
        """Function that resets a files stats if transfer is restarted
        :param file_name:
        :type string:
        :return None:
        """
        self.files[file_name]["last_sent_bytes"] = 0
        self.files[file_name]["bytes_per_sec"] = 0
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
            if len(file_name) > 10:
                file_name_str = f"{file_name[0:6]}..{file_name[-2:]}"
            else:
                file_name_str = file_name
            sent_bytes, sent_bytes_unit = bytes_display(
                self.files[file_name]["sent_bytes"]
            )
            bytes_per_sec, bytes_per_sec_unit = bytes_display(
                self.files[file_name]["bytes_per_sec"]
            )
            percent_done = self.files[file_name]["percent_done"]
            txt_lines.append(
                f"{file_name_str} {progress_bar(percent_done)} "
                f"{percent_done:>3}% {sent_bytes:>6.1f}{sent_bytes_unit} "
                f"{bytes_per_sec:>6.1f}{bytes_per_sec_unit}/s"
            )
        txt_lines.append(pad_string(""))
        txt_lines.append(f"{pad_string(self.total_progress_str())}")
        # display the three most recent error strings
        err_idx = -3
        while err_idx < 0:
            txt_lines.append(self.error_list[err_idx])
            err_idx += 1
        try:
            self.redraw_screen(txt_lines)
        except curses.error:
            abandon_curses()
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
            # when using curses window, \n results in the following line starting
            # at the column the previous line ended at. This quickly becomes
            # illegible. Idea here is to put any error logs in a list
            # and only display the most recent additions in update_screen_contents()
            padded_string = pad_string(error)
            self.error_list.append(f"{padded_string}")

    def start_progress(self, use_curses):
        """Function that starts the timer thread (and thus progress output
        Initiates the curses window (if applicable)
        :param use_curses:
        :type bool:
        :return None:
        """
        self.curses = self.check_term_size(use_curses)
        if self.curses:
            self.stdscr = prepare_curses()
        self.initiate_timer_thread()

    def stop_progress(self):
        """Function that stops the timer thread (and thus progress output)
        Then shuts down the curses window (if applicable)
        :return None:
        """
        self.stop_timer_thread()
        abandon_curses()

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
