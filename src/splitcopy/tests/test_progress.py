from curses import error as curses_error
from threading import Thread

from pytest import MonkeyPatch
from splitcopy.progress import (
    Progress,
    abandon_curses,
    bytes_display,
    percent_val,
    prepare_curses,
    progress_bar,
)


def get_chunk_data():
    chunks = [
        ["chunk0", 1024],
        ["chunk1", 1024],
        ["chunk2", 1024],
        ["chunk3", 1024],
        ["chunk4", 1024],
        ["chunk5", 1024],
        ["chunk6", 1024],
        ["chunk7", 1024],
        ["chunk8", 1024],
        ["chunk9", 1024],
        ["chunk10", 1024],
        ["chunk11", 1024],
        ["chunk12", 1024],
        ["chunk13", 1024],
        ["chunk14", 1024],
        ["chunk15", 1024],
        ["chunk16", 1024],
        ["chunk17", 1024],
        ["chunk18", 1024],
        ["chunk19", 1024],
        ["chunk20", 1024],
    ]
    total_file_size = 21504
    return total_file_size, chunks


class Test_Progress:
    def test_percent_val(self):
        expected = 10
        result = percent_val(100, 10)
        assert result == expected

    def test_progress_bar(self):
        expected = "[#####" + " " * 45 + "]"
        result = progress_bar(10)
        assert result == expected

    def test_bytes_display_kb(self):
        expected = (0.48828125, "KB")
        result = bytes_display(500)
        assert result == expected

    def test_bytes_display_mb(self):
        expected = (4.76837158203125, "MB")
        result = bytes_display(5000000)
        assert result == expected

    def test_bytes_display_gb(self):
        expected = (4.656612873077393, "GB")
        result = bytes_display(5000000000)
        assert result == expected

    def test_prepare_curses(self, monkeypatch: MonkeyPatch):
        expected = True
        monkeypatch.setattr("curses.initscr", lambda: True)
        monkeypatch.setattr("curses.noecho", lambda: True)
        monkeypatch.setattr("curses.cbreak", lambda: True)
        result = prepare_curses()
        assert result == expected

    def test_abandon_curses_fail(self, monkeypatch: MonkeyPatch):
        def nocbreak():
            raise AttributeError

        monkeypatch.setattr("curses.nocbreak", nocbreak)
        result = abandon_curses()
        expected = None
        assert result == expected

    def test_abandon_curses(self, monkeypatch: MonkeyPatch):
        expected = None
        monkeypatch.setattr("curses.nocbreak", lambda: True)
        monkeypatch.setattr("curses.echo", lambda: True)
        monkeypatch.setattr("curses.endwin", lambda: True)
        result = abandon_curses()
        assert result == expected

    def test_check_term_size_nocurses(self):
        expected = False
        progress = Progress()
        result = progress.check_term_size(False)
        assert result == expected

    def test_check_term_size_is_too_big(self):
        expected = False
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        # shutil.get_terminal_size() will by default return 80,24
        # as self.chunks + 4 > 24 it should fail
        result = progress.check_term_size(True)
        assert result == expected

    def test_check_term_size_is_ok(self):
        expected = True
        # make len(chunks) == 20
        total_file_size, chunks = get_chunk_data()
        del chunks[0]
        progress = Progress()
        progress.add_chunks(total_file_size, chunks)
        # shutil.get_terminal_size() will by default return 80,24
        # as self.chunks + 4 <= 24 it should return True
        result = progress.check_term_size(True)
        assert result == expected

    def test_initiate_timer_thread(self):
        expected = None
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.stop_timer = True
        result = progress.initiate_timer_thread()
        assert result == expected

    def test_refresh_timer_stop(self):
        expected = True
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        self.stop_timer = True
        timer = Thread(
            name="testing_refresh_timer",
            target=progress.refresh_timer,
            args=(1, lambda: self.stop_timer),
        )
        timer.start()
        timer.join()  # loop must have exited or this wouldn't sucessfully stop the thread
        result = timer._is_stopped
        assert result == expected

    def test_refresh_timer_nocurses(self, monkeypatch: MonkeyPatch):
        expected = True

        def rates_update(self):
            pass

        def totals_update(self):
            pass

        monkeypatch.setattr(Progress, "rates_update", rates_update)
        monkeypatch.setattr(Progress, "totals_update", totals_update)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        self.stop_timer = False
        timer = Thread(
            name="testing_refresh_timer",
            target=progress.refresh_timer,
            args=(1, lambda: self.stop_timer),
        )
        timer.start()
        self.stop_timer = True
        timer.join()
        result = timer._is_stopped
        assert result == expected

    def test_refresh_timer_curses(self, monkeypatch: MonkeyPatch):
        expected = True

        def rates_update(self):
            pass

        def totals_update(self):
            pass

        def update_screen_contents(self):
            pass

        def print_error(self, error):
            pass

        monkeypatch.setattr(Progress, "rates_update", rates_update)
        monkeypatch.setattr(Progress, "totals_update", totals_update)
        monkeypatch.setattr(Progress, "update_screen_contents", update_screen_contents)
        monkeypatch.setattr(Progress, "print_error", print_error)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.curses = True
        self.stop_timer = False
        timer = Thread(
            name="testing_refresh_timer",
            target=progress.refresh_timer,
            args=(1, lambda: self.stop_timer),
        )
        timer.start()
        self.stop_timer = True
        timer.join()
        result = timer._is_stopped
        assert result == expected

    def test_stop_timer_thread_fail(self):
        class timer:
            def join():
                raise AttributeError

        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.timer = timer
        result = progress.stop_timer_thread()
        expected = None
        assert result == expected

    def test_stop_timer_thread(self):
        expected = True

        def loop_thread(self, stop):
            while True:
                if stop():
                    break

        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.timer = Thread(
            name="testing_stop_timer_thread",
            target=loop_thread,
            args=(1, lambda: progress.stop_timer),
        )
        progress.timer.start()
        progress.stop_timer_thread()
        result = progress.timer._is_stopped
        assert result == expected

    def test_report_progress_complete(self, monkeypatch: MonkeyPatch):
        expected = True

        def file_percentage_update(self, file_name, file_size, sent):
            pass

        file_name = "chunk20"
        file_size = 20
        sent = 20
        monkeypatch.setattr(Progress, "file_percentage_update", file_percentage_update)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.report_progress(file_name, file_size, sent)
        result = progress.files[file_name]["complete"]
        assert result == expected

    def test_report_progress_incomplete(self, monkeypatch: MonkeyPatch):
        expected = False

        def file_percentage_update(self, file_name, file_size, sent):
            pass

        file_name = "chunk20"
        file_size = 20
        sent = 19
        monkeypatch.setattr(Progress, "file_percentage_update", file_percentage_update)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.report_progress(file_name, file_size, sent)
        result = progress.files[file_name]["complete"]
        assert result == expected

    def test_disp_total_progress(self, capsys, monkeypatch: MonkeyPatch):
        expected = "\rfoo"

        def total_progress_str(self):
            return "foo"

        monkeypatch.setattr(Progress, "total_progress_str", total_progress_str)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.disp_total_progress()
        captured = capsys.readouterr()
        result = captured.out
        assert result == expected

    def test_file_percentage_update(self, monkeypatch: MonkeyPatch):
        expected = 10
        file_name = "chunk20"
        file_size = 1024
        sent = 102

        def percent_val(file_size, sent):
            return 10

        monkeypatch.setattr("splitcopy.progress.percent_val", percent_val)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.file_percentage_update(file_name, file_size, sent)
        result = progress.files[file_name]["percent_done"]
        assert result == expected

    def test_totals_update(self, monkeypatch: MonkeyPatch):
        expected = (1024, 1, 4)

        def percent_val(file_size, sent):
            return 4

        monkeypatch.setattr("splitcopy.progress.percent_val", percent_val)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.files["chunk0"]["sent_bytes"] = 1024
        progress.files["chunk0"]["complete"] = 1
        progress.totals_update()
        sum_bytes_sent = progress.totals["sum_bytes_sent"]
        sum_completed = progress.totals["sum_completed"]
        percent_done = progress.totals["percent_done"]
        result = (sum_bytes_sent, sum_completed, percent_done)
        assert result == expected

    def test_total_progress_str(self, monkeypatch: MonkeyPatch):
        expected = "0% done 0.0KB/0.0KB    0.0KB/s (0/21 chunks completed)"

        def bytes_display(byte_val):
            return 0.0, "KB"

        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        monkeypatch.setattr("splitcopy.progress.bytes_display", bytes_display)
        result = progress.total_progress_str()
        assert result == expected

    def test_rates_update(self):
        expected = 1024
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.files["chunk0"]["sent_bytes"] = 1024
        progress.rates_update()
        result = progress.totals["sum_bytes_per_sec"]
        assert result == expected

    def test_zero_file_stats(self):
        expected = 0
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.files["chunk0"]["sent_bytes"] = 1024
        progress.zero_file_stats("chunk0")
        result = progress.files["chunk0"]["sent_bytes"]
        assert result == expected

    def test_update_screen_contents(self, capsys, monkeypatch: MonkeyPatch):
        expected = (
            f"['chunk0 [{' ' * 50}]   0%    0.0KB    0.0KB/s', "
            f"'chunk1 [{' ' * 50}]   0%    0.0KB    0.0KB/s', "
            f"'chunk2 [{' ' * 50}]   0%    0.0KB    0.0KB/s', "
            "'', "
            "'0% done 0.0KB/0.0KB    0.0KB/s (0/3 chunks completed)', "
            "'', "
            "'', "
            "'']\n"
        )

        def progress_bar(percent_done):
            return f"[{' ' * 50}]"

        def bytes_display(num_bytes):
            return 0.0, "KB"

        def pad_string(foo):
            return foo

        def total_progress_str(self):
            return "0% done 0.0KB/0.0KB    0.0KB/s (0/3 chunks completed)"

        def redraw_screen(self, txt_lines):
            print(txt_lines)

        monkeypatch.setattr("splitcopy.progress.progress_bar", progress_bar)
        monkeypatch.setattr("splitcopy.progress.bytes_display", bytes_display)
        monkeypatch.setattr("splitcopy.progress.pad_string", pad_string)
        monkeypatch.setattr(Progress, "total_progress_str", total_progress_str)
        monkeypatch.setattr(Progress, "redraw_screen", redraw_screen)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        del chunks[3:21]
        progress.add_chunks(total_file_size, chunks)
        progress.update_screen_contents()
        captured = capsys.readouterr()
        result = captured.out
        assert result == expected

    def test_update_screen_contents_fail(self, monkeypatch: MonkeyPatch):
        def progress_bar(percent_done):
            return f"[{' ' * 50}]"

        def bytes_display(num_bytes):
            return 0.0, "KB"

        def pad_string(foo):
            return foo

        def total_progress_str(self):
            return "0% done 0.0KB/0.0KB    0.0KB/s (0/3 chunks completed)"

        def redraw_screen(self, txt_lines):
            raise curses_error

        monkeypatch.setattr("splitcopy.progress.progress_bar", progress_bar)
        monkeypatch.setattr("splitcopy.progress.bytes_display", bytes_display)
        monkeypatch.setattr("splitcopy.progress.pad_string", pad_string)
        monkeypatch.setattr(Progress, "total_progress_str", total_progress_str)
        monkeypatch.setattr(Progress, "redraw_screen", redraw_screen)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        progress.update_screen_contents()
        result = progress.curses
        expected = False
        assert result == expected

    def test_update_screen_contents_longfilename(
        self, capsys, monkeypatch: MonkeyPatch
    ):
        expected = (
            f"['somelo..e0 [{' ' * 50}]   0%    0.0KB    0.0KB/s', "
            f"'somelo..e1 [{' ' * 50}]   0%    0.0KB    0.0KB/s', "
            f"'somelo..e2 [{' ' * 50}]   0%    0.0KB    0.0KB/s', "
            "'', "
            "'0% done 0.0KB/0.0KB    0.0KB/s (0/3 chunks completed)', "
            "'', "
            "'', "
            "'']\n"
        )

        def progress_bar(percent_done):
            return f"[{' ' * 50}]"

        def bytes_display(num_bytes):
            return 0.0, "KB"

        def pad_string(foo):
            return foo

        def total_progress_str(self):
            return "0% done 0.0KB/0.0KB    0.0KB/s (0/3 chunks completed)"

        def redraw_screen(self, txt_lines):
            print(txt_lines)

        chunks = [
            ["somelongname0", 1024],
            ["somelongname1", 1024],
            ["somelongname2", 1024],
        ]
        total_file_size = 3072
        monkeypatch.setattr("splitcopy.progress.progress_bar", progress_bar)
        monkeypatch.setattr("splitcopy.progress.bytes_display", bytes_display)
        monkeypatch.setattr("splitcopy.progress.pad_string", pad_string)
        monkeypatch.setattr(Progress, "total_progress_str", total_progress_str)
        monkeypatch.setattr(Progress, "redraw_screen", redraw_screen)
        progress = Progress()
        progress.add_chunks(total_file_size, chunks)
        progress.update_screen_contents()
        captured = capsys.readouterr()
        result = captured.out
        assert result == expected

    def test_print_error_nocurses(self, capsys, monkeypatch: MonkeyPatch):
        expected = "\nfoo\n"
        progress = Progress()
        progress.print_error("foo")
        captured = capsys.readouterr()
        result = captured.out
        assert result == expected

    def test_print_error_curses(self, monkeypatch: MonkeyPatch):
        expected = ["", "", "", "foo"]

        def pad_string(foo):
            return foo

        progress = Progress()
        progress.curses = True
        monkeypatch.setattr("splitcopy.progress.pad_string", pad_string)
        progress.print_error("foo")
        result = progress.error_list
        assert result == expected

    def test_start_progress(self, monkeypatch: MonkeyPatch):
        expected = True

        def prepare_curses():
            return True

        def check_term_size(self, foo):
            return True

        def initiate_timer_thread(self):
            pass

        monkeypatch.setattr("splitcopy.progress.prepare_curses", prepare_curses)
        monkeypatch.setattr(Progress, "check_term_size", check_term_size)
        monkeypatch.setattr(Progress, "initiate_timer_thread", initiate_timer_thread)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        foo = True
        progress.start_progress(foo)
        result = progress.stdscr
        assert result == expected

    def test_stop_progress(self, monkeypatch: MonkeyPatch):
        expected = None

        def abandon_curses():
            pass

        def stop_timer_thread(self):
            pass

        monkeypatch.setattr("splitcopy.progress.abandon_curses", abandon_curses)
        monkeypatch.setattr(Progress, "stop_timer_thread", stop_timer_thread)
        progress = Progress()
        total_file_size, chunks = get_chunk_data()
        progress.add_chunks(total_file_size, chunks)
        result = progress.stop_progress()
        assert result == expected

    def test_redraw_screen(self, capsys):
        expected = "[[0, 0, 'foo'], [1, 0, 'bar']]\n"

        class MockCurses:
            def __init__(self):
                self.lines = []

            def addstr(self, y, x, str):
                self.lines.append([y, x, str])

            def refresh(self):
                print(self.lines)

        progress = Progress()
        progress.stdscr = MockCurses()
        progress.redraw_screen(["foo", "bar"])
        captured = capsys.readouterr()
        result = captured.out
        assert result == expected
