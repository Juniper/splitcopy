import concurrent.futures
import datetime
import os
import re
import time
from contextlib import contextmanager
from ftplib import error_proto
from threading import Thread

from pytest import MonkeyPatch, raises
from scp import SCPException
from splitcopy.get import SplitCopyGet, TransferError


class MockProgress:
    def __init__(self):
        self.totals = {}
        self.totals["percent_done"] = 0

    def start_progress(self, use_curses):
        pass

    def stop_progress(self):
        pass

    def add_chunks(self, file_size, chunks):
        pass

    def zero_file_stats(self, file_name):
        pass

    def print_error(self, err):
        pass

    def report_progress(self):
        pass


class MockOpen:
    def __init__(self, file, perms):
        self.data = ["abcdef0123456789"]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, *args):
        result = None
        try:
            result = self.data[0]
            del self.data[0]
        except IndexError:
            result = None
        return result

    def write(self, data):
        pass


class MockSSHShell:
    def __init__(self):
        self._transport = None
        self.socket = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def close(self, *args):
        pass

    def socket_open(self):
        self.socket = True

    def channel_open(self):
        pass

    def invoke_shell(self):
        pass

    def stdout_read(self, **kwargs):
        pass

    def run(self, *args, **kwargs):
        pass

    def transport_open(self):
        self._transport = True

    def worker_thread_auth(self):
        return True


class MockFTP:
    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def get(self, *args):
        pass


class MockSCPClient:
    def __init__(self, transport, progress=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def get(self, *args):
        pass

    def put(self, *args):
        pass


class MockSplitCopyShared:
    def __init__(self):
        pass

    def juniper_cli_check(*args):
        return True

    def close(self, **kwargs):
        raise SystemExit

    def connect(self, shell, **ssh_kwargs):
        return MockSSHShell(), ssh_kwargs

    def which_os(self):
        return True, False, 12.0, 7.4

    def which_proto(self, copy_proto):
        return copy_proto, "a_password"

    def req_binaries(self, junos, evo):
        pass

    def remote_cleanup(self, **kwargs):
        pass

    def file_split_size(self, *args):
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=5, thread_name_prefix="ThreadPoolWorker"
        )
        return 1000, executor

    def storage_check_remote(self, *args):
        pass

    def storage_check_local(self, *args):
        pass

    def mkdir_remote(self):
        return "/var/tmp/foo"

    def limit_check(self, *args):
        return ["deactivate system login retry-options"]

    def limits_rollback(self):
        pass

    @contextmanager
    def tempdir(*args):
        yield

    def return_tmpdir(self):
        return "/tmp"


class MockHash:
    def __init__(self):
        pass

    def update(self, data):
        pass

    def hexdigest(self):
        return "abcdef0123456789"


class TestSplitCopyGet:
    def test_handlesigint(self):
        scget = SplitCopyGet()
        scget.scs = MockSplitCopyShared()
        with raises(SystemExit):
            scget.handlesigint("SigInt", "stack")

    def test_get(self, monkeypatch: MonkeyPatch):
        scget = SplitCopyGet()
        scget.scs = MockSplitCopyShared()
        scget.progress = MockProgress()

        def validate_remote_path_get():
            pass

        def parse_target_arg():
            return "", "", ""

        def delete_target_local():
            pass

        def remote_filesize():
            return 1000000

        def remote_sha_get():
            return "abcdef012345"

        def split_file_remote(scp_lib, file_size, split_size, remote_tmpdir):
            pass

        def get_chunk_info(remote_tmpdir):
            return [["a", 1234], ["b", 1234], ["c", 1234]]

        def get_files(ftp_lib, ssh_lib, scp_lib, chunk, remote_tmpdir, ssh_kwargs):
            return None

        def join_files_local():
            pass

        def local_sha_get(hash):
            pass

        def inc_percentage():
            for n in range(90, 101):
                time.sleep(0.1)
                scget.progress.totals["percent_done"] = n

        def compare_file_sizes(*args):
            pass

        monkeypatch.setattr(scget, "validate_remote_path_get", validate_remote_path_get)
        monkeypatch.setattr(scget, "parse_target_arg", parse_target_arg)
        monkeypatch.setattr(scget, "delete_target_local", delete_target_local)
        monkeypatch.setattr(scget, "remote_filesize", remote_filesize)
        monkeypatch.setattr(scget, "remote_sha_get", remote_sha_get)
        monkeypatch.setattr(scget, "split_file_remote", split_file_remote)
        monkeypatch.setattr(scget, "get_chunk_info", get_chunk_info)
        monkeypatch.setattr(scget, "get_files", get_files)
        monkeypatch.setattr(scget, "join_files_local", join_files_local)
        monkeypatch.setattr(scget, "local_sha_get", local_sha_get)
        monkeypatch.setattr(scget, "compare_file_sizes", compare_file_sizes)
        thread = Thread(
            name="inc_percentage_done",
            target=inc_percentage,
        )
        thread.start()
        result = scget.get()
        thread.join()

        assert isinstance(result[0], datetime.datetime), isinstance(
            result[1], datetime.datetime
        )

    def test_get_noverify(self, monkeypatch: MonkeyPatch):
        scget = SplitCopyGet()
        scget.scs = MockSplitCopyShared()
        scget.progress = MockProgress()

        def validate_remote_path_get():
            pass

        def parse_target_arg():
            return "", "", ""

        def delete_target_local():
            pass

        def remote_filesize():
            return 1000000

        def split_file_remote(scp_lib, file_size, split_size, remote_tmpdir):
            pass

        def get_chunk_info(remote_tmpdir):
            return [["a", 1234], ["b", 1234], ["c", 1234]]

        def get_files(ftp_lib, ssh_lib, scp_lib, chunk, remote_tmpdir, ssh_kwargs):
            return None

        def join_files_local():
            pass

        def inc_percentage():
            for n in range(90, 101):
                time.sleep(0.1)
                scget.progress.totals["percent_done"] = n

        def compare_file_sizes(*args):
            pass

        scget.noverify = True
        monkeypatch.setattr(scget, "validate_remote_path_get", validate_remote_path_get)
        monkeypatch.setattr(scget, "parse_target_arg", parse_target_arg)
        monkeypatch.setattr(scget, "delete_target_local", delete_target_local)
        monkeypatch.setattr(scget, "remote_filesize", remote_filesize)
        monkeypatch.setattr(scget, "split_file_remote", split_file_remote)
        monkeypatch.setattr(scget, "get_chunk_info", get_chunk_info)
        monkeypatch.setattr(scget, "get_files", get_files)
        monkeypatch.setattr(scget, "join_files_local", join_files_local)
        monkeypatch.setattr(scget, "compare_file_sizes", compare_file_sizes)
        thread = Thread(
            name="inc_percentage_done",
            target=inc_percentage,
        )
        thread.start()
        result = scget.get()
        thread.join()
        assert isinstance(result[0], datetime.datetime), isinstance(
            result[1], datetime.datetime
        )

    def test_get_fail(self, monkeypatch: MonkeyPatch):
        def validate_remote_path_get():
            pass

        def parse_target_arg():
            return "", "", ""

        def delete_target_local():
            pass

        def remote_filesize():
            return 1000000

        def remote_sha_get():
            return "abcdef012345"

        def split_file_remote(scp_lib, file_size, split_size, remote_tmpdir):
            pass

        def get_chunk_info(remote_tmpdir):
            return [["a", 1234], ["b", 1234], ["c", 1234]]

        def get_files(ftp_lib, ssh_lib, scp_lib, chunk, remote_tmpdir, ssh_kwargs):
            raise TransferError

        scget = SplitCopyGet()
        scget.scs = MockSplitCopyShared()
        scget.progress = MockProgress()
        monkeypatch.setattr(scget, "validate_remote_path_get", validate_remote_path_get)
        monkeypatch.setattr(scget, "parse_target_arg", parse_target_arg)
        monkeypatch.setattr(scget, "delete_target_local", delete_target_local)
        monkeypatch.setattr(scget, "remote_filesize", remote_filesize)
        monkeypatch.setattr(scget, "remote_sha_get", remote_sha_get)
        monkeypatch.setattr(scget, "split_file_remote", split_file_remote)
        monkeypatch.setattr(scget, "get_chunk_info", get_chunk_info)
        monkeypatch.setattr(scget, "get_files", get_files)

        with raises(SystemExit):
            scget.get()

    def test_get_chunk_info_cmdfail(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.scs = MockSplitCopyShared()
        scget.remote_file = "somefile.0.gz"
        with raises(SystemExit):
            scget.get_chunk_info("/var/tmp/splitcopy_somefile.0.gz.220622105712")

    def test_get_chunk_info_matchfail(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = (
                    "ls -l /var/tmp/splitcopy_somefile.0.gz.220622105712/\n"
                    "total 2K\n"
                    "-rw------- 1 foo bar    269 Jun 22 00:57 split.sh\n"
                    "foo@bar:~$"
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.scs = MockSplitCopyShared()
        scget.remote_file = "somefile.0.gz"
        with raises(SystemExit):
            scget.get_chunk_info("/var/tmp/splitcopy_somefile.0.gz.220622105712")

    def test_get_chunk_info(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = (
                    "ls -l /var/tmp/splitcopy_somefile.0.gz.220622105712/\n"
                    "total 6640K\n"
                    "-rw------- 1 foo bar 677888 Jun 22 00:57 somefile.0.gz_00\n"
                    "-rw------- 1 foo bar 673790 Jun 22 00:57 somefile.0.gz_01\n"
                    "-rw------- 1 foo bar    269 Jun 22 00:57 split.sh\n"
                    "foo@bar:~$"
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_file = "somefile.0.gz"
        result = scget.get_chunk_info("/var/tmp/splitcopy_somefile.0.gz.220622105712")
        expected = [["somefile.0.gz_00", 677888], ["somefile.0.gz_01", 673790]]
        assert expected == result

    def test_validate_remote_path_get_fail(self, monkeypatch: MonkeyPatch):
        def expand_remote_dir():
            raise ValueError

        def dirname(*args):
            return "/var/tmp"

        def basename(*args):
            return "foobar"

        scget = SplitCopyGet()
        scget.scs = MockSplitCopyShared()
        monkeypatch.setattr("os.path.dirname", dirname)
        monkeypatch.setattr("os.path.basename", basename)
        monkeypatch.setattr(scget, "expand_remote_dir", expand_remote_dir)
        with raises(SystemExit):
            scget.validate_remote_path_get()

    def test_validate_remote_path_get(self, monkeypatch: MonkeyPatch):
        scget = SplitCopyGet()
        monkeypatch.setattr(scget, "expand_remote_dir", lambda: True)
        monkeypatch.setattr(scget, "path_startswith_tilda", lambda: True)
        monkeypatch.setattr(scget, "verify_path_is_not_directory", lambda: True)
        monkeypatch.setattr(scget, "verify_file_exists", lambda: True)
        monkeypatch.setattr(scget, "verify_file_is_readable", lambda: True)
        monkeypatch.setattr(scget, "check_if_symlink", lambda: True)
        scget.remote_path = "/var/tmp/foobar"
        scget.validate_remote_path_get()
        assert (
            scget.remote_dir == "/var/tmp"
            and scget.remote_file == "foobar"
            and scget.remote_path == "/var/tmp/foobar"
        )

    def test_parse_target_arg_isdir(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return True

        scget = SplitCopyGet()
        scget.target = "/var/tmp"
        scget.remote_file = "foo"
        monkeypatch.setattr("os.path.isdir", isdir)
        result = scget.parse_target_arg()
        assert result == ("/var/tmp", "foo", "/var/tmp/foo")

    def test_parse_target_arg_isdir_tilda(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return True

        def expanduser(*args):
            return "/homes/foo/tmp/"

        scget = SplitCopyGet()
        scget.target = "~/tmp"
        scget.remote_file = "foo"
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        result = scget.parse_target_arg()
        assert result == ("/homes/foo/tmp", "foo", "/homes/foo/tmp/foo")

    def test_parse_target_arg_dotdir(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return True

        def abspath(*args):
            return "/homes/foo/tmp"

        scget = SplitCopyGet()
        scget.target = "./tmp"
        scget.remote_file = "foo"
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.path.abspath", abspath)
        result = scget.parse_target_arg()
        assert result == ("/homes/foo/tmp", "foo", "/homes/foo/tmp/foo")

    def test_parse_target_arg_file(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            if re.match(r"/var/tmp/foo", args[0]):
                return False
            else:
                return True

        scget = SplitCopyGet()
        scget.target = "/var/tmp/foo"
        scget.remote_file = "foo"
        monkeypatch.setattr("os.path.isdir", isdir)
        result = scget.parse_target_arg()
        assert result == ("/var/tmp", "foo", "/var/tmp/foo")

    def test_parse_target_arg_file_diffname(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            if re.match(r"/var/tmp/foo", args[0]):
                return False
            else:
                return True

        scget = SplitCopyGet()
        scget.target = "/var/tmp/foo"
        scget.remote_file = "bar"
        monkeypatch.setattr("os.path.isdir", isdir)
        result = scget.parse_target_arg()
        assert result == ("/var/tmp", "foo", "/var/tmp/foo")

    def test_parse_target_arg_file_tilda(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            if re.match(r"~/bar", args[0]):
                return False
            else:
                return True

        def expanduser(*args):
            return "/homes/foo/bar"

        scget = SplitCopyGet()
        scget.target = "~/bar"
        scget.remote_file = "bar"
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        result = scget.parse_target_arg()
        assert result == ("/homes/foo", "bar", "/homes/foo/bar")

    def test_parse_target_arg_file_dotdir(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            if re.match(r"\./tmp/bar", args[0]):
                return False
            else:
                return True

        def abspath(*args):
            return "/homes/foo/tmp/bar"

        def expanduser(*args):
            return "/homes/foo/tmp/bar"

        scget = SplitCopyGet()
        scget.target = "./tmp/bar"
        scget.remote_file = "bar"
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.path.abspath", abspath)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        result = scget.parse_target_arg()
        assert result == ("/homes/foo/tmp", "bar", "/homes/foo/tmp/bar")

    def test_parse_target_arg_nodir(self, monkeypatch: MonkeyPatch):
        def getcwd():
            return "/homes/foo"

        def isdir(*args):
            return False

        scget = SplitCopyGet()
        scget.target = "bar"
        scget.remote_file = "bar"
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.getcwd", getcwd)
        result = scget.parse_target_arg()
        assert result == ("/homes/foo", "bar", "/homes/foo/bar")

    def test_parse_target_arg_nodir_diffname(self, monkeypatch: MonkeyPatch):
        def getcwd():
            return "/homes/foo"

        def isdir(*args):
            return False

        scget = SplitCopyGet()
        scget.target = "bar"
        scget.remote_file = "foobar"
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.getcwd", getcwd)
        result = scget.parse_target_arg()
        assert result == ("/homes/foo", "bar", "/homes/foo/bar")

    def test_expand_remote_dir_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_dir = "."
        with raises(ValueError):
            scget.expand_remote_dir()

    def test_expand_remote_dir_none_shell(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "foo@bar:~$ pwd\n/homes/foo/bar\nfoo@bar:~$"
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "testfile"
        scget.remote_dir = os.path.dirname(scget.remote_path)
        scget.remote_file = os.path.basename(scget.remote_path)
        scget.expand_remote_dir()
        assert (
            scget.remote_dir == "/homes/foo/bar"
            and scget.remote_path == "/homes/foo/bar/testfile"
        )

    def test_expand_remote_dir_none_exec(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "/homes/foo/bar"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "testfile"
        scget.remote_dir = os.path.dirname(scget.remote_path)
        scget.remote_file = os.path.basename(scget.remote_path)
        scget.expand_remote_dir()
        assert (
            scget.remote_dir == "/homes/foo/bar"
            and scget.remote_path == "/homes/foo/bar/testfile"
        )

    def test_expand_remote_dir_shell(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "foo@bar:~$ pwd\n/homes/foo/bar\nfoo@bar:~$"
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "./testfile"
        scget.remote_dir = os.path.dirname(scget.remote_path)
        scget.remote_file = os.path.basename(scget.remote_path)
        scget.expand_remote_dir()
        assert (
            scget.remote_dir == "/homes/foo/bar"
            and scget.remote_path == "/homes/foo/bar/testfile"
        )

    def test_expand_remote_dir_exec(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "/homes/foo/bar"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "./testfile"
        scget.remote_dir = os.path.dirname(scget.remote_path)
        scget.remote_file = os.path.basename(scget.remote_path)
        scget.expand_remote_dir()
        assert (
            scget.remote_dir == "/homes/foo/bar"
            and scget.remote_path == "/homes/foo/bar/testfile"
        )

    def test_expand_remote_dir2_shell(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "foo@bar:~$ pwd\n/homes/foo/bar\nfoo@bar:~$"
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "./tmp/testfile"
        scget.remote_dir = os.path.dirname(scget.remote_path)
        scget.remote_file = os.path.basename(scget.remote_path)
        scget.expand_remote_dir()
        assert (
            scget.remote_dir == "/homes/foo/bar/tmp"
            and scget.remote_path == "/homes/foo/bar/tmp/testfile"
        )

    def test_expand_remote_dir2_exec(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "/homes/foo/bar"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "./tmp/testfile"
        scget.remote_dir = os.path.dirname(scget.remote_path)
        scget.remote_file = os.path.basename(scget.remote_path)
        scget.expand_remote_dir()
        assert (
            scget.remote_dir == "/homes/foo/bar/tmp"
            and scget.remote_path == "/homes/foo/bar/tmp/testfile"
        )

    def test_path_startswith_tilda_cmdfail(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_dir = "~foo/bar"
        with raises(ValueError):
            scget.path_startswith_tilda()

    def test_path_startswith_tilda_shell(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "foo@bar:~$ ls -d ~/bar\n/homes/foo/bar\nfoo@bar:~$"
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell2()
        scget.remote_dir = "~foo/bar"
        scget.remote_file = "test"
        scget.path_startswith_tilda()
        assert (
            scget.remote_dir == "/homes/foo/bar"
            and scget.remote_path == "/homes/foo/bar/test"
        )

    def test_path_startswith_tilda_exec(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "/homes/foo/bar"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_dir = "~foo/bar"
        scget.remote_file = "test"
        scget.path_startswith_tilda()
        assert (
            scget.remote_dir == "/homes/foo/bar"
            and scget.remote_path == "/homes/foo/bar/test"
        )

    def test_verify_path_is_not_directory_fail(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "/var/tmp"
        with raises(ValueError):
            scget.verify_path_is_not_directory()

    def test_verify_file_exists_fail(self):
        class MockSSHShell2(MockSSHShell):
            def __init__(self):
                pass

            def run(self, cmd):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "/var/tmp"
        with raises(ValueError):
            scget.verify_file_exists()

    def test_verify_file_is_readable_fail(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "/var/tmp"
        with raises(ValueError):
            scget.verify_file_is_readable()

    def test_check_if_symlink_shell(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = (
                    "foo@bar:~$ ls -l /tmp/foo\n"
                    "lrwxrwxrwx 1 foo bar 43 Jun 22 05:48 /tmp/foo -> /var/tmp/foo\n"
                    "foo@bar:~$"
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "/tmp/foo"
        scget.check_if_symlink()
        assert scget.filesize_path == "/var/tmp/foo"

    def test_check_if_symlink_exec(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "lrwxrwxrwx 1 foo bar 43 Jun 22 05:48 /tmp/foo -> /var/tmp/foo"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "/tmp/foo"
        scget.check_if_symlink()
        assert scget.filesize_path == "/var/tmp/foo"

    def test_check_if_symlink_samedir_shell(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = (
                    "foo@bar:~$ ls -l /tmp/foo\n"
                    "lrwxrwxrwx 1 foo bar 43 Jun 22 05:48 /tmp/foo -> bar\n"
                    "foo@bar:~$"
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell2()
        scget.remote_dir = "/tmp"
        scget.remote_path = "/tmp/foo"
        scget.check_if_symlink()
        assert scget.filesize_path == "/tmp/bar"

    def test_check_if_symlink_samedir_exec(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "lrwxrwxrwx 1 foo bar 43 Jun 22 05:48 /tmp/foo -> bar"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_dir = "/tmp"
        scget.remote_path = "/tmp/foo"
        scget.check_if_symlink()
        assert scget.filesize_path == "/tmp/bar"

    def test_check_if_symlink_fail(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = ""
                if re.match(r"ls -l", cmd):
                    result = False
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.remote_path = "/tmp/foo"
        with raises(ValueError):
            scget.check_if_symlink()

    def test_delete_target_local(self, monkeypatch: MonkeyPatch):
        def exists(*args):
            return True

        def remove(*args):
            return True

        monkeypatch.setattr("os.path.exists", exists)
        monkeypatch.setattr("os.remove", remove)
        monkeypatch.setattr("os.path.sep", "/")
        scget = SplitCopyGet()
        scget.local_dir = "/var/tmp"
        scget.local_file = "foo"
        result = scget.delete_target_local()
        expected = None
        assert expected == result

    def test_remote_filesize_shell(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = (
                    "foo@bar:~$ ls -l /var/tmp/foo\n"
                    "-rw------- 1 foo bar 69927631 Mar 29 06:49 /var/tmp/foo\n"
                    "foo@bar:~$"
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell2()
        result = scget.remote_filesize()
        assert result == 69927631

    def test_remote_filesize_exec(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "-rw------- 1 foo bar 69927631 Mar 29 06:49 /var/tmp/foo"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        result = scget.remote_filesize()
        assert result == 69927631

    def test_remote_filesize_fail(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        scget.scs = MockSplitCopyShared()
        with raises(SystemExit):
            scget.remote_filesize()

    def test_remote_sha_get(self, monkeypatch: MonkeyPatch):
        def find_existing_sha_files():
            return True, ""

        def process_existing_sha_files(stdout):
            return {256: "9f77f4653b052b76af5de0fde3f7c58ae15bfaf3"}

        scget = SplitCopyGet()
        monkeypatch.setattr(scget, "find_existing_sha_files", find_existing_sha_files)
        monkeypatch.setattr(
            scget, "process_existing_sha_files", process_existing_sha_files
        )
        scget.sshshell = MockSSHShell()
        result = scget.remote_sha_get()
        assert result == {256: "9f77f4653b052b76af5de0fde3f7c58ae15bfaf3"}

    def test_remote_sha_get_shasum(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "shasum", 1

        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout):
                result = True
                stdout = (
                    "foo@bar ~ % shasum -a 1 /var/tmp/foo\n"
                    "9f77f4653b052b76af5de0fde3f7c58ae15bfaf3  foo\n"
                    "foo@bar ~ %"
                )
                return result, stdout

        def find_existing_sha_files():
            return False, ""

        scget = SplitCopyGet()
        monkeypatch.setattr(scget, "find_existing_sha_files", find_existing_sha_files)
        scget.sshshell = MockSSHShell2()
        scget.scs = MockSplitCopyShared2()
        result = scget.remote_sha_get()
        assert result == {1: "9f77f4653b052b76af5de0fde3f7c58ae15bfaf3"}

    def test_remote_sha_get_sha1sum_fail(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "sha1sum", 1

        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout):
                result = False
                stdout = ""
                return result, stdout

        def find_existing_sha_files():
            return False, ""

        scget = SplitCopyGet()
        monkeypatch.setattr(scget, "find_existing_sha_files", find_existing_sha_files)
        scget.sshshell = MockSSHShell2()
        scget.scs = MockSplitCopyShared2()
        with raises(SystemExit):
            scget.remote_sha_get()

    def test_remote_sha_get_regex_fail(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "shasum", 1

        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout):
                result = True
                stdout = ""
                return result, stdout

        def find_existing_sha_files():
            return False, ""

        scget = SplitCopyGet()
        monkeypatch.setattr(scget, "find_existing_sha_files", find_existing_sha_files)
        scget.sshshell = MockSSHShell2()
        scget.scs = MockSplitCopyShared2()
        with raises(SystemExit):
            scget.remote_sha_get()

    def test_find_existing_sha_files(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "ls output"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        result = scget.find_existing_sha_files()
        assert result == (True, "ls output")

    def test_process_existing_sha_files_shell(self):
        output = (
            "/var/tmp/foo.sha1\n"
            "/var/tmp/foo.sha224\n"
            "/var/tmp/foo.sha256\n"
            "/var/tmp/foo.sha384\n"
            "/var/tmp/foo.sha512\n"
        )

        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = (
                    "foo@bar:~$ cat filename\n"
                    "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13 filename\n"
                    "foo@bar:~$ "
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell2()
        result = scget.process_existing_sha_files(output)
        assert result == {
            1: "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13",
            224: "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13",
            256: "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13",
            384: "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13",
            512: "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13",
        }

    def test_process_existing_sha_files_exec(self):
        output = (
            "/var/tmp/foo.sha1\n"
            "/var/tmp/foo.sha224\n"
            "/var/tmp/foo.sha256\n"
            "/var/tmp/foo.sha384\n"
            "/var/tmp/foo.sha512\n"
        )

        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                result = True
                stdout = "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13 filename"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        result = scget.process_existing_sha_files(output)
        assert result == {
            1: "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13",
            224: "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13",
            256: "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13",
            384: "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13",
            512: "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13",
        }

    def test_process_existing_sha_files_fail(self):
        output = "/var/tmp/foo.sha\n" "/var/tmp/foo.sha224\n"

        class MockSSHShell2(MockSSHShell):
            def run(self, cmd):
                return False, ""

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        result = scget.process_existing_sha_files(output)
        assert result == {}

    def test_split_file_remote(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout):
                result = True
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        result = scget.split_file_remote(MockSCPClient, 1000000, 100000, "/var/tmp")
        assert result == None

    def test_split_file_remote_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout):
                result = False
                stdout = ""
                return result, stdout

        def close(err_str, hard_close):
            raise SystemExit

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell2()
        monkeypatch.setattr(scget.scs, "close", close)
        with raises(SystemExit):
            scget.split_file_remote(MockSCPClient, 1000000, 100000, "/var/tmp")

    def test_get_files_ftp(self):
        scget = SplitCopyGet()
        scget.progress = MockProgress()
        scget.copy_proto = "ftp"

        result = scget.get_files(
            MockFTP,
            MockSSHShell,
            MockSCPClient,
            ["chunk0", 1999],
            "/var/tmp/foo",
            {},
        )
        assert result == None

    def test_get_files_ftp_fail(self, monkeypatch: MonkeyPatch):
        class MockFTP2(MockFTP):
            def get(self, *args):
                raise error_proto

        def sleep(secs):
            pass

        def stat(*args):
            stat.st_size = 10000
            stat.st_mode = 1
            stat.st_mtime = None
            return stat

        monkeypatch.setattr("time.sleep", sleep)
        monkeypatch.setattr("os.stat", stat)
        scget = SplitCopyGet()
        scget.progress = MockProgress()
        scget.copy_proto = "ftp"
        with raises(TransferError):
            scget.get_files(
                MockFTP2, MockSSHShell, MockSCPClient, ["chunk0", 1999], "/tmp/", {}
            )

    def test_get_files_ftp_filenotfound_fail(self, monkeypatch: MonkeyPatch):
        class MockFTP2(MockFTP):
            def get(self, *args):
                raise error_proto

        def sleep(secs):
            pass

        monkeypatch.setattr("time.sleep", sleep)
        scget = SplitCopyGet()
        scget.progress = MockProgress()
        scget.copy_proto = "ftp"
        with raises(TransferError):
            scget.get_files(
                MockFTP2, MockSSHShell, MockSCPClient, ["chunk0", 1999], "/tmp/", {}
            )

    def test_get_files_scp(self):
        scget = SplitCopyGet()
        scget.progress = MockProgress()
        scget.copy_proto = "scp"

        result = scget.get_files(
            MockFTP,
            MockSSHShell,
            MockSCPClient,
            ["chunk0", 1999],
            "/var/tmp/foo",
            {},
        )
        assert result == None

    def test_get_files_scp_fail(self, monkeypatch: MonkeyPatch):
        class MockSCPClient2(MockSCPClient):
            def get(self, *args):
                raise SCPException

        def sleep(secs):
            pass

        monkeypatch.setattr("time.sleep", sleep)
        scget = SplitCopyGet()
        scget.progress = MockProgress()
        scget.copy_proto = "scp"
        with raises(TransferError):
            scget.get_files(
                MockFTP, MockSSHShell, MockSCPClient2, ["chunk0", 1999], "/tmp/", {}
            )

    def test_get_files_scp_authfail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def worker_thread_auth(self):
                return False

        def sleep(secs):
            pass

        monkeypatch.setattr("time.sleep", sleep)
        scget = SplitCopyGet()
        scget.progress = MockProgress()
        scget.copy_proto = "scp"
        with raises(TransferError):
            scget.get_files(
                MockFTP, MockSSHShell2, MockSCPClient, ["chunk0", 1999], "/tmp/", {}
            )

    def test_join_files_local(self, monkeypatch: MonkeyPatch):
        def isfile(path):
            return True

        def glob(path):
            return ["file1", "file2"]

        monkeypatch.setattr("glob.glob", glob)
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("os.path.isfile", isfile)
        monkeypatch.setattr("os.path.sep", "/")
        scget = SplitCopyGet()
        scget.remote_file = "foo"
        scget.local_file = "foo"
        scget.local_dir = "/var/tmp"
        scget.scs = MockSplitCopyShared()

        result = scget.join_files_local()
        assert result == None

    def test_join_files_local_fail(self, monkeypatch: MonkeyPatch):
        def isfile(path):
            return False

        def glob(path):
            return ["file1", "file2"]

        monkeypatch.setattr("glob.glob", glob)
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("os.path.isfile", isfile)
        monkeypatch.setattr("os.path.sep", "/")
        scget = SplitCopyGet()
        scget.remote_file = "foo"
        scget.local_file = "foo"
        scget.local_dir = "/var/tmp"
        scget.scs = MockSplitCopyShared()
        with raises(SystemExit):
            scget.join_files_local()

    def test_local_sha_get(self, monkeypatch: MonkeyPatch):
        class MockHash:
            def __init__(self):
                pass

            def update(self, data):
                pass

            def hexdigest(self):
                return "abcdef0123456789"

        class Mock512(MockHash):
            pass

        class Mock384(MockHash):
            pass

        class Mock256(MockHash):
            pass

        class Mock224(MockHash):
            pass

        class Mock1(MockHash):
            pass

        scget = SplitCopyGet()
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("os.path.sep", "/")
        monkeypatch.setattr("hashlib.sha512", Mock512)
        monkeypatch.setattr("hashlib.sha384", Mock384)
        monkeypatch.setattr("hashlib.sha256", Mock256)
        monkeypatch.setattr("hashlib.sha224", Mock224)
        monkeypatch.setattr("hashlib.sha1", Mock1)
        sha_hash = {
            1: "abcdef0123456789",
            224: "abcdef0123456789",
            256: "abcdef0123456789",
            384: "abcdef0123456789",
            512: "abcdef0123456789",
        }
        scget.local_file = "foo"
        scget.local_dir = "/var/tmp"
        for i in [512, 384, 256, 224, 1]:
            result = scget.local_sha_get(sha_hash)
            assert result == None
            del sha_hash[i]

    def test_local_sha_get_mismatch(self, monkeypatch: MonkeyPatch):
        class Mock512(MockHash):
            pass

        class Mock384(MockHash):
            pass

        class Mock256(MockHash):
            pass

        class Mock224(MockHash):
            pass

        class Mock1(MockHash):
            pass

        scget = SplitCopyGet()
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("os.path.sep", "/")
        monkeypatch.setattr("hashlib.sha512", Mock512)
        monkeypatch.setattr("hashlib.sha384", Mock384)
        monkeypatch.setattr("hashlib.sha256", Mock256)
        monkeypatch.setattr("hashlib.sha224", Mock224)
        monkeypatch.setattr("hashlib.sha1", Mock1)
        scget.scs = MockSplitCopyShared()
        sha_hash = {
            512: "0bcdef0123456789",
        }
        scget.local_file = "foo"
        scget.local_dir = "/var/tmp"
        with raises(SystemExit):
            scget.local_sha_get(sha_hash)

    def test_compare_file_sizes(self, capsys, monkeypatch: MonkeyPatch):
        scget = SplitCopyGet()

        def getsize(*args):
            return 781321216

        monkeypatch.setattr("os.path.getsize", getsize)
        result = scget.compare_file_sizes(781321216)
        captured = capsys.readouterr()
        result = captured.out
        expected = "local and remote file sizes match\n"
        assert result == expected

    def test_compare_file_sizes_fail(self, capsys, monkeypatch: MonkeyPatch):
        scget = SplitCopyGet()
        scget.scs = MockSplitCopyShared()

        def getsize(*args):
            return 781311

        monkeypatch.setattr("os.path.getsize", getsize)
        with raises(SystemExit):
            scget.compare_file_sizes(781321216)
