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

    def mkdir_remote(self, *args):
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

    def ssh_cmd(*args, **kwargs):
        return (True, "")

    def enter_shell(self):
        return True


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

        def validate_remote_path_get(*args):
            return ("file", "dir", "path", "filesize_path")

        def delete_target_local(*args):
            pass

        def remote_filesize(*args):
            return 1000000

        def remote_sha_get(*args):
            return "abcdef012345"

        def split_file_remote(*args):
            pass

        def get_chunk_info(*args):
            return [["a", 1234], ["b", 1234], ["c", 1234]]

        def get_files(*args):
            return None

        def join_files_local(*args):
            pass

        def local_sha_get(*args):
            pass

        def determine_local_filename(*args):
            return "foo"

        def verify_local_dir_perms(*args):
            pass

        def expand_local_dir(*args):
            return "/var/tmp"

        def inc_percentage():
            for n in range(90, 101):
                time.sleep(0.1)
                scget.progress.totals["percent_done"] = n

        def compare_file_sizes(*args):
            pass

        monkeypatch.setattr(scget, "validate_remote_path_get", validate_remote_path_get)
        monkeypatch.setattr(scget, "expand_local_dir", expand_local_dir)
        monkeypatch.setattr(scget, "verify_local_dir_perms", verify_local_dir_perms)
        monkeypatch.setattr(scget, "determine_local_filename", determine_local_filename)
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

        def validate_remote_path_get(*args):
            return ("file", "dir", "path", "filesize_path")

        def delete_target_local(*args):
            pass

        def remote_filesize(*args):
            return 1000000

        def split_file_remote(*args):
            pass

        def get_chunk_info(*args):
            return [["a", 1234], ["b", 1234], ["c", 1234]]

        def get_files(*args):
            return None

        def join_files_local(*args):
            pass

        def determine_local_filename(*args):
            return "foo"

        def verify_local_dir_perms(*args):
            pass

        def expand_local_dir(*args):
            return "/var/tmp"

        def inc_percentage():
            for n in range(90, 101):
                time.sleep(0.1)
                scget.progress.totals["percent_done"] = n

        def compare_file_sizes(*args):
            pass

        scget.noverify = True
        monkeypatch.setattr(scget, "validate_remote_path_get", validate_remote_path_get)
        monkeypatch.setattr(scget, "expand_local_dir", expand_local_dir)
        monkeypatch.setattr(scget, "verify_local_dir_perms", verify_local_dir_perms)
        monkeypatch.setattr(scget, "determine_local_filename", determine_local_filename)
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
        def validate_remote_path_get(*args):
            return ("file", "dir", "path", "filesize_path")

        def determine_local_filename(*args):
            return "foo"

        def verify_local_dir_perms(*args):
            pass

        def expand_local_dir(*args):
            return "/var/tmp"

        def delete_target_local(*args):
            pass

        def remote_filesize(*args):
            return 1000000

        def remote_sha_get(*args):
            return "abcdef012345"

        def split_file_remote(*args):
            pass

        def get_chunk_info(*args):
            return [["a", 1234], ["b", 1234], ["c", 1234]]

        def get_files(*args):
            raise TransferError

        scget = SplitCopyGet()
        scget.scs = MockSplitCopyShared()
        scget.progress = MockProgress()
        monkeypatch.setattr(scget, "validate_remote_path_get", validate_remote_path_get)
        monkeypatch.setattr(scget, "expand_local_dir", expand_local_dir)
        monkeypatch.setattr(scget, "verify_local_dir_perms", verify_local_dir_perms)
        monkeypatch.setattr(scget, "determine_local_filename", determine_local_filename)
        monkeypatch.setattr(scget, "delete_target_local", delete_target_local)
        monkeypatch.setattr(scget, "remote_filesize", remote_filesize)
        monkeypatch.setattr(scget, "remote_sha_get", remote_sha_get)
        monkeypatch.setattr(scget, "split_file_remote", split_file_remote)
        monkeypatch.setattr(scget, "get_chunk_info", get_chunk_info)
        monkeypatch.setattr(scget, "get_files", get_files)

        with raises(SystemExit):
            scget.get()

    def test_get_chunk_info_cmdfail(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(SystemExit):
            remote_tmpdir = "/var/tmp/splitcopy_somefile.0.gz.220622105712"
            remote_file = "somefile.0.gz"
            scget.get_chunk_info(remote_tmpdir, remote_file)

    def test_get_chunk_info_matchfail(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = (
                    "ls -l /var/tmp/splitcopy_somefile.0.gz.220622105712/\n"
                    "total 2K\n"
                    "-rw------- 1 foo bar    269 Jun 22 00:57 split.sh\n"
                    "foo@bar:~$"
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(SystemExit):
            remote_tmpdir = "/var/tmp/splitcopy_somefile.0.gz.220622105712"
            remote_file = "somefile.0.gz"
            scget.get_chunk_info(remote_tmpdir, remote_file)

    def test_get_chunk_info(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
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
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        remote_tmpdir = "/var/tmp/splitcopy_somefile.0.gz.220622105712"
        remote_file = "somefile.0.gz"
        result = scget.get_chunk_info(remote_tmpdir, remote_file)
        expected = [["somefile.0.gz_00", 677888], ["somefile.0.gz_01", 673790]]
        assert expected == result

    def test_validate_remote_path_get_fail(self, monkeypatch: MonkeyPatch):
        scget = SplitCopyGet()
        scget.scs = MockSplitCopyShared()

        def verify_path_exists(*args):
            raise ValueError

        monkeypatch.setattr(scget, "verify_path_exists", verify_path_exists)
        with raises(SystemExit):
            remote_path = "/var/tmp"
            scget.validate_remote_path_get(remote_path)

    def test_validate_remote_path_get(self, monkeypatch: MonkeyPatch):
        scget = SplitCopyGet()

        def expand_remote_path(*args):
            return "/var/tmp/foobar"

        def path_startswith_tilda(*args):
            return "/var/tmp/foobar"

        def verify_path_is_not_directory(*args):
            return False

        def verify_path_exists(*args):
            return True

        def verify_path_is_readable(*args):
            return True

        def check_if_symlink(*args):
            return "/var/tmp/foobar"

        def dirname(*args):
            return "/var/tmp"

        def basename(*args):
            return "foobar"

        monkeypatch.setattr(scget, "expand_remote_path", expand_remote_path)
        monkeypatch.setattr(scget, "path_startswith_tilda", path_startswith_tilda)
        monkeypatch.setattr(
            scget, "verify_path_is_not_directory", verify_path_is_not_directory
        )
        monkeypatch.setattr(scget, "verify_path_exists", verify_path_exists)
        monkeypatch.setattr(scget, "verify_path_is_readable", verify_path_is_readable)
        monkeypatch.setattr(scget, "check_if_symlink", check_if_symlink)
        monkeypatch.setattr("os.path.dirname", dirname)
        monkeypatch.setattr("os.path.basename", basename)
        remote_path = "/var/tmp/foobar"
        result = scget.validate_remote_path_get(remote_path)
        assert result == (
            "foobar",
            "/var/tmp",
            "/var/tmp/foobar",
            "/var/tmp/foobar",
        )

    def test_expand_local_dir_isdir(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return True

        def expanduser(*args):
            return "/var/tmp/"

        def abspath(*args):
            return "/var/tmp"

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        monkeypatch.setattr("os.path.abspath", abspath)
        target = "/var/tmp"
        result = scget.expand_local_dir(target)
        assert result == ("/var/tmp")

    def test_expand_local_dir_isdir_tilda(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return True

        def expanduser(*args):
            return "/homes/foo/tmp/"

        def abspath(*args):
            return "/homes/foo/tmp"

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        monkeypatch.setattr("os.path.abspath", abspath)
        target = "~/tmp"
        result = scget.expand_local_dir(target)
        assert result == "/homes/foo/tmp"

    def test_expand_local_dir_dotdir(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return True

        def expanduser(*args):
            return "./tmp"

        def abspath(*args):
            return "/homes/foo/tmp"

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        monkeypatch.setattr("os.path.abspath", abspath)
        target = "./tmp"
        result = scget.expand_local_dir(target)
        assert result == "/homes/foo/tmp"

    def test_expand_local_dir_dirfile(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            if args[0] == "/opt/foo/somefile":
                return False
            else:
                return True

        def expanduser(*args):
            return "/opt/foo/somefile"

        def abspath(*args):
            return "/opt/foo/somefile"

        def dirname(*args):
            return "/opt/foo"

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        monkeypatch.setattr("os.path.abspath", abspath)
        monkeypatch.setattr("os.path.dirname", dirname)
        target = "/opt/foo/somefile"
        result = scget.expand_local_dir(target)
        assert result == "/opt/foo"

    def test_expand_local_dir_file(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return False

        def expanduser(*args):
            return "somefile"

        def abspath(*args):
            return "somefile"

        def dirname(*args):
            return ""

        def getcwd(*args):
            return "/homes/foo"

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        monkeypatch.setattr("os.path.abspath", abspath)
        monkeypatch.setattr("os.path.dirname", dirname)
        monkeypatch.setattr("os.getcwd", getcwd)
        target = "somefile"
        result = scget.expand_local_dir(target)
        assert result == "/homes/foo"

    def test_test_local_dir_perms(self, monkeypatch: MonkeyPatch):
        class MockTemporaryfile:
            def __init__(*args, **kwargs):
                pass

            def __enter__(self):
                pass

            def __exit__(self, *args):
                pass

        scget = SplitCopyGet()
        monkeypatch.setattr("tempfile.TemporaryFile", MockTemporaryfile)
        local_dir = "/var/tmp"
        result = scget.verify_local_dir_perms(local_dir)
        assert result == None

    def test_test_local_dir_perms_fail(self, monkeypatch: MonkeyPatch):
        class MockTemporaryfile:
            def __init__(*args, **kwargs):
                pass

            def __enter__(self):
                pass

            def __exit__(self, *args):
                raise PermissionError

        scget = SplitCopyGet()
        monkeypatch.setattr("tempfile.TemporaryFile", MockTemporaryfile)
        with raises(SystemExit):
            local_dir = "/var/tmp"
            scget.verify_local_dir_perms(local_dir)

    def test_determine_local_filename(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return True

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        target = "/var/tmp"
        remote_path = "foo"
        result = scget.determine_local_filename(target, remote_path)
        assert result == "foo"

    def test_determine_local_filename_diffname(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return False

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        target = "/var/tmp/foo"
        remote_path = "/var/tmp/bar"
        result = scget.determine_local_filename(target, remote_path)
        assert result == "foo"

    def test_determine_local_filename_tilda(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return False

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        target = "~/bar"
        remote_path = "/var/tmp/bar"
        result = scget.determine_local_filename(target, remote_path)
        assert result == "bar"

    def test_determine_local_filename_dotdir(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return False

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        target = "./tmp/bar"
        remote_path = "/var/tmp/bar"
        result = scget.determine_local_filename(target, remote_path)
        assert result == "bar"

    def test_determine_local_filename_nodir(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return False

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        target = "bar"
        remote_path = "/var/tmp/bar"
        result = scget.determine_local_filename(target, remote_path)
        assert result == "bar"

    def test_determine_local_filename_nodir_diffname(self, monkeypatch: MonkeyPatch):
        def isdir(*args):
            return False

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isdir", isdir)
        target = "bar"
        remote_path = "/var/tmp/foobar"
        result = scget.determine_local_filename(target, remote_path)
        assert result == "bar"

    def test_expand_remote_path_fail(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(ValueError):
            scget.expand_remote_path(".")

    def test_expand_remote_path_none_shell(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "foo@bar:~$ pwd\n/homes/foo/bar\nfoo@bar:~$"
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.expand_remote_path("testfile")
        assert result == "/homes/foo/bar/testfile"

    def test_expand_remote_path_none_exec(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "/homes/foo/bar"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.expand_remote_path("testfile")
        assert result == "/homes/foo/bar/testfile"

    def test_expand_remote_path_shell(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "foo@bar:~$ pwd\n/homes/foo/bar\nfoo@bar:~$"
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.expand_remote_path("./testfile")
        assert result == "/homes/foo/bar/testfile"

    def test_expand_remote_path_exec(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "/homes/foo/bar"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.expand_remote_path("./testfile")
        assert result == "/homes/foo/bar/testfile"

    def test_expand_remote_path2_shell(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "foo@bar:~$ pwd\n/homes/foo/bar\nfoo@bar:~$"
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.expand_remote_path("./tmp/testfile")
        assert result == "/homes/foo/bar/tmp/testfile"

    def test_expand_remote_path2_exec(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "/homes/foo/bar"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.expand_remote_path("./tmp/testfile")
        assert result == "/homes/foo/bar/tmp/testfile"

    def test_path_startswith_tilda_cmdfail(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(ValueError):
            scget.path_startswith_tilda("~foo/bar")

    def test_path_startswith_tilda_shell(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "foo@bar:~$ ls -d ~/bar\n/homes/foo/bar\nfoo@bar:~$"
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.path_startswith_tilda("~foo/bar")
        assert result == "/homes/foo/bar"

    def test_path_startswith_tilda_exec(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "/homes/foo/bar"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.path_startswith_tilda("~foo/bar")
        assert result == "/homes/foo/bar"

    def test_verify_path_is_not_directory_fail(self):
        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared()
        with raises(ValueError):
            scget.verify_path_is_not_directory("/var/tmp")

    def test_verify_path_is_not_directory(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.verify_path_is_not_directory("/var/tmp")
        assert result == False

    def test_verify_path_exists_fail(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(ValueError):
            scget.verify_path_exists("/var/tmp")

    def test_verify_path_exists(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.verify_path_exists("/var/tmp")
        assert result == True

    def test_verify_path_is_readable_fail(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(ValueError):
            scget.verify_path_is_readable("/var/tmp")

    def test_verify_path_is_readable(self):
        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared()
        result = scget.verify_path_is_readable("/var/tmp")
        assert result == True

    def test_check_if_symlink_shell(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = (
                    "foo@bar:~$ ls -l /tmp/foo\n"
                    "lrwxrwxrwx 1 foo bar 43 Jun 22 05:48 /tmp/foo -> /var/tmp/foo\n"
                    "foo@bar:~$"
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.check_if_symlink("/tmp/foo")
        assert result == "/var/tmp/foo"

    def test_check_if_symlink_exec(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "lrwxrwxrwx 1 foo bar 43 Jun 22 05:48 /tmp/foo -> /var/tmp/foo"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.check_if_symlink("/tmp/foo")
        assert result == "/var/tmp/foo"

    def test_check_if_symlink_samedir_shell(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = (
                    "foo@bar:~$ ls -l /tmp/foo\n"
                    "lrwxrwxrwx 1 foo bar 43 Jun 22 05:48 /tmp/foo -> bar\n"
                    "foo@bar:~$"
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.check_if_symlink("/tmp/foo")
        assert result == "/tmp/bar"

    def test_check_if_symlink_samedir_exec(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "lrwxrwxrwx 1 foo bar 43 Jun 22 05:48 /tmp/foo -> bar"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.check_if_symlink("/tmp/foo")
        assert result == "/tmp/bar"

    def test_check_if_symlink_fail(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = ""
                if re.match(r"ls -l", args[1]):
                    result = False
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(ValueError):
            scget.check_if_symlink("/tmp/foo")

    def test_check_target_exists(self, monkeypatch: MonkeyPatch):
        def exists(*args):
            return True

        def isfile(*args):
            return False

        def islink(*args):
            return True

        scget = SplitCopyGet()
        monkeypatch.setattr("os.path.isfile", isfile)
        monkeypatch.setattr("os.path.islink", islink)
        monkeypatch.setattr("os.path.exists", exists)
        result = scget.check_target_exists("/var/tmp/foo")
        assert result == True

    def test_delete_target_local_overwrite(self, monkeypatch: MonkeyPatch):
        def remove(*args):
            return True

        def check_target_exists(*args):
            return True

        scget = SplitCopyGet()
        scget.overwrite = True
        monkeypatch.setattr("os.remove", remove)
        monkeypatch.setattr(scget, "check_target_exists", check_target_exists)
        result = scget.delete_target_local("/var/tmp/foo")
        assert result == None

    def test_delete_target_local_overwrite_permfail_ssh(self, monkeypatch: MonkeyPatch):
        def remove(*args):
            raise PermissionError

        def check_target_exists(*args):
            return True

        scget = SplitCopyGet()
        scget.scs = MockSplitCopyShared()
        scget.overwrite = True
        scget.sshshell = True
        monkeypatch.setattr("os.remove", remove)
        monkeypatch.setattr(scget, "check_target_exists", check_target_exists)
        with raises(SystemExit):
            scget.delete_target_local("/var/tmp/foo")

    def test_delete_target_local_no_overwrite(self, monkeypatch: MonkeyPatch):
        def check_target_exists(*args):
            return True

        scget = SplitCopyGet()
        monkeypatch.setattr(scget, "check_target_exists", check_target_exists)
        with raises(SystemExit):
            scget.delete_target_local("/var/tmp/foo")

    def test_remote_filesize_shell(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = (
                    "foo@bar:~$ ls -l /var/tmp/foo\n"
                    "-rw------- 1 foo bar 69927631 Mar 29 06:49 /var/tmp/foo\n"
                    "foo@bar:~$"
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        filesize_path = "/var/tmp/foo"
        result = scget.remote_filesize(filesize_path)
        assert result == 69927631

    def test_remote_filesize_exec(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "-rw------- 1 foo bar 69927631 Mar 29 06:49 /var/tmp/foo"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        filesize_path = "/var/tmp/foo"
        result = scget.remote_filesize(filesize_path)
        assert result == 69927631

    def test_remote_filesize_fail(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(SystemExit):
            filesize_path = "/var/tmp/foo"
            scget.remote_filesize(filesize_path)

    def test_remote_filesize_0bytes(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "-rw------- 1 foo bar 0 Mar 29 06:49 /var/tmp/foo"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(SystemExit):
            filesize_path = "/var/tmp/foo"
            scget.remote_filesize(filesize_path)

    def test_remote_filesize_0bytes_shell(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = (
                    "foo@bar:~$ ls -l /var/tmp/foo\n"
                    "-rw------- 1 foo bar 0 Mar 29 06:49 /var/tmp/foo\n"
                    "foo@bar:~$"
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(SystemExit):
            filesize_path = "/var/tmp/foo"
            scget.remote_filesize(filesize_path)

    def test_remote_sha_get(self, monkeypatch: MonkeyPatch):
        def find_existing_sha_files(*args):
            return True, ""

        def process_existing_sha_files(stdout):
            return {256: "9f77f4653b052b76af5de0fde3f7c58ae15bfaf3"}

        scget = SplitCopyGet()
        monkeypatch.setattr(scget, "find_existing_sha_files", find_existing_sha_files)
        monkeypatch.setattr(
            scget, "process_existing_sha_files", process_existing_sha_files
        )
        scget.sshshell = MockSSHShell()
        remote_path = "/var/tmp"
        result = scget.remote_sha_get(remote_path)
        assert result == {256: "9f77f4653b052b76af5de0fde3f7c58ae15bfaf3"}

    def test_remote_sha_get_shasum(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "shasum", 1

            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = (
                    "foo@bar ~ % shasum -a 1 /var/tmp/foo\n"
                    "9f77f4653b052b76af5de0fde3f7c58ae15bfaf3  foo\n"
                    "foo@bar ~ %"
                )
                return result, stdout

        def find_existing_sha_files(*args):
            return False, ""

        scget = SplitCopyGet()
        monkeypatch.setattr(scget, "find_existing_sha_files", find_existing_sha_files)
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        remote_path = "/var/tmp"
        result = scget.remote_sha_get(remote_path)
        assert result == {1: "9f77f4653b052b76af5de0fde3f7c58ae15bfaf3"}

    def test_remote_sha_get_sha1sum_fail(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "sha1sum", 1

            def ssh_cmd(*args, **kwargs):
                result = False
                stdout = ""
                return result, stdout

        def find_existing_sha_files(*args):
            return False, ""

        scget = SplitCopyGet()
        monkeypatch.setattr(scget, "find_existing_sha_files", find_existing_sha_files)
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(SystemExit):
            remote_path = "/var/tmp"
            scget.remote_sha_get(remote_path)

    def test_remote_sha_get_regex_fail(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "shasum", 1

            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = ""
                return result, stdout

        def find_existing_sha_files(*args):
            return False, ""

        scget = SplitCopyGet()
        monkeypatch.setattr(scget, "find_existing_sha_files", find_existing_sha_files)
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        with raises(SystemExit):
            remote_path = "/var/tmp"
            scget.remote_sha_get(remote_path)

    def test_find_existing_sha_files(self):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "ls output"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        remote_path = "/var/tmp"
        result = scget.find_existing_sha_files(remote_path)
        assert result == (True, "ls output")

    def test_process_existing_sha_files_shell(self):
        output = (
            "/var/tmp/foo.sha1\n"
            "/var/tmp/foo.sha224\n"
            "/var/tmp/foo.sha256\n"
            "/var/tmp/foo.sha384\n"
            "/var/tmp/foo.sha512\n"
        )

        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = (
                    "foo@bar:~$ cat filename\n"
                    "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13 filename\n"
                    "foo@bar:~$ "
                )
                return result, stdout

        scget = SplitCopyGet()
        scget.use_shell = True
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
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

        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = True
                stdout = "9771ff758f7b66a7933783b8f2e541ed69031daa0cf233acc9eb42f34f885a13 filename"
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
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

        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                return False, ""

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        result = scget.process_existing_sha_files(output)
        assert result == {}

    def test_split_file_remote(self, monkeypatch: MonkeyPatch):
        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared()
        scpclient = MockSCPClient
        file_size = 1000000
        split_size = 100000
        remote_tmpdir = "/var/tmp"
        remote_path = "/var/tmp/foo"
        remote_file = "foo"
        monkeypatch.setattr("builtins.open", MockOpen)
        result = scget.split_file_remote(
            scpclient,
            file_size,
            split_size,
            remote_tmpdir,
            remote_path,
            remote_file,
        )
        assert result == None

    def test_split_file_remote_fail(self, monkeypatch: MonkeyPatch):
        class MockSplitCopyShared2(MockSplitCopyShared):
            def ssh_cmd(*args, **kwargs):
                result = False
                stdout = ""
                return result, stdout

        scget = SplitCopyGet()
        scget.sshshell = MockSSHShell()
        scget.scs = MockSplitCopyShared2()
        monkeypatch.setattr("builtins.open", MockOpen)
        with raises(SystemExit):
            scpclient = MockSCPClient
            file_size = 1000000
            split_size = 100000
            remote_tmpdir = "/var/tmp"
            remote_path = "/var/tmp/foo"
            remote_file = "foo"
            scget.split_file_remote(
                scpclient,
                file_size,
                split_size,
                remote_tmpdir,
                remote_path,
                remote_file,
            )

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
        scget.scs = MockSplitCopyShared()
        remote_file = "foo"
        local_path = "/var/tmp/foo"
        result = scget.join_files_local(local_path, remote_file)
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
        scget.scs = MockSplitCopyShared()
        with raises(SystemExit):
            remote_file = "foo"
            local_path = "/var/tmp/foo"
            scget.join_files_local(local_path, remote_file)

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
        for i in [512, 384, 256, 224, 1]:
            local_path = "/var/tmp/foo"
            result = scget.local_sha_get(sha_hash, local_path)
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
        monkeypatch.setattr("hashlib.sha512", Mock512)
        monkeypatch.setattr("hashlib.sha384", Mock384)
        monkeypatch.setattr("hashlib.sha256", Mock256)
        monkeypatch.setattr("hashlib.sha224", Mock224)
        monkeypatch.setattr("hashlib.sha1", Mock1)
        scget.scs = MockSplitCopyShared()
        sha_hash = {
            512: "0bcdef0123456789",
        }
        with raises(SystemExit):
            local_path = "/var/tmp/foo"
            scget.local_sha_get(sha_hash, local_path)

    def test_compare_file_sizes(self, capsys, monkeypatch: MonkeyPatch):
        scget = SplitCopyGet()

        def getsize(*args):
            return 781321216

        monkeypatch.setattr("os.path.getsize", getsize)
        remote_dir = "/var/tmp"
        remote_file = "foobar"
        local_path = "/homes/foo/bar"
        result = scget.compare_file_sizes(
            781321216, remote_dir, remote_file, local_path
        )
        captured = capsys.readouterr()
        result = captured.out
        expected = "local and remote file sizes match\n"
        assert result == expected

    def test_compare_file_sizes_fail(self, monkeypatch: MonkeyPatch):
        scget = SplitCopyGet()
        scget.scs = MockSplitCopyShared()

        def getsize(*args):
            return 781311

        monkeypatch.setattr("os.path.getsize", getsize)
        with raises(SystemExit):
            remote_dir = "/var/tmp"
            remote_file = "foobar"
            local_path = "/homes/foo/bar"
            scget.compare_file_sizes(781321216, remote_dir, remote_file, local_path)
