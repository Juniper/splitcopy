import concurrent.futures
import datetime
import re
import time
from contextlib import contextmanager
from ftplib import error_proto
from threading import Thread

from paramiko import SSHException
from pytest import MonkeyPatch, raises
from scp import SCPException
from splitcopy.put import SplitCopyPut, TransferError


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
    def __init__(self, file, perms, newline=None):
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

    def seek(self, bytes):
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

    def put(self, *args):
        pass

    def size(self, *args):
        return 1000

    def sendcmd(self, cmd):
        pass


class MockSCPClient:
    def __init__(self, transport, progress=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def put(self, *args):
        pass


class MockSplitCopyShared:
    def __init__(self):
        pass

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


class MockHash:
    def __init__(self):
        pass

    def update(self, data):
        pass

    def hexdigest(self):
        return "abcdef0123456789"


class TestSplitCopyPut:
    def test_handlesigint(self, monkeypatch: MonkeyPatch):
        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared()
        with raises(SystemExit):
            scput.handlesigint("SigInt", "stack")

    def test_put(self, monkeypatch: MonkeyPatch):
        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared()
        scput.progress = MockProgress()

        def validate_remote_path_put():
            pass

        def check_target_exists():
            return True

        def delete_target_remote():
            pass

        def determine_local_filesize():
            return 1000000

        def local_sha_put():
            return "sha384sum", 384, "abcdef0123456789"

        def split_file_local(file_size, split_size):
            pass

        def get_chunk_info():
            return [["chunk0", 1000], ["chunk1", 1000]]

        def put_files(*args):
            pass

        def join_files_remote(*args):
            pass

        def remote_sha_put(*args):
            pass

        def compare_file_sizes(*args):
            pass

        def inc_percentage():
            for n in range(90, 101):
                time.sleep(0.1)
                scput.progress.totals["percent_done"] = n

        monkeypatch.setattr(scput, "validate_remote_path_put", validate_remote_path_put)
        monkeypatch.setattr(scput, "check_target_exists", check_target_exists)
        monkeypatch.setattr(scput, "delete_target_remote", delete_target_remote)
        monkeypatch.setattr(scput, "determine_local_filesize", determine_local_filesize)
        monkeypatch.setattr(scput, "local_sha_put", local_sha_put)
        monkeypatch.setattr(scput, "split_file_local", split_file_local)
        monkeypatch.setattr(scput, "get_chunk_info", get_chunk_info)
        monkeypatch.setattr(scput, "put_files", put_files)
        monkeypatch.setattr(scput, "join_files_remote", join_files_remote)
        monkeypatch.setattr(scput, "compare_file_sizes", compare_file_sizes)
        monkeypatch.setattr(scput, "remote_sha_put", remote_sha_put)
        thread = Thread(
            name="inc_percentage_done",
            target=inc_percentage,
        )
        thread.start()
        result = scput.put()
        thread.join()
        assert isinstance(result[0], datetime.datetime) and isinstance(
            result[1], datetime.datetime
        )

    def test_put_noverify(self, monkeypatch: MonkeyPatch):
        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared()
        scput.progress = MockProgress()

        def validate_remote_path_put():
            pass

        def check_target_exists():
            return True

        def delete_target_remote():
            pass

        def determine_local_filesize():
            return 1000000

        def split_file_local(*args):
            pass

        def get_chunk_info():
            return [["chunk0", 1000], ["chunk1", 1000]]

        def put_files(*args):
            pass

        def join_files_remote(*args):
            pass

        def compare_file_sizes(*args):
            pass

        def inc_percentage():
            for n in range(90, 101):
                time.sleep(0.1)
                scput.progress.totals["percent_done"] = n

        scput.noverify = True
        monkeypatch.setattr(scput, "validate_remote_path_put", validate_remote_path_put)
        monkeypatch.setattr(scput, "check_target_exists", check_target_exists)
        monkeypatch.setattr(scput, "delete_target_remote", delete_target_remote)
        monkeypatch.setattr(scput, "determine_local_filesize", determine_local_filesize)
        monkeypatch.setattr(scput, "split_file_local", split_file_local)
        monkeypatch.setattr(scput, "get_chunk_info", get_chunk_info)
        monkeypatch.setattr(scput, "put_files", put_files)
        monkeypatch.setattr(scput, "join_files_remote", join_files_remote)
        monkeypatch.setattr(scput, "compare_file_sizes", compare_file_sizes)
        thread = Thread(
            name="inc_percentage_done",
            target=inc_percentage,
        )
        thread.start()
        result = scput.put()
        thread.join()
        assert isinstance(result[0], datetime.datetime) and isinstance(
            result[1], datetime.datetime
        )

    def test_put_fail(self, monkeypatch: MonkeyPatch):
        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared()
        scput.progress = MockProgress()

        def validate_remote_path_put():
            pass

        def check_target_exists():
            return True

        def delete_target_remote():
            pass

        def determine_local_filesize():
            return 1000000

        def local_sha_put():
            return "sha384sum", 384, "abcdef0123456789"

        def split_file_local(*args):
            pass

        def get_chunk_info():
            return [["chunk0", 1000], ["chunk1", 1000]]

        def put_files(*args):
            raise TransferError

        monkeypatch.setattr(scput, "validate_remote_path_put", validate_remote_path_put)
        monkeypatch.setattr(scput, "check_target_exists", check_target_exists)
        monkeypatch.setattr(scput, "delete_target_remote", delete_target_remote)
        monkeypatch.setattr(scput, "determine_local_filesize", determine_local_filesize)
        monkeypatch.setattr(scput, "local_sha_put", local_sha_put)
        monkeypatch.setattr(scput, "split_file_local", split_file_local)
        monkeypatch.setattr(scput, "get_chunk_info", get_chunk_info)
        monkeypatch.setattr(scput, "put_files", put_files)

        with raises(SystemExit):
            scput.put()

    def test_get_chunk_info(self, monkeypatch: MonkeyPatch):
        def listdir(path):
            return ["somefile_aa", "somefile_ab"]

        def stat(*args):
            stat.st_size = 10000
            return stat

        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared()
        scput.local_file = "somefile"
        monkeypatch.setattr("os.listdir", listdir)
        monkeypatch.setattr("os.stat", stat)
        result = scput.get_chunk_info()
        assert result == [["somefile_aa", 10000], ["somefile_ab", 10000]]

    def test_get_chunk_info_matchfail(self, monkeypatch: MonkeyPatch):
        def listdir(path):
            return ["foo", "bar"]

        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared()
        scput.local_file = "somefile"
        monkeypatch.setattr("os.listdir", listdir)
        with raises(SystemExit):
            scput.get_chunk_info()

    def test_validate_remote_path_put_isdir(self):
        class MockSSHShell2(MockSSHShell):
            def run(cmd):
                return (True, "")

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2
        scput.local_file = "foo"
        scput.remote_path = "/var/tmp"
        result = scput.validate_remote_path_put()
        assert result == None

    def test_validate_remote_path_existingfile_basename_match(self):
        class MockSSHShell2(MockSSHShell):
            def run(cmd):
                if re.match(r"test -d", cmd):
                    return False, ""
                else:
                    return True, ""

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2
        scput.local_file = "foo"
        scput.remote_path = "/var/tmp/foo"
        result = scput.validate_remote_path_put()
        assert result == None

    def test_validate_remote_path_put_newfile_basename_nomatch(self):
        class MockSSHShell2(MockSSHShell):
            self.instance = 0

            def run(cmd):
                if re.match(r"test -d", cmd) and not self.instance:
                    self.instance += 1
                    return False, ""
                elif re.match(r"test -d", cmd):
                    return True, ""
                else:
                    return False, ""

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2
        scput.local_file = "foo"
        scput.remote_path = "/var/tmp/bar"
        result = scput.validate_remote_path_put()
        assert result == None

    def test_validate_remote_path_put_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(cmd):
                return (False, "")

        def dirname(path):
            return "/var/tmp"

        monkeypatch.setattr("os.path.dirname", dirname)
        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2
        scput.scs = MockSplitCopyShared()
        scput.local_file = "foo"
        scput.remote_path = "/var/tmp/foo"
        with raises(SystemExit):
            scput.validate_remote_path_put()

    def test_check_target_exists(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(cmd):
                return (True, "")

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2
        result = scput.check_target_exists()
        assert result == True

    def test_delete_target_remote(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(cmd):
                return (True, "")

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2
        result = scput.delete_target_remote()
        assert result == None

    def test_delete_target_remote_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(cmd):
                return (False, "")

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2
        scput.scs = MockSplitCopyShared()
        with raises(SystemExit):
            scput.delete_target_remote()

    def test_determine_local_filesize(self, monkeypatch: MonkeyPatch):
        def getsize(path):
            return 10000

        scput = SplitCopyPut()
        monkeypatch.setattr("os.path.getsize", getsize)
        result = scput.determine_local_filesize()
        assert result == 10000

    def test_local_sha_put_512(self, monkeypatch: MonkeyPatch):
        def isfile(path):
            result = False
            if re.search(r".*sha512", path):
                result = True
            return result

        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "sha512sum", 512

        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared2()
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("os.path.isfile", isfile)
        result = scput.local_sha_put()
        assert result == ("sha512sum", 512, {512: "abcdef0123456789"})

    def test_local_sha_put_384(self, monkeypatch: MonkeyPatch):
        def isfile(path):
            result = False
            if re.search(r".*sha384", path):
                result = True
            return result

        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "sha384sum", 384

        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared2()
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("os.path.isfile", isfile)
        result = scput.local_sha_put()
        assert result == ("sha384sum", 384, {384: "abcdef0123456789"})

    def test_local_sha_put_256(self, monkeypatch: MonkeyPatch):
        def isfile(path):
            result = False
            if re.search(r".*sha256", path):
                result = True
            return result

        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "sha256sum", 256

        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared2()
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("os.path.isfile", isfile)
        result = scput.local_sha_put()
        assert result == ("sha256sum", 256, {256: "abcdef0123456789"})

    def test_local_sha_put_224(self, monkeypatch: MonkeyPatch):
        def isfile(path):
            result = False
            if re.search(r".*sha224", path):
                result = True
            return result

        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "sha224sum", 224

        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared2()
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("os.path.isfile", isfile)
        result = scput.local_sha_put()
        assert result == ("sha224sum", 224, {224: "abcdef0123456789"})

    def test_local_sha_put_1(self, monkeypatch: MonkeyPatch):
        def isfile(path):
            result = False
            if re.search(r".*sha1", path):
                result = True
            return result

        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "sha1sum", 1

        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared2()
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("os.path.isfile", isfile)
        result = scput.local_sha_put()
        assert result == ("sha1sum", 1, {1: "abcdef0123456789"})

    def test_local_sha_put_none(self, monkeypatch: MonkeyPatch):
        def isfile(path):
            return False

        class MockSplitCopyShared2(MockSplitCopyShared):
            def req_sha_binaries(self, sha_hash):
                return "shasum", 1

        class Mock1(MockHash):
            pass

        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared2()
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("os.path.isfile", isfile)
        monkeypatch.setattr("hashlib.sha1", Mock1)
        result = scput.local_sha_put()
        assert result == ("shasum", 1, {1: "abcdef0123456789"})

    def test_split_file_local(self, monkeypatch: MonkeyPatch):
        scput = SplitCopyPut()
        monkeypatch.setattr("builtins.open", MockOpen)
        file_size = 100000
        split_size = 3000
        result = scput.split_file_local(file_size, split_size)
        assert result == None

    def test_split_file_local_fail(self, monkeypatch: MonkeyPatch):
        class MockOpen2(MockOpen):
            def __init__(self, *args):
                pass

            def seek(self, bytes):
                raise OSError

        scput = SplitCopyPut()
        scput.scs = MockSplitCopyShared()
        monkeypatch.setattr("builtins.open", MockOpen2)
        file_size = 100000
        split_size = 10000
        with raises(SystemExit):
            scput.split_file_local(file_size, split_size)

    def test_join_files_remote(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout):
                return True, ""

        chunks = [["somefile_aa", 10000], ["somefile_ab", 10000]]
        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2()
        scput.scs = MockSplitCopyShared()
        scput.remote_dir = "/var/tmp/foo"
        scput.remote_file = "somefile"
        monkeypatch.setattr("builtins.open", MockOpen)
        result = scput.join_files_remote(MockSCPClient, chunks, "/tmp/foo")
        assert result == None

    def test_join_files_remote_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout):
                return False, ""

        chunks = [["somefile_aa", 10000], ["somefile_ab", 10000]]
        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2()
        scput.scs = MockSplitCopyShared()
        scput.remote_dir = "/var/tmp/foo"
        scput.remote_file = "somefile"
        monkeypatch.setattr("builtins.open", MockOpen)
        with raises(SystemExit):
            scput.join_files_remote(MockSCPClient, chunks, "/tmp/foo")

    def test_join_files_remote_exception(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout):
                raise SSHException

        chunks = [["somefile_aa", 10000], ["somefile_ab", 10000]]
        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2()
        scput.scs = MockSplitCopyShared()
        scput.remote_dir = "/var/tmp/foo"
        scput.remote_file = "somefile"
        monkeypatch.setattr("builtins.open", MockOpen)
        with raises(SystemExit):
            scput.join_files_remote(MockSCPClient, chunks, "/tmp/foo")

    def test_compare_file_sizes(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout=30):
                stdout = (
                    b"foo@bar ~ % ls -l /var/tmp/foo\r\r\n"
                    b"-rw-r--r--  1 foo  bar  100000 19 Dec  2019 /var/tmp/foo\r\n"
                    b"foo@bar ~ % "
                ).decode()
                return True, stdout

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2()
        result = scput.compare_file_sizes(100000)
        assert result == None

    def test_compare_file_sizes_cmd_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout=30):
                return False, ""

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2()
        scput.scs = MockSplitCopyShared()
        with raises(SystemExit):
            scput.compare_file_sizes(100000)

    def test_compare_file_sizes_mismatch(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout=30):
                stdout = (
                    b"foo@bar ~ % ls -l /var/tmp/foo\r\r\n"
                    b"-rw-r--r--  1 foo  bar  400000 19 Dec  2019 /var/tmp/foo\r\n"
                    b"foo@bar ~ %"
                ).decode()
                return True, stdout

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2()
        scput.scs = MockSplitCopyShared()
        with raises(SystemExit):
            scput.compare_file_sizes(100000)

    def test_remote_sha_put(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout=30):
                stdout = (
                    "foo@bar ~ % sha224sum -a 224 /var/tmp/foo\n"
                    "d2a90f1c9edd2e9771306d8c8f4a4fc802181b973ee8167fcaff98f4 "
                    "/var/tmp/foo\n"
                    "foo@bar ~ % \n"
                )
                return True, stdout

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2()
        scput.scs = MockSplitCopyShared()
        sha_bin = "sha224sum"
        sha_len = 224
        sha_hash = {224: "d2a90f1c9edd2e9771306d8c8f4a4fc802181b973ee8167fcaff98f4"}
        result = scput.remote_sha_put(sha_bin, sha_len, sha_hash)
        expected = None
        assert expected == result

    def test_remote_sha_put_cmd_fail(self, capsys, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout=30):
                return False, ""

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2()
        scput.scs = MockSplitCopyShared()
        sha_bin = "shasum"
        sha_len = 224
        sha_hash = {224: "d2a90f1c9edd2e9771306d8c8f4a4fc802181b973ee8167fcaff98f4"}
        scput.remote_sha_put(sha_bin, sha_len, sha_hash)
        captured = capsys.readouterr()
        assert re.search(r"remote sha hash generation failed", captured.out)

    def test_remote_sha_put_hash_fail(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout=30):
                return True, ""

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2()
        scput.scs = MockSplitCopyShared()
        sha_bin = "shasum"
        sha_len = 224
        sha_hash = {224: "d2a90f1c9edd2e9771306d8c8f4a4fc802181b973ee8167fcaff98f4"}
        with raises(SystemExit):
            scput.remote_sha_put(sha_bin, sha_len, sha_hash)

    def test_remote_sha_put_hash_mismatch(self):
        class MockSSHShell2(MockSSHShell):
            def run(self, cmd, timeout=30):
                stdout = (
                    "foo@bar ~ % shasum -a 224 /var/tmp/foo\n"
                    "d2a90f1c9edd2e9771306d8c8f4a4fc802181b973ee8167fceff98f4 "
                    "/var/tmp/foo\n"
                    "foo@bar ~ % \n"
                )
                return True, stdout

        scput = SplitCopyPut()
        scput.sshshell = MockSSHShell2()
        scput.scs = MockSplitCopyShared()
        sha_bin = "shasum"
        sha_len = 224
        sha_hash = {224: "d2a90f1c9edd2e9771306d8c8f4a4fc802181b973ee8167fcaff98f4"}
        with raises(SystemExit):
            scput.remote_sha_put(sha_bin, sha_len, sha_hash)

    def test_put_files_ftp(self):
        scput = SplitCopyPut()
        scput.progress = MockProgress()
        scput.copy_proto = "ftp"
        result = scput.put_files(
            MockFTP, MockSSHShell, MockSCPClient, ["chunk0", 1999], "/tmp/", {}
        )
        assert result == None

    def test_put_files_ftp_fail(self, monkeypatch: MonkeyPatch):
        class MockFTP2(MockFTP):
            def put(self, *args):
                raise error_proto

        def sleep(secs):
            pass

        monkeypatch.setattr("time.sleep", sleep)
        scput = SplitCopyPut()
        scput.progress = MockProgress()
        scput.copy_proto = "ftp"
        with raises(TransferError):
            scput.put_files(
                MockFTP2, MockSSHShell, MockSCPClient, ["chunk0", 1999], "/tmp/", {}
            )

    def test_put_files_ftp_sendcmd_fail(self, monkeypatch: MonkeyPatch):
        class MockFTP2(MockFTP):
            def put(self, *args):
                raise error_proto

            def sendcmd(self, cmd):
                raise error_proto

        def sleep(secs):
            pass

        monkeypatch.setattr("time.sleep", sleep)
        scput = SplitCopyPut()
        scput.progress = MockProgress()
        scput.copy_proto = "ftp"
        with raises(TransferError):
            scput.put_files(
                MockFTP2, MockSSHShell, MockSCPClient, ["chunk0", 1999], "/tmp/", {}
            )

    def test_put_files_scp(self):
        scput = SplitCopyPut()
        scput.progress = MockProgress()
        scput.copy_proto = "scp"
        result = scput.put_files(
            MockFTP, MockSSHShell, MockSCPClient, ["chunk0", 1999], "/tmp/", {}
        )
        assert result == None

    def test_put_files_scp_fail(self, monkeypatch: MonkeyPatch):
        class MockSCPClient2(MockSCPClient):
            def put(self, *args):
                raise SCPException

        def sleep(secs):
            pass

        monkeypatch.setattr("time.sleep", sleep)
        scput = SplitCopyPut()
        scput.progress = MockProgress()
        scput.copy_proto = "scp"
        with raises(TransferError):
            scput.put_files(
                MockFTP, MockSSHShell, MockSCPClient2, ["chunk0", 1999], "/tmp/", {}
            )

    def test_put_files_scp_auth_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def worker_thread_auth(self):
                return False

        def sleep(secs):
            pass

        monkeypatch.setattr("time.sleep", sleep)
        scput = SplitCopyPut()
        scput.progress = MockProgress()
        scput.copy_proto = "scp"
        with raises(TransferError):
            scput.put_files(
                MockFTP, MockSSHShell2, MockSCPClient, ["chunk0", 1999], "/tmp/", {}
            )