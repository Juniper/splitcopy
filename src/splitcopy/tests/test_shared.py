from ftplib import error_reply
from socket import timeout as socket_timeout

from pytest import MonkeyPatch, raises
from splitcopy.shared import SplitCopyShared, pad_string


def test_pad_string():
    result = pad_string("foo")
    assert result == "foo" + " " * 77


class Test_Shared:
    def test_connect_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            def socket_open(self):
                pass

            def transport_open(self):
                pass

            def main_thread_auth(self):
                return False

            def set_transport_keepalive(self):
                pass

            def close(self):
                pass

        scs = SplitCopyShared()
        with raises(SystemExit):
            scs.connect(MockSSHShell)

    def test_connect_success(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            def socket_open(self):
                pass

            def transport_open(self):
                pass

            def main_thread_auth(self):
                return True

            def set_transport_keepalive(self):
                pass

        scs = SplitCopyShared()
        ssh_kwargs = {
            "hostname": "foo",
            "username": "bar",
            "ssh_port": 22,
        }
        result = scs.connect(MockSSHShell, **ssh_kwargs)
        assert result == (scs.sshshell, ssh_kwargs)

    def test_juniper_cli_check_jnpr(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, "\nerror: unknown command: uname"

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.juniper_cli_check()
        assert result == True

    def test_juniper_cli_check_not_jnpr(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, "Linux"

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.juniper_cli_check()
        assert result == False

    def test_juniper_cli_check_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return False, ""

            def close(*args):
                pass

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        with raises(SystemExit):
            scs.juniper_cli_check()

    def test_which_proto_ftp_success_with_password(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def __init__(self):
                self.kwargs = {}
                self.kwargs["password"] = "foobar"

        def ftp_port_check():
            return True

        def ftp_login_check(passwd):
            return True

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "ftp_port_check", ftp_port_check)
        monkeypatch.setattr(scs, "ftp_login_check", ftp_login_check)
        result = scs.which_proto("ftp")
        assert result == ("ftp", "foobar")

    def test_which_proto_ftp_success_with_nopassword(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def __init__(self):
                self.kwargs = {}
                self.kwargs["password"] = None

        def ftp_port_check():
            return True

        def ftp_login_check(passwd):
            return True

        def getpass(prompt, stream):
            return "foobar"

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "ftp_port_check", ftp_port_check)
        monkeypatch.setattr(scs, "ftp_login_check", ftp_login_check)
        monkeypatch.setattr("getpass.getpass", getpass)
        result = scs.which_proto("ftp")
        assert result == ("ftp", "foobar")

    def test_which_proto_ftp_port_not_open(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def __init__(self):
                self.kwargs = {}
                self.kwargs["password"] = "foobar"

        def ftp_port_check():
            return False

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "ftp_port_check", ftp_port_check)
        result = scs.which_proto("ftp")
        assert result == ("scp", "foobar")

    def test_which_proto_ftp_fail_login(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def __init__(self):
                self.kwargs = {}
                self.kwargs["password"] = "foobar"

        def ftp_port_check():
            return True

        def ftp_login_check(passwd):
            return False

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "ftp_port_check", ftp_port_check)
        monkeypatch.setattr(scs, "ftp_login_check", ftp_login_check)
        result = scs.which_proto("ftp")
        assert result == ("scp", "foobar")

    def test_which_proto_ftp_fail_login_ftperror(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def __init__(self):
                self.kwargs = {}
                self.kwargs["password"] = "foobar"

        def ftp_port_check():
            return True

        def ftp_login_check(passwd):
            raise error_reply

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "ftp_port_check", ftp_port_check)
        monkeypatch.setattr(scs, "ftp_login_check", ftp_login_check)
        result = scs.which_proto("ftp")
        assert result == ("scp", "foobar")

    def test_which_proto_ftp_fail_login_socketerror(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def __init__(self):
                self.kwargs = {}
                self.kwargs["password"] = "foobar"

        def ftp_port_check():
            return True

        def ftp_login_check(passwd):
            raise socket_timeout

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "ftp_port_check", ftp_port_check)
        monkeypatch.setattr(scs, "ftp_login_check", ftp_login_check)
        result = scs.which_proto("ftp")
        assert result == ("scp", "foobar")

    def test_which_proto_scp(self):
        class MockSSHShell:
            def __init__(self):
                self.kwargs = {}
                self.kwargs["password"] = "foobar"

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.which_proto("scp")
        assert result == ("scp", "foobar")

    def test_ftp_port_check(self, monkeypatch: MonkeyPatch):
        class MockSocket:
            def create_connection(address, timeout):
                pass

        scs = SplitCopyShared()
        result = scs.ftp_port_check(socket_lib=MockSocket)
        assert result == True

    def test_ftp_port_check_timeout(self, monkeypatch: MonkeyPatch):
        class MockSocket:
            def create_connection(address, timeout):
                raise socket_timeout

        scs = SplitCopyShared()
        result = scs.ftp_port_check(socket_lib=MockSocket)
        assert result == False

    def test_ftp_port_check_refused(self, monkeypatch: MonkeyPatch):
        class MockSocket:
            def create_connection(address, timeout):
                raise ConnectionRefusedError

        scs = SplitCopyShared()
        result = scs.ftp_port_check(socket_lib=MockSocket)
        assert result == False

    def test_ftp_login_check_success(self, monkeypatch: MonkeyPatch):
        class MockFTP:
            def __init__(self, **kwargs):
                pass

            def __enter__(self):
                pass

            def __exit__(self, exc_type, exc_value, exc_tb):
                pass

        scs = SplitCopyShared()
        result = scs.ftp_login_check("foobar", ftp_lib=MockFTP)
        assert result == True

    def test_ftp_login_check_fail(self, monkeypatch: MonkeyPatch):
        class MockFTP:
            def __init__(self, **kwargs):
                raise SystemExit

        scs = SplitCopyShared()
        with raises(SystemExit):
            scs.ftp_login_check("foobar", ftp_lib=MockFTP)

    def test_which_os_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return False, ""

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.which_os()

    def test_which_os_evo(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, "uname\nLinux\nfoo@bar:~$"

        def evo_os():
            return True

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        monkeypatch.setattr(scs, "evo_os", evo_os)
        result = scs.which_os()
        assert result == (False, True, float(), float())

    def test_which_os_junos(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, "uname\nJUNOS\nfoo@bar:~$"

        def which_sshd():
            return 7.1

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        monkeypatch.setattr(scs, "which_sshd", which_sshd)
        result = scs.which_os()
        assert result == (True, False, 6.3, 7.1)

    def test_which_os_junos_bsdx(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, "uname\nFreeBSD\nfoo@bar:~$"

        def junos_os():
            return True

        def which_sshd():
            return 7.1

        def which_bsd():
            return 12.1

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        monkeypatch.setattr(scs, "junos_os", junos_os)
        monkeypatch.setattr(scs, "which_sshd", which_sshd)
        monkeypatch.setattr(scs, "which_bsd", which_bsd)
        result = scs.which_os()
        assert result == (True, False, 12.1, 7.1)

    def test_which_os_junos_bsdx_asroot(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, "FreeBSD"

        def junos_os():
            return True

        def which_sshd():
            return 7.1

        def which_bsd():
            return 12.1

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "junos_os", junos_os)
        monkeypatch.setattr(scs, "which_sshd", which_sshd)
        monkeypatch.setattr(scs, "which_bsd", which_bsd)
        result = scs.which_os()
        assert result == (True, False, 12.1, 7.1)

    def test_evo_os(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, ""

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.evo_os()
        assert result == True

    def test_junos_os_bsd6(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, "uname -i\nJUNIPER\nfoo@bar:~$"

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        result = scs.junos_os()
        assert result == True

    def test_junos_os_bsdx(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, "uname -i\nJNPR\nfoo@bar:~$"

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        result = scs.junos_os()
        assert result == True

    def test_which_bsd_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return False, ""

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.which_bsd()

    def test_which_bsd_jnpr(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, "uname -r\nFreeBSD-12.1\nfoo@bar:~$"

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        result = scs.which_bsd()
        assert result == 12.1

    def test_which_bsd_nonjnpr(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, "FreeBSD-12.1"

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.which_bsd()
        assert result == 12.1

    def test_which_sshd_jnpr_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True, combine=False):
                return False, "foobar"

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.which_sshd()

    def test_which_sshd_nonjnpr_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True, combine=False):
                return False, "foobar"

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.which_sshd()

    def test_which_sshd(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=False, combine=False):
                return (
                    False,
                    (
                        "sshd -v\n"
                        "sshd: illegal option -- v\n"
                        "OpenSSH_8.6p1, LibreSSL 3.3.6\n"
                    ),
                )

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        result = scs.which_sshd()
        assert result == 8.6

    def test_which_sshd_jnpr_asroot(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=False, combine=False):
                return (
                    False,
                    "sshd: illegal option -- v\n" "OpenSSH_8.6p1, LibreSSL 3.3.6\n",
                )

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.which_sshd()
        assert result == 8.6

    def test_req_binaries_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return False, ""

            def close(err_str):
                raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        with raises(SystemExit):
            scs.req_binaries(get_op=False, junos=False, evo=False)

    def test_req_binaries(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, ""

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.req_binaries(get_op=False, junos=False, evo=False)
        assert result == None

    def test_req_binaries_getop(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, ""

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.req_binaries(get_op=True, junos=False, evo=False)
        assert result == None

    def test_req_sha_binaries_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return False, ""

            def close(err_str):
                raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        sha_hash = {}
        sha_hash[1] = True
        sha_hash[512] = True
        with raises(SystemExit):
            scs.req_sha_binaries(sha_hash)

    def test_req_sha_binaries(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, ""

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        sha_hash = {}
        sha_hash[1] = True
        sha_hash[224] = True
        sha_hash[256] = True
        sha_hash[384] = True
        sha_hash[512] = True
        result = scs.req_sha_binaries(sha_hash)
        assert result == ("shasum", 512)

    def test_close_err_str(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def close(err_str):
                pass

        def remote_cleanup():
            pass

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.rm_remote_tmp = True
        scs.command_list = ["foo"]
        monkeypatch.setattr(scs, "remote_cleanup", remote_cleanup)
        with raises(SystemExit):
            scs.close(err_str="foobar", config_rollback=False, hard_close=False)

    def test_close_config_rollback(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def close(err_str):
                pass

        def remote_cleanup():
            pass

        def limits_rollback():
            pass

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.rm_remote_tmp = True
        scs.command_list = ["foo"]
        monkeypatch.setattr(scs, "remote_cleanup", remote_cleanup)
        monkeypatch.setattr(scs, "limits_rollback", limits_rollback)
        with raises(SystemExit):
            scs.close(err_str=None, config_rollback=True, hard_close=False)

    def test_close_hard_close(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def close(err_str):
                pass

        def _exit(code):
            raise SystemExit

        def rmtree(path):
            raise PermissionError

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.local_tmpdir = "foobar"
        monkeypatch.setattr("shutil.rmtree", rmtree)
        monkeypatch.setattr("os._exit", _exit)
        scs.rm_remote_tmp = False
        with raises(SystemExit):
            scs.close(err_str=None, config_rollback=False, hard_close=True)

    def test_file_split_size(self, monkeypatch: MonkeyPatch):
        def cpu_count():
            return 4

        def pool_executor(max_workers, thread_name_prefix):
            return True

        scs = SplitCopyShared()
        monkeypatch.setattr("os.cpu_count", cpu_count)
        monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor", pool_executor)
        file_size = 100000
        sshd_version = 8.2
        bsd_version = 12.0
        evo = False
        copy_proto = "scp"
        result = scs.file_split_size(
            file_size, sshd_version, bsd_version, evo, copy_proto
        )
        assert result == (7693, True)

    def test_file_split_size2(self, monkeypatch: MonkeyPatch):
        def cpu_count():
            return 4

        def pool_executor(max_workers, thread_name_prefix):
            return True

        scs = SplitCopyShared()
        monkeypatch.setattr("os.cpu_count", cpu_count)
        monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor", pool_executor)
        file_size = 100000
        sshd_version = 7.4
        bsd_version = 6.3
        evo = False
        copy_proto = "scp"
        result = scs.file_split_size(
            file_size, sshd_version, bsd_version, evo, copy_proto
        )
        assert result == (10000, True)

    def test_file_split_size3(self, monkeypatch: MonkeyPatch):
        def cpu_count():
            return 4

        def pool_executor(max_workers, thread_name_prefix):
            return True

        scs = SplitCopyShared()
        monkeypatch.setattr("os.cpu_count", cpu_count)
        monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor", pool_executor)
        file_size = 100000
        sshd_version = 7.3
        bsd_version = 6.3
        evo = False
        copy_proto = "scp"
        result = scs.file_split_size(
            file_size, sshd_version, bsd_version, evo, copy_proto
        )
        assert result == (7693, True)

    def test_file_split_size4(self, monkeypatch: MonkeyPatch):
        def cpu_count():
            return 4

        def pool_executor(max_workers, thread_name_prefix):
            return True

        scs = SplitCopyShared()
        monkeypatch.setattr("os.cpu_count", cpu_count)
        monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor", pool_executor)
        file_size = 100000
        sshd_version = 7.3
        bsd_version = 11.0
        evo = False
        copy_proto = "scp"
        result = scs.file_split_size(
            file_size, sshd_version, bsd_version, evo, copy_proto
        )
        result == (5000, True)

    def test_file_split_size_evo(self, monkeypatch: MonkeyPatch):
        def cpu_count():
            return 4

        def pool_executor(max_workers, thread_name_prefix):
            return True

        scs = SplitCopyShared()
        monkeypatch.setattr("os.cpu_count", cpu_count)
        monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor", pool_executor)
        file_size = 100000
        sshd_version = 7.3
        bsd_version = float()
        evo = True
        copy_proto = "scp"
        result = scs.file_split_size(
            file_size, sshd_version, bsd_version, evo, copy_proto
        )
        result == (7693, True)

    def test_file_split_size_linux(self, monkeypatch: MonkeyPatch):
        def cpu_count():
            return 4

        def pool_executor(max_workers, thread_name_prefix):
            return True

        scs = SplitCopyShared()
        monkeypatch.setattr("os.cpu_count", cpu_count)
        monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor", pool_executor)
        file_size = 100000
        sshd_version = 7.3
        bsd_version = float()
        evo = False
        copy_proto = "scp"
        result = scs.file_split_size(
            file_size, sshd_version, bsd_version, evo, copy_proto
        )
        assert result == (20000, True)

    def test_file_split_size_cpu_count_fail(self, monkeypatch: MonkeyPatch):
        def cpu_count():
            raise NotImplementedError

        def pool_executor(max_workers, thread_name_prefix):
            return True

        scs = SplitCopyShared()
        monkeypatch.setattr("os.cpu_count", cpu_count)
        monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor", pool_executor)
        file_size = 100000
        sshd_version = 8.2
        bsd_version = 12.0
        evo = False
        copy_proto = "ftp"
        result = scs.file_split_size(
            file_size, sshd_version, bsd_version, evo, copy_proto
        )
        assert result == (20000, True)

    def test_file_split_size_low_cpu_count(self, monkeypatch: MonkeyPatch):
        def cpu_count():
            return 1

        def pool_executor(max_workers, thread_name_prefix):
            return True

        scs = SplitCopyShared()
        monkeypatch.setattr("os.cpu_count", cpu_count)
        monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor", pool_executor)
        file_size = 100000
        sshd_version = 8.2
        bsd_version = float()
        evo = False
        copy_proto = "scp"
        result = scs.file_split_size(
            file_size, sshd_version, bsd_version, evo, copy_proto
        )
        assert result == (20000, True)

    def test_mkdir_remote_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return False, ""

        def close(err_str):
            raise SystemExit

        class datetime:
            def strftime(time, fmt):
                return "20220609231003"

            def now():
                pass

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.get_op = True
        scs.remote_file = "foobar"
        monkeypatch.setattr(scs, "close", close)
        monkeypatch.setattr("datetime.datetime", datetime)
        with raises(SystemExit):
            scs.mkdir_remote()

    def test_mkdir_remote_get(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, ""

        class datetime:
            def strftime(time, fmt):
                return "20220609231003"

            def now():
                pass

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.get_op = True
        scs.remote_file = "foobar"
        monkeypatch.setattr("datetime.datetime", datetime)
        result = scs.mkdir_remote()
        assert result == "/var/tmp/splitcopy_foobar.20220609231003"

    def test_mkdir_remote_put(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, ""

        class datetime:
            def strftime(time, fmt):
                return "20220609231003"

            def now():
                pass

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.get_op = False
        scs.remote_file = "foobar"
        scs.remote_dir = "/tmp"
        monkeypatch.setattr("datetime.datetime", datetime)
        result = scs.mkdir_remote()
        assert result == "/tmp/splitcopy_foobar.20220609231003"

    def test_storage_check_remote_cmd_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return False, ""

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.storage_check_remote(100000, 7693)

    def test_storage_check_remote_blocks_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return True, ""

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.storage_check_remote(100000, 7693)

    def test_storage_check_remote_get_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return (
                    True,
                    (
                        "df -k /tmp\n"
                        "Filesystem           1K-blocks  Used Available Use% Mounted on\n"
                        "/dev/mapper/vg00-tmp 60 316488560 0   100% /tmp\n"
                    ),
                )

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        scs.get_op = True
        scs.remote_dir = "/tmp"
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.storage_check_remote(100000, 7693)

    def test_storage_check_remote_put_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return (
                    True,
                    (
                        "df -k /tmp\n"
                        "Filesystem           1K-blocks  Used Available Use% Mounted on\n"
                        "/dev/mapper/vg00-tmp 60 316488560 0   100% /tmp\n"
                    ),
                )

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        scs.get_op = False
        scs.remote_dir = "/tmp"
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.storage_check_remote(100000, 7693)

    def test_storage_check_remote_success(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                return (
                    True,
                    (
                        "df -k /tmp\n"
                        "Filesystem           1K-blocks  Used Available Use% Mounted on\n"
                        "/dev/mapper/vg00-tmp 316488560 64716 303471912   1% /tmp\n"
                    ),
                )

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.get_op = False
        scs.remote_dir = "/tmp"
        result = scs.storage_check_remote(100000, 7693)
        assert result == None

    def test_storage_check_local_fail(self, monkeypatch: MonkeyPatch):
        def gettempdir():
            return "/tmp/foo"

        def disk_usage(path):
            return [494384795648, 215990648832, 816]

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        monkeypatch.setattr("shutil.disk_usage", disk_usage)
        monkeypatch.setattr("tempfile.gettempdir", gettempdir)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.storage_check_local(100000)

    def test_storage_check_local_get_fail(self, monkeypatch: MonkeyPatch):
        def gettempdir():
            return "/tmp/foo"

        def disk_usage(path):
            if path == "/tmp/foo":
                result = [494384795648, 215990648832, 278394146816]
            else:
                result = [494384795648, 215990648832, 816]
            return result

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        scs.get_op = True
        scs.local_dir = "/var/tmp"
        monkeypatch.setattr("shutil.disk_usage", disk_usage)
        monkeypatch.setattr("tempfile.gettempdir", gettempdir)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.storage_check_local(100000)

    def test_storage_check_local_get(self, monkeypatch: MonkeyPatch):
        def gettempdir():
            return "/tmp/foo"

        def disk_usage(path):
            return [494384795648, 215990648832, 278394146816]

        scs = SplitCopyShared()
        scs.get_op = True
        scs.local_dir = "/var/tmp"
        monkeypatch.setattr("shutil.disk_usage", disk_usage)
        monkeypatch.setattr("tempfile.gettempdir", gettempdir)
        result = scs.storage_check_local(100000)
        assert result == None

    def test_change_dir(self, monkeypatch: MonkeyPatch):
        def getcwd():
            return "/tmp"

        def chdir(path):
            return True

        def expanduser(path):
            return path

        monkeypatch.setattr("os.getcwd", getcwd)
        monkeypatch.setattr("os.chdir", chdir)
        monkeypatch.setattr("os.path.expanduser", expanduser)

        scs = SplitCopyShared()
        scs.local_tmpdir = "/var/tmp/foo"
        with scs.change_dir() as foo:
            result = foo
        assert result == None

    def test_tempdir(self, monkeypatch: MonkeyPatch):
        def mkdtemp():
            return "/var/tmp/foo"

        def rmtree(path):
            pass

        def getcwd():
            return "/tmp"

        def chdir(path):
            return True

        def expanduser(path):
            return path

        monkeypatch.setattr("os.getcwd", getcwd)
        monkeypatch.setattr("os.chdir", chdir)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        monkeypatch.setattr("tempfile.mkdtemp", mkdtemp)
        monkeypatch.setattr("shutil.rmtree", rmtree)

        scs = SplitCopyShared()
        with scs.tempdir() as foo:
            result = foo
        assert result == "/var/tmp/foo"

    def test_return_tmpdir(self):
        scs = SplitCopyShared()
        scs.local_tmpdir = "/var/tmp/foo"
        result = scs.return_tmpdir()
        assert result == "/var/tmp/foo"

    def test_find_configured_limits(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True):
                stdout = cmd.split()[4]
                return True, f"set {stdout}\n"

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.find_configured_limits(["foo", "bar"])
        assert result == "set foo\nset bar\n"

    def test_limit_check(self, monkeypatch: MonkeyPatch):
        def find_configured_limits(*args):
            return ""

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "find_configured_limits", find_configured_limits)
        result = scs.limit_check("ftp")
        assert result == []

    def test_limit_check_deactivate(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True, timeout=60):
                return True, "commit complete\r\nExiting configuration mode"

        def find_configured_limits(*args):
            return (
                '% cli -c "show configuration system services | display set | no-more"\r\r\n'
                "set system services ftp connection-limit 4\r\n"
                '% cli -c "show configuration system login | display set | no-more"\r\r\n'
                "set system login retry-options foo\r\n"
                '% cli -c "show configuration groups | display set | no-more"\r\r\n'
                "set groups foo system services ftp rate-limit 6\r\n"
                "set groups foo system login retry-options bar\r\n"
            )

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        monkeypatch.setattr(scs, "find_configured_limits", find_configured_limits)
        result = scs.limit_check("ftp")
        assert result == [
            "deactivate system services ftp connection-limit;",
            "deactivate groups foo system services ftp rate-limit;",
            "deactivate system login retry-options;",
            "deactivate groups foo system login retry-options;",
        ]

    def test_limit_check_deactivate_commit_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def run(self, cmd, exitcode=True, timeout=60):
                return True, ""

        def close(err_str):
            raise SystemExit

        def find_configured_limits(*args):
            return "set services ftp connection-limit 4"

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "find_configured_limits", find_configured_limits)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.limit_check("ftp")

    def test_limits_rollback_fail(self, capsys):
        class MockSSHShell:
            def run(self, cmd, exitcode=True, timeout=10):
                return True, "foobar"

        scs = SplitCopyShared()
        scs.command_list = ["deactivate foo"]
        scs.sshshell = MockSSHShell()
        result = scs.limits_rollback()
        captured = capsys.readouterr()
        result = captured.out
        assert result == (
            "Error: failed to revert the configuration changes. output was:\nfoobar\n"
        )

    def test_limits_rollback(self, capsys):
        class MockSSHShell:
            def run(self, cmd, exitcode=True, timeout=10):
                return True, "commit complete\r\nExiting configuration mode"

        scs = SplitCopyShared()
        scs.command_list = ["deactivate foo"]
        scs.use_shell = True
        scs.sshshell = MockSSHShell()
        result = scs.limits_rollback()
        captured = capsys.readouterr()
        result = captured.out
        assert result == "configuration changes made have been reverted\n"

    def test_remote_cleanup_fail(self, capsys):
        class MockSSHShell:
            def run(self, cmd, exitcode=True, timeout=10):
                return False, ""

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        scs.remote_tmpdir = "/var/tmp/foo"
        remote_dir = "/tmp/"
        remote_file = "foo"
        result = scs.remote_cleanup(remote_dir=remote_dir, remote_file=remote_file)
        captured = capsys.readouterr()
        result = captured.out
        assert result == (
            "\rdeleting remote tmp directory...                                                \n"
            "unable to delete the tmp directory /var/tmp/foo on remote host, delete it manually\n"
        )

    def test_remote_cleanup_get(self):
        class MockSSHShell:
            def run(self, cmd, exitcode=True, timeout=10):
                return True, ""

        scs = SplitCopyShared()
        scs.get_op = True
        scs.sshshell = MockSSHShell()
        result = scs.remote_cleanup()
        assert result == None

    def test_remote_cleanup_put(self):
        class MockSSHShell:
            def run(self, cmd, exitcode=True, timeout=10):
                return True, ""

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.remote_cleanup()
        assert result == None
