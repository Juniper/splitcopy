from ftplib import error_reply
from socket import timeout as socket_timeout

# 3rd party
from paramiko.ssh_exception import SSHException
from pytest import MonkeyPatch, raises

# local
from splitcopy.shared import SplitCopyShared, pad_string


def test_pad_string():
    result = pad_string("foo")
    assert result == "foo" + " " * 77


class MockTransport:
    def __init__(self, **kwargs):
        self.active = True


class MockChannel:
    def __init__(self, **kwargs):
        self.closed = False


class MockSSHShell:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.hostname = self.kwargs.get("hostname")
        self.username = self.kwargs.get("username")
        self.ssh_port = self.kwargs.get("ssh_port")
        self._chan = MockChannel()
        self._transport = MockTransport()
        self.use_shell = False

    def socket_open(self):
        pass

    def transport_open(self):
        pass

    def main_thread_auth(self):
        return True

    def set_transport_keepalive(self):
        pass

    def close(self):
        pass

    def close_channel(self):
        pass

    def channel_open(self):
        pass

    def invoke_shell(self):
        pass

    def stdout_read(self, **kwargs):
        pass

    def shell_cmd(self, *args):
        return True, ""

    def exec_cmd(self, *args):
        return True, ""


class Test_Shared:
    def test_connect_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def main_thread_auth(self):
                return False

        scs = SplitCopyShared()
        with raises(SystemExit):
            scs.connect(MockSSHShell2)

    def test_connect_success(self, monkeypatch: MonkeyPatch):
        scs = SplitCopyShared()
        ssh_kwargs = {
            "hostname": "foo",
            "username": "bar",
            "ssh_port": 22,
        }
        result = scs.connect(MockSSHShell, **ssh_kwargs)
        assert result == (scs.sshshell, ssh_kwargs)

    def test_juniper_cli_check_jnpr(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args):
            return True, "\nerror: unknown command: uname"

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.juniper_cli_check()
        assert result == True

    def test_juniper_cli_check_not_jnpr(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args):
            return True, "Linux"

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.juniper_cli_check()
        assert result == False

    def test_juniper_cli_check_fail(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args):
            return False, ""

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)

        with raises(SystemExit):
            scs.juniper_cli_check()

    def test_which_proto_ftp_success_with_password(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def __init__(self):
                self.kwargs = {}
                self.kwargs["password"] = "foobar"

        def ftp_port_check():
            return True

        def ftp_login_check(passwd):
            return True

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell2()
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
        def ssh_cmd(*args):
            return False, ""

        def close(*args, **kwargs):
            raise SystemExit

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.which_os()

    def test_which_os_evo(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args):
            return True, "uname\nLinux\nfoo@bar:~$"

        def evo_os():
            return True

        scs = SplitCopyShared()
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "evo_os", evo_os)
        result = scs.which_os()
        assert result == (False, True, float(), float())

    def test_which_os_junos(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args):
            return True, "uname\nJUNOS\nfoo@bar:~$"

        def which_sshd():
            return 7.1

        scs = SplitCopyShared()
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "which_sshd", which_sshd)
        result = scs.which_os()
        assert result == (True, False, 6.3, 7.1)

    def test_which_os_junos_bsdx(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args):
            return True, "uname\nFreeBSD\nfoo@bar:~$"

        def junos_os():
            return True

        def which_sshd():
            return 7.1

        def which_bsd():
            return 12.1

        scs = SplitCopyShared()
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "junos_os", junos_os)
        monkeypatch.setattr(scs, "which_sshd", which_sshd)
        monkeypatch.setattr(scs, "which_bsd", which_bsd)
        result = scs.which_os()
        assert result == (True, False, 12.1, 7.1)

    def test_which_os_junos_bsdx_asroot(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, "FreeBSD"

        def junos_os():
            return True

        def which_sshd():
            return 7.1

        def which_bsd():
            return 12.1

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "junos_os", junos_os)
        monkeypatch.setattr(scs, "which_sshd", which_sshd)
        monkeypatch.setattr(scs, "which_bsd", which_bsd)
        result = scs.which_os()
        assert result == (True, False, 12.1, 7.1)

    def test_evo_os(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, ""

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.evo_os()
        assert result == True

    def test_junos_os_bsd6(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, "uname -i\nJUNIPER\nfoo@bar:~$"

        scs = SplitCopyShared()
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.junos_os()
        assert result == True

    def test_junos_os_bsdx(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, "uname -i\nJNPR\nfoo@bar:~$"

        scs = SplitCopyShared()
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.junos_os()
        assert result == True

    def test_which_bsd_fail(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return False, ""

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.which_bsd()

    def test_which_bsd_jnpr(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, "uname -r\nFreeBSD-12.1\nfoo@bar:~$"

        scs = SplitCopyShared()
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.which_bsd()
        assert result == 12.1

    def test_which_bsd_nonjnpr(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, "FreeBSD-12.1"

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.which_bsd()
        assert result == 12.1

    def test_which_sshd_jnpr_fail(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return False, "foobar"

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.which_sshd()

    def test_which_sshd_nonjnpr_fail(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return False, "foobar"

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.which_sshd()

    def test_which_sshd(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return (
                False,
                (
                    "sshd -v\n"
                    "sshd: illegal option -- v\n"
                    "OpenSSH_8.6p1, LibreSSL 3.3.6\n"
                ),
            )

        scs = SplitCopyShared()
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.which_sshd()
        assert result == 8.6

    def test_which_sshd_jnpr_asroot(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return (
                False,
                "sshd: illegal option -- v\n" "OpenSSH_8.6p1, LibreSSL 3.3.6\n",
            )

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.which_sshd()
        assert result == 8.6

    def test_req_binaries_fail(self, monkeypatch: MonkeyPatch):
        def close(err_str):
            raise SystemExit

        def ssh_cmd(*args):
            return False, ""

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.req_binaries(junos=False, evo=False)

    def test_req_binaries(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args):
            return True, ""

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.req_binaries(junos=False, evo=False)
        assert result == None

    def test_req_binaries_get(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args):
            return True, ""

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        scs.copy_op = "get"
        result = scs.req_binaries(junos=False, evo=False)
        assert result == None

    def test_req_sha_binaries_fail(self, monkeypatch: MonkeyPatch):
        def close(err_str):
            raise SystemExit

        def ssh_cmd(*args):
            return False, ""

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        sha_hash = {}
        sha_hash[1] = True
        sha_hash[512] = True
        with raises(SystemExit):
            scs.req_sha_binaries(sha_hash)

    def test_req_sha_binaries(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args):
            return True, ""

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        sha_hash = {}
        sha_hash[1] = True
        sha_hash[224] = True
        sha_hash[256] = True
        sha_hash[384] = True
        sha_hash[512] = True
        result = scs.req_sha_binaries(sha_hash)
        assert result == ("shasum", 512)

    def test_close_soft(self):
        class MockSSHShell2(MockSSHShell):
            def __init__(self):
                self._chan = MockChannel()
                self._chan.closed = True
                self._transport = MockTransport()
                self._transport.active = False

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell2()
        with raises(SystemExit):
            scs.close()

    def test_close_err_soft(self):
        class MockSSHShell2(MockSSHShell):
            def __init__(self):
                self._chan = MockChannel()
                self._chan.closed = True
                self._transport = MockTransport()
                self._transport.active = False

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell2()
        with raises(SystemExit):
            scs.close(err_str="foo")

    def test_close_hard_close(self, monkeypatch: MonkeyPatch):
        def _exit(*args):
            raise SystemExit

        def rmtree(*args):
            pass

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.local_tmpdir = "foobar"
        scs.hard_close = True
        monkeypatch.setattr("shutil.rmtree", rmtree)
        monkeypatch.setattr("os._exit", _exit)
        with raises(SystemExit):
            scs.close()

    def test_close_hard_close_permerror(self, monkeypatch: MonkeyPatch):
        def _exit(*args):
            raise SystemExit

        def rmtree(*args):
            raise PermissionError

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.local_tmpdir = "foobar"
        scs.hard_close = True
        monkeypatch.setattr("shutil.rmtree", rmtree)
        monkeypatch.setattr("os._exit", _exit)
        with raises(SystemExit):
            scs.close()

    def test_close_ssh_active(self, monkeypatch: MonkeyPatch):
        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        scs.hard_close = False
        with raises(SystemExit):
            scs.close()

    def test_close_ssh_active_rm_remote_tmp(self, monkeypatch: MonkeyPatch):
        def remote_cleanup():
            pass

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        scs.hard_close = False
        scs.rm_remote_tmp = True
        monkeypatch.setattr(scs, "remote_cleanup", remote_cleanup)
        with raises(SystemExit):
            scs.close()

    def test_close_ssh_active_command_list(self, monkeypatch: MonkeyPatch):
        def limits_rollback():
            pass

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        scs.use_shell = True
        scs.hard_close = False
        scs.command_list = ["groups foo", "groups bar"]
        monkeypatch.setattr(scs, "limits_rollback", limits_rollback)
        with raises(SystemExit):
            scs.close()

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
        def ssh_cmd(*args, **kwargs):
            return False, ""

        def close(err_str):
            raise SystemExit

        class datetime:
            def strftime(time, fmt):
                return "20220609231003"

            def now():
                pass

        scs = SplitCopyShared()
        scs.copy_op = "get"
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        monkeypatch.setattr("datetime.datetime", datetime)
        with raises(SystemExit):
            remote_dir = "/var/tmp"
            remote_file = "foobar"
            scs.mkdir_remote(remote_dir, remote_file)

    def test_mkdir_remote_get(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, ""

        class datetime:
            def strftime(time, fmt):
                return "20220609231003"

            def now():
                pass

        scs = SplitCopyShared()
        scs.copy_op = "get"
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr("datetime.datetime", datetime)
        remote_dir = "/var/tmp"
        remote_file = "foobar"
        result = scs.mkdir_remote(remote_dir, remote_file)
        assert result == "/var/tmp/splitcopy_foobar.20220609231003"

    def test_mkdir_remote_put(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, ""

        class datetime:
            def strftime(time, fmt):
                return "20220609231003"

            def now():
                pass

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr("datetime.datetime", datetime)
        remote_dir = "/tmp"
        remote_file = "foobar"
        result = scs.mkdir_remote(remote_dir, remote_file)
        assert result == "/tmp/splitcopy_foobar.20220609231003"

    def test_storage_check_remote_cmd_fail(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return False, ""

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            remote_dir = "/tmp"
            file_size = 100000
            split_size = 7693
            scs.storage_check_remote(file_size, split_size, remote_dir)

    def test_storage_check_remote_blocks_fail(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, ""

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            remote_dir = "/tmp"
            file_size = 100000
            split_size = 7693
            scs.storage_check_remote(file_size, split_size, remote_dir)

    def test_storage_check_remote_not_enough_blocks(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, (
                "Filesystem   1024-blocks      Used Available Capacity iused      ifree"
                " %iused  Mounted on\n/dev/disk3s5   482797652 472797652 -1000000 "
                "98% 1588060 1957553000    0%   /System/Volumes/Data\n"
            )

        def close(err_str):
            raise SystemExit

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            remote_dir = "/tmp"
            file_size = 10000000
            split_size = 769300
            scs.storage_check_remote(file_size, split_size, remote_dir)

    def test_storage_check_remote_get_fail(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
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
        scs.use_shell = True
        scs.copy_op = "get"
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            remote_dir = "/tmp"
            file_size = 100000
            split_size = 7693
            scs.storage_check_remote(file_size, split_size, remote_dir)

    def test_storage_check_remote_put_fail(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
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
        scs.use_shell = True
        monkeypatch.setattr(scs, "close", close)
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        with raises(SystemExit):
            remote_dir = "/tmp"
            file_size = 100000
            split_size = 7693
            scs.storage_check_remote(file_size, split_size, remote_dir)

    def test_storage_check_remote_success(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return (
                True,
                (
                    "df -k /tmp\n"
                    "Filesystem           1K-blocks  Used Available Use% Mounted on\n"
                    "/dev/mapper/vg00-tmp 316488560 64716 303471912   1% /tmp\n"
                ),
            )

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        remote_dir = "/tmp"
        file_size = 100000
        split_size = 7693
        result = scs.storage_check_remote(file_size, split_size, remote_dir)
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
        scs.copy_op = "get"
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
        scs.copy_op = "get"
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
        def ssh_cmd(*args, **kwargs):
            stdout = args[0].split()[4]
            return True, f"set {stdout}\n"

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        config_stanzas = ["foo", "bar"]
        limits = ["bar", "foo"]
        result = scs.find_configured_limits(config_stanzas, limits)
        assert result == "set foo\nset bar\n"

    def test_limit_check(self, monkeypatch: MonkeyPatch):
        def find_configured_limits(*args):
            return ""

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "find_configured_limits", find_configured_limits)
        result = scs.limit_check("ftp")
        assert result == []

    def test_limit_check_deactivate(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
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
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "find_configured_limits", find_configured_limits)
        result = scs.limit_check("ftp")
        assert result == [
            "deactivate system services ftp connection-limit;",
            "deactivate groups foo system services ftp rate-limit;",
            "deactivate system login retry-options;",
            "deactivate groups foo system login retry-options;",
        ]

    def test_limit_check_deactivate_commit_fail(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, ""

        def close(err_str):
            raise SystemExit

        def find_configured_limits(*args):
            return "set services ftp connection-limit 4"

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        monkeypatch.setattr(scs, "find_configured_limits", find_configured_limits)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.limit_check("ftp")

    def test_limits_rollback_fail(self, capsys, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, "foobar"

        scs = SplitCopyShared()
        scs.command_list = ["deactivate foo"]
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.limits_rollback()
        captured = capsys.readouterr()
        result = captured.out
        assert result == (
            "Error: failed to revert the configuration changes. output was:\nfoobar\n"
        )

    def test_limits_rollback(self, capsys, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, "commit complete\r\nExiting configuration mode"

        scs = SplitCopyShared()
        scs.command_list = ["deactivate foo"]
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.limits_rollback()
        captured = capsys.readouterr()
        result = captured.out
        assert result == "configuration changes made have been reverted\n"

    def test_remote_cleanup_fail(self, capsys, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return False, ""

        scs = SplitCopyShared()
        scs.use_shell = True
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        scs.remote_tmpdir = "/var/tmp/foo"
        remote_dir = "/tmp/"
        remote_file = "foo"
        result = scs.remote_cleanup(remote_dir=remote_dir, remote_file=remote_file)
        captured = capsys.readouterr()
        stdout = captured.out
        assert result == False and stdout == (
            "\rdeleting remote tmp directory...                                                \n"
            "unable to delete the tmp directory /var/tmp/foo on remote host, delete it manually\n"
        )

    def test_remote_cleanup_get(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, ""

        scs = SplitCopyShared()
        scs.copy_op = "get"
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.remote_cleanup()
        assert result == True

    def test_remote_cleanup_put(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return True, ""

        scs = SplitCopyShared()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.remote_cleanup()
        assert result == True

    def test_ssh_cmd_shell(self, monkeypatch: MonkeyPatch):
        scs = SplitCopyShared()
        scs.use_shell = True
        scs.sshshell = MockSSHShell()
        result = scs.ssh_cmd("foo")
        assert result == (True, "")

    def test_ssh_cmd_exec(self, monkeypatch: MonkeyPatch):
        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        result = scs.ssh_cmd("foo")
        assert result == (True, "")

    def test_ssh_cmd_shell_timeout_once(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def shell_cmd(self, *args):
                timeout = args[1]
                if timeout == 0.2:
                    return (True, "")
                else:
                    raise TimeoutError

        def enter_shell(*args, **kwargs):
            pass

        scs = SplitCopyShared()
        scs.use_shell = True
        scs.sshshell = MockSSHShell2()
        monkeypatch.setattr(scs, "enter_shell", enter_shell)
        result = scs.ssh_cmd("foo", timeout=0.1)
        assert result == (True, "")

    def test_ssh_cmd_shell_ssh_exception(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def shell_cmd(self, *args):
                raise SSHException

        def close(*args, **kwargs):
            raise SystemExit

        scs = SplitCopyShared()
        scs.use_shell = True
        scs.sshshell = MockSSHShell2()
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.ssh_cmd("foo")

    def test_ssh_cmd_shell_oserror_exception(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def shell_cmd(self, *args):
                raise OSError

        def close(*args, **kwargs):
            raise SystemExit

        scs = SplitCopyShared()
        scs.use_shell = True
        scs.sshshell = MockSSHShell2()
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.ssh_cmd("foo")

    def test_ssh_cmd_shell_timeout_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def shell_cmd(self, *args):
                raise TimeoutError

        def close(*args, **kwargs):
            raise SystemExit

        def enter_shell(*args, **kwargs):
            pass

        scs = SplitCopyShared()
        scs.use_shell = True
        scs.sshshell = MockSSHShell2()
        monkeypatch.setattr(scs, "enter_shell", enter_shell)
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.ssh_cmd("foo", timeout=500)

    def test_ssh_cmd_exec_fail(self, monkeypatch: MonkeyPatch):
        class MockSSHShell:
            def exec_cmd(self, *args):
                raise SSHException

        def close(*args, **kwargs):
            raise SystemExit

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "close", close)
        with raises(SystemExit):
            scs.ssh_cmd("foo")

    def test_enter_shell(self, monkeypatch: MonkeyPatch):
        def ssh_cmd(*args, **kwargs):
            return (True, "")

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell()
        monkeypatch.setattr(scs, "ssh_cmd", ssh_cmd)
        result = scs.enter_shell()
        assert result == True

    def test_enter_shell_exception(self, monkeypatch: MonkeyPatch):
        class MockSSHShell2(MockSSHShell):
            def channel_open(*args, **kwargs):
                raise SSHException

        scs = SplitCopyShared()
        scs.sshshell = MockSSHShell2()
        with raises(SystemExit):
            scs.enter_shell()
