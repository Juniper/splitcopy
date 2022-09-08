import datetime
import re
from argparse import Namespace
from socket import gaierror

import splitcopy.splitcopy as splitcopy
from pytest import MonkeyPatch, raises


class MockOpen:
    def __init__(self, file, perms, newline=None):
        self.data = ["abcdef0123456789"]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class MockSplitCopyGet:
    def __init__(self, **kwargs):
        pass

    def get(*args):
        return (datetime.datetime.now(), datetime.datetime.now())


class MockSplitCopyPut:
    def __init__(self, **kwargs):
        pass

    def put(*args):
        return (datetime.datetime.now(), datetime.datetime.now())


def test_parse_args(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(source="/var/tmp/foo", target="192.168.64.7:/var/tmp/")

    monkeypatch.setattr("argparse.ArgumentParser.parse_args", parse_args)
    result = splitcopy.parse_args()
    assert result == Namespace(source="/var/tmp/foo", target="192.168.64.7:/var/tmp/")


def test_parse_arg_as_local_abspath(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "/var/tmp/foo"

    def abspath(*args):
        return "/var/tmp/foo"

    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("builtins.open", MockOpen)
    result = splitcopy.parse_arg_as_local("/var/tmp/foo")
    assert result == ("foo", "/var/tmp", "/var/tmp/foo")


def test_parse_arg_as_local_tilda(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "/homes/foobar/tmp/foo"

    def abspath(*args):
        return "/homes/foobar/tmp/foo"

    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("builtins.open", MockOpen)
    result = splitcopy.parse_arg_as_local("~/tmp/foo")
    assert result == ("foo", "/homes/foobar/tmp", "/homes/foobar/tmp/foo")


def test_parse_arg_as_local_fileonly(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "/homes/foobar/foo"

    def abspath(*args):
        return "/homes/foobar/foo"

    monkeypatch.setattr("builtins.open", MockOpen)
    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("os.path.abspath", abspath)
    result = splitcopy.parse_arg_as_local("foo")
    assert result == ("foo", "/homes/foobar", "/homes/foobar/foo")


def test_parse_arg_as_local_dotfile(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "/homes/foobar/foo"

    def abspath(*args):
        return "/homes/foobar/foo"

    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("builtins.open", MockOpen)
    result = splitcopy.parse_arg_as_local("./foo")
    assert result == ("foo", "/homes/foobar", "/homes/foobar/foo")


def test_parse_arg_as_local_permerror(monkeypatch: MonkeyPatch):
    class MockOpen2(MockOpen):
        def __enter__(self):
            raise PermissionError

    def expanduser(*args):
        return "/var/tmp/foo"

    def abspath(*args):
        return "/var/tmp/foo"

    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("builtins.open", MockOpen2)
    with raises(PermissionError):
        splitcopy.parse_arg_as_local("/var/tmp/foo")


def test_parse_arg_as_local_filenotfounderror(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "/var/tmp/foo"

    def abspath(*args):
        return "/var/tmp/foo"

    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("os.path.abspath", abspath)
    with raises(FileNotFoundError):
        splitcopy.parse_arg_as_local("/var/tmp/foo")


def test_parse_arg_as_local_isdirerror(monkeypatch: MonkeyPatch):
    class MockOpen2(MockOpen):
        def __enter__(self):
            raise IsADirectoryError

    def expanduser(*args):
        return "/var/tmp/foo"

    def abspath(*args):
        return "/var/tmp/foo"

    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("builtins.open", MockOpen2)
    with raises(IsADirectoryError):
        splitcopy.parse_arg_as_local("/var/tmp")


def test_parse_arg_as_remote_incorrect_format(monkeypatch: MonkeyPatch):
    def splitdrive(*args):
        return ["", ""]

    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    with raises(ValueError):
        splitcopy.parse_arg_as_remote("someone@foobar")


def test_parse_arg_as_remote_inc_username(monkeypatch: MonkeyPatch):
    def splitdrive(*args):
        return ["", ""]

    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    result = splitcopy.parse_arg_as_remote("someone@foobar:/var/tmp/foo")
    assert result == ("someone", "foobar", "/var/tmp/foo")


def test_parse_arg_as_remote_without_username(monkeypatch: MonkeyPatch):
    def getuser():
        return "someone"

    def splitdrive(*args):
        return ["", ""]

    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    monkeypatch.setattr("getpass.getuser", getuser)
    result = splitcopy.parse_arg_as_remote("foobar:/var/tmp/foo")
    assert result == ("someone", "foobar", "/var/tmp/foo")


def test_parse_arg_as_remote_nodir(monkeypatch: MonkeyPatch):
    def splitdrive(*args):
        return ["", ""]

    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    result = splitcopy.parse_arg_as_remote("someone@foobar:foo")
    assert result == ("someone", "foobar", "foo")


def test_parse_arg_as_remote_dotdir(monkeypatch: MonkeyPatch):
    def splitdrive(*args):
        return ["", ""]

    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    result = splitcopy.parse_arg_as_remote("someone@foobar:./foo")
    assert result == ("someone", "foobar", "./foo")


def test_parse_arg_as_remote_tilda(monkeypatch: MonkeyPatch):
    def splitdrive(*args):
        return ["", ""]

    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    result = splitcopy.parse_arg_as_remote("someone@foobar:~/foo")
    assert result == ("someone", "foobar", "~/foo")


def test_parse_arg_as_remote_nofile(monkeypatch: MonkeyPatch):
    def splitdrive(*args):
        return ["", ""]

    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    result = splitcopy.parse_arg_as_remote("someone@foobar:")
    assert result == ("someone", "foobar", "")


def test_parse_arg_as_remote_windows_local(monkeypatch: MonkeyPatch):
    def splitdrive(*args):
        return ["C:", ""]

    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    with raises(ValueError):
        splitcopy.parse_arg_as_remote("someone@foobar:")


def test_open_ssh_keyfile_filenotfounderror(monkeypatch: MonkeyPatch):
    class MockOpen2(MockOpen):
        def __enter__(self):
            raise FileNotFoundError

    def expanduser(*args):
        return "/var/tmp/sshkey"

    def abspath(*args):
        return "/var/tmp/sshkey"

    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("builtins.open", MockOpen2)
    with raises(FileNotFoundError):
        splitcopy.open_ssh_keyfile("/var/tmp/sshkey")


def test_open_ssh_keyfile_permerror(monkeypatch: MonkeyPatch):
    class MockOpen2(MockOpen):
        def __enter__(self):
            raise PermissionError

    def expanduser(*args):
        return "/var/tmp/sshkey"

    def abspath(*args):
        return "/var/tmp/sshkey"

    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("builtins.open", MockOpen2)
    with raises(PermissionError):
        splitcopy.open_ssh_keyfile("/var/tmp/sshkey")


def test_open_ssh_keyfile_isdirerror(monkeypatch: MonkeyPatch):
    class MockOpen2(MockOpen):
        def __enter__(self):
            raise IsADirectoryError

    def expanduser(*args):
        return "/var/tmp/sshkey"

    def abspath(*args):
        return "/var/tmp/sshkey"

    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("builtins.open", MockOpen2)
    with raises(IsADirectoryError):
        splitcopy.open_ssh_keyfile("/var/tmp/sshkey")


def test_open_ssh_keyfile(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "/var/tmp/sshkey"

    def abspath(*args):
        return "/var/tmp/sshkey"

    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("builtins.open", MockOpen)
    result = splitcopy.open_ssh_keyfile("/var/tmp/sshkey")
    assert result == True


def test_main_invalid_loglevel(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            log=["foobar"],
        )

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    with raises(ValueError):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_both_args_remote(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="192.168.65.2:/var/tmp/foo",
            target="192.168.65.2:/var/tmp/foo",
            noverify=False,
            log=None,
            nocurses=False,
            overwrite=False,
        )

    def parse_arg_as_remote(*args):
        return (None, "192.168.65.2", "/var/tmp/foo")

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_neither_args_remote(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foo",
            target="/var/tmp/foo",
            noverify=False,
            log=None,
            nocurses=False,
            overwrite=False,
        )

    def parse_arg_as_remote(*args):
        raise ValueError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_get_nofile(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="foo@192.168.3.2:",
            target="/var/tmp/foo",
            noverify=False,
            log=None,
            nocurses=False,
            overwrite=False,
        )

    def parse_arg_as_remote(*args):
        if args[0] == "foo@192.168.3.2:":
            return ("foo", "192.168.3.2", None)
        else:
            raise ValueError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_get_scp_success(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="192.168.64.7:/var/tmp/foobar",
            target="/var/tmp/bar",
            noverify=False,
            log=None,
            nocurses=False,
            pwd=None,
            scp=True,
            ssh_key=None,
            ssh_port=None,
            split_timeout=None,
            overwrite=False,
        )

    def parse_arg_as_remote(*args):
        if args[0] == "192.168.64.7:/var/tmp/foobar":
            return ("foo", "192.168.64.7", "/var/tmp/foobar")
        else:
            raise ValueError

    def gethostbyname(*args):
        return "192.168.64.7"

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    result = splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)
    assert result == None


def test_main_get_resolution_fail(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="foo@192.168.64.7:/var/tmp/foobar",
            target="/var/tmp/bar",
            noverify=False,
            log=None,
            nocurses=False,
            pwd=None,
            scp=True,
            ssh_key=None,
            ssh_port=None,
            split_timeout=None,
            overwrite=False,
        )

    def parse_arg_as_remote(*args):
        if args[0] == "foo@192.168.64.7:/var/tmp/foobar":
            return ("foo", "192.168.64.7", "/var/tmp/foobar")
        else:
            raise ValueError

    def gethostbyname(*args):
        raise gaierror

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_src_filenotfounderror_windows(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="C:\\tmp\\foo",
            target="192.168.64.7:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            overwrite=False,
        )

    def parse_arg_as_remote(*args):
        if args[0] == "192.168.64.7:/var/tmp/":
            return (None, "192.168.64.7", "/var/tmp/")
        else:
            raise ValueError

    def parse_arg_as_local(*args):
        raise FileNotFoundError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_local", parse_arg_as_local)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_src_permerror(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foo",
            target="192.168.64.7:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            overwrite=False,
        )

    def parse_arg_as_local(*args):
        raise PermissionError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_local", parse_arg_as_local)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_src_isadirerror(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foo",
            target="192.168.64.7:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=True,
            overwrite=False,
        )

    def parse_arg_as_local(*args):
        raise IsADirectoryError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_local", parse_arg_as_local)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_ftp_success(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="192.168.64.7:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            pwd=["somepwd"],
            scp=None,
            ssh_key=None,
            ssh_port=[22],
            split_timeout=[300],
            overwrite=False,
        )

    def parse_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        if args[0] == "192.168.64.7:/var/tmp/":
            return ("foo", "192.168.64.7", "/var/tmp")
        else:
            raise ValueError

    def gethostbyname(*args):
        return "192.168.64.7"

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_local", parse_arg_as_local)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    result = splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)
    assert result == None


def test_main_put_sshkey_filenotfounderror(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="somerandomhost:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            pwd=None,
            scp=None,
            ssh_key=["/var/tmp/sshkey"],
            ssh_port=None,
            split_timeout=None,
            overwrite=False,
        )

    def parse_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        if args[0] == "somerandomhost:/var/tmp/":
            return (None, "somerandomhost", "/var/tmp")
        else:
            raise ValueError

    def gethostbyname(*args):
        return "192.168.64.7"

    def open_ssh_keyfile(*args):
        raise FileNotFoundError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_local", parse_arg_as_local)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("splitcopy.splitcopy.open_ssh_keyfile", open_ssh_keyfile)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_sshkey_permerror(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="somerandomhost:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            pwd=None,
            scp=None,
            ssh_key=["/var/tmp/sshkey"],
            ssh_port=None,
            split_timeout=None,
            overwrite=False,
        )

    def parse_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        if args[0] == "somerandomhost:/var/tmp/":
            return (None, "somerandomhost", "/var/tmp")
        else:
            raise ValueError

    def gethostbyname(*args):
        return "192.168.64.7"

    def open_ssh_keyfile(*args):
        raise PermissionError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_local", parse_arg_as_local)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("splitcopy.splitcopy.open_ssh_keyfile", open_ssh_keyfile)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_sshkey_isadirerror(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="somerandomhost:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            pwd=None,
            scp=None,
            ssh_key=["/var/tmp/sshkey"],
            ssh_port=None,
            split_timeout=None,
            overwrite=False,
        )

    def parse_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        if args[0] == "somerandomhost:/var/tmp/":
            return (None, "somerandomhost", "/var/tmp")
        else:
            raise ValueError

    def gethostbyname(*args):
        return "192.168.64.7"

    def open_ssh_keyfile(*args):
        raise IsADirectoryError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_local", parse_arg_as_local)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("splitcopy.splitcopy.open_ssh_keyfile", open_ssh_keyfile)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_ftp_sshport_notint(capsys, monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="192.168.64.7:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            pwd=None,
            scp=None,
            ssh_key=None,
            ssh_port=["foo"],
            split_timeout=None,
            overwrite=False,
        )

    def parse_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        if args[0] == "192.168.64.7:/var/tmp/":
            return (None, "192.168.64.7", "/var/tmp")
        else:
            raise ValueError

    def gethostbyname(*args):
        return "192.168.64.7"

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_local", parse_arg_as_local)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_ftp_split_timeout_notint(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="192.168.64.7:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            pwd=None,
            scp=None,
            ssh_key=None,
            ssh_port=None,
            split_timeout=["foo"],
            overwrite=False,
        )

    def parse_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        if args[0] == "192.168.64.7:/var/tmp/":
            return (None, "192.168.64.7", "/var/tmp")
        else:
            raise ValueError

    def gethostbyname(*args):
        return "192.168.64.7"

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_local", parse_arg_as_local)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_handlesigint():
    with raises(SystemExit):
        splitcopy.handlesigint("SigInt", "stack")
