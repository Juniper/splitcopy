import datetime
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


def test_parse_source_arg_as_local_1(monkeypatch: MonkeyPatch):
    monkeypatch.setattr("builtins.open", MockOpen)
    result = splitcopy.parse_source_arg_as_local("/var/tmp/foo")
    assert result == ("foo", "/var/tmp", "/var/tmp/foo")


def test_parse_source_arg_as_local_2(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "/homes/foobar/tmp/foo"

    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("builtins.open", MockOpen)
    result = splitcopy.parse_source_arg_as_local("~/tmp/foo")
    assert result == ("foo", "/homes/foobar/tmp", "/homes/foobar/tmp/foo")


def test_parse_source_arg_as_local_3(monkeypatch: MonkeyPatch):
    def abspath(*args):
        return "/homes/foobar/foo"

    monkeypatch.setattr("builtins.open", MockOpen)
    monkeypatch.setattr("os.path.abspath", abspath)
    result = splitcopy.parse_source_arg_as_local("foo")
    assert result == ("foo", "/homes/foobar", "/homes/foobar/foo")


def test_parse_source_arg_as_local_4(monkeypatch: MonkeyPatch):
    def abspath(*args):
        return "/homes/foobar/foo"

    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("builtins.open", MockOpen)
    result = splitcopy.parse_source_arg_as_local("./foo")
    assert result == ("foo", "/homes/foobar", "/homes/foobar/foo")


def test_parse_source_arg_as_local_perm_fail(monkeypatch: MonkeyPatch):
    class MockOpen2(MockOpen):
        def __enter__(self):
            raise PermissionError

    monkeypatch.setattr("builtins.open", MockOpen2)
    with raises(PermissionError):
        splitcopy.parse_source_arg_as_local("/var/tmp/foo")


def test_parse_source_arg_as_local_file_notfound(monkeypatch: MonkeyPatch):
    class MockOpen2(MockOpen):
        def __enter__(self):
            raise FileNotFoundError

    monkeypatch.setattr("builtins.open", MockOpen2)
    with raises(FileNotFoundError):
        splitcopy.parse_source_arg_as_local("/var/tmp/foo")


def test_parse_source_arg_as_local_isdir(monkeypatch: MonkeyPatch):
    class MockOpen2(MockOpen):
        def __enter__(self):
            raise IsADirectoryError

    monkeypatch.setattr("builtins.open", MockOpen2)
    with raises(IsADirectoryError):
        splitcopy.parse_source_arg_as_local("/var/tmp")


def test_parse_arg_as_remote_incorrect_format():
    with raises(ValueError):
        splitcopy.parse_arg_as_remote("someone@foobar", "source")


def test_parse_arg_as_remote_inc_username():
    result = splitcopy.parse_arg_as_remote("someone@foobar:/var/tmp/foo", "source")
    assert result == ("someone", "foobar", "/var/tmp/foo")


def test_parse_arg_as_remote_without_username(monkeypatch: MonkeyPatch):
    def getuser():
        return "someone"

    monkeypatch.setattr("getpass.getuser", getuser)
    result = splitcopy.parse_arg_as_remote("foobar:/var/tmp/foo", "source")
    assert result == ("someone", "foobar", "/var/tmp/foo")


def test_parse_arg_as_remote_nodir():
    result = splitcopy.parse_arg_as_remote("someone@foobar:foo", "source")
    assert result == ("someone", "foobar", "foo")


def test_parse_arg_as_remote_dotdir():
    result = splitcopy.parse_arg_as_remote("someone@foobar:./foo", "source")
    assert result == ("someone", "foobar", "./foo")


def test_parse_arg_as_remote_tilda():
    result = splitcopy.parse_arg_as_remote("someone@foobar:~/foo", "source")
    assert result == ("someone", "foobar", "~/foo")


def test_parse_arg_as_remote_nofile():
    result = splitcopy.parse_arg_as_remote("someone@foobar:", "source")
    assert result == ("someone", "foobar", "")


def test_main_filenotfounderror_local_windows(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="C:\\tmp\\foo",
            target="192.168.64.7:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            overwrite=False,
        )

    def splitdrive(*args):
        return ["C:", "tmp\\foo"]

    def isfile(*args):
        return False

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("os.path.isfile", isfile)
    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_permerror_local(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foo",
            target="192.168.64.7:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            overwrite=False,
        )

    def isfile(*args):
        return True

    def parse_source_arg_as_local(*args):
        raise PermissionError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_source_arg_as_local", parse_source_arg_as_local
    )
    monkeypatch.setattr("os.path.isfile", isfile)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_isadirerror_local(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foo",
            target="192.168.64.7:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=True,
            overwrite=False,
        )

    def isfile(*args):
        return False

    def isdir(*args):
        return True

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("os.path.isfile", isfile)
    monkeypatch.setattr("os.path.isdir", isdir)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_invalid_loglevel(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            log=["foobar"],
        )

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    with raises(ValueError):
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
            ssh_key=["/var/tmp/sshkey"],
            ssh_port=[22],
            split_timeout=[300],
            overwrite=False,
        )

    def parse_source_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        return ("foo", "192.168.64.7", "/var/tmp")

    def gethostbyname(*args):
        return "192.168.64.7"

    def isfile(*args):
        return True

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_source_arg_as_local", parse_source_arg_as_local
    )
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("os.path.isfile", isfile)
    result = splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)
    assert result == None


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

    def isfile(*args):
        return False

    def isdir(*args):
        return False

    def parse_arg_as_remote(*args):
        return ("foo", "192.168.64.7", "/var/tmp/foobar")

    def gethostbyname(*args):
        return "192.168.64.7"

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("os.path.isfile", isfile)
    monkeypatch.setattr("os.path.isdir", isdir)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    result = splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)
    assert result == None


def test_main_put_parse_arg_as_remote_fail(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="192.168.64.7:/var/tmp/",
            noverify=False,
            log=None,
            nocurses=False,
            pwd=["somepwd"],
            scp=None,
            ssh_key=["/var/tmp/sshkey"],
            ssh_port=[22],
            split_timeout=[300],
            overwrite=False,
        )

    def isfile(*args):
        return True

    def parse_source_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        raise ValueError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_source_arg_as_local", parse_source_arg_as_local
    )
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("os.path.isfile", isfile)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_get_parse_arg_as_remote_fail(monkeypatch: MonkeyPatch):
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

    def isfile(*args):
        return False

    def isdir(*args):
        return False

    def parse_arg_as_remote(*args):
        raise ValueError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("os.path.isfile", isfile)
    monkeypatch.setattr("os.path.isdir", isdir)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_get_resolution_fail(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="somerandomhost:/var/tmp/foobar",
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

    def isfile(*args):
        return False

    def isdir(*args):
        return False

    def parse_arg_as_remote(*args):
        return ("foo", "somerandomhost", "/var/tmp/foobar")

    def gethostbyname(*args):
        raise gaierror

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    monkeypatch.setattr("os.path.isfile", isfile)
    monkeypatch.setattr("os.path.isdir", isdir)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_ftp_sshkey_notfound(monkeypatch: MonkeyPatch):
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

    def parse_source_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        return ("foo", "somerandomhost", "/var/tmp")

    def gethostbyname(*args):
        return "192.168.64.7"

    def isfile(*args):
        if args[0] == "/var/tmp/foobar":
            return True
        else:
            return False

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_source_arg_as_local", parse_source_arg_as_local
    )
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("os.path.isfile", isfile)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_ftp_sshport_notint(monkeypatch: MonkeyPatch):
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

    def parse_source_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        return ("foo", "192.168.64.7", "/var/tmp")

    def gethostbyname(*args):
        return "192.168.64.7"

    def isfile(*args):
        return True

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_source_arg_as_local", parse_source_arg_as_local
    )
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("os.path.isfile", isfile)
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

    def parse_source_arg_as_local(*args):
        return ("foobar", "/var/tmp", "/var/tmp/foobar")

    def parse_arg_as_remote(*args):
        return ("foo", "192.168.64.7", "/var/tmp")

    def gethostbyname(*args):
        return "192.168.64.7"

    def isfile(*args):
        return True

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_source_arg_as_local", parse_source_arg_as_local
    )
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("os.path.isfile", isfile)
    with raises(SystemExit):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_handlesigint():
    with raises(SystemExit):
        splitcopy.handlesigint("SigInt", "stack")
