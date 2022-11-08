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


def test_windows_path(monkeypatch: MonkeyPatch):
    def splitdrive(*args):
        return ("C:", "\\windows\\system32")

    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    result = splitcopy.windows_path("C:\\windows\\system32")
    assert result == True


def test_windows_path_fail(monkeypatch: MonkeyPatch):
    def splitdrive(*args):
        return ("", "/var/tmp")

    monkeypatch.setattr("os.path.splitdrive", splitdrive)
    result = splitcopy.windows_path("/var/tmp")
    assert result == False


def test_parse_src_arg_as_local_abspath(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "/var/tmp/foo"

    def abspath(*args):
        return "/var/tmp/foo"

    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("builtins.open", MockOpen)
    result = splitcopy.parse_src_arg_as_local("/var/tmp/foo")
    assert result == ("foo", "/var/tmp", "/var/tmp/foo")


def test_parse_src_arg_as_local_tilda(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "/homes/foobar/tmp/foo"

    def abspath(*args):
        return "/homes/foobar/tmp/foo"

    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("builtins.open", MockOpen)
    result = splitcopy.parse_src_arg_as_local("~/tmp/foo")
    assert result == ("foo", "/homes/foobar/tmp", "/homes/foobar/tmp/foo")


def test_parse_src_arg_as_local_fileonly(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "foo"

    def abspath(*args):
        return "/homes/foobar/foo"

    monkeypatch.setattr("builtins.open", MockOpen)
    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("os.path.abspath", abspath)
    result = splitcopy.parse_src_arg_as_local("foo")
    assert result == ("foo", "/homes/foobar", "/homes/foobar/foo")


def test_parse_src_arg_as_local_dotfile(monkeypatch: MonkeyPatch):
    def expanduser(*args):
        return "./foo"

    def abspath(*args):
        return "/homes/foobar/foo"

    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("builtins.open", MockOpen)
    result = splitcopy.parse_src_arg_as_local("./foo")
    assert result == ("foo", "/homes/foobar", "/homes/foobar/foo")


def test_parse_src_arg_as_local_permerror(monkeypatch: MonkeyPatch):
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
        splitcopy.parse_src_arg_as_local("/var/tmp/foo")


def test_parse_src_arg_as_local_filenotfounderror(monkeypatch: MonkeyPatch):
    class MockOpen2(MockOpen):
        def __enter__(self):
            raise FileNotFoundError

    def expanduser(*args):
        return "/var/tmp/foo"

    def abspath(*args):
        return "/var/tmp/foo"

    monkeypatch.setattr("os.path.expanduser", expanduser)
    monkeypatch.setattr("os.path.abspath", abspath)
    monkeypatch.setattr("builtins.open", MockOpen2)
    with raises(FileNotFoundError):
        splitcopy.parse_src_arg_as_local("/var/tmp/foo")


def test_parse_src_arg_as_local_isdirerror(monkeypatch: MonkeyPatch):
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
        splitcopy.parse_src_arg_as_local("/var/tmp")


def test_parse_arg_as_remote_incorrect_format(monkeypatch: MonkeyPatch):
    with raises(ValueError):
        splitcopy.parse_arg_as_remote("someone@foobar")


def test_parse_arg_as_remote_inc_username(monkeypatch: MonkeyPatch):
    result = splitcopy.parse_arg_as_remote("someone@foobar:/var/tmp/foo")
    assert result == ("someone", "foobar", "/var/tmp/foo")


def test_parse_arg_as_remote_without_username(monkeypatch: MonkeyPatch):
    def getuser():
        return "someone"

    monkeypatch.setattr("getpass.getuser", getuser)
    result = splitcopy.parse_arg_as_remote("foobar:/var/tmp/foo")
    assert result == ("someone", "foobar", "/var/tmp/foo")


def test_parse_arg_as_remote_nodir(monkeypatch: MonkeyPatch):
    result = splitcopy.parse_arg_as_remote("someone@foobar:foo")
    assert result == ("someone", "foobar", "foo")


def test_parse_arg_as_remote_dotdir(monkeypatch: MonkeyPatch):
    result = splitcopy.parse_arg_as_remote("someone@foobar:./foo")
    assert result == ("someone", "foobar", "./foo")


def test_parse_arg_as_remote_tilda(monkeypatch: MonkeyPatch):
    result = splitcopy.parse_arg_as_remote("someone@foobar:~/foo")
    assert result == ("someone", "foobar", "~/foo")


def test_parse_arg_as_remote_nofile(monkeypatch: MonkeyPatch):
    result = splitcopy.parse_arg_as_remote("someone@foobar:")
    assert result == ("someone", "foobar", "")


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


def test_process_args_src_permerror(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        raise PermissionError

    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    source = "/var/tmp/foo"
    target = "192.168.64.7:/var/tmp/"
    with raises(
        SystemExit,
        match=(
            f"'{source}' exists, but file cannot be read due to a permissions error"
        ),
    ):
        splitcopy.process_args(source, target)


def test_process_args_src_isadirerror(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        raise IsADirectoryError

    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    source = "/var/tmp"
    target = "192.168.64.7:/var/tmp/"
    with raises(SystemExit, match=f"'{source}' is a directory, not a file"):
        splitcopy.process_args(source, target)


def test_process_args_both_args_remote(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        raise FileNotFoundError

    def parse_arg_as_remote(*args):
        return (None, "192.168.65.2", "/var/tmp/foo")

    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    source = "192.168.85.2:/var/tmp/foo"
    target = "192.168.25.2:/var/tmp/foo"
    with raises(
        SystemExit,
        match=(
            f"both '{source}' and '{target}' are remote paths - "
            "one path must be local, the other remote"
        ),
    ):
        splitcopy.process_args(source, target)


def test_process_args_put(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        return "foo", "/var/tmp", "/var/tmp/foo"

    def parse_arg_as_remote(*args):
        if args[0] == "/var/tmp/foo":
            raise ValueError
        else:
            return (None, "192.168.65.2", "/var/tmp/foo")

    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    source = "/var/tmp/foo"
    target = "192.168.25.2:/var/tmp/foo"
    result = splitcopy.process_args(source, target)
    assert result == {
        "user": None,
        "host": "192.168.65.2",
        "remote_path": "/var/tmp/foo",
        "local_dir": "/var/tmp",
        "local_file": "foo",
        "local_path": "/var/tmp/foo",
        "copy_op": "put",
        "target": "192.168.25.2:/var/tmp/foo",
    }


def test_process_args_bad_target_format(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        return "foo", "/var/tmp", "/var/tmp/foo"

    def parse_arg_as_remote(*args):
        raise ValueError

    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    source = "/var/tmp/foo"
    target = "foo@192.168.3.2"
    with raises(
        SystemExit,
        match=f"file '{source}' found, remote path '{target}' is not in the correct format \\[user@\\]host:path",
    ):
        splitcopy.process_args(source, target)


def test_process_args_both_args_local(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        return "foo", "/var/tmp", "/var/tmp/foo"

    def parse_arg_as_remote(*args):
        raise ValueError

    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    source = "/var/tmp/foo"
    target = "/var/tmp/foo2"
    with raises(
        SystemExit,
        match=(
            f"file '{source}' found, remote path '{target}' is not in the correct format \\[user@\\]host:path"
        ),
    ):
        splitcopy.process_args(source, target)


def test_process_args_no_local_file(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        raise FileNotFoundError

    def parse_arg_as_remote(*args):
        if args[0] == "foo@192.168.3.2:":
            return ("foo", "192.168.3.2", "")
        else:
            raise ValueError

    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    source = "/var/tmp/foo"
    target = "foo@192.168.3.2:"
    with raises(
        SystemExit,
        match=f"'{source}' file not found",
    ):
        splitcopy.process_args(source, target)


def test_process_args_both_args_local_no_local(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        raise FileNotFoundError

    def parse_arg_as_remote(*args):
        raise ValueError

    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    source = "/var/tmp/foo"
    target = "/var/tmp/foo2"
    with raises(
        SystemExit,
        match=f"'{source}' file not found",
    ):
        splitcopy.process_args(source, target)


def test_process_args_no_remote_filepath(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        raise FileNotFoundError

    def parse_arg_as_remote(*args):
        if args[0] == "foo@192.168.3.2:":
            return ("foo", "192.168.3.2", "")
        else:
            raise ValueError

    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    source = "foo@192.168.3.2:"
    target = "/var/tmp/foo"
    with raises(SystemExit, match=f"'{source}' does not specify a filepath"):
        splitcopy.process_args(source, target)


def test_process_args_get(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        raise FileNotFoundError

    def parse_arg_as_remote(*args):
        if args[0] == "/var/tmp/foo":
            raise ValueError
        else:
            return (None, "192.168.25.2", "/var/tmp/foo")

    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    source = "192.168.25.2:/var/tmp/foo"
    target = "/var/tmp/foo"
    result = splitcopy.process_args(source, target)
    assert result == {
        "user": None,
        "host": "192.168.25.2",
        "remote_path": "/var/tmp/foo",
        "local_dir": "",
        "local_file": "",
        "local_path": "",
        "copy_op": "get",
        "target": "/var/tmp/foo",
    }


def test_process_args_resolution_fail(monkeypatch: MonkeyPatch):
    def parse_src_arg_as_local(*args):
        return "foo", "/var/tmp", "/var/tmp/foo"

    def parse_arg_as_remote(*args):
        if args[0] == "foo@foo:/var/tmp/foobar":
            return ("foo", "foo", "/var/tmp/foobar")
        else:
            raise ValueError

    def gethostbyname(*args):
        raise gaierror

    monkeypatch.setattr(
        "splitcopy.splitcopy.parse_src_arg_as_local", parse_src_arg_as_local
    )
    monkeypatch.setattr("splitcopy.splitcopy.parse_arg_as_remote", parse_arg_as_remote)
    monkeypatch.setattr("socket.gethostbyname", gethostbyname)
    source = "/var/tmp/foo"
    target = "foo@foo:/var/tmp/foobar"
    with raises(
        SystemExit, match=f"Could not resolve hostname 'foo', resolution failed"
    ):
        splitcopy.process_args(source, target)


def test_main_get_scp_success(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="192.168.64.7:/var/tmp/foobar",
            target="/var/tmp/bar",
            pwd="lab123",
            ssh_key=None,
            scp=True,
            noverify=False,
            split_timeout=None,
            ssh_port=None,
            overwrite=False,
            nocurses=True,
            log=None,
        )

    def process_args(*args):
        return {"copy_op": "get"}

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.process_args", process_args)
    result = splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)
    assert result == True


def test_main_put_ftp_success(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="192.168.64.7:/var/tmp/",
            pwd=None,
            ssh_key=None,
            scp=False,
            noverify=False,
            split_timeout=None,
            ssh_port=None,
            overwrite=False,
            nocurses=False,
            log=None,
        )

    def process_args(*args):
        return {"copy_op": "put"}

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.process_args", process_args)
    result = splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)
    assert result == True


def test_main_get_scp_loglevel(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="192.168.64.7:/var/tmp/foobar",
            target="/var/tmp/bar",
            pwd=None,
            ssh_key=None,
            scp=True,
            noverify=False,
            split_timeout=None,
            ssh_port=None,
            overwrite=False,
            nocurses=False,
            log=["debug"],
        )

    def process_args(*args):
        return {"copy_op": "get"}

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.process_args", process_args)
    result = splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)
    assert result == True


def test_main_get_scp_bad_loglevel(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="192.168.64.7:/var/tmp/foobar",
            target="/var/tmp/bar",
            pwd=None,
            ssh_key=None,
            scp=True,
            noverify=False,
            split_timeout=None,
            ssh_port=None,
            overwrite=False,
            nocurses=False,
            log=["123"],
        )

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    with raises(ValueError, match=f"Invalid log level: 123"):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_sshkey_filenotfounderror(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="somerandomhost:/var/tmp/",
            pwd=None,
            ssh_key=["/var/tmp/sshkey"],
            scp=True,
            noverify=False,
            split_timeout=None,
            ssh_port=None,
            overwrite=False,
            nocurses=False,
            log=None,
        )

    def open_ssh_keyfile(*args):
        raise FileNotFoundError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.open_ssh_keyfile", open_ssh_keyfile)
    with raises(SystemExit, match="'/var/tmp/sshkey' file does not exist"):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_sshkey_permerror(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="somerandomhost:/var/tmp/",
            pwd=None,
            ssh_key=["/var/tmp/sshkey"],
            scp=True,
            noverify=False,
            split_timeout=None,
            ssh_port=None,
            overwrite=False,
            nocurses=False,
            log=None,
        )

    def open_ssh_keyfile(*args):
        raise PermissionError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.open_ssh_keyfile", open_ssh_keyfile)
    with raises(
        SystemExit,
        match="'/var/tmp/sshkey' exists, but file cannot be read due to a permissions error",
    ):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_sshkey_isadirerror(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="somerandomhost:/var/tmp/",
            pwd=None,
            ssh_key=["/var/tmp/sshkey"],
            scp=True,
            noverify=False,
            split_timeout=None,
            ssh_port=None,
            overwrite=False,
            nocurses=False,
            log=None,
        )

    def open_ssh_keyfile(*args):
        raise IsADirectoryError

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    monkeypatch.setattr("splitcopy.splitcopy.open_ssh_keyfile", open_ssh_keyfile)
    with raises(SystemExit, match="'/var/tmp/sshkey' is a directory, not a file"):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_ftp_sshport_notint(capsys, monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="192.168.64.7:/var/tmp/",
            pwd=None,
            ssh_key=None,
            scp=True,
            noverify=False,
            split_timeout=None,
            ssh_port=["foo"],
            overwrite=False,
            nocurses=False,
            log=None,
        )

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    with raises(SystemExit, match="ssh_port must be an integer"):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_main_put_ftp_split_timeout_notint(monkeypatch: MonkeyPatch):
    def parse_args(*args):
        return Namespace(
            source="/var/tmp/foobar",
            target="192.168.64.7:/var/tmp/",
            pwd=None,
            ssh_key=None,
            scp=True,
            noverify=False,
            split_timeout=["foo"],
            ssh_port=None,
            overwrite=False,
            nocurses=False,
            log=None,
        )

    monkeypatch.setattr("splitcopy.splitcopy.parse_args", parse_args)
    with raises(SystemExit, match="split_timeout must be an integer"):
        splitcopy.main(MockSplitCopyGet, MockSplitCopyPut)


def test_handlesigint():
    with raises(SystemExit):
        splitcopy.handlesigint("SigInt", "stack")
