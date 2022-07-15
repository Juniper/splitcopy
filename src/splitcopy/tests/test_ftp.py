import logging
from tempfile import NamedTemporaryFile

from pytest import MonkeyPatch
from splitcopy.ftp import FTP


class MockLogger:
    def __init__(self):
        self.level = 10

    def getEffectiveLevel(self):
        return self.level

    def removeHandler(self, hdlr):
        pass

    def addHandler(self, hdlr):
        pass


class mockFTP:
    def __init__(self, **kwargs):
        return None


def mockgetlogger(name=None):
    return MockLogger()


def init_ftp(file_size=None, progress=None, **kwargs):
    return FTP(file_size, progress, **kwargs)


class TestFTP:
    def test_context_manager(self, monkeypatch: MonkeyPatch):
        def quit(self):
            pass

        monkeypatch.setattr(logging, "getLogger", mockgetlogger)
        monkeypatch.setattr("logging.Logger", MockLogger)
        monkeypatch.setattr("ftplib.FTP", mockFTP)
        monkeypatch.setattr(FTP, "quit", quit)
        ftp = init_ftp()
        with ftp as foo:
            result = True
        expected = True
        assert expected == result

    def test_put(self, monkeypatch: MonkeyPatch):
        def storbinary(cmd, fp, callback, rest):
            callback(b"foobar" * 10)

        class MockProgress:
            def __init__(self):
                pass

            def report_progress(self, file_name, file_size, sent):
                pass

        monkeypatch.setattr("ftplib.FTP", mockFTP)
        mockprog = MockProgress()
        ftp = init_ftp(file_size=100, progress=mockprog)
        monkeypatch.setattr(ftp, "storbinary", storbinary)
        remote_file = "/var/tmp/remote"
        restart_marker = 10
        with NamedTemporaryFile() as tmpfile:
            local_file = tmpfile.name
            result = ftp.put(local_file, remote_file, restart_marker)
        expected = None
        assert expected == result

    def test_get(self, monkeypatch: MonkeyPatch):
        def retrbinary(cmd, callback, rest):
            callback(b"foobar" * 10)

        class MockProgress:
            def __init__(self):
                pass

            def report_progress(self, file_name, file_size, sent):
                pass

        monkeypatch.setattr("ftplib.FTP", mockFTP)
        mockprog = MockProgress()
        ftp = init_ftp(file_size=100, progress=mockprog)
        monkeypatch.setattr(ftp, "retrbinary", retrbinary)
        remote_file = "/var/tmp/remote"
        restart_marker = 10
        with NamedTemporaryFile() as tmpfile:
            local_file = tmpfile.name
            result = ftp.get(remote_file, local_file, restart_marker)
        expected = None
        assert expected == result
