from socket import gaierror

from paramiko.ssh_exception import (
    AuthenticationException,
    BadAuthenticationType,
    PasswordRequiredException,
    SSHException,
)
from pytest import MonkeyPatch, raises
from splitcopy.paramikoshell import SSHShell


def init_paramikoshell(**kwargs):
    return SSHShell(**kwargs)


class TestParamikoShell:
    def test_context_manager(self, monkeypatch: MonkeyPatch):
        class MockSocket:
            def settimeout(timeout):
                return True

        def create_connection(host, timeout):
            return MockSocket

        def start_client(sock):
            pass

        monkeypatch.setattr("paramiko.Transport.start_client", start_client)
        monkeypatch.setattr("socket.create_connection", create_connection)
        with SSHShell(hostname="foo", username="bar", ssh_port=22) as foo:
            result = None
        assert result == None

    def test_socket_open(self, monkeypatch: MonkeyPatch):
        def socket_proxy():
            pass

        def socket_direct():
            pass

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "socket_proxy", socket_proxy)
        monkeypatch.setattr(paramikoshell, "socket_direct", socket_direct)
        result = paramikoshell.socket_open()
        assert result == None

    def test_socket_proxy(self, monkeypatch: MonkeyPatch):
        def expanduser(path):
            return "/homes/foo/.ssh/config"

        def isfile(path):
            return True

        class MockOpen:
            def __init__(self, filename):
                self.filename = filename

            def __enter__(self):
                return self.filename

            def __exit__(self, exc_type, exc_value, exc_tb):
                pass

        class MockSSHConfig:
            def parse(self, fh):
                pass

            def lookup(self, str):
                result = {}
                result["proxycommand"] = "somestring"
                return result

        def mockproxycommand(cmd):
            return True

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr("os.path.expanduser", expanduser)
        monkeypatch.setattr("os.path.isfile", isfile)
        monkeypatch.setattr("builtins.open", MockOpen)
        monkeypatch.setattr("paramiko.SSHConfig", MockSSHConfig)
        monkeypatch.setattr("paramiko.proxy.ProxyCommand", mockproxycommand)
        result = paramikoshell.socket_proxy()
        assert result == True

    def test_socket_direct(self, monkeypatch: MonkeyPatch):
        def create_connection(host, timeout):
            return True

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr("socket.create_connection", create_connection)
        result = paramikoshell.socket_direct()
        assert result == True

    def test_socket_direct_resolution_fail(self, monkeypatch: MonkeyPatch):
        def create_connection(host, timeout):
            raise gaierror

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr("socket.create_connection", create_connection)
        with raises(ConnectionError):
            paramikoshell.socket_direct()

    def test_socket_direct_timeout_fail(self, monkeypatch: MonkeyPatch):
        def create_connection(host, timeout):
            raise ConnectionRefusedError

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr("socket.create_connection", create_connection)
        with raises(ConnectionError):
            paramikoshell.socket_direct()

    def test_get_pkey_from_file_nosupport(self, monkeypatch: MonkeyPatch):
        def from_private_key_file(filename):
            raise AttributeError

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(
            "paramiko.Ed25519Key.from_private_key_file", from_private_key_file
        )
        result = paramikoshell.get_pkey_from_file("OPENSSH", "/homes/foo/.ssh/bar")
        assert result == None

    def test_get_pkey_from_file_pwd_required(self, monkeypatch: MonkeyPatch):
        def from_private_key_file(filename):
            raise PasswordRequiredException

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(
            "paramiko.ECDSAKey.from_private_key_file", from_private_key_file
        )
        with raises(PasswordRequiredException):
            paramikoshell.get_pkey_from_file("EC", "/homes/foo/.ssh/bar")

    def test_get_pkey_from_file_dsa(self, monkeypatch: MonkeyPatch):
        def from_private_key_file(filename):
            return "dsa key"

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(
            "paramiko.DSSKey.from_private_key_file", from_private_key_file
        )
        result = paramikoshell.get_pkey_from_file("DSA", "/homes/foo/.ssh/bar")
        assert result == "dsa key"

    def test_get_pkey_from_file_rsa(self, monkeypatch: MonkeyPatch):
        def from_private_key_file(filename):
            return "rsa key"

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(
            "paramiko.RSAKey.from_private_key_file", from_private_key_file
        )
        result = paramikoshell.get_pkey_from_file("RSA", "/homes/foo/.ssh/bar")
        assert result == "rsa key"

    def test_transport_open(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def __init__(self, sock):
                pass

            def start_client(self):
                return True

        monkeypatch.setattr("paramiko.Transport", MockTransport)
        paramikoshell = init_paramikoshell()
        paramikoshell.socket = True
        result = paramikoshell.transport_open()
        assert result == None

    def test_worker_thread_auth_agent(self, monkeypatch: MonkeyPatch):
        def auth_using_agent():
            pass

        def is_authenticated():
            return True

        paramikoshell = init_paramikoshell(auth_method="agent")
        monkeypatch.setattr(paramikoshell, "auth_using_agent", auth_using_agent)
        monkeypatch.setattr(paramikoshell, "is_authenticated", is_authenticated)
        result = paramikoshell.worker_thread_auth()
        assert result == True

    def test_worker_thread_auth_keyfile(self, monkeypatch: MonkeyPatch):
        def auth_using_provided_keyfile():
            pass

        def is_authenticated():
            return True

        paramikoshell = init_paramikoshell(auth_method="publickey")
        monkeypatch.setattr(
            paramikoshell, "auth_using_provided_keyfile", auth_using_provided_keyfile
        )
        monkeypatch.setattr(paramikoshell, "is_authenticated", is_authenticated)
        result = paramikoshell.worker_thread_auth()
        assert result == True

    def test_worker_thread_auth_keyb(self, monkeypatch: MonkeyPatch):
        def auth_using_keyb():
            pass

        def is_authenticated():
            return True

        paramikoshell = init_paramikoshell(auth_method="keyboard-interactive")
        monkeypatch.setattr(paramikoshell, "auth_using_keyb", auth_using_keyb)
        monkeypatch.setattr(paramikoshell, "is_authenticated", is_authenticated)
        result = paramikoshell.worker_thread_auth()
        assert result == True

    def test_worker_thread_auth_password(self, monkeypatch: MonkeyPatch):
        def password_auth():
            pass

        def is_authenticated():
            return True

        paramikoshell = init_paramikoshell(auth_method=None)
        monkeypatch.setattr(paramikoshell, "password_auth", password_auth)
        monkeypatch.setattr(paramikoshell, "is_authenticated", is_authenticated)
        result = paramikoshell.worker_thread_auth()
        assert result == True

    def test_main_thread_auth_type_none(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def auth_none(username):
                raise BadAuthenticationType("Bad authentication type", None)

        paramikoshell = init_paramikoshell(username="foo")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        with raises(SSHException):
            paramikoshell.main_thread_auth()

    def test_main_thread_auth_using_agent(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def auth_none(username):
                raise BadAuthenticationType(
                    "Bad authentication type",
                    ["publickey", "keyboard-interactive", "password"],
                )

        def is_authenticated():
            return True

        def auth_using_agent():
            return True

        paramikoshell = init_paramikoshell(username="foo", key_filename=None)
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "auth_using_agent", auth_using_agent)
        monkeypatch.setattr(paramikoshell, "is_authenticated", is_authenticated)
        result = paramikoshell.main_thread_auth()
        assert result == True

    def test_main_thread_auth_using_keyfiles(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def auth_none(username):
                raise BadAuthenticationType(
                    "Bad authentication type",
                    ["publickey", "keyboard-interactive", "password"],
                )

        def is_authenticated():
            return True

        def auth_using_agent():
            return False

        def auth_using_keyfiles():
            return True

        paramikoshell = init_paramikoshell(username="foo", key_filename=None)
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "auth_using_agent", auth_using_agent)
        monkeypatch.setattr(paramikoshell, "auth_using_keyfiles", auth_using_keyfiles)
        monkeypatch.setattr(paramikoshell, "is_authenticated", is_authenticated)
        result = paramikoshell.main_thread_auth()
        assert result == True

    def test_main_thread_auth_using_keyfiles_key(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def auth_none(username):
                raise BadAuthenticationType(
                    "Bad authentication type",
                    ["publickey", "keyboard-interactive", "password"],
                )

        def is_authenticated():
            return True

        def auth_using_provided_keyfile():
            return True

        paramikoshell = init_paramikoshell(username="foo", key_filename="/var/tmp/foo")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(
            paramikoshell, "auth_using_provided_keyfile", auth_using_provided_keyfile
        )
        monkeypatch.setattr(paramikoshell, "is_authenticated", is_authenticated)
        result = paramikoshell.main_thread_auth()
        assert result == True

    def test_main_thread_auth_using_keyb(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def auth_none(username):
                raise BadAuthenticationType(
                    "Bad authentication type",
                    ["publickey", "keyboard-interactive", "password"],
                )

        def is_authenticated():
            return True

        def auth_using_keyb():
            return True

        def auth_using_agent():
            return False

        def auth_using_keyfiles():
            return False

        paramikoshell = init_paramikoshell(username="foo", key_filename=None)
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "auth_using_keyb", auth_using_keyb)
        monkeypatch.setattr(paramikoshell, "is_authenticated", is_authenticated)
        monkeypatch.setattr(paramikoshell, "auth_using_agent", auth_using_agent)
        monkeypatch.setattr(paramikoshell, "auth_using_keyfiles", auth_using_keyfiles)
        result = paramikoshell.main_thread_auth()
        assert result == True

    def test_main_thread_auth_using_password(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def auth_none(username):
                raise BadAuthenticationType(
                    "Bad authentication type",
                    ["publickey", "keyboard-interactive", "password"],
                )

        def is_authenticated():
            return True

        def auth_using_keyb():
            return False

        def auth_using_agent():
            return False

        def auth_using_keyfiles():
            return False

        def password_auth():
            return True

        paramikoshell = init_paramikoshell(username="foo", key_filename=None)
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "auth_using_keyb", auth_using_keyb)
        monkeypatch.setattr(paramikoshell, "is_authenticated", is_authenticated)
        monkeypatch.setattr(paramikoshell, "auth_using_agent", auth_using_agent)
        monkeypatch.setattr(paramikoshell, "auth_using_keyfiles", auth_using_keyfiles)
        monkeypatch.setattr(paramikoshell, "password_auth", password_auth)
        result = paramikoshell.main_thread_auth()
        assert result == True

    def test_main_thread_auth_fail(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def auth_none(username):
                raise BadAuthenticationType(
                    "Bad authentication type",
                    ["publickey", "keyboard-interactive", "password"],
                )

        def is_authenticated():
            return False

        def auth_using_keyb():
            return False

        def auth_using_agent():
            return False

        def auth_using_keyfiles():
            return False

        def password_auth():
            return False

        paramikoshell = init_paramikoshell(username="foo", key_filename=None)
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "auth_using_keyb", auth_using_keyb)
        monkeypatch.setattr(paramikoshell, "is_authenticated", is_authenticated)
        monkeypatch.setattr(paramikoshell, "auth_using_agent", auth_using_agent)
        monkeypatch.setattr(paramikoshell, "auth_using_keyfiles", auth_using_keyfiles)
        monkeypatch.setattr(paramikoshell, "password_auth", password_auth)
        result = paramikoshell.main_thread_auth()
        assert result == False

    def test_ask_password(self, monkeypatch: MonkeyPatch):
        def getpass(prompt, stream):
            return "a_password"

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr("getpass.getpass", getpass)
        result = paramikoshell.ask_password()
        assert result == "a_password"

    def test_password_auth_fail(self, monkeypatch: MonkeyPatch):
        def ask_password():
            return "a_password"

        class MockTransport:
            def auth_password(username, password):
                raise AuthenticationException

        paramikoshell = init_paramikoshell(password="", username="foo")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "ask_password", ask_password)
        result = paramikoshell.password_auth()
        assert result == False

    def test_password_auth(self, monkeypatch: MonkeyPatch):
        def ask_password():
            return "a_password"

        class MockTransport:
            def auth_password(username, password):
                return True

        paramikoshell = init_paramikoshell(username="foo", password="")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "ask_password", ask_password)
        result = paramikoshell.password_auth()
        assert result == True

    def test_auth_using_keyb_too_many_fields(self, monkeypatch: MonkeyPatch):
        def ask_password():
            return "a_password"

        class MockTransport:
            def auth_interactive(username, handler):
                handler(None, None, ["foo", "bar"])

        paramikoshell = init_paramikoshell(password="", username="foo")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "ask_password", ask_password)
        result = paramikoshell.auth_using_keyb()
        assert result == False

    def test_auth_using_keyb_nofields(self, monkeypatch: MonkeyPatch):
        def ask_password():
            return "a_password"

        class MockTransport:
            def auth_interactive(username, handler):
                handler(None, None, [])

        paramikoshell = init_paramikoshell(password="", username="foo")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "ask_password", ask_password)
        result = paramikoshell.auth_using_keyb()
        assert result == True

    def test_auth_using_keyb(self, monkeypatch: MonkeyPatch):
        def ask_password():
            return "a_password"

        class MockTransport:
            def auth_interactive(username, handler):
                handler(None, None, ["foo"])

        paramikoshell = init_paramikoshell(password="", username="foo")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "ask_password", ask_password)
        result = paramikoshell.auth_using_keyb()
        assert result == True

    def test_auth_using_agent_fail(self, monkeypatch: MonkeyPatch):
        class MockAgent:
            def __init__(self):
                pass

            def get_keys(self):
                keys = [MockAgentKey("foo", "bar")]
                return keys

        class MockAgentKey:
            def __init__(self, agent, blob):
                self.agent = agent
                self.blob = blob
                self.name = "foobar"

            def get_name(self):
                return self.name

        class MockTransport:
            def auth_publickey(username, pkey):
                raise SSHException

        monkeypatch.setattr("paramiko.Agent", MockAgent)
        monkeypatch.setattr("paramiko.AgentKey", MockAgentKey)
        paramikoshell = init_paramikoshell(username="foo")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        result = paramikoshell.auth_using_agent()
        assert result == False

    def test_auth_using_agent(self, monkeypatch: MonkeyPatch):
        class MockAgent:
            def __init__(self):
                pass

            def get_keys(self):
                keys = [MockAgentKey("foo", "bar")]
                return keys

        class MockAgentKey:
            def __init__(self, agent, blob):
                self.agent = agent
                self.blob = blob
                self.name = "foobar"

            def get_name(self):
                return self.name

        class MockTransport:
            def auth_publickey(username, pkey):
                return True

        monkeypatch.setattr("paramiko.Agent", MockAgent)
        monkeypatch.setattr("paramiko.AgentKey", MockAgentKey)
        paramikoshell = init_paramikoshell(username="foo")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        result = paramikoshell.auth_using_agent()
        assert result == True

    def test_auth_using_keyfiles_fail(self, monkeypatch: MonkeyPatch):
        def expanduser(path):
            return path

        def isfile(path):
            return True

        def key_auth_common(type, path):
            raise PasswordRequiredException

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr("os.path.isfile", isfile)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        monkeypatch.setattr(paramikoshell, "key_auth_common", key_auth_common)
        result = paramikoshell.auth_using_keyfiles()
        assert result == False

    def test_auth_using_keyfiles(self, monkeypatch: MonkeyPatch):
        def expanduser(path):
            return path

        def isfile(path):
            return True

        def key_auth_common(type, path):
            return True

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr("os.path.isfile", isfile)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        monkeypatch.setattr(paramikoshell, "key_auth_common", key_auth_common)
        result = paramikoshell.auth_using_keyfiles()
        assert result == True

    def test_key_auth_common_pwd_required(self, monkeypatch: MonkeyPatch):
        def get_pkey_from_file(type, path):
            raise PasswordRequiredException

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "get_pkey_from_file", get_pkey_from_file)
        with raises(PasswordRequiredException):
            paramikoshell.key_auth_common("foo", "bar")

    def test_key_auth_common_fail(self, monkeypatch: MonkeyPatch):
        def get_pkey_from_file(type, path):
            return "foobar"

        class MockTransport:
            def auth_publickey(username, pkey):
                raise SSHException

        paramikoshell = init_paramikoshell(username="foo")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "get_pkey_from_file", get_pkey_from_file)
        result = paramikoshell.key_auth_common("foo", "bar")
        assert result == False

    def test_key_auth_common(self, monkeypatch: MonkeyPatch):
        def get_pkey_from_file(type, path):
            return "foobar"

        class MockTransport:
            def auth_publickey(username, pkey):
                return True

        paramikoshell = init_paramikoshell(username="foo")
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        monkeypatch.setattr(paramikoshell, "get_pkey_from_file", get_pkey_from_file)
        result = paramikoshell.key_auth_common("foo", "bar")
        assert result == True

    def test_auth_using_provided_keyfile_fail(self, monkeypatch: MonkeyPatch):
        def key_auth_common(type, path):
            raise PasswordRequiredException

        paramikoshell = init_paramikoshell(key_filename="/var/tmp/foo")
        monkeypatch.setattr(paramikoshell, "key_auth_common", key_auth_common)
        result = paramikoshell.auth_using_provided_keyfile()
        assert result == False

    def test_auth_using_provided_keyfile(self, monkeypatch: MonkeyPatch):
        def key_auth_common(type, path):
            return True

        paramikoshell = init_paramikoshell(key_filename="/var/tmp/foo")
        monkeypatch.setattr(paramikoshell, "key_auth_common", key_auth_common)
        result = paramikoshell.auth_using_provided_keyfile()
        assert result == True

    def test_is_authenticated_fail(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def is_authenticated():
                return False

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        result = paramikoshell.is_authenticated()
        assert result == False

    def test_is_authenticated(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def is_authenticated():
                return True

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        result = paramikoshell.is_authenticated()
        assert result == True

    def test_channel_open(self, monkeypatch: MonkeyPatch):
        class MockChannel:
            def __init__(self):
                pass

        class MockTransport:
            def open_session():
                return MockChannel()

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        result = paramikoshell.channel_open()
        assert result == None

    def test_invoke_shell(self, monkeypatch: MonkeyPatch):
        class MockChannel:
            def __init__(self):
                pass

            def get_pty(self):
                pass

            def invoke_shell(self):
                pass

        paramikoshell = init_paramikoshell()
        paramikoshell._chan = MockChannel()
        result = paramikoshell.invoke_shell()
        assert result == None

    def test_stdout_read_timeout(self, monkeypatch: MonkeyPatch):
        class MockChannel:
            def __init__(self):
                pass

            def recv(self, nbytes):
                return b"foobar"

        def select(*args):
            return True, False, False

        monkeypatch.setattr("select.select", select)
        paramikoshell = init_paramikoshell()
        paramikoshell._chan = MockChannel()
        with raises(TimeoutError):
            paramikoshell.stdout_read(timeout=0.1)

    def test_stdout_read(self, monkeypatch: MonkeyPatch):
        class MockChannel:
            def __init__(self):
                pass

            def recv(self, nbytes):
                return b"foo@bar# "

        def select(*args):
            return True, False, False

        monkeypatch.setattr("select.select", select)
        paramikoshell = init_paramikoshell()
        paramikoshell._chan = MockChannel()
        result = paramikoshell.stdout_read(timeout=10)
        assert result == "foo@bar# "

    def test_set_keepalive(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def set_keepalive(timer):
                pass

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        result = paramikoshell.set_keepalive()
        assert result == None

    def test_write(self, monkeypatch: MonkeyPatch):
        class MockChannel:
            def __init__(self):
                pass

            def send(self, string):
                pass

        paramikoshell = init_paramikoshell()
        paramikoshell._chan = MockChannel()
        result = paramikoshell.write("foo")
        assert result == None

    def test_close(self, monkeypatch: MonkeyPatch):
        def close_channel():
            pass

        def close_transport():
            pass

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "close_channel", close_channel)
        monkeypatch.setattr(paramikoshell, "close_transport", close_transport)
        result = paramikoshell.close()
        assert result == None

    def test_close_channel_fail(self, monkeypatch: MonkeyPatch):
        class MockChannel:
            def __init__(self):
                pass

            def close(self):
                raise AttributeError

        paramikoshell = init_paramikoshell()
        paramikoshell._chan = MockChannel()
        result = paramikoshell.close_channel()
        assert result == None

    def test_close_channel(self, monkeypatch: MonkeyPatch):
        class MockChannel:
            def __init__(self):
                pass

            def close(self):
                pass

        paramikoshell = init_paramikoshell()
        paramikoshell._chan = MockChannel()
        result = paramikoshell.close_channel()
        assert result == None

    def test_close_transport(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def close():
                pass

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        result = paramikoshell.close_transport()
        assert result == None

    def test_close_transport_fail(self, monkeypatch: MonkeyPatch):
        class MockTransport:
            def close():
                raise AttributeError

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "_transport", MockTransport)
        result = paramikoshell.close_transport()
        assert result == None

    def test_restart_pty(self, monkeypatch: MonkeyPatch):
        class MockChannel:
            def __init__(self):
                pass

            def close(self):
                pass

        def channel_open():
            pass

        def invoke_shell():
            pass

        paramikoshell = init_paramikoshell()
        paramikoshell._chan = MockChannel()
        monkeypatch.setattr(paramikoshell, "channel_open", channel_open)
        monkeypatch.setattr(paramikoshell, "invoke_shell", invoke_shell)
        result = paramikoshell.restart_pty()
        assert result == None

    def test_run_timeout(self, monkeypatch: MonkeyPatch):
        def write(string):
            pass

        def stdout_read(timeout):
            raise TimeoutError

        def restart_pty():
            pass

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "write", write)
        monkeypatch.setattr(paramikoshell, "stdout_read", stdout_read)
        monkeypatch.setattr(paramikoshell, "restart_pty", restart_pty)
        result = paramikoshell.run("cmd")
        assert result == (False, "timeout running 'cmd'")

    def test_run(self, monkeypatch: MonkeyPatch):
        def write(string):
            pass

        def stdout_read(timeout):
            return b"echo $?\r\n\x1b[?2004l\r0\r\n\x1b[?2004hfoo@ubuntu:~$ ".decode()

        paramikoshell = init_paramikoshell()
        monkeypatch.setattr(paramikoshell, "write", write)
        monkeypatch.setattr(paramikoshell, "stdout_read", stdout_read)
        result = paramikoshell.run("cmd")
        assert result == (True, "echo $?\r\n0\r\nfoo@ubuntu:~$ ")
