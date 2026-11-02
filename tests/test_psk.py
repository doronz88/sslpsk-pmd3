"""TLS-PSK tests for sslpsk_pmd3, run against the installed package.

The ``set_psk_*_callback`` tests are ported from CPython's ``test_ssl.test_psk`` /
``test_psk_tls1_3`` (Python 3.13+, where ``SSLPSKContext`` uses the native implementation).
"""

import asyncio
import gc
import socket
import ssl
import sys
import threading
import traceback

import pytest

import sslpsk_pmd3
from sslpsk_pmd3 import sslpsk
from sslpsk_pmd3.sslpsk import SSLPSKContext

PSK = bytes.fromhex("c033f52671c61c8128f7f8a40be88038bcf2b07a6eb3095c36e3759f0cf40837")
TIMEOUT = 10
HAS_NATIVE_PSK = hasattr(ssl.SSLContext, "set_psk_client_callback") and sys.version_info >= (3, 13)


@pytest.fixture(autouse=True, scope="session")
def _initialize_openssl():
    # OpenSSL 1.1.1 on Windows ARM64 (CPython 3.9/3.10) races when two threads create their
    # first SSL_CTX concurrently ("malloc failure"), independently of this package.
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def client_context(cls=SSLPSKContext, version=ssl.TLSVersion.TLSv1_2):
    ctx = cls(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = version
    ctx.maximum_version = version
    ctx.set_ciphers("PSK")
    return ctx


def server_context(cls=SSLPSKContext, version=ssl.TLSVersion.TLSv1_2):
    ctx = cls(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = version
    ctx.maximum_version = version
    ctx.set_ciphers("PSK")
    return ctx


class EchoServer:
    """Accepts ``count`` connections, echoing one message (reversed) on each."""

    def __init__(self, context, count=1):
        self.context = context
        self.count = count
        self.errors = []
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(TIMEOUT)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        for _ in range(self.count):
            try:
                conn, _ = self.listener.accept()
            except OSError as e:
                self.errors.append(e)
                return
            conn.settimeout(TIMEOUT)
            try:
                with self.context.wrap_socket(conn, server_side=True) as tls:
                    tls.sendall(tls.recv(64)[::-1])
            except (OSError, ssl.SSLError) as e:
                self.errors.append(e)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.thread.join(TIMEOUT)
        self.listener.close()


def exchange(context, port, data=b"pymobiledevice3"):
    with context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)) as tls:
        tls.sendall(data)
        reply = tls.recv(64)
        assert reply == data[::-1]
        return tls.version(), tls.cipher()


# ---------- Python 3.13 API (backported on older versions) ----------


def test_native_api_psk():
    client = client_context()
    client.set_psk_client_callback(lambda hint: (None, PSK))
    server = server_context()
    server.set_psk_server_callback(lambda identity: PSK)
    with EchoServer(server) as srv:
        version, cipher = exchange(client, srv.port)
    assert not srv.errors
    assert version == "TLSv1.2"
    assert "PSK" in cipher[0]


def test_native_api_incorrect_psk_fails():
    client = client_context()
    client.set_psk_client_callback(lambda hint: (None, bytes.fromhex("cafebabe")))
    server = server_context()
    server.set_psk_server_callback(lambda identity: PSK)
    with EchoServer(server) as srv:
        with pytest.raises((ssl.SSLError, ConnectionError)):
            exchange(client, srv.port)
    assert srv.errors


@pytest.mark.parametrize(
    ("identity_hint", "client_identity"),
    [("identity-hint", "client-identity"), ("身份暗示", "客户身份")],
)
def test_native_api_hint_and_identity_reach_peer(identity_hint, client_identity):
    seen = {}

    def client_callback(hint):
        seen["hint"] = hint
        return client_identity, PSK

    def server_callback(identity):
        seen["identity"] = identity
        return PSK

    client = client_context()
    client.set_psk_client_callback(client_callback)
    server = server_context()
    server.set_psk_server_callback(server_callback, identity_hint)
    with EchoServer(server) as srv:
        exchange(client, srv.port)
    assert not srv.errors
    assert seen == {"hint": identity_hint, "identity": client_identity}


def test_native_api_no_hint_is_none():
    seen = {}

    def client_callback(hint):
        seen["hint"] = hint
        return None, PSK

    def server_callback(identity):
        seen["identity"] = identity
        return PSK

    client = client_context()
    client.set_psk_client_callback(client_callback)
    server = server_context()
    server.set_psk_server_callback(server_callback)
    with EchoServer(server) as srv:
        exchange(client, srv.port)
    assert seen == {"hint": None, "identity": None}


def test_native_api_wrong_side_raises():
    with pytest.raises(ssl.SSLError, match="Cannot add PSK server callback"):
        client_context().set_psk_server_callback(lambda identity: PSK, "hint")
    with pytest.raises(ssl.SSLError, match="Cannot add PSK client callback"):
        server_context().set_psk_client_callback(lambda hint: (None, PSK))


def test_native_api_rejects_non_callable():
    with pytest.raises(TypeError):
        client_context().set_psk_client_callback(PSK)
    with pytest.raises(TypeError):
        server_context().set_psk_server_callback(PSK)


def test_native_api_callback_can_be_removed():
    client = client_context()
    client.set_psk_client_callback(lambda hint: (None, PSK))
    client.set_psk_client_callback(None)
    server = server_context()
    server.set_psk_server_callback(lambda identity: PSK)
    with EchoServer(server) as srv:
        with pytest.raises((ssl.SSLError, ConnectionError)):
            exchange(client, srv.port)


def test_native_api_tls1_3():
    seen = {}

    def client_callback(hint):
        seen["hint"] = hint
        return "client-identity", PSK

    def server_callback(identity):
        seen["identity"] = identity
        return PSK

    client = client_context(version=ssl.TLSVersion.TLSv1_3)
    client.set_psk_client_callback(client_callback)
    server = server_context(version=ssl.TLSVersion.TLSv1_3)
    server.set_psk_server_callback(server_callback, "identity-hint")
    with EchoServer(server) as srv:
        version, _ = exchange(client, srv.port)
    assert not srv.errors
    assert version == "TLSv1.3"
    # the identity hint is not sent to the client in TLS 1.3
    assert seen == {"hint": None, "identity": "client-identity"}


# ---------- psk/hint attributes ----------


@pytest.mark.parametrize(
    "client_psk",
    [PSK, (PSK, b"client1"), lambda hint: (PSK, b"client1"), lambda hint: PSK],
    ids=["bytes", "tuple", "callable-tuple", "callable-bytes"],
)
def test_psk_attribute_forms(client_psk):
    client = client_context()
    client.psk = client_psk
    server = server_context()
    server.psk = PSK
    with EchoServer(server) as srv:
        exchange(client, srv.port)
    assert not srv.errors


def test_psk_attribute_hint_and_identity():
    seen = {}

    def client_psk(hint):
        seen["hint"] = hint
        return PSK, b"client1"

    def server_psk(identity):
        seen["identity"] = identity
        return PSK

    client = client_context()
    client.psk = client_psk
    server = server_context()
    server.psk = server_psk
    server.hint = b"server1"
    with EchoServer(server) as srv:
        exchange(client, srv.port)
    assert seen == {"hint": b"server1", "identity": b"client1"}


def test_pymobiledevice3_client_construction():
    # tunnel_service.RemotePairingProtocol.start_tcp_tunnel() on Python < 3.13
    client = SSLPSKContext(ssl.PROTOCOL_TLSv1_2)
    client.psk = PSK
    client.set_ciphers("PSK")
    server = server_context()
    server.psk = PSK
    with EchoServer(server) as srv:
        exchange(client, srv.port)
    assert not srv.errors


def test_legacy_wrap_socket():
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(TIMEOUT)
    errors = []

    def serve():
        try:
            conn, _ = listener.accept()
            conn.settimeout(TIMEOUT)
            with sslpsk_pmd3.wrap_socket(
                conn, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="PSK", psk=PSK, hint=b"hint"
            ) as tls:
                tls.sendall(tls.recv(64)[::-1])
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    sock = socket.create_connection(listener.getsockname(), timeout=TIMEOUT)
    with sslpsk_pmd3.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="PSK", psk=(PSK, b"id")) as tls:
        tls.sendall(b"ping")
        assert tls.recv(4) == b"gnip"
    thread.join(TIMEOUT)
    listener.close()
    assert not errors


# ---------- I/O models ----------


def test_asyncio_client_and_server():
    calls = []
    original = sslpsk._ssl_set_psk_client_callback

    def counting(sock, cb):
        calls.append(sock)
        return original(sock, cb)

    async def main():
        server_ctx = server_context()
        server_ctx.set_psk_server_callback(lambda identity: PSK)

        async def handle(reader, writer):
            writer.write((await reader.read(64))[::-1])
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ctx)
        port = server.sockets[0].getsockname()[1]
        client_ctx = SSLPSKContext(ssl.PROTOCOL_TLSv1_2)
        client_ctx.psk = PSK
        client_ctx.set_ciphers("PSK")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port, ssl=client_ctx, server_hostname=""), TIMEOUT
        )
        writer.write(b"pymobiledevice3")
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(64), TIMEOUT)
        writer.close()
        server.close()
        await server.wait_closed()
        return reply

    sslpsk._ssl_set_psk_client_callback = counting
    try:
        assert asyncio.run(main()) == b"3ecivedelibomyp"
    finally:
        sslpsk._ssl_set_psk_client_callback = original
    # do_handshake() is re-entered on WANT_READ; the callback must be registered once
    assert len(calls) == 1


def test_memory_bio():
    client_ctx = client_context()
    client_ctx.set_psk_client_callback(lambda hint: ("id", PSK))
    server_ctx = server_context()
    server_ctx.set_psk_server_callback(lambda identity: PSK, "hint")
    pipes = [ssl.MemoryBIO() for _ in range(4)]
    client = client_ctx.wrap_bio(pipes[0], pipes[1])
    server = server_ctx.wrap_bio(pipes[2], pipes[3], server_side=True)

    def pump():
        pipes[2].write(pipes[1].read())
        pipes[0].write(pipes[3].read())

    done = {"client": False, "server": False}
    for _ in range(20):
        for name, obj in (("client", client), ("server", server)):
            if not done[name]:
                try:
                    obj.do_handshake()
                    done[name] = True
                except ssl.SSLWantReadError:
                    pass
        pump()
        if all(done.values()):
            break
    assert all(done.values())
    client.write(b"hello")
    pump()
    assert server.read(5) == b"hello"


def test_concurrent_connections_use_their_own_callbacks():
    count = 16
    keys = {f"client-{i}": bytes([i]) * 32 for i in range(count)}
    server = server_context()
    server.set_psk_server_callback(lambda identity: keys[identity])
    errors = []

    def connect(identity):
        try:
            ctx = client_context()
            ctx.set_psk_client_callback(lambda hint: (identity, keys[identity]))
            exchange(ctx, srv.port, identity.encode())
        except Exception:  # noqa: BLE001
            errors.append(traceback.format_exc())

    with EchoServer(server, count=count) as srv:
        threads = [threading.Thread(target=connect, args=(name,)) for name in keys]
        for t in threads:
            t.start()
        for t in threads:
            t.join(TIMEOUT)
    assert not errors, "\n".join(errors)
    assert not srv.errors


# ---------- callback registry ----------


def test_callbacks_are_released():
    gc.collect()
    before = len(sslpsk._callbacks)
    client = client_context()
    client.psk = PSK
    server = server_context()
    server.psk = PSK
    with EchoServer(server, count=20) as srv:
        for _ in range(20):
            exchange(client, srv.port)
    gc.collect()
    assert len(sslpsk._callbacks) == before


def test_stale_finalizer_keeps_reused_address_entry():
    class Owner:
        pass

    first, second = Owner(), Owner()
    sslpsk._register_callback(first, -1, lambda _: None)
    sslpsk._register_callback(second, -1, lambda _: None)  # same SSL* reused
    del first
    gc.collect()
    assert -1 in sslpsk._callbacks
    del second
    gc.collect()
    assert -1 not in sslpsk._callbacks


# ---------- failure handling ----------


@pytest.mark.parametrize(
    "bad_callback",
    [
        lambda hint: 1 / 0,
        lambda hint: "not a tuple",
        lambda hint: (None, "str-not-bytes"),
        lambda hint: (None, b"x" * 4096),
    ],
    ids=["raises", "wrong-type", "psk-not-bytes", "psk-too-long"],
)
def test_bad_client_callback_fails_handshake(bad_callback):
    unraisable = []
    hook, sys.unraisablehook = sys.unraisablehook, unraisable.append
    try:
        client = client_context()
        client.set_psk_client_callback(bad_callback)
        server = server_context()
        server.set_psk_server_callback(lambda identity: PSK)
        with EchoServer(server) as srv:
            with pytest.raises((ssl.SSLError, ConnectionError)):
                exchange(client, srv.port)
    finally:
        sys.unraisablehook = hook


def test_bad_server_callback_fails_handshake():
    hook, sys.unraisablehook = sys.unraisablehook, lambda _: None
    try:
        client = client_context()
        client.set_psk_client_callback(lambda hint: (None, PSK))
        server = server_context()
        server.set_psk_server_callback(lambda identity: 1 / 0)
        with EchoServer(server) as srv:
            with pytest.raises((ssl.SSLError, ConnectionError)):
                exchange(client, srv.port)
        assert srv.errors
    finally:
        sys.unraisablehook = hook


# ---------- interoperability with CPython's native implementation ----------


@pytest.mark.skipif(not HAS_NATIVE_PSK, reason="needs Python 3.13+ native TLS-PSK")
def test_psk_attribute_client_against_native_server():
    client = client_context()
    client.psk = (PSK, b"client1")
    server = server_context(cls=ssl.SSLContext)
    server.set_psk_server_callback(lambda identity: PSK)
    with EchoServer(server) as srv:
        exchange(client, srv.port)
    assert not srv.errors


@pytest.mark.skipif(not HAS_NATIVE_PSK, reason="needs Python 3.13+ native TLS-PSK")
def test_native_client_against_psk_attribute_server():
    client = client_context(cls=ssl.SSLContext)
    client.set_psk_client_callback(lambda hint: ("client1", PSK))
    server = server_context()
    server.psk = PSK
    server.hint = b"server1"
    with EchoServer(server) as srv:
        exchange(client, srv.port)
    assert not srv.errors


# ---------- OpenSSL binding ----------


def test_binding_resolves_interpreter_openssl():
    from sslpsk_pmd3 import _openssl_binding

    addresses = _openssl_binding.bind_addresses()
    assert len(addresses) == len(_openssl_binding.FUNCTIONS)
    assert all(addresses)


@pytest.mark.skipif(sys.platform == "win32", reason="dladdr-based check")
def test_binding_addresses_belong_to_ssl_image_or_libssl():
    import ctypes
    import os

    from sslpsk_pmd3 import _openssl_binding

    dladdr = _openssl_binding._dladdr_function()
    ssl_image = _openssl_binding._DlInfo()
    assert dladdr(_openssl_binding._ssl_c_function_address(), ctypes.byref(ssl_image))
    for address in _openssl_binding.bind_addresses():
        info = _openssl_binding._DlInfo()
        assert dladdr(address, ctypes.byref(info))
        name = os.path.basename(os.fsdecode(info.dli_fname)).lower()
        assert info.dli_fbase == ssl_image.dli_fbase or name.startswith(("libssl", "libcrypto")), name


def test_binding_failure_is_a_clean_error(monkeypatch):
    from sslpsk_pmd3 import _openssl_binding

    monkeypatch.setattr(_openssl_binding, "FUNCTIONS", _openssl_binding.FUNCTIONS + ("sslpsk_no_such_function",))
    with pytest.raises(RuntimeError):
        _openssl_binding.bind_addresses()


@pytest.mark.skipif(sys.platform == "win32", reason="dladdr-based binding")
def test_binding_without_dladdr_symbol_names(monkeypatch):
    # glibc's dladdr() names no symbol for hidden code (python-build-standalone on Linux);
    # the binding must not depend on it.
    from sslpsk_pmd3 import _openssl_binding

    expected = _openssl_binding.bind_addresses()
    real_factory = _openssl_binding._dladdr_function

    def factory():
        real = real_factory()

        def dladdr(address, info_ref):
            result = real(address, info_ref)
            info_ref._obj.dli_sname = None
            info_ref._obj.dli_saddr = None
            return result

        return dladdr

    monkeypatch.setattr(_openssl_binding, "_dladdr_function", factory)
    assert _openssl_binding.bind_addresses() == expected


@pytest.mark.skipif(not getattr(sys, "_is_gil_enabled", None) or sys._is_gil_enabled(), reason="free-threaded only")
def test_free_threaded_import_keeps_gil_disabled():
    import os
    import subprocess

    env = {k: v for k, v in os.environ.items() if k != "PYTHON_GIL"}
    code = "import sslpsk_pmd3.sslpsk, sys; print(sys._is_gil_enabled())"
    result = subprocess.run(
        [sys.executable, "-W", "error::RuntimeWarning", "-c", code], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
