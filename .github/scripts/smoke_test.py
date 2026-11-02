"""TLS 1.2 PSK handshake through SSLPSKContext on both ends (the pymobiledevice3 code path)."""

import socket
import ssl
import threading

from sslpsk_pmd3.sslpsk import SSLPSKContext

PSK = b"\x01" * 32
CIPHERS = "PSK-AES256-CBC-SHA:PSK-AES128-CBC-SHA"


def make_context(server_side: bool) -> SSLPSKContext:
    if server_side:
        ctx = SSLPSKContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        # Same construction pymobiledevice3 uses for its TCP tunnel client
        ctx = SSLPSKContext(ssl.PROTOCOL_TLSv1_2)
    ctx.set_ciphers(CIPHERS)
    ctx.psk = PSK
    return ctx


def main() -> None:
    print(ssl.OPENSSL_VERSION)
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(10)
    port = listener.getsockname()[1]
    errors = []

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            with make_context(server_side=True).wrap_socket(conn, server_side=True) as tls:
                tls.sendall(tls.recv(4).upper())
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with make_context(server_side=False).wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10)) as tls:
        tls.sendall(b"ping")
        reply = tls.recv(4)
        print(tls.version(), tls.cipher())
    thread.join(timeout=10)
    listener.close()
    assert not errors, errors
    assert reply == b"PING", reply
    print("OK")


if __name__ == "__main__":
    main()
