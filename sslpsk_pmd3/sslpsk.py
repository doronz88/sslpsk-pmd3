# Copyright 2017 David R. Bild
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

from __future__ import absolute_import

import _ssl
import ssl
import threading
import weakref

from sslpsk_pmd3 import _openssl_binding, _sslpsk

_bind_lock = threading.Lock()
_bound = False


def _ensure_bound():
    """Binds _sslpsk to the OpenSSL used by _ssl, on first use."""
    global _bound
    with _bind_lock:
        if not _bound:
            _sslpsk.sslpsk_bind(*_openssl_binding.bind_addresses())
            _bound = True


# ssl_id (the SSL* address) -> (callback, weakref to the owning socket/object)
_callbacks = {}


def _register_callback(sock, ssl_id, callback):
    def unregister(ref):
        # SSL* addresses are reused once an SSL is freed (on close()), possibly before this
        # socket object is collected; only remove the entry if it is still ours.
        entry = _callbacks.get(ssl_id)
        if entry is not None and entry[1] is ref:
            del _callbacks[ssl_id]

    _callbacks[ssl_id] = (callback, weakref.ref(sock, unregister))


def _python_psk_client_callback(ssl_id, hint):
    """Called by _sslpsk.c to return the (psk, identity) tuple for the socket with
    the specified ssl socket.

    """
    entry = _callbacks.get(ssl_id)
    if entry is None:
        return (b"", b"")
    res = entry[0](hint)
    return res if isinstance(res, tuple) else (res, b"")


def _sslobj(sock):
    """Returns the underlying PySLLSocket object with which the C extension
    functions interface.

    """
    if isinstance(sock._sslobj, _ssl._SSLSocket):
        return sock._sslobj
    else:
        return sock._sslobj._sslobj


def _python_psk_server_callback(ssl_id, identity):
    """Called by _sslpsk.c to return the psk for the socket with the specified
    ssl socket.

    """
    entry = _callbacks.get(ssl_id)
    if entry is None:
        return b""
    return entry[0](identity)


_sslpsk.sslpsk_set_python_psk_client_callback(_python_psk_client_callback)
_sslpsk.sslpsk_set_python_psk_server_callback(_python_psk_server_callback)


def _ssl_set_psk_client_callback(sock, psk_cb):
    _ensure_bound()
    ssl_id = _sslpsk.sslpsk_set_psk_client_callback(_sslobj(sock))
    _register_callback(sock, ssl_id, psk_cb)


def _ssl_set_psk_server_callback(sock, psk_cb, hint):
    _ensure_bound()
    ssl_id = _sslpsk.sslpsk_set_accept_state(_sslobj(sock))
    _ = _sslpsk.sslpsk_set_psk_server_callback(_sslobj(sock))
    _ = _sslpsk.sslpsk_use_psk_identity_hint(_sslobj(sock), hint if hint else b"")
    _register_callback(sock, ssl_id, psk_cb)


def _decode_peer_string(value):
    # Mirrors CPython 3.13: an absent or empty hint/identity is None
    return value.decode("utf-8") if value else None


def _native_client_callback(callback):
    def adapter(hint):
        identity, psk = callback(_decode_peer_string(hint))
        return psk, identity.encode("utf-8") if identity is not None else b""

    return adapter


def _native_server_callback(callback):
    return lambda identity: callback(_decode_peer_string(identity))


def _ssl_setup_psk_callbacks(sslobj):
    # do_handshake() is re-entered after every WANT_READ/WANT_WRITE on non-blocking sockets
    if getattr(sslobj, "_sslpsk_configured", False):
        return
    sslobj._sslpsk_configured = True
    context = sslobj.context
    if sslobj.server_side:
        server_callback = getattr(context, "_sslpsk_server_callback", None)
        if server_callback is not None:
            hint = context._sslpsk_identity_hint
            _ssl_set_psk_server_callback(
                sslobj, _native_server_callback(server_callback), hint.encode("utf-8") if hint else b""
            )
            return
    else:
        client_callback = getattr(context, "_sslpsk_client_callback", None)
        if client_callback is not None:
            _ssl_set_psk_client_callback(sslobj, _native_client_callback(client_callback))
            return
    psk = context.psk
    hint = context.hint
    if psk:
        if sslobj.server_side:
            cb = psk if callable(psk) else lambda _identity: psk
            _ssl_set_psk_server_callback(sslobj, cb, hint)
        else:
            cb = psk if callable(psk) else lambda _hint: psk if isinstance(psk, tuple) else (psk, b"")
            _ssl_set_psk_client_callback(sslobj, cb)


class SSLPSKContext(ssl.SSLContext):
    """``ssl.SSLContext`` with TLS-PSK support.

    Two interfaces are available:

    * ``set_psk_client_callback()``/``set_psk_server_callback()``, identical to Python 3.13+
      (where the native implementation is used) and provided here for older versions.
    * The original ``psk``/``hint`` attributes.
    """

    @property
    def psk(self):
        return getattr(self, "_psk", None)

    @psk.setter
    def psk(self, psk):
        self._psk = psk

    @property
    def hint(self):
        return getattr(self, "_hint", None)

    @hint.setter
    def hint(self, hint):
        self._hint = hint

    if not hasattr(ssl.SSLContext, "set_psk_client_callback"):

        def set_psk_client_callback(self, callback):
            """Backport of ``ssl.SSLContext.set_psk_client_callback()`` (Python 3.13).

            :param callback: ``callable(hint: str | None) -> (identity: str | None, psk: bytes)``,
                or ``None`` to remove it
            """
            if self.protocol == ssl.PROTOCOL_TLS_SERVER:
                raise ssl.SSLError("Cannot add PSK client callback to a PROTOCOL_TLS_SERVER context")
            if callback is not None and not callable(callback):
                raise TypeError("callback must be callable")
            self._sslpsk_client_callback = callback

        def set_psk_server_callback(self, callback, identity_hint=None):
            """Backport of ``ssl.SSLContext.set_psk_server_callback()`` (Python 3.13).

            :param callback: ``callable(identity: str | None) -> psk: bytes``, or ``None`` to remove it
            :param identity_hint: ``str`` sent to clients (TLS 1.2 and below), or ``None``
            """
            if self.protocol == ssl.PROTOCOL_TLS_CLIENT:
                raise ssl.SSLError("Cannot add PSK server callback to a PROTOCOL_TLS_CLIENT context")
            if callback is not None and not callable(callback):
                raise TypeError("callback must be callable")
            if identity_hint is not None and not isinstance(identity_hint, str):
                raise TypeError("identity_hint must be str or None")
            self._sslpsk_server_callback = callback
            self._sslpsk_identity_hint = identity_hint if callback is not None else None


class SSLPSKObject(ssl.SSLObject):
    def do_handshake(self, *args, **kwargs):
        _ssl_setup_psk_callbacks(self)
        super().do_handshake(*args, **kwargs)


class SSLPSKSocket(ssl.SSLSocket):
    def do_handshake(self, *args, **kwargs):
        _ssl_setup_psk_callbacks(self)
        super().do_handshake(*args, **kwargs)


SSLPSKContext.sslobject_class = SSLPSKObject
SSLPSKContext.sslsocket_class = SSLPSKSocket

def wrap_socket(
    sock,
    keyfile=None,
    certfile=None,
    server_side=False,
    cert_reqs=ssl.CERT_NONE,
    ssl_version=ssl.PROTOCOL_TLS,
    ca_certs=None,
    do_handshake_on_connect=True,
    suppress_ragged_eofs=True,
    ciphers=None,
    psk=None,
    hint=None,
):
    """``ssl.wrap_socket()`` (removed in Python 3.12) with TLS-PSK support.

    :param psk: client: ``bytes``, ``(psk, identity)`` or ``callable(hint) -> (psk, identity)``;
        server: ``bytes`` or ``callable(identity) -> psk``
    :param hint: server identity hint (``bytes``)
    """
    context = SSLPSKContext(ssl_version)
    context.check_hostname = False
    context.verify_mode = cert_reqs
    if ca_certs:
        context.load_verify_locations(ca_certs)
    if certfile:
        context.load_cert_chain(certfile, keyfile)
    if ciphers:
        context.set_ciphers(ciphers)
    context.psk = psk
    context.hint = hint
    return context.wrap_socket(
        sock=sock,
        server_side=server_side,
        do_handshake_on_connect=do_handshake_on_connect,
        suppress_ragged_eofs=suppress_ragged_eofs,
    )
