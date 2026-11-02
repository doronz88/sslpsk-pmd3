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


_callbacks = {}


class FinalizerRef(weakref.ref):
    """subclass weakref.ref so that attributes can be added"""


def _register_callback(sock, ssl_id, callback):
    _callbacks[ssl_id] = callback
    callback.unregister = FinalizerRef(sock, _unregister_callback)
    callback.unregister.ssl_id = ssl_id


def _unregister_callback(ref):
    del _callbacks[ref.ssl_id]


def _python_psk_client_callback(ssl_id, hint):
    """Called by _sslpsk.c to return the (psk, identity) tuple for the socket with
    the specified ssl socket.

    """
    if ssl_id not in _callbacks:
        return (b"", b"")
    else:
        res = _callbacks[ssl_id](hint)
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
    if ssl_id not in _callbacks:
        return b""
    else:
        return _callbacks[ssl_id](identity)


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

def _ssl_setup_psk_callbacks(sslobj):
    # do_handshake() is re-entered after every WANT_READ/WANT_WRITE on non-blocking sockets
    if getattr(sslobj, "_sslpsk_configured", False):
        return
    sslobj._sslpsk_configured = True
    psk = sslobj.context.psk
    hint = sslobj.context.hint
    if psk:
        if sslobj.server_side:
            cb = psk if callable(psk) else lambda _identity: psk
            _ssl_set_psk_server_callback(sslobj, cb, hint)
        else:
            cb = psk if callable(psk) else lambda _hint: psk if isinstance(psk, tuple) else (psk, b"")
            _ssl_set_psk_client_callback(sslobj, cb)


class SSLPSKContext(ssl.SSLContext):
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
