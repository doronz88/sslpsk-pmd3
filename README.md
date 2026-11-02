# sslpsk-pmd3

[![PyPI version](https://badge.fury.io/py/sslpsk-pmd3.svg)](https://badge.fury.io/py/sslpsk-pmd3)

TLS-PSK for Python's `ssl` module. Fork of sslpsk with support for the latest Python versions.

`SSLPSKContext` provides Python 3.13's `set_psk_client_callback()`/`set_psk_server_callback()` on every
supported version (on 3.13+ they are the native implementation):

```python
import ssl
from sslpsk_pmd3 import SSLPSKContext

client = SSLPSKContext(ssl.PROTOCOL_TLS_CLIENT)
client.check_hostname = False
client.verify_mode = ssl.CERT_NONE
client.set_ciphers("PSK")
client.set_psk_client_callback(lambda hint: ("client-identity", b"secret"))

server = SSLPSKContext(ssl.PROTOCOL_TLS_SERVER)
server.set_ciphers("PSK")
server.set_psk_server_callback(lambda identity: b"secret", identity_hint="server-hint")
```

The original interface is still supported: set `context.psk` (and `context.hint` on servers), or use
`sslpsk_pmd3.wrap_socket(sock, psk=..., hint=..., ...)`.

No OpenSSL is linked or bundled: the extension binds at runtime to the OpenSSL used by the
interpreter's own `_ssl` module.
