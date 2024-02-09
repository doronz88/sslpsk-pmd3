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

import sys

from setuptools import Extension, setup

if sys.platform == 'win32':
    libraries = ['libcrypto', 'libssl']
else:
    libraries = ['crypto','ssl']

extension_openssl1 = Extension(
    "sslpsk_pmd3._sslpsk_openssl1",
    sources=["sslpsk_pmd3/_sslpsk.c"],
    libraries=libraries,
    include_dirs=["openssl1/include/"],
    library_dirs=["openssl1/lib/VC/"],
    define_macros=[
        ("OPENSSL_VER", "openssl1"),
        ("INIT_SSLPSK_OPENSSL", "init_sslpsk_openssl1"),
        ("PYINIT_SSLPSK_OPENSSL", "PyInit__sslpsk_openssl1"),
    ],
)

extension_openssl3 = Extension(
    "sslpsk_pmd3._sslpsk_openssl3",
    sources=["sslpsk_pmd3/_sslpsk.c"],
    libraries=libraries,
    include_dirs=["openssl3/include/"],
    library_dirs=["openssl3/lib/VC/"],
    define_macros=[
        ("OPENSSL_VER", "openssl3"),
        ("INIT_SSLPSK_OPENSSL", "init_sslpsk_openssl3"),
        ("PYINIT_SSLPSK_OPENSSL", "PyInit__sslpsk_openssl3"),
    ],
)

setup(name='pytun-pmd3', ext_modules=[extension_openssl1, extension_openssl3])
