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

import os
import platform
import shutil
import sys

from setuptools import Extension, setup

if sys.platform == 'win32' and platform.architecture()[0] == '64bit':
    LIB_NAMES = ['libssl64MD', 'libcrypto64MD']
    DLL_NAMES = ['libcrypto-3-x64', 'libssl-3-x64']
elif sys.platform == 'win32' and platform.architecture()[0] == '32bit':
    LIB_NAMES = ['libssl32MD', 'libcrypto32MD']
    DLL_NAMES = ['libcrypto-3', 'libssl-3']
else:
    LIB_NAMES = ['ssl']
    DLL_NAMES = []

_sslpsk3 = Extension('sslpsk3._sslpsk3',
                     sources=['sslpsk3/_sslpsk3.c'],
                     libraries=LIB_NAMES,
                     include_dirs=['openssl/include/'],
                     library_dirs=['openssl/lib/VC/']
                     )

try:
    # Symlink the libs so they can be included in the package data
    if sys.platform == 'win32':
        for lib in DLL_NAMES:
            shutil.copy2('openssl/bin/%s.dll' % lib, 'sslpsk3/')

    setup(
        name='sslpsk3',
        version='1.0.0',
        description='Adds TLS-PSK support to the Python ssl package',
        author='Sidney Kuyateh',
        author_email='sidneyjohn23@kuyateh.eu',
        license="Apache 2.0",
        url='https://github.com/autinerd/sslpsk3',
        keywords=['ssl', 'tls', 'psk', 'tls-psk', 'preshared key'],
        classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: Apache Software License',
            'Programming Language :: Python',
            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
            'Programming Language :: Python :: 3.10',
            'Programming Language :: Python :: Implementation :: CPython',
            'Operating System :: POSIX',
            'Operating System :: Unix',
            'Operating System :: MacOS',
            'Operating System :: Microsoft'
        ],
        packages=['sslpsk3', 'sslpsk3.test'],
        ext_modules=[_sslpsk3],
        package_data={'': ['%s.dll' % lib for lib in DLL_NAMES]},
        test_suite='sslpsk3.test',
        zip_safe=False
    )
except OSError:
    if sys.platform == 'win32' and platform.architecture()[0] == '64bit':
        print('''
Build not possible! Please insert the files
    bin/libcrypto-1_1-x64.dll
    bin/libssl-1_1-x64.dll
    include/openssl/*.h
    lib/VC/*.lib
from the OpenSSL-Win64 installation directory into the openssl/ directory''')
    elif sys.platform == 'win32' and platform.architecture()[0] == '32bit':
        print('''
Build not possible! Please insert the files
    bin/libcrypto-1_1-x86.dll
    bin/libssl-1_1-x86.dll
    include/openssl/*.h
    lib/VC/*.lib
from the OpenSSL-Win32 installation directory into the openssl/ directory''')
finally:
    if sys.platform == 'win32':
        for lib in DLL_NAMES:
            os.remove('sslpsk3/%s.dll' % lib)
