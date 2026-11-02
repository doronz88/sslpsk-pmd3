"""Locate the OpenSSL functions belonging to the interpreter's own ``_ssl`` module.

The ``SSL*`` objects that ``_sslpsk`` manipulates are created by ``_ssl``, so the
functions operating on them must come from that exact OpenSSL build: any other copy
(a bundled one, the system one, LibreSSL/BoringSSL) may lay out ``SSL`` differently
and crash or corrupt memory.

Lookup order:

1. ``dlsym``/``GetProcAddress`` scoped to the image containing ``_ssl`` (and its
   dependencies). Covers interpreters linking libssl dynamically.
2. The static symbol table of that image. Covers interpreters that link OpenSSL
   statically with hidden visibility (e.g. python-build-standalone, used by uv),
   where the symbols exist but are not exported.

Every result is checked to really live in ``_ssl``'s image or a libssl/libcrypto it
loaded, so a same-named function from an unrelated library is never used.
"""

import _ssl
import ctypes
import glob
import os
import struct
import sys

FUNCTIONS = (
    "SSL_set_psk_client_callback",
    "SSL_set_psk_server_callback",
    "SSL_use_psk_identity_hint",
    "SSL_set_accept_state",
    "SSL_set_session_id_context",
)

_POINTER_SIZE = ctypes.sizeof(ctypes.c_void_p)


def _read_pointer(address):
    return ctypes.c_void_p.from_address(address).value


def _ssl_c_function_address():
    """Returns the address of a C function implemented by ``_ssl``."""
    func = _ssl.RAND_status
    # PyCFunctionObject: PyObject_HEAD, then PyMethodDef *m_ml
    method_def = _read_pointer(id(func) + object.__basicsize__)
    # PyMethodDef: const char *ml_name, PyCFunction ml_meth, ...
    name = ctypes.string_at(_read_pointer(method_def))
    if name != func.__name__.encode():
        raise RuntimeError("sslpsk_pmd3: unexpected builtin function layout")
    return _read_pointer(method_def + _POINTER_SIZE)


def _is_openssl_library(path):
    name = os.path.basename(path).lower()
    return name.startswith("libssl") or name.startswith("libcrypto")


def bind_addresses():
    """Returns the addresses of ``FUNCTIONS`` within the OpenSSL used by ``_ssl``."""
    if sys.platform == "win32":
        return _windows_addresses()
    return _posix_addresses()


def _windows_addresses():
    # _ssl.pyd links libssl dynamically; CPython ships it next to _ssl.pyd and it is
    # already loaded, so loading it by full path returns that same module.
    ssl_module_dir = os.path.dirname(_ssl.__file__)
    for path in sorted(glob.glob(os.path.join(ssl_module_dir, "libssl*.dll"))):
        library = ctypes.CDLL(path)
        try:
            return [ctypes.cast(getattr(library, name), ctypes.c_void_p).value for name in FUNCTIONS]
        except AttributeError:
            continue
    raise RuntimeError("sslpsk_pmd3: libssl not found next to {}".format(_ssl.__file__))


class _DlInfo(ctypes.Structure):
    _fields_ = [
        ("dli_fname", ctypes.c_char_p),
        ("dli_fbase", ctypes.c_void_p),
        ("dli_sname", ctypes.c_char_p),
        ("dli_saddr", ctypes.c_void_p),
    ]


def _dladdr_function():
    for library in (None, "libdl.so.2", "libc.so"):
        try:
            dladdr = ctypes.CDLL(library).dladdr
        except (OSError, AttributeError):
            continue
        dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(_DlInfo)]
        dladdr.restype = ctypes.c_int
        return dladdr
    raise RuntimeError("sslpsk_pmd3: dladdr() is unavailable")


def _posix_addresses():
    dladdr = _dladdr_function()

    def image_of(address):
        info = _DlInfo()
        if not dladdr(address, ctypes.byref(info)) or not info.dli_fbase:
            return None
        return info

    ssl_image = image_of(_ssl_c_function_address())
    if ssl_image is None:
        raise RuntimeError("sslpsk_pmd3: cannot locate the image containing _ssl")
    image_path = os.fsdecode(ssl_image.dli_fname or b"")
    if not os.path.isabs(image_path):
        # glibc reports the main executable by an empty name or its argv[0]
        image_path = os.path.realpath(sys.executable)

    def is_trusted(address):
        info = image_of(address)
        if info is None:
            return False
        if info.dli_fbase == ssl_image.dli_fbase:
            return True
        return _is_openssl_library(os.fsdecode(info.dli_fname or b""))

    # 1. Exported symbols reachable from _ssl's image
    try:
        library = ctypes.CDLL(image_path)
        addresses = [ctypes.cast(getattr(library, name), ctypes.c_void_p).value for name in FUNCTIONS]
    except (OSError, AttributeError):
        addresses = None
    if addresses is not None and all(is_trusted(address) for address in addresses):
        return addresses

    # 2. Hidden symbols in _ssl's image, from its static symbol table. The load-address
    # computation is validated against a symbol of that image the dynamic linker resolved.
    reference, reference_address = _exported_reference(ssl_image, image_path, image_of)
    if sys.platform == "darwin":
        symbols = _macho_symbols(ssl_image.dli_fbase, FUNCTIONS + (reference,))
    else:
        symbols = _elf_symbols(image_path, ssl_image.dli_fbase, FUNCTIONS + (reference,))
    if symbols.get(reference) != reference_address:
        raise RuntimeError("sslpsk_pmd3: symbol table of {} does not match its loaded image".format(image_path))

    missing = [name for name in FUNCTIONS if name not in symbols]
    if missing:
        raise RuntimeError(
            "sslpsk_pmd3: cannot locate {} used by _ssl ({}) in {}".format(
                ", ".join(missing), _ssl.OPENSSL_VERSION, image_path
            )
        )
    return [symbols[name] for name in FUNCTIONS]


def _exported_reference(ssl_image, image_path, image_of):
    """Returns ``(name, address)`` of an exported function in _ssl's image.

    glibc's dladdr() only names a symbol that contains the address (none for hidden code),
    so fall back to symbols the image always exports: PyInit__ssl when _ssl is a shared
    module, the C API when _ssl is built into the interpreter.
    """
    if ssl_image.dli_sname and ssl_image.dli_saddr:
        return ssl_image.dli_sname.decode(), ssl_image.dli_saddr
    libraries = [ctypes.CDLL(None)]
    try:
        libraries.append(ctypes.CDLL(image_path))
    except OSError:
        pass  # e.g. glibc cannot dlopen() a PIE executable; it is in the global scope anyway
    for name in ("PyInit__ssl", "Py_IsInitialized", "PyObject_GetAttr"):
        for library in libraries:
            try:
                address = ctypes.cast(getattr(library, name), ctypes.c_void_p).value
            except AttributeError:
                continue
            info = image_of(address)
            if info is not None and info.dli_fbase == ssl_image.dli_fbase:
                return name, address
    raise RuntimeError("sslpsk_pmd3: no exported symbol to validate {} against".format(image_path))


def _elf_symbols(path, load_base, names):
    """Resolves ``names`` from the ``.symtab``/``.dynsym`` sections of a loaded ELF image."""
    wanted = {name.encode() for name in names}
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        raise RuntimeError("sslpsk_pmd3: {} is not an ELF file".format(path))
    is_64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"

    if is_64:
        e_phoff, e_shoff = struct.unpack_from(endian + "QQ", data, 0x20)
        e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from(endian + "HHHH", data, 0x36)
        phdr_fmt, shdr_fmt, sym_fmt = endian + "IIQQQQQQ", endian + "IIQQQQIIQQ", endian + "IBBHQQ"
    else:
        e_phoff, e_shoff = struct.unpack_from(endian + "II", data, 0x1C)
        e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from(endian + "HHHH", data, 0x2A)
        phdr_fmt, shdr_fmt, sym_fmt = endian + "IIIIIIII", endian + "IIIIIIIIII", endian + "IIIBBH"

    # dli_fbase is the start of the first PT_LOAD mapping; symbol values are relative to
    # the link-time address of that mapping.
    page_mask = ~(os.sysconf("SC_PAGE_SIZE") - 1)
    first_load_vaddr = None
    for i in range(e_phnum):
        fields = struct.unpack_from(phdr_fmt, data, e_phoff + i * e_phentsize)
        p_type = fields[0]
        p_vaddr = fields[3] if is_64 else fields[2]
        if p_type == 1:  # PT_LOAD
            first_load_vaddr = p_vaddr
            break
    if first_load_vaddr is None:
        raise RuntimeError("sslpsk_pmd3: {} has no PT_LOAD segment".format(path))
    load_bias = load_base - (first_load_vaddr & page_mask)

    sections = [struct.unpack_from(shdr_fmt, data, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    found = {}
    for section in sections:
        sh_type = section[1]
        if sh_type not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
            continue
        sh_offset, sh_size, sh_link = section[4], section[5], section[6]
        strtab_offset = sections[sh_link][4]
        for entry in struct.iter_unpack(sym_fmt, data[sh_offset:sh_offset + sh_size]):
            if is_64:
                st_name, st_info, _st_other, st_shndx, st_value, _st_size = entry
            else:
                st_name, st_value, _st_size, st_info, _st_other, st_shndx = entry
            if st_shndx == 0 or st_value == 0 or (st_info & 0xF) != 2:  # defined STT_FUNC only
                continue
            end = data.index(b"\0", strtab_offset + st_name)
            name = data[strtab_offset + st_name:end]
            if name in wanted:
                found.setdefault(name.decode(), load_bias + st_value)
    return found


def _macho_symbols(header_address, names):
    """Resolves ``names`` from the ``LC_SYMTAB`` of a loaded Mach-O image (read from memory)."""
    wanted = {b"_" + name.encode() for name in names}
    magic = ctypes.c_uint32.from_address(header_address).value
    if magic != 0xFEEDFACF:
        raise RuntimeError("sslpsk_pmd3: unsupported Mach-O image")
    _cputype, _cpusubtype, _filetype, ncmds, _sizeofcmds, _flags, _reserved = struct.unpack(
        "<iiIIIII", ctypes.string_at(header_address + 4, 28)
    )

    slide = None
    linkedit = None
    symtab = None
    offset = header_address + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", ctypes.string_at(offset, 8))
        if cmd == 0x19:  # LC_SEGMENT_64
            segname, vmaddr, _vmsize, fileoff = struct.unpack("<16sQQQ", ctypes.string_at(offset + 8, 40))
            segname = segname.rstrip(b"\0")
            if segname == b"__TEXT":
                slide = header_address - vmaddr
            elif segname == b"__LINKEDIT":
                linkedit = (vmaddr, fileoff)
        elif cmd == 0x2:  # LC_SYMTAB
            symtab = struct.unpack("<IIII", ctypes.string_at(offset + 8, 16))
        offset += cmdsize
    if slide is None or linkedit is None or symtab is None:
        raise RuntimeError("sslpsk_pmd3: Mach-O image has no symbol table")

    symoff, nsyms, stroff, strsize = symtab
    linkedit_base = linkedit[0] + slide - linkedit[1]
    symbol_table = ctypes.string_at(linkedit_base + symoff, nsyms * 16)
    strings = ctypes.string_at(linkedit_base + stroff, strsize)

    found = {}
    for n_strx, n_type, _n_sect, _n_desc, n_value in struct.iter_unpack("<IBBhQ", symbol_table):
        if n_type & 0xE0 or (n_type & 0x0E) != 0x0E:  # skip N_STAB, keep N_SECT
            continue
        name = strings[n_strx:strings.index(b"\0", n_strx)]
        if name in wanted:
            found.setdefault(name[1:].decode(), n_value + slide)
    return found
