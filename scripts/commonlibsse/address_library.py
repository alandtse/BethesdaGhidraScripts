"""Skyrim SE / AE / VR address library database loader.

SE (1.5.97) and AE (1.6.1170) ship as compressed .bin files in the meh321
V1/V2 format.  VR (1.4.15) ships as a flat CSV with a metadata row.  All
three share the SE-derived ID namespace, so a single ID can be looked up
across all three DBs.
"""

from __future__ import annotations

import glob
import os
import struct
import sys
from typing import Dict, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
from pe_version import get_pe_version  # noqa: E402


def _read_dotnet_string(f) -> str:
    """Read a .NET BinaryWriter-style length-prefixed string."""
    length = 0
    shift = 0
    while True:
        b = struct.unpack('<B', f.read(1))[0]
        length |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            break
    return f.read(length).decode('utf-8')


def load_relib_version(relib_path: str, target_version: Tuple[int, ...]) -> Dict[int, int]:
    """Load ID-to-RVA mappings for a specific version from a .relib file.

    Returns an empty dict if the version is not found in the database.
    """
    if not os.path.exists(relib_path):
        return {}

    target_tuple = tuple(target_version)

    with open(relib_path, 'rb') as f:
        fmt_version = struct.unpack('<i', f.read(4))[0]
        _high_vid = struct.unpack('<Q', f.read(8))[0]
        _ptr_size = struct.unpack('<i', f.read(4))[0]

        has_module = struct.unpack('<B', f.read(1))[0]
        if has_module:
            _read_dotnet_string(f)

        num_versions = struct.unpack('<i', f.read(4))[0]

        for _ in range(num_versions):
            n_components = struct.unpack('<i', f.read(4))[0]
            ver = tuple(struct.unpack('<I', f.read(4))[0] for _ in range(n_components))

            has_overwrite = struct.unpack('<B', f.read(1))[0]
            if has_overwrite:
                _read_dotnet_string(f)

            _base_addr = struct.unpack('<q', f.read(8))[0]
            value_count = struct.unpack('<i', f.read(4))[0]

            if ver == target_tuple:
                db = {}
                for _ in range(value_count):
                    k = struct.unpack('<Q', f.read(8))[0]
                    v = struct.unpack('<I', f.read(4))[0]
                    db[k] = v
                return db

            # Skip values for non-matching versions
            f.seek(value_count * 12, 1)

            if fmt_version >= 2:
                hash_count = struct.unpack('<i', f.read(4))[0]
                f.seek(hash_count * 16, 1)

    return {}


def list_relib_versions(relib_path: str) -> list:
    """List all versions available in a .relib file."""
    if not os.path.exists(relib_path):
        return []

    versions = []
    with open(relib_path, 'rb') as f:
        fmt_version = struct.unpack('<i', f.read(4))[0]
        _high_vid = struct.unpack('<Q', f.read(8))[0]
        _ptr_size = struct.unpack('<i', f.read(4))[0]

        has_module = struct.unpack('<B', f.read(1))[0]
        if has_module:
            _read_dotnet_string(f)

        num_versions = struct.unpack('<i', f.read(4))[0]

        for _ in range(num_versions):
            n_components = struct.unpack('<i', f.read(4))[0]
            ver = tuple(struct.unpack('<I', f.read(4))[0] for _ in range(n_components))
            versions.append(ver)

            has_overwrite = struct.unpack('<B', f.read(1))[0]
            if has_overwrite:
                _read_dotnet_string(f)

            _base_addr = struct.unpack('<q', f.read(8))[0]
            value_count = struct.unpack('<i', f.read(4))[0]
            f.seek(value_count * 12, 1)

            if fmt_version >= 2:
                hash_count = struct.unpack('<i', f.read(4))[0]
                f.seek(hash_count * 16, 1)

    return versions


class AddressLibrary:
    """Loads address-library databases mapping relocation IDs to RVAs."""

    def __init__(self):
        self.se_db: Dict[int, int] = {}
        self.ae_db: Dict[int, int] = {}
        self.vr_db: Dict[int, int] = {}
        self.ae1799_db: Dict[int, int] = {}

    def load_bin(self, file_path: str) -> Dict[int, int]:
        if not os.path.exists(file_path):
            return {}
        db = {}
        with open(file_path, 'rb') as f:
            f.read(4)   # fmt
            f.read(16)  # version
            name_len = struct.unpack('<I', f.read(4))[0]
            f.read(name_len)
            ptr_size   = struct.unpack('<I', f.read(4))[0]
            addr_count = struct.unpack('<I', f.read(4))[0]
            pvid = 0; poffset = 0
            for _ in range(addr_count):
                type_byte = struct.unpack('<B', f.read(1))[0]
                low = type_byte & 0xF; high = type_byte >> 4
                if   low == 0: id_val = struct.unpack('<Q', f.read(8))[0]
                elif low == 1: id_val = pvid + 1
                elif low == 2: id_val = pvid + struct.unpack('<B', f.read(1))[0]
                elif low == 3: id_val = pvid - struct.unpack('<B', f.read(1))[0]
                elif low == 4: id_val = pvid + struct.unpack('<H', f.read(2))[0]
                elif low == 5: id_val = pvid - struct.unpack('<H', f.read(2))[0]
                elif low == 6: id_val = struct.unpack('<H', f.read(2))[0]
                elif low == 7: id_val = struct.unpack('<I', f.read(4))[0]
                tpoffset = (poffset // ptr_size) if (high & 8) != 0 else poffset
                h_type = high & 7
                if   h_type == 0: off_val = struct.unpack('<Q', f.read(8))[0]
                elif h_type == 1: off_val = tpoffset + 1
                elif h_type == 2: off_val = tpoffset + struct.unpack('<B', f.read(1))[0]
                elif h_type == 3: off_val = tpoffset - struct.unpack('<B', f.read(1))[0]
                elif h_type == 4: off_val = tpoffset + struct.unpack('<H', f.read(2))[0]
                elif h_type == 5: off_val = tpoffset - struct.unpack('<H', f.read(2))[0]
                elif h_type == 6: off_val = struct.unpack('<H', f.read(2))[0]
                elif h_type == 7: off_val = struct.unpack('<I', f.read(4))[0]
                if (high & 8) != 0: off_val *= ptr_size
                db[id_val] = off_val; pvid = id_val; poffset = off_val
        return db

    @staticmethod
    def load_bin_v5(file_path: str) -> Dict[int, int]:
        """Load AE 1.7.99+'s format-5 address library: a fixed 96-byte header
        (format int32, version uint32[4], name char[64], pointerSize int32,
        dataFormat int32, offsetCount int32) followed by a dense
        uint32_t[offsetCount] array, direct-indexed by id (0 = absent).
        """
        if not os.path.exists(file_path):
            return {}
        with open(file_path, 'rb') as f:
            data = f.read()
        fmt = struct.unpack_from('<i', data, 0)[0]
        if fmt != 5:
            return {}
        offset_count = struct.unpack_from('<i', data, 92)[0]
        arr = struct.unpack_from('<{}I'.format(offset_count), data, 96)
        return {i: off for i, off in enumerate(arr) if off != 0}

    @staticmethod
    def load_csv(file_path: str, skip_meta: bool = True) -> Dict[int, int]:
        """Read an 'id,offset' CSV file (header + optional metadata row).

        The community VR address libraries (Old, etc.) ship as CSV rather
        than the meh321 binary format.  Format:

          id,offset                          # header line
          <metadata>,<game-version-string>   # one metadata row (skipped)
          <id>,<hex-offset>                  # entries

        ``offset`` is parsed as hex without a ``0x`` prefix.
        """
        if not os.path.exists(file_path):
            return {}
        db: Dict[int, int] = {}
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        start = 2 if skip_meta and len(lines) > 1 else 1
        for line in lines[start:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(',')
            if len(parts) != 2:
                continue
            try:
                db[int(parts[0])] = int(parts[1], 16)
            except ValueError:
                continue
        return db

    def load_all(self, base_path: str) -> None:
        sse_dir = os.path.join(base_path, 'sse')
        self.se_db = self.load_bin(os.path.join(sse_dir, 'version-1-5-97-0.bin'))
        self.ae_db = self.load_bin(os.path.join(sse_dir, 'versionlib-1-6-1170-0.bin'))
        self.vr_db = self.load_csv(os.path.join(sse_dir, 'version-1-4-15-0.csv'))
        self.ae1799_db = self.load_bin_v5(os.path.join(sse_dir, 'versionlib-1-7-99-0.bin'))
