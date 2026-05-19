"""Starfield address library database loader.

Auto-selects the matching ``addresslibrary/starfield/versionlib-X-Y-Z-W.bin``
for the caller's PE version.  Drop in a new bin for a future SF patch and
the loader picks it up without code changes.  Format is meh321's V5 (flat
``uint32[id]`` array indexed by ID); V1/V2 binaries are also accepted.
"""

from __future__ import annotations

import os
import re
import struct
from typing import Dict, List, Optional, Tuple


_VERSIONLIB_RE = re.compile(r'^versionlib-(\d+-\d+-\d+-\d+)\.bin$')


def _ver_to_filename(ver: Tuple[int, ...]) -> str:
    parts = list(ver)
    while len(parts) < 4:
        parts.append(0)
    return '-'.join(str(x) for x in parts[:4])


def _ver_to_label(ver: Tuple[int, ...]) -> str:
    parts = list(ver)
    while len(parts) < 4:
        parts.append(0)
    return '.'.join(str(x) for x in parts[:4])


class AddressLibrary:
    """Loads the Starfield address-library database mapping IDs to RVAs."""

    def __init__(self):
        self.sf_db: Dict[int, int] = {}
        self.sf_version: Optional[Tuple[int, int, int, int]] = None

    def load_bin(self, file_path: str) -> Dict[int, int]:
        """Read a Starfield versionlib .bin file.

        Starfield uses meh321's database format V5, which is much simpler
        than the V1/V2 delta-encoded format that SSE/F4 use::

          fmt          u32          (== 5)
          version[4]   4 x u32
          name         char[64]     zero-padded
          ptr_size     u64
          addr_count   u32
          entries      u32[addr_count]   indexed by id, value = rva

        Zero-valued entries are treated as "no mapping" and skipped.  V1/V2
        binaries are also accepted for forward compatibility.
        """
        if not os.path.exists(file_path):
            return {}
        with open(file_path, 'rb') as f:
            data = f.read()
        return self._parse_bytes(data)

    @staticmethod
    def _parse_bytes(data: bytes) -> Dict[int, int]:
        db: Dict[int, int] = {}
        fmt = struct.unpack_from('<I', data, 0)[0]
        if fmt == 5:
            # Header: 4 (fmt) + 16 (version) + 64 (name) + 8 (ptr_size) + 4 (addr_count) = 96 bytes
            addr_count = struct.unpack_from('<I', data, 92)[0]
            entries_off = 96
            for i in range(addr_count):
                off = struct.unpack_from('<I', data, entries_off + i * 4)[0]
                if off:
                    db[i] = off
            return db

        # V1 / V2 fallback (delta encoding).
        import io
        f = io.BytesIO(data)
        f.read(4)                                              # fmt
        f.read(16)                                             # version
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
    def available_versions(base_path: str) -> List[Tuple[int, int, int, int]]:
        """Scan addresslibrary/starfield/ for versionlib-X-Y-Z-W.bin files.

        Returns sorted list of version tuples for every well-named bin found.
        """
        sf_dir = os.path.join(base_path, 'starfield')
        if not os.path.isdir(sf_dir):
            return []
        versions: List[Tuple[int, int, int, int]] = []
        for fname in os.listdir(sf_dir):
            m = _VERSIONLIB_RE.match(fname)
            if not m:
                continue
            parts = tuple(int(x) for x in m.group(1).split('-'))
            if len(parts) == 4:
                versions.append(parts)  # type: ignore[arg-type]
        return sorted(versions)

    def load_all(self, base_path: str,
                 pe_version: Optional[Tuple[int, ...]] = None) -> None:
        """Load the SF versionlib matching ``pe_version``.

        ``pe_version`` is the tuple returned by ``get_pe_version`` on the
        Starfield binary; the loader resolves it to
        ``versionlib-X-Y-Z-W.bin`` in ``base_path/starfield/``.  If the
        matching bin is missing, raises ``FileNotFoundError`` listing every
        version present so the caller can surface a clear error.

        Passing ``pe_version=None`` is treated as "auto-pick the newest
        bin present" -- a soft fallback for callers that don't have an
        exe to probe (e.g. one-off offline tooling).  Production pipeline
        callers should always pass the detected PE version through.
        """
        sf_dir = os.path.join(base_path, 'starfield')
        available = self.available_versions(base_path)

        if pe_version is None:
            if not available:
                raise FileNotFoundError(
                    'No Starfield versionlib bins found in {}.  Expected at '
                    'least one versionlib-X-Y-Z-W.bin file.'.format(sf_dir))
            chosen = available[-1]
        else:
            target = tuple(pe_version)
            while len(target) < 4:
                target = target + (0,)
            target = target[:4]
            if target not in available:
                avail_str = ', '.join(_ver_to_label(v) for v in available) or '(none)'
                raise FileNotFoundError(
                    'No address library for Starfield {} in {}.  '
                    'Available versions: {}.  Drop the matching '
                    'versionlib-{}.bin into addresslibrary/starfield/.'.format(
                        _ver_to_label(target), sf_dir, avail_str,
                        _ver_to_filename(target)))
            chosen = target  # type: ignore[assignment]

        path = os.path.join(sf_dir, 'versionlib-{}.bin'.format(_ver_to_filename(chosen)))
        self.sf_db = self.load_bin(path)
        if self.sf_db:
            self.sf_version = chosen  # type: ignore[assignment]
