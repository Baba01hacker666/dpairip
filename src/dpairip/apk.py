"""Small, dependency free APK/ZIP reader and writer.

``zipfile`` can read archives but it neither lets us control the alignment of
stored entries nor patch checksums in place, both of which matter when an app
verifies its own archive.  This module implements just enough of the format.
"""

from __future__ import annotations

import io
import os
import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

LOCAL_HEADER = 0x04034B50
CENTRAL_HEADER = 0x02014B50
END_RECORD = 0x06054B50

# entries that must stay uncompressed / aligned for Android to mmap them
STORED_SUFFIXES = (".so", ".arsc", ".oat", ".odex", ".vdex")
ALIGN_4096_SUFFIXES = (".so",)


class ZipError(ValueError):
    pass


@dataclass
class Entry:
    name: str
    data: bytes
    compress: bool = True
    align: int = 1
    mtime: int = 0
    mode: int = 0o644

    @property
    def method(self) -> int:
        return 8 if self.compress else 0


@dataclass
class Apk:
    entries: List[Entry] = field(default_factory=list)

    # -- reading ---------------------------------------------------------
    @classmethod
    def from_bytes(cls, data: bytes) -> "Apk":
        return cls(cls._parse(data))

    @classmethod
    def from_file(cls, path: str) -> "Apk":
        with open(path, "rb") as handle:
            return cls.from_bytes(handle.read())

    @staticmethod
    def _parse(data: bytes) -> List[Entry]:
        end = _find_end_record(data)
        _disk, _cd_disk, _count_disk, count, cd_size, cd_off, _comment = struct.unpack_from(
            "<HHHHIIH", data, end + 4
        )
        entries: List[Entry] = []
        offset = cd_off
        for _ in range(count):
            if struct.unpack_from("<I", data, offset)[0] != CENTRAL_HEADER:
                raise ZipError("invalid central directory")
            (
                _ver_made, _ver, _flags, method, mtime, _mdate, crc, csize, usize,
                name_len, extra_len, comment_len, _disk_start, _internal,
                _external, local_off,
            ) = struct.unpack_from("<HHHHHHIIIHHHHHII", data, offset + 4)
            name = data[offset + 46:offset + 46 + name_len].decode("utf-8", "replace")
            local = local_off
            if struct.unpack_from("<I", data, local)[0] != LOCAL_HEADER:
                raise ZipError(f"invalid local header for {name}")
            local_name_len, local_extra_len = struct.unpack_from("<HH", data, local + 26)
            start = local + 30 + local_name_len + local_extra_len
            raw = data[start:start + csize]
            if method == 8:
                payload = zlib.decompress(raw, -15)
            elif method == 0:
                payload = raw
            else:
                raise ZipError(f"unsupported compression {method} for {name}")
            entries.append(
                Entry(
                    name=name,
                    data=payload,
                    compress=method == 8,
                    align=_alignment_for(name),
                    mtime=mtime,
                )
            )
            offset += 46 + name_len + extra_len + comment_len
        return entries

    # -- editing ---------------------------------------------------------
    def names(self) -> List[str]:
        return [entry.name for entry in self.entries]

    def has(self, name: str) -> bool:
        return any(entry.name == name for entry in self.entries)

    def get(self, name: str) -> bytes:
        for entry in self.entries:
            if entry.name == name:
                return entry.data
        raise KeyError(name)

    def find(self, name: str) -> Optional[Entry]:
        for entry in self.entries:
            if entry.name == name:
                return entry
        return None

    def put(self, name: str, data: bytes, compress: Optional[bool] = None) -> None:
        if compress is None:
            compress = not name.endswith(STORED_SUFFIXES)
        existing = self.find(name)
        if existing is not None:
            existing.data = data
            existing.compress = compress
            existing.align = _alignment_for(name)
            return
        self.entries.append(
            Entry(name, data, compress, _alignment_for(name))
        )

    def remove(self, name: str) -> bool:
        before = len(self.entries)
        self.entries = [entry for entry in self.entries if entry.name != name]
        return len(self.entries) != before

    def remove_matching(self, predicate) -> List[str]:
        removed = [entry.name for entry in self.entries if predicate(entry.name)]
        self.entries = [entry for entry in self.entries if not predicate(entry.name)]
        return removed

    def dex_names(self) -> List[str]:
        names = [
            entry.name
            for entry in self.entries
            if entry.name.startswith("classes") and entry.name.endswith(".dex")
            and "/" not in entry.name
        ]
        return sorted(names, key=_dex_order)

    def next_dex_name(self) -> str:
        existing = set(self.dex_names())
        if "classes.dex" not in existing:
            return "classes.dex"
        index = 2
        while f"classes{index}.dex" in existing:
            index += 1
        return f"classes{index}.dex"

    # -- writing ---------------------------------------------------------
    def to_bytes(self) -> bytes:
        return _write_zip(self.entries)

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(self.to_bytes())


def _alignment_for(name: str) -> int:
    if name.endswith(ALIGN_4096_SUFFIXES):
        return 4096
    if name.endswith(".arsc") or name == "AndroidManifest.xml":
        return 4
    return 1


def _dex_order(name: str) -> Tuple[int, str]:
    stem = name[:-4]
    if stem == "classes":
        return (1, name)
    try:
        return (int(stem[7:]), name)
    except ValueError:
        return (10_000, name)


def _find_end_record(data: bytes) -> int:
    start = max(0, len(data) - 0xFFFF - 22)
    for offset in range(len(data) - 22, start - 1, -1):
        if struct.unpack_from("<I", data, offset)[0] == END_RECORD:
            return offset
    raise ZipError("end of central directory not found")


def _write_zip(entries: Sequence[Entry]) -> bytes:
    out = bytearray()
    directory: List[dict] = []

    for entry in entries:
        raw = entry.data
        if entry.method == 8:
            compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
            payload = compressor.compress(raw) + compressor.flush()
        else:
            payload = raw
        crc = zlib.crc32(raw) & 0xFFFFFFFF
        name_bytes = entry.name.encode("utf-8")
        extra = b""
        if entry.method == 0 and entry.align > 1:
            pad = (-(len(out) + 30 + len(name_bytes))) % entry.align
            if pad:
                if pad < 4:
                    pad += entry.align
                extra = struct.pack("<HH", 0xD935, pad - 4) + b"\x00" * (pad - 4)
        offset = len(out)
        out += struct.pack(
            "<IHHHHHIIIHH",
            LOCAL_HEADER,
            20,
            0,
            entry.method,
            entry.mtime & 0xFFFF,
            (entry.mtime >> 16) & 0xFFFF,
            crc,
            len(payload),
            len(raw),
            len(name_bytes),
            len(extra),
        )
        out += name_bytes + extra + payload
        directory.append(
            dict(
                name=name_bytes,
                crc=crc,
                csize=len(payload),
                usize=len(raw),
                offset=offset,
                method=entry.method,
                mtime=entry.mtime,
                extra=extra,
            )
        )

    cd_offset = len(out)
    for item in directory:
        out += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            CENTRAL_HEADER,
            20,
            20,
            0,
            item["method"],
            item["mtime"] & 0xFFFF,
            (item["mtime"] >> 16) & 0xFFFF,
            item["crc"],
            item["csize"],
            item["usize"],
            len(item["name"]),
            len(item["extra"]),
            0,
            0,
            0,
            0,
            item["offset"],
        )
        out += item["name"] + item["extra"]
    cd_size = len(out) - cd_offset
    out += struct.pack(
        "<IHHHHIIH", END_RECORD, 0, 0, len(directory), len(directory), cd_size, cd_offset, 0
    )
    return bytes(out)


def patch_dex_crc(target_path: str, source_crc: Dict[str, int]) -> List[str]:
    """Copy the CRC32 values of ``classes*.dex`` from the original archive.

    Android's package manager does not verify them, but apps that hash their own
    base APK do, which is exactly what we need to satisfy when replacing a
    patched ``base.apk`` on a rooted device.
    """
    with open(target_path, "r+b") as handle:
        data = bytearray(handle.read())
        end = _find_end_record(bytes(data))
        _d, _c, _cd, count, _size, cd_off, _comment = struct.unpack_from(
            "<HHHHIIH", data, end + 4
        )
        patched: List[str] = []
        offset = cd_off
        for _ in range(count):
            fields = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, offset)
            name_len, extra_len, comment_len = fields[10], fields[11], fields[12]
            local_off = fields[16]
            name = bytes(data[offset + 46:offset + 46 + name_len]).decode("utf-8", "replace")
            wanted = source_crc.get(name)
            if wanted is not None and name.startswith("classes") and name.endswith(".dex"):
                struct.pack_into("<I", data, offset + 16, wanted)
                local_name_len, local_extra_len = struct.unpack_from("<HH", data, local_off + 26)
                struct.pack_into("<I", data, local_off + 14, wanted)
                patched.append(name)
            offset += 46 + name_len + extra_len + comment_len
        handle.seek(0)
        handle.write(bytes(data))
        handle.truncate()
    return patched
