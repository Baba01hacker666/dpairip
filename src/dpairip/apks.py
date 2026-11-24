"""APK and split-bundle handling.

``Module`` is the in-memory unit the patches work on.  It keeps dex files as
bytes and only materialises an IR when a transform actually needs one, which
keeps the common case (small logging patch) fast and leaves untouched dex files
byte-for-byte identical.
"""

from __future__ import annotations

import hashlib
import os
import struct
import zipfile
import zlib
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import axml, log
from .apk import Apk, Entry
from .dex import reader, writer
from .dex.model import DexIR
from .errors import DpairipError

MANIFEST = "AndroidManifest.xml"


def repair_dex_header(data: bytearray) -> None:
    """Recompute the SHA-1 signature and adler32 checksum of a patched dex."""

    if len(data) < 0x70:
        raise ValueError("dex is too small")
    struct.pack_into("<I", data, 32, len(data))
    data[12:32] = hashlib.sha1(bytes(data[32:])).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF)


@dataclass
class DexEntry:
    name: str
    data: bytes
    ir: Optional[DexIR] = None
    dirty: bool = False


class Module:
    """A mutable APK with lazily parsed dex files and binary manifest."""

    def __init__(self, apk: Apk) -> None:
        self.apk = apk
        self.dexes: Dict[str, DexEntry] = {}
        for name in apk.dex_names():
            self.dexes[name] = DexEntry(name, apk.get(name))
        self._manifest: Optional[axml.Document] = None
        self._manifest_dirty = False

    # -- construction -----------------------------------------------------
    @classmethod
    def load(cls, path: str) -> "Module":
        return cls(Apk.from_file(path))

    @classmethod
    def from_bundle(cls, path: str) -> "Module":
        return cls(merge_bundle(path))

    # -- dex access -------------------------------------------------------
    def dex_names(self) -> List[str]:
        order = self.apk.dex_names()
        return sorted(self.dexes, key=lambda name: order.index(name) if name in order else 10_000)

    def raw(self, name: str) -> bytes:
        return self.dexes[name].data

    def ir(self, name: str) -> DexIR:
        entry = self.dexes[name]
        if entry.ir is None:
            entry.ir = reader.parse(entry.data)
        return entry.ir

    def mark_dirty(self, name: str) -> None:
        self.dexes[name].dirty = True

    def patch_raw(self, name: str, patcher: Callable[[bytearray], int]) -> int:
        """Edit raw dex bytes in place and fix the header checksums."""

        entry = self.dexes[name]
        blob = bytearray(entry.data)
        changed = patcher(blob)
        if changed:
            repair_dex_header(blob)
            entry.data = bytes(blob)
            entry.ir = None
            self.apk.put(name, entry.data)
        return changed

    def add_dex(self, data: bytes, name: Optional[str] = None,
                ir: Optional[DexIR] = None) -> str:
        name = name or self.apk.next_dex_name()
        self.dexes[name] = DexEntry(name, data, ir, ir is not None)
        self.apk.put(name, data)
        return name

    def remove_dex(self, name: str) -> None:
        self.dexes.pop(name, None)
        self.apk.remove(name)

    # -- manifest ---------------------------------------------------------
    def manifest(self) -> Optional[axml.Document]:
        if self._manifest is None and self.apk.has(MANIFEST):
            self._manifest = axml.parse(self.apk.get(MANIFEST))
        return self._manifest

    def set_manifest(self, document: axml.Document) -> None:
        self._manifest = document
        self._manifest_dirty = True

    # -- output -----------------------------------------------------------
    def flush(self) -> None:
        for entry in self.dexes.values():
            if not entry.dirty:
                continue
            if entry.ir is None:
                entry.ir = reader.parse(entry.data)
            entry.data = writer.write(entry.ir)
            self.apk.put(entry.name, entry.data)
            entry.dirty = False
        if self._manifest_dirty and self._manifest is not None:
            self.apk.put(MANIFEST, self._manifest.to_bytes())
            self._manifest_dirty = False

    def save(self, path: str) -> str:
        self.flush()
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.apk.save(path)
        return path

    def dex_crcs(self) -> Dict[str, int]:
        return {name: zlib.crc32(entry.data) & 0xFFFFFFFF
                for name, entry in self.dexes.items()}


# ---------------------------------------------------------------------------
# split bundle merging
# ---------------------------------------------------------------------------

@dataclass
class _BundleMember:
    name: str
    apk: Apk
    document: Optional[axml.Document]
    split: str

    @property
    def is_base(self) -> bool:
        return not self.split


def _read_manifest(apk: Apk) -> Optional[axml.Document]:
    try:
        return axml.parse(apk.get(MANIFEST))
    except (KeyError, ValueError, IndexError, struct.error):
        return None


def _load_members(path: str) -> List[_BundleMember]:
    members: List[_BundleMember] = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".apk"):
                continue
            try:
                apk = Apk.from_bytes(archive.read(info))
                document = _read_manifest(apk)
                split = ""
                if document is not None:
                    from .manifest import split_name
                    split = split_name(document)
                members.append(_BundleMember(info.filename, apk, document, split))
            except Exception as exc:  # pragma: no cover - corrupt split
                log.warn(f"ignoring unreadable bundle member {info.filename}: {exc}")
    return members


def _base_member(members: Sequence[_BundleMember]) -> _BundleMember:
    bases = [member for member in members if member.is_base]
    if not bases:
        raise DpairipError("no base APK found in bundle")

    def score(member: _BundleMember) -> Tuple[int, int]:
        name = member.name.lower()
        value = 0
        if "standalone" in name or "universal" in name:
            value += 10
        if "base-master" in name or name.rsplit("/", 1)[-1] == "base.apk":
            value += 5
        return (value, len(member.apk.entries))

    return max(bases, key=score)


def merge_bundle(path: str) -> Apk:
    """Zip-level merge of an ``.apks``/``.xapk`` bundle into one APK.

    Split dex files, assets and native libraries are copied into the base.
    Split resource tables and manifests are intentionally *not* merged: the
    base resource table stays authoritative and Android falls back to default
    resources when a split-specific density or locale is unavailable.
    """

    members = _load_members(path)
    if not members:
        raise DpairipError(f"no APK members found in {path}")
    base = _base_member(members)
    log.merge(f"bundle contains {len(members)} APK(s); base is {base.name}")

    result = Apk()
    for entry in base.apk.entries:
        result.entries.append(Entry(entry.name, entry.data, entry.compress,
                                    entry.align, entry.mtime, entry.mode))

    added_dex = 0
    added_assets = 0
    added_libs = 0
    for member in members:
        if member is base:
            continue
        if "standalone" in member.name.lower() or "universal" in member.name.lower():
            continue
        for entry in member.apk.entries:
            name = entry.name
            if name == MANIFEST or name == "resources.arsc" or name.startswith("res/"):
                continue
            if name.startswith("META-INF/"):
                continue
            if name.startswith("classes") and name.endswith(".dex") and "/" not in name:
                result.put(result.next_dex_name(), entry.data, entry.compress)
                added_dex += 1
            elif name.startswith("assets/"):
                if not result.has(name):
                    result.put(name, entry.data, entry.compress)
                    added_assets += 1
            elif name.startswith("lib/"):
                if not result.has(name):
                    result.put(name, entry.data, False)
                    added_libs += 1

    document = _read_manifest(result)
    if document is None:
        raise DpairipError("merged APK has no readable AndroidManifest.xml")
    from .manifest import patch as patch_manifest
    patch_manifest(document)
    result.put(MANIFEST, document.to_bytes())

    log.merge(f"merged {added_dex} dex, {added_assets} assets, {added_libs} libraries")
    return result
