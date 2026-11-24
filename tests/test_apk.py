from __future__ import annotations

import struct
import zipfile

from dpairip.apk import Apk, patch_dex_crc


def test_apk_round_trip_and_alignment(tmp_path):
    apk = Apk()
    apk.put("AndroidManifest.xml", b"manifest")
    apk.put("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
    apk.put("lib/arm64-v8a/test.so", b"\x7fELF" + b"\x00" * 100)
    path = tmp_path / "test.apk"
    apk.save(str(path))

    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        assert archive.namelist() == apk.names()
        for entry in apk.entries:
            assert archive.read(entry.name) == entry.data
        info = archive.getinfo("lib/arm64-v8a/test.so")
        raw = path.read_bytes()
        data_offset = (info.header_offset + 30 + len(info.filename.encode())
                       + struct.unpack_from("<H", raw, info.header_offset + 28)[0])
        assert data_offset % 4096 == 0


def test_next_dex_name():
    apk = Apk()
    assert apk.next_dex_name() == "classes.dex"
    apk.put("classes.dex", b"a")
    assert apk.next_dex_name() == "classes2.dex"
    apk.put("classes3.dex", b"b")
    assert apk.next_dex_name() == "classes2.dex"
    assert apk.dex_names() == ["classes.dex", "classes3.dex"]


def test_patch_dex_crc(tmp_path):
    apk = Apk()
    apk.put("classes.dex", b"original")
    path = tmp_path / "target.apk"
    apk.save(str(path))

    with zipfile.ZipFile(path) as archive:
        source_crc = {i.filename: i.CRC for i in archive.infolist()}
    apk.put("classes.dex", b"modified")
    apk.save(str(path))
    patched = patch_dex_crc(str(path), source_crc)
    assert patched == ["classes.dex"]
    with zipfile.ZipFile(path) as archive:
        assert archive.getinfo("classes.dex").CRC == source_crc["classes.dex"]
