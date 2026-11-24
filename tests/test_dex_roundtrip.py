from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from dpairip.dex import insns, reader, writer
from dpairip.dex.model import ClassDef, DexIR, EncodedValue, FieldDef, MethodRef, Proto
from dpairip.gen.asm import MethodBuilder, make_class, make_method

REAL_APKS = [
    Path("/home/baba01hacker/apks/stickyhover/stickyhover.apk"),
    Path("/home/baba01hacker/apks/tracket/tracket.apk"),
]


def _small_dex() -> bytes:
    body = MethodBuilder(2, 1)
    body.const4(0, 7).invoke_static(
        MethodRef("Lhelper;", "go", Proto.parse("(I)V")), 0, 1).return_void()
    classes = [
        make_class("Lsample/Main;", "Ljava/lang/Object;", 1,
                   static_fields=[FieldDef("value", "Ljava/lang/String;", 0x9)],
                   direct_methods=[make_method("run", Proto.parse("(I)V"), 0x9, body)]),
        make_class("Lhelper;", "Ljava/lang/Object;", 1),
    ]
    return writer.write(DexIR(classes))


def assert_header_valid(data: bytes) -> None:
    assert struct.unpack_from("<I", data, 32)[0] == len(data)
    assert hashlib.sha1(data[32:]).digest() == data[12:32]
    assert zlib.adler32(data[12:]) & 0xFFFFFFFF == struct.unpack_from("<I", data, 8)[0]


def test_small_dex_round_trip():
    original = _small_dex()
    assert_header_valid(original)
    ir = reader.parse(original)
    assert {cls.type for cls in ir.classes} == {"Lsample/Main;", "Lhelper;"}
    rebuilt = writer.write(ir)
    assert_header_valid(rebuilt)
    again = reader.parse(rebuilt)
    assert len(again.classes) == 2
    method = again.find_class("Lsample/Main;").find_method("run")
    assert any(isinstance(value, MethodRef) and value.name == "go"
               for _word, _kind, value, _width in method.code.refs)


def test_compact_encoded_float():
    raw_reader = reader._Reader.__new__(reader._Reader)
    raw_reader.data = bytes([0x30, 0x20, 0x42])  # size 2, 40.0f
    value, offset = raw_reader.read_encoded_value(0, None)
    assert value.value == 40.0
    assert offset == 3
    raw_reader.data = bytes([0x70, 0x00, 0x00, 0x80, 0x3F])  # 1.0f
    value, offset = raw_reader.read_encoded_value(0, None)
    assert value.value == 1.0 and offset == 5


def test_fixed_width_float_and_double_values():
    ir = DexIR([make_class(
        "LValues;", "Ljava/lang/Object;", 1,
        static_fields=[
            FieldDef("f", "F", 0x19, EncodedValue("float", 40.0)),
            FieldDef("d", "D", 0x19, EncodedValue("double", 90.25)),
        ],
    )])
    data = writer.write(ir)
    assert_header_valid(data)
    parsed = reader.parse(data)
    fields = {f.name: f.initial.value for f in parsed.find_class("LValues;").static_fields}
    assert fields == {"f": 40.0, "d": 90.25}


def test_method_handles_and_call_sites():
    from dpairip.dex.model import CallSiteRef, MethodHandleRef
    from dpairip.gen.asm import method_ref

    handle = MethodHandleRef(4, method_ref("LBootstrap;", "make", "()Ljava/lang/Object;"))
    site = CallSiteRef(handle, "run", Proto.parse("()Ljava/lang/Runnable;"))
    body = MethodBuilder(2, 0)
    body.emit("const-method-handle", 0, handle)
    body.emit("const-method-type", 1, site.proto)
    body.emit("invoke-custom", 0, site)
    body.move_result_object(0).return_object(0)
    ir = DexIR([make_class("LTest;", "Ljava/lang/Object;", 1,
                           direct_methods=[make_method("go", Proto.parse("()Ljava/lang/Object;"),
                                                       0x9, body)])])
    data = writer.write(ir)
    assert data[4:7] == b"038"
    parsed = reader.parse(data)
    refs = {kind for _w, kind, _v, _x in parsed.find_class("LTest;").find_method("go").code.refs}
    assert refs == {"method_handle", "proto", "callsite"}
    assert writer.write(parsed)[4:7] == b"038"


@pytest.mark.skipif(not any(p.exists() for p in REAL_APKS), reason="no local sample APKs")
@pytest.mark.parametrize("apk", [p for p in REAL_APKS if p.exists()])
def test_real_dex_round_trip(apk: Path):
    with zipfile.ZipFile(apk) as archive:
        names = [n for n in archive.namelist()
                 if n.startswith("classes") and n.endswith(".dex") and "/" not in n]
        assert names
        for name in names[:2]:  # keep the test reasonably quick
            original = archive.read(name)
            ir = reader.parse(original)
            rebuilt = writer.write(ir)
            assert reader.is_dex(rebuilt)
            assert len(reader.parse(rebuilt).classes) == len(ir.classes)
            assert rebuilt[4:7] == original[4:7]
            for method in (m for c in ir.classes for m in c.all_methods()):
                code = getattr(method, "code", None)
                if code is not None and hasattr(code, "units"):
                    for addr, unit, size in insns.iter_instructions(code.units):
                        assert addr + size <= len(code.units)
