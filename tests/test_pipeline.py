from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib

from dpairip import axml, manifest
from dpairip.apk import Apk
from dpairip.apks import Module
from dpairip.dex import reader, writer
from dpairip.dex.model import DexIR, MethodRef, Proto
from dpairip.gen.asm import MethodBuilder, make_class, make_method, method_ref
from dpairip.patches import patch_logging, patch_translation


def assert_header_valid(data: bytes) -> None:
    assert struct.unpack_from("<I", data, 32)[0] == len(data)
    assert hashlib.sha1(data[32:]).digest() == data[12:32]
    assert zlib.adler32(data[12:]) & 0xFFFFFFFF == struct.unpack_from("<I", data, 8)[0]


def _types(apk: Apk) -> set:
    result = set()
    for name in apk.dex_names():
        result.update(cls.type for cls in reader.parse(apk.get(name)).classes)
    return result


def test_logging_patch(fake_pairip_apk, tmp_path):
    module = Module.load(str(fake_pairip_apk))
    result = patch_logging(module)  # non-root behaviour is the default
    assert len(result["junk"]) == 2
    out = tmp_path / "patched.apk"
    module.save(str(out))

    apk = Apk.from_file(str(out))
    names = _types(apk)
    assert "Ldpairip/runtime/Dumper;" in names
    assert "Ldpairip/runtime/Application;" in names
    for name in apk.dex_names():
        assert_header_valid(apk.get(name))
    doc = axml.parse(apk.get("AndroidManifest.xml"))
    assert manifest.application_class(doc) == "dpairip.runtime.Application"
    app = doc.element("manifest/application")
    debuggable = app.attribute(doc.pool, resource_id=axml.RES_DEBUGGABLE)
    assert debuggable is not None and axml.bool_value(doc.pool, debuggable) is True
    from dpairip.manifest import permissions
    assert "android.permission.WRITE_EXTERNAL_STORAGE" in permissions(doc)

    shell = reader.parse(apk.get("classes.dex"))
    assert not any(
        isinstance(value, MethodRef) and value.name == "verifyIntegrity"
        for cls in shell.classes for method in cls.all_methods()
        if hasattr(method.code, "refs")
        for _word, _kind, value, _width in method.code.refs
    )
    assert {cls.type for cls in shell.classes} >= {"La/a;", "Lb/b;", "Lcom/example/App;"}


def test_translation_patch(fake_pairip_apk, dictionary, tmp_path):
    module = Module.load(str(fake_pairip_apk))
    patch_translation(module, str(dictionary))
    out = tmp_path / "translated.apk"
    module.save(str(out))

    apk = Apk.from_file(str(out))
    assert not any("libpairipcore.so" in name for name in apk.names())
    names = _types(apk)
    assert "Lcom/example/Real;" in names
    assert "Ldpairip/runtime/Bridge;" in names
    assert "Lcom/pairip/VMRunner;" in names
    assert "Lcom/pairip/application/Application;" not in names
    for name in apk.dex_names():
        assert_header_valid(apk.get(name))

    doc = axml.parse(apk.get("AndroidManifest.xml"))
    assert manifest.application_class(doc) == "com.example.App"

    shell = reader.parse(apk.get("classes.dex"))
    clinit = shell.find_class("Lcom/example/App;").find_method("<clinit>")
    assert any(isinstance(value, MethodRef) and value.name == "launch"
               for _word, _kind, value, _width in clinit.code.refs)

    bridge = None
    for name in apk.dex_names():
        bridge = reader.parse(apk.get(name)).find_class("Ldpairip/runtime/Bridge;")
        if bridge is not None:
            break
    assert bridge is not None
    restore = bridge.find_method("restore0")
    assert any(value == "secret-value"
               for _word, kind, value, _width in restore.code.refs if kind == "string")


def test_bundle_merge(fake_pairip_apk, tmp_path):
    init = MethodBuilder(1, 1)
    split_dex = writer.write(DexIR([make_class(
        "Lsplit/Extra;", "Ljava/lang/Object;", 1,
        direct_methods=[make_method("<init>", Proto.parse("()V"),
                                    0x10001, init.invoke_direct(
                                        method_ref("Ljava/lang/Object;", "<init>", "()V"),
                                        0).return_void())],
    )]))

    split_doc = axml.parse(zipfile.ZipFile(
        "/home/baba01hacker/apks/tracket/tracket.apk").read("AndroidManifest.xml"))
    axml.set_attribute_string(split_doc.root, split_doc.pool, "split", "config.test")
    split = Apk()
    split.put("AndroidManifest.xml", split_doc.to_bytes())
    split.put("classes.dex", split_dex)
    split.put("assets/split.bin", b"asset")
    split.put("lib/arm64-v8a/libextra.so", b"ELF")
    split_path = tmp_path / "split.apk"
    split.save(str(split_path))

    bundle = tmp_path / "bundle.apks"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.write(fake_pairip_apk, "base.apk")
        archive.write(split_path, "split_config.test.apk")

    module = Module.from_bundle(str(bundle))
    apk = module.apk
    assert "Lsplit/Extra;" in _types(apk)
    assert apk.has("assets/split.bin")
    assert apk.has("lib/arm64-v8a/libextra.so")
    assert len(apk.dex_names()) == 2
