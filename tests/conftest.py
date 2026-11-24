"""Shared fixtures: a tiny, self-contained fake PairIP application."""

from __future__ import annotations

import json
import struct
import zipfile
from pathlib import Path

import pytest

from dpairip import axml
from dpairip.apk import Apk
from dpairip.dex import writer
from dpairip.dex.model import (
    ACC_CONSTRUCTOR,
    ACC_PROTECTED,
    ACC_PUBLIC,
    ACC_STATIC,
    DexIR,
    FieldDef,
    Proto,
)
from dpairip.gen.asm import MethodBuilder, field_ref, make_class, make_method, method_ref


def _m(owner, name, desc):
    return method_ref(owner, name, desc)


def _make_shell_dex() -> bytes:
    app_init = MethodBuilder(1, 1)
    app_init.invoke_direct(_m("Landroid/app/Application;", "<init>", "()V"), 0).return_void()
    app_clinit = MethodBuilder(1, 0)
    app_clinit.sget_object(0, field_ref("La/a;", "x", "Ljava/lang/String;")).return_void()
    app = make_class(
        "Lcom/example/App;", "Landroid/app/Application;", ACC_PUBLIC,
        direct_methods=[
            make_method("<init>", Proto.parse("()V"), ACC_PUBLIC | ACC_CONSTRUCTOR, app_init),
            make_method("<clinit>", Proto.parse("()V"), ACC_STATIC | ACC_CONSTRUCTOR, app_clinit),
        ],
    )
    junk_a = make_class("La/a;", "Ljava/lang/Object;", ACC_PUBLIC,
                        static_fields=[FieldDef("x", "Ljava/lang/String;", ACC_STATIC | 1)])
    junk_b = make_class("Lb/b;", "Ljava/lang/Object;", ACC_PUBLIC,
                        static_fields=[FieldDef("m", "Ljava/lang/reflect/Method;", ACC_STATIC | 1)])

    pairip_init = MethodBuilder(1, 1)
    pairip_init.invoke_direct(_m("Lcom/example/App;", "<init>", "()V"), 0).return_void()
    attach = MethodBuilder(2, 2)
    attach.invoke("super", _m("Lcom/example/App;", "attachBaseContext",
                              "(Landroid/content/Context;)V"), 0, 1)
    attach.invoke_static(_m("Lcom/pairip/SignatureCheck;", "verifyIntegrity",
                            "(Landroid/content/Context;)V"), 1)
    attach.invoke_static(_m("Lcom/pairip/StartupLauncher;", "launch", "()V"))
    attach.return_void()
    pairip_app = make_class(
        "Lcom/pairip/application/Application;", "Lcom/example/App;", ACC_PUBLIC,
        direct_methods=[make_method("<init>", Proto.parse("()V"),
                                    ACC_PUBLIC | ACC_CONSTRUCTOR, pairip_init)],
        virtual_methods=[make_method("attachBaseContext",
                                     Proto.parse("(Landroid/content/Context;)V"),
                                     ACC_PROTECTED, attach)],
    )
    sig = make_class(
        "Lcom/pairip/SignatureCheck;", "Ljava/lang/Object;", ACC_PUBLIC,
        direct_methods=[make_method("verifyIntegrity",
                                    Proto.parse("(Landroid/content/Context;)V"),
                                    ACC_PUBLIC | ACC_STATIC, MethodBuilder(1, 1).return_void())],
    )
    launcher = make_class(
        "Lcom/pairip/StartupLauncher;", "Ljava/lang/Object;", ACC_PUBLIC,
        direct_methods=[make_method("launch", Proto.parse("()V"),
                                    ACC_PUBLIC | ACC_STATIC, MethodBuilder(1, 0).return_void())],
    )
    vm = make_class(
        "Lcom/pairip/VMRunner;", "Ljava/lang/Object;", ACC_PUBLIC,
        direct_methods=[make_method("invoke",
                                    Proto.parse("(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"),
                                    ACC_PUBLIC | ACC_STATIC,
                                    MethodBuilder(3, 2).const4(0, 0).return_object(0))],
    )
    return writer.write(DexIR([app, junk_a, junk_b, pairip_app, sig, launcher, vm]))


def _make_real_dex() -> bytes:
    init = MethodBuilder(1, 1)
    init.invoke_direct(_m("Ljava/lang/Object;", "<init>", "()V"), 0).return_void()
    return writer.write(DexIR([make_class(
        "Lcom/example/Real;", "Ljava/lang/Object;", ACC_PUBLIC,
        direct_methods=[make_method("<init>", Proto.parse("()V"),
                                    ACC_PUBLIC | ACC_CONSTRUCTOR, init)],
    )]))


def _manifest() -> bytes:
    data = Path("/home/baba01hacker/apks/tracket/tracket.apk")
    if data.exists():
        with zipfile.ZipFile(data) as archive:
            raw = archive.read("AndroidManifest.xml")
        document = axml.parse(raw)
        app = document.element("manifest/application")
        axml.set_attribute_string(app, document.pool, "name",
                                  "com.pairip.application.Application")
        return document.to_bytes()
    raise RuntimeError("fixture manifest is unavailable")


@pytest.fixture
def fake_pairip_apk(tmp_path: Path) -> Path:
    path = tmp_path / "sample.apk"
    apk = Apk()
    apk.put("AndroidManifest.xml", _manifest())
    apk.put("classes.dex", _make_shell_dex())
    real = _make_real_dex()
    payload = (b"\x00IAP\x02" + b"\x00" * 100)
    payload = payload[:32] + struct.pack("<I", len(real)) + payload[36:] + real
    apk.put("assets/payload.bin", payload)
    apk.put("lib/arm64-v8a/libpairipcore.so", b"\x7fELF fake")
    apk.save(str(path))
    return path


@pytest.fixture
def dictionary(tmp_path: Path) -> Path:
    path = tmp_path / "pairip.json"
    path.write_text(json.dumps({
        "a.a": {"type": "java.lang.String", "fields": {"x": "secret-value"}},
        "b.b": {"type": "java.lang.reflect.Method",
                "fields": {"m": "public static void a.b.c()"}},
    }), encoding="utf-8")
    return path
