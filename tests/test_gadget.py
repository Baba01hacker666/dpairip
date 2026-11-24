from __future__ import annotations

import json

from dpairip.apk import Apk
from dpairip.apks import Module
from dpairip.dex import reader
from dpairip.patches import embed_gadget, patch_logging


def test_embed_renamed_gadget(fake_pairip_apk, tmp_path):
    gadget = tmp_path / "gadget.so"
    gadget.write_bytes(b"\x7fELF" + b"\x00" * 4096)

    module = Module.load(str(fake_pairip_apk))
    patch_logging(module, gadget_lib="dpairip")
    info = embed_gadget(module, str(gadget), abi="arm64-v8a",
                        libname="dpairip", junk=["a.a", "b.b"],
                        output="/data/data/com.test/files/pairip.json")

    out = tmp_path / "gadget.apk"
    module.save(str(out))
    apk = Apk.from_file(str(out))

    assert apk.has(info["library"])
    assert apk.has(info["config"])
    assert apk.has(info["script"])
    assert apk.get(info["library"]) == gadget.read_bytes()
    config = json.loads(apk.get(info["config"]).decode())
    assert config["interaction"]["type"] == "script"
    assert config["interaction"]["path"] == info["script"].rsplit("/", 1)[-1]
    script = apk.get(info["script"]).decode()
    assert "a.a" in script and "b.b" in script
    assert "/data/data/com.test/files/pairip.json" in script

    dex = next(reader.parse(apk.get(name)) for name in apk.dex_names()
               if "Ldpairip/runtime/Application;" in
               {c.type for c in reader.parse(apk.get(name)).classes})
    clinit = dex.find_class("Ldpairip/runtime/Application;").find_method("<clinit>")
    assert any(value == "dpairip" for _w, kind, value, _x in clinit.code.refs
               if kind == "string")
