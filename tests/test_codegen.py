from __future__ import annotations

from dpairip.dex import reader, writer
from dpairip.dex.model import DexIR, FieldRef, MethodRef
from dpairip.gen import runtime


def test_runtime_classes_are_valid_dex():
    fields = [
        runtime.JunkField("La/a;", "x", runtime.STRING, "hello"),
        runtime.JunkField("Lb/b;", "m", runtime.METHOD, "public static void a.b.c()"),
    ]
    classes = [runtime.dumper_class(["La/a;", "Lb/b;"]),
               runtime.proxy_application_class("Lcom/pairip/application/Application;")]
    classes += runtime.bridge_classes(fields)
    classes.append(runtime.app_stub("Landroid/app/Application;"))
    data = writer.write(DexIR(classes))
    parsed = reader.parse(data)
    assert len(parsed.classes) == len(classes)
    assert {c.type for c in parsed.classes} >= {runtime.DUMPER, runtime.BRIDGE, runtime.LOOKUP}

    restore = parsed.find_class(runtime.BRIDGE).find_method("restore0")
    strings = [value for _w, kind, value, _x in restore.code.refs if kind == "string"]
    assert "hello" in strings
    assert "public static void a.b.c()" in strings

    dumper = parsed.find_class(runtime.DUMPER)
    assert dumper.find_method("write") is not None
    assert dumper.find_method("writeShared") is not None
    assert dumper.find_method("writePublic") is not None
    dump_refs = [str(value) for _w, _k, value, _x
                 in dumper.find_method("dump").code.refs]
    assert any("getExternalFilesDir" in ref for ref in dump_refs)
    shared_refs = [value for _w, _k, value, _x
                   in dumper.find_method("writeShared").code.refs if _k == "string"]
    assert "content://media/external/downloads" in shared_refs
    assert "pairip.json" in shared_refs


def test_junk_stub_and_launch_injection():
    from dpairip.gen.asm import MethodBuilder, make_class, make_method
    from dpairip.dex.model import Proto

    body = MethodBuilder(1, 0)
    body.sget_object(0, FieldRef("La/a;", "x", "Ljava/lang/String;")).return_void()
    original = make_class("Lcom/example/App;", "Landroid/app/Application;", 1,
                          direct_methods=[make_method("<clinit>", Proto.parse("()V"), 0x8008,
                                                      body)])
    # first check the symbolic path, then the RawCode path used on real dexes
    assert runtime.inject_launch(original)
    parsed = reader.parse(writer.write(DexIR([original])))
    raw = parsed.find_class("Lcom/example/App;")
    assert runtime.inject_launch(raw)
    refs = [value for _w, kind, value, _x in raw.find_method("<clinit>").code.refs]
    assert sum(isinstance(value, MethodRef) and value.name == "launch"
               for value in refs) == 2

    pairip = make_class("Lcom/pairip/VMRunner;", "Ljava/lang/Object;", 1)
    stub = runtime.stub_class(pairip, {"Lcom/pairip/VMRunner;": pairip})
    assert stub.superclass == "Ljava/lang/Object;" and not stub.all_methods()


def test_parse_dictionary(tmp_path):
    path = tmp_path / "d.json"
    path.write_text('{"a.b":{"type":"java.lang.String","fields":{"x":"v"}}}', encoding="utf-8")
    fields = runtime.parse_dictionary(str(path))
    assert len(fields) == 1
    assert fields[0].owner == "La/b;"
    assert fields[0].value == "v"
