"""Generation of the small runtime dex used by both patch modes.

Everything here is created from Python data structures and assembled by
:mod:`dpairip.gen.asm`; no prebuilt dex blob is shipped with the package.  The
classes are deliberately named under ``Ldpairip/runtime/`` so they cannot clash
with anything in the target application.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..dex import insns
from ..dex.model import (
    ACC_ABSTRACT,
    ACC_ANNOTATION,
    ACC_CONSTRUCTOR,
    ACC_FINAL,
    ACC_INTERFACE,
    ACC_NATIVE,
    ACC_PRIVATE,
    ACC_PROTECTED,
    ACC_PUBLIC,
    ACC_STATIC,
    ACC_SYNCHRONIZED,
    ClassDef,
    DexIR,
    EncodedValue,
    FieldDef,
    FieldRef,
    MethodDef,
    Proto,
    RawCode,
    TryBlock,
)
from .asm import (
    MethodBuilder,
    default_return,
    field_ref,
    make_class,
    make_method,
    method_ref,
    word_count,
)

DUMPER = "Ldpairip/runtime/Dumper;"
BRIDGE = "Ldpairip/runtime/Bridge;"
LOOKUP = "Ldpairip/runtime/MethodLookup;"
PROXY = "Ldpairip/runtime/Application;"

PAIRIP_PREFIXES = ("Lcom/pairip/", "Lantik/")
PAIRIP_APP = "Lcom/pairip/application/Application;"
OBJECT = "Ljava/lang/Object;"
STRING = "Ljava/lang/String;"
METHOD = "Ljava/lang/reflect/Method;"
CONTEXT = "Landroid/content/Context;"
APPLICATION = "Landroid/app/Application;"

STRING_TYPE = "java.lang.String"
METHOD_TYPE = "java.lang.reflect.Method"


def is_pairip(desc: Optional[str]) -> bool:
    return bool(desc) and desc.startswith(PAIRIP_PREFIXES)


def descriptor_to_class(desc: str) -> str:
    return desc[1:-1].replace("/", ".") if desc.startswith("L") and desc.endswith(";") else desc


def class_to_descriptor(name: str) -> str:
    return "L" + name.replace(".", "/") + ";"


# ---------------------------------------------------------------------------
# runtime definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class JunkField:
    owner: str
    name: str
    type: str
    value: str

    @property
    def ref(self) -> FieldRef:
        return field_ref(self.owner, self.name, self.type)


def _json_ref(name: str, descriptor: str) -> MethodRef:
    return method_ref("Lorg/json/JSONObject;", name, descriptor)


def _json_string_put() -> MethodRef:
    return _json_ref("put", "(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;")


# -- dumper -----------------------------------------------------------------

def _dump_class_method() -> MethodDef:
    put = _json_string_put()
    json_init = method_ref("Lorg/json/JSONObject;", "<init>", "()V")
    json_null = field_ref("Lorg/json/JSONObject;", "NULL", "Ljava/lang/Object;")

    b = MethodBuilder(10, 2, 2)
    b.new_instance(0, "Lorg/json/JSONObject;").invoke_direct(json_init, 0)
    b.const4(1, 0)                                   # detected field type
    b.invoke_virtual(method_ref("Ljava/lang/Class;", "getDeclaredFields", "()[Ljava/lang/reflect/Field;"), 9)
    b.move_result_object(2)
    b.array_length(3, 2)
    b.const4(4, 0)
    b.label("loop")
    b.if_ge(4, 3, "done")
    b.aget_object(5, 2, 4)
    b.invoke_virtual(method_ref("Ljava/lang/reflect/Field;", "getModifiers", "()I"), 5)
    b.move_result(6)
    b.invoke_static(method_ref("Ljava/lang/reflect/Modifier;", "isStatic", "(I)Z"), 6)
    b.move_result(6)
    b.if_eqz(6, "next")
    b.const4(6, 1)
    b.invoke_virtual(method_ref("Ljava/lang/reflect/Field;", "setAccessible", "(Z)V"), 5, 6)
    b.if_nez(1, "typed")
    b.invoke_virtual(method_ref("Ljava/lang/reflect/Field;", "getType", "()Ljava/lang/Class;"), 5)
    b.move_result_object(6)
    b.invoke_virtual(method_ref("Ljava/lang/Class;", "getName", "()Ljava/lang/String;"), 6)
    b.move_result_object(1)
    b.label("typed")
    b.const4(6, 0)
    b.invoke_virtual(
        method_ref("Ljava/lang/reflect/Field;", "get",
                   "(Ljava/lang/Object;)Ljava/lang/Object;"), 5, 6)
    b.move_result_object(6)
    b.invoke_virtual(method_ref("Ljava/lang/reflect/Field;", "getName", "()Ljava/lang/String;"), 5)
    b.move_result_object(7)
    b.if_nez(6, "not_null")
    b.sget_object(6, json_null)
    b.invoke_virtual(put, 0, 7, 6)
    b.goto("next")
    b.label("not_null")
    b.invoke_virtual(method_ref("Ljava/lang/Object;", "toString", "()Ljava/lang/String;"), 6)
    b.move_result_object(6)
    b.invoke_virtual(put, 0, 7, 6)
    b.label("next")
    b.add_int_lit8(4, 4, 1)
    b.goto("loop")
    b.label("done")
    b.new_instance(2, "Lorg/json/JSONObject;")
    b.invoke_direct(json_init, 2)
    b.const_string(3, "type")
    b.invoke_virtual(put, 2, 3, 1)
    b.const_string(3, "fields")
    b.invoke_virtual(put, 2, 3, 0)
    b.invoke_virtual(method_ref("Ljava/lang/Class;", "getName", "()Ljava/lang/String;"), 9)
    b.move_result_object(3)
    b.invoke_virtual(put, 8, 3, 2)
    b.return_void()
    return make_method("dumpClass", Proto.parse(
        "(Lorg/json/JSONObject;Ljava/lang/Class;)V"),
        ACC_PRIVATE | ACC_STATIC, b)


def _write_dump_method() -> MethodDef:
    """Write one JSON document into a directory (private or external)."""

    file_init = method_ref("Ljava/io/File;", "<init>", "(Ljava/io/File;Ljava/lang/String;)V")
    out_init = method_ref("Ljava/io/FileOutputStream;", "<init>", "(Ljava/io/File;)V")
    b = MethodBuilder(6, 2, 2)  # p0 = directory (v4), p1 = JSONObject (v5)
    b.label("start")
    b.new_instance(0, "Ljava/io/File;")
    b.const_string(1, "pairip.json")
    b.invoke_direct(file_init, 0, 4, 1)
    b.new_instance(2, "Ljava/io/FileOutputStream;")
    b.invoke_direct(out_init, 2, 0)
    b.const4(0, 2)
    b.invoke_virtual(_json_ref("toString", "(I)Ljava/lang/String;"), 5, 0)
    b.move_result_object(0)
    b.const_string(1, "UTF-8")
    b.invoke_virtual(method_ref("Ljava/lang/String;", "getBytes",
                                "(Ljava/lang/String;)[B"), 0, 1)
    b.move_result_object(0)
    b.invoke_virtual(method_ref("Ljava/io/FileOutputStream;", "write", "([B)V"), 2, 0)
    b.invoke_virtual(method_ref("Ljava/io/FileOutputStream;", "close", "()V"), 2)
    b.label("try_end")
    b.goto("finish")
    b.label("catch")
    b.move_exception(0)
    b.invoke_virtual(method_ref("Ljava/lang/Throwable;", "printStackTrace", "()V"), 0)
    b.label("finish")
    b.return_void()
    b.protect("start", "try_end", [(None, "catch")])
    return make_method("write", Proto.parse("(Ljava/io/File;Lorg/json/JSONObject;)V"),
                       ACC_PRIVATE | ACC_STATIC, b)


def _write_shared_method() -> MethodDef:
    """Publish the dump to Downloads via MediaStore (no root, no permission)."""

    values_init = method_ref("Landroid/content/ContentValues;", "<init>", "()V")
    values_put = method_ref("Landroid/content/ContentValues;", "put",
                            "(Ljava/lang/String;Ljava/lang/String;)V")
    uri_parse = method_ref("Landroid/net/Uri;", "parse",
                           "(Ljava/lang/String;)Landroid/net/Uri;")
    resolver = method_ref("Landroid/content/Context;", "getContentResolver",
                          "()Landroid/content/ContentResolver;")
    insert = method_ref("Landroid/content/ContentResolver;", "insert",
                        "(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;")
    stream = method_ref("Landroid/content/ContentResolver;", "openOutputStream",
                        "(Landroid/net/Uri;)Ljava/io/OutputStream;")

    b = MethodBuilder(8, 2, 2)  # p0 = Context (v6), p1 = JSONObject (v7)
    b.label("start")
    b.new_instance(0, "Landroid/content/ContentValues;")
    b.invoke_direct(values_init, 0)
    b.const_string(1, "_display_name")
    b.const_string(2, "pairip.json")
    b.invoke_virtual(values_put, 0, 1, 2)
    b.const_string(1, "mime_type")
    b.const_string(2, "application/json")
    b.invoke_virtual(values_put, 0, 1, 2)
    b.const_string(1, "content://media/external/downloads")
    b.invoke_static(uri_parse, 1)
    b.move_result_object(1)
    b.invoke_virtual(resolver, 6)
    b.move_result_object(2)
    b.invoke_virtual(insert, 2, 1, 0)
    b.move_result_object(1)
    b.if_eqz(1, "try_end")
    b.invoke_virtual(stream, 2, 1)
    b.move_result_object(1)
    b.if_eqz(1, "try_end")
    b.const4(4, 2)
    b.invoke_virtual(_json_ref("toString", "(I)Ljava/lang/String;"), 7, 4)
    b.move_result_object(4)
    b.const_string(5, "UTF-8")
    b.invoke_virtual(method_ref("Ljava/lang/String;", "getBytes",
                                "(Ljava/lang/String;)[B"), 4, 5)
    b.move_result_object(4)
    b.invoke_virtual(method_ref("Ljava/io/OutputStream;", "write", "([B)V"), 1, 4)
    b.invoke_virtual(method_ref("Ljava/io/OutputStream;", "close", "()V"), 1)
    b.label("try_end")
    b.return_void()
    b.label("catch")
    b.move_exception(0)
    b.invoke_virtual(method_ref("Ljava/lang/Throwable;", "printStackTrace", "()V"), 0)
    b.return_void()
    b.protect("start", "try_end", [(None, "catch")])
    return make_method("writeShared",
                       Proto.parse("(Landroid/content/Context;Lorg/json/JSONObject;)V"),
                       ACC_PRIVATE | ACC_STATIC, b)


def _write_public_method() -> MethodDef:
    """Legacy fallback: plain file in the public Downloads folder."""

    b = MethodBuilder(2, 1, 1)
    b.label("start")
    b.const_string(0, "Download")
    b.invoke_static(method_ref("Landroid/os/Environment;",
                               "getExternalStoragePublicDirectory",
                               "(Ljava/lang/String;)Ljava/io/File;"), 0)
    b.move_result_object(0)
    b.invoke_static(method_ref(DUMPER, "write",
                               "(Ljava/io/File;Lorg/json/JSONObject;)V"), 0, 1)
    b.label("try_end")
    b.return_void()
    b.label("catch")
    b.move_exception(0)
    b.invoke_virtual(method_ref("Ljava/lang/Throwable;", "printStackTrace", "()V"), 0)
    b.return_void()
    b.protect("start", "try_end", [(None, "catch")])
    return make_method("writePublic", Proto.parse("(Lorg/json/JSONObject;)V"),
                       ACC_PRIVATE | ACC_STATIC, b)


def dumper_class(junk_classes: Sequence[str]) -> ClassDef:
    """Serialise the populated junk fields to app-private *and* external storage.

    The external copy lives in ``/sdcard/Android/data/<package>/files/`` so it
    can be pulled with plain ``adb pull`` -- no root, CorePatch or base.apk swap
    is needed.  The private copy is kept for compatibility with the reference
    flow.
    """

    json_init = method_ref("Lorg/json/JSONObject;", "<init>", "()V")
    file_init = method_ref("Ljava/io/File;", "<init>", "(Ljava/io/File;Ljava/lang/String;)V")

    b = MethodBuilder(7, 1, 2)
    b.label("start")
    b.invoke_virtual(method_ref("Landroid/content/Context;", "getFilesDir", "()Ljava/io/File;"), 6)
    b.move_result_object(0)
    b.invoke_virtual(method_ref("Ljava/io/File;", "getParentFile", "()Ljava/io/File;"), 0)
    b.move_result_object(0)
    b.new_instance(1, "Ljava/io/File;")
    b.const_string(2, "dictionary")
    b.invoke_direct(file_init, 1, 0, 2)
    b.invoke_virtual(method_ref("Ljava/io/File;", "mkdirs", "()Z"), 1)
    b.move_result(0)
    b.new_instance(0, "Lorg/json/JSONObject;")
    b.invoke_direct(json_init, 0)
    for desc in junk_classes:
        b.const_class(2, desc)
        b.invoke_static(method_ref(DUMPER, "dumpClass",
                                   "(Lorg/json/JSONObject;Ljava/lang/Class;)V"), 0, 2)

    # private copy first, so a failure of external storage cannot lose it
    b.invoke_static(method_ref(DUMPER, "write",
                               "(Ljava/io/File;Lorg/json/JSONObject;)V"), 1, 0)
    b.const4(2, 0)
    b.invoke_virtual(method_ref("Landroid/content/Context;", "getExternalFilesDir",
                                "(Ljava/lang/String;)Ljava/io/File;"), 6, 2)
    b.move_result_object(1)
    b.invoke_virtual(method_ref("Ljava/io/File;", "mkdirs", "()Z"), 1)
    b.move_result(2)
    b.invoke_static(method_ref(DUMPER, "write",
                               "(Ljava/io/File;Lorg/json/JSONObject;)V"), 1, 0)
    b.invoke_static(method_ref(DUMPER, "writeShared",
                               "(Landroid/content/Context;Lorg/json/JSONObject;)V"), 6, 0)
    b.invoke_static(method_ref(DUMPER, "writePublic",
                               "(Lorg/json/JSONObject;)V"), 0)
    b.label("try_end")
    b.goto("finish")
    b.label("catch")
    b.move_exception(0)
    b.invoke_virtual(method_ref("Ljava/lang/Throwable;", "printStackTrace", "()V"), 0)
    b.label("finish")
    b.return_void()
    b.protect("start", "try_end", [(None, "catch")])

    dump = make_method("dump", Proto.parse("(Landroid/content/Context;)V"),
                       ACC_PUBLIC | ACC_STATIC, b)
    return make_class(
        DUMPER, OBJECT, ACC_PUBLIC | ACC_FINAL,
        direct_methods=[_dump_class_method(), _write_dump_method(),
                        _write_shared_method(), _write_public_method(), dump],
        source_file="Dumper.java",
    )


def proxy_application_class(parent: str, load_library: Optional[str] = None) -> ClassDef:
    """Thin ``Application`` subclass that dumps the dictionary after startup.

    ``load_library`` loads a bundled native library (e.g. a renamed Frida
    Gadget) from the static initializer, before the protector's
    ``attachBaseContext`` runs.
    """

    constructor = MethodBuilder(1, 1)
    constructor.invoke_direct(method_ref(parent, "<init>", "()V"), 0)
    constructor.return_void()

    attach = MethodBuilder(2, 2)
    attach.invoke("super", method_ref(parent, "attachBaseContext", "(Landroid/content/Context;)V"), 0, 1)
    attach.invoke_static(method_ref(DUMPER, "dump", "(Landroid/content/Context;)V"), 1)
    attach.return_void()

    create = MethodBuilder(1, 1)
    create.invoke("super", method_ref(parent, "onCreate", "()V"), 0)
    create.invoke_static(method_ref(DUMPER, "dump", "(Landroid/content/Context;)V"), 0)
    create.return_void()

    direct = [make_method("<init>", Proto.parse("()V"),
                          ACC_PUBLIC | ACC_CONSTRUCTOR, constructor)]
    if load_library:
        bootstrap = MethodBuilder(2, 0, 1)
        bootstrap.label("start")
        bootstrap.const_string(0, load_library)
        bootstrap.invoke_static(method_ref("Ljava/lang/System;", "loadLibrary",
                                           "(Ljava/lang/String;)V"), 0)
        bootstrap.label("try_end")
        bootstrap.goto("done")
        bootstrap.label("catch")
        bootstrap.move_exception(0)
        bootstrap.invoke_virtual(method_ref("Ljava/lang/Throwable;", "printStackTrace", "()V"), 0)
        bootstrap.label("done")
        bootstrap.return_void()
        bootstrap.protect("start", "try_end", [(None, "catch")])
        direct.append(make_method("<clinit>", Proto.parse("()V"),
                                  ACC_STATIC | ACC_CONSTRUCTOR, bootstrap))

    return make_class(
        PROXY, parent, ACC_PUBLIC,
        direct_methods=direct,
        virtual_methods=[
            make_method("attachBaseContext", Proto.parse("(Landroid/content/Context;)V"),
                        ACC_PROTECTED, attach),
            make_method("onCreate", Proto.parse("()V"), ACC_PUBLIC, create),
        ],
        source_file="Application.java",
    )


# -- bridge -----------------------------------------------------------------

_RESTORE_CHUNK = 180


def _lookup_method() -> MethodDef:
    b = MethodBuilder(10, 1, 2)
    b.label("start")
    b.const_string(0, "(")
    b.invoke_virtual(method_ref("Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"), 9, 0)
    b.move_result(0)
    b.const4(1, 0)
    b.invoke_virtual(method_ref("Ljava/lang/String;", "substring", "(II)Ljava/lang/String;"), 9, 1, 0)
    b.move_result_object(0)
    b.invoke_virtual(method_ref("Ljava/lang/String;", "trim", "()Ljava/lang/String;"), 0)
    b.move_result_object(0)
    b.const_string(1, " ")
    b.invoke_virtual(method_ref("Ljava/lang/String;", "lastIndexOf", "(Ljava/lang/String;)I"), 0, 1)
    b.move_result(1)
    b.add_int_lit8(1, 1, 1)
    b.invoke_virtual(method_ref("Ljava/lang/String;", "substring", "(I)Ljava/lang/String;"), 0, 1)
    b.move_result_object(1)
    b.const_string(2, ".")
    b.invoke_virtual(method_ref("Ljava/lang/String;", "lastIndexOf", "(Ljava/lang/String;)I"), 1, 2)
    b.move_result(2)
    b.const4(3, 0)
    b.invoke_virtual(method_ref("Ljava/lang/String;", "substring", "(II)Ljava/lang/String;"), 1, 3, 2)
    b.move_result_object(2)
    b.invoke_static(method_ref("Ljava/lang/Class;", "forName",
                               "(Ljava/lang/String;)Ljava/lang/Class;"), 2)
    b.move_result_object(3)
    b.invoke_virtual(method_ref("Ljava/lang/Class;", "getDeclaredMethods",
                                "()[Ljava/lang/reflect/Method;"), 3)
    b.move_result_object(4)
    b.array_length(5, 4)
    b.const4(6, 0)
    b.label("loop")
    b.if_ge(6, 5, "end_try")
    b.aget_object(7, 4, 6)
    b.invoke_virtual(method_ref("Ljava/lang/reflect/Method;", "toGenericString",
                                "()Ljava/lang/String;"), 7)
    b.move_result_object(8)
    b.invoke_virtual(method_ref("Ljava/lang/String;", "equals", "(Ljava/lang/Object;)Z"), 8, 9)
    b.move_result(8)
    b.if_eqz(8, "next")
    b.return_object(7)
    b.label("next")
    b.add_int_lit8(6, 6, 1)
    b.goto("loop")
    b.label("end_try")
    b.goto("null_result")
    b.label("catch")
    b.move_exception(0)
    b.invoke_virtual(method_ref("Ljava/lang/Throwable;", "printStackTrace", "()V"), 0)
    b.label("null_result")
    b.const4(0, 0)
    b.return_object(0)
    b.protect("start", "end_try", [("Ljava/lang/Exception;", "catch")])
    return make_method("get", Proto.parse("(Ljava/lang/String;)Ljava/lang/reflect/Method;"),
                       ACC_PUBLIC | ACC_STATIC, b)


def lookup_class() -> ClassDef:
    return make_class(LOOKUP, OBJECT, ACC_PUBLIC | ACC_FINAL,
                      direct_methods=[_lookup_method()],
                      source_file="MethodLookup.java")


def bridge_classes(fields: Sequence[JunkField]) -> List[ClassDef]:
    """Classes that restore the dictionary and expose the VM entry points."""

    launched = field_ref(BRIDGE, "launched", "Z")
    chunks = [list(fields[i:i + _RESTORE_CHUNK])
              for i in range(0, len(fields), _RESTORE_CHUNK)] or [[]]

    restore_names = []
    chunk_methods: List[MethodDef] = []
    for index, chunk in enumerate(chunks):
        name = f"restore{index}"
        restore_names.append(name)
        b = MethodBuilder(1, 0, 1)
        b.label("start")
        for entry in chunk:
            b.const_string(0, entry.value)
            if entry.type == METHOD:
                b.invoke_static(method_ref(LOOKUP, "get",
                                           "(Ljava/lang/String;)Ljava/lang/reflect/Method;"), 0)
                b.move_result_object(0)
            b.sput_object(0, entry.ref)
        b.label("try_end")
        b.goto("done")
        b.label("catch")
        b.move_exception(0)
        b.invoke_virtual(method_ref("Ljava/lang/Throwable;", "printStackTrace", "()V"), 0)
        b.label("done")
        b.return_void()
        b.protect("start", "try_end", [(None, "catch")])
        chunk_methods.append(make_method(name, Proto.parse("()V"),
                                         ACC_PRIVATE | ACC_STATIC, b))

    restore = MethodBuilder(1, 0, max(1, len(chunks)))
    for name in restore_names:
        restore.invoke_static(method_ref(BRIDGE, name, "()V"))
    restore.return_void()

    launch = MethodBuilder(1, 0, 1)
    launch.sget_boolean(0, launched)
    launch.if_eqz(0, "done")
    launch.const4(0, 1)
    launch.sput_boolean(0, launched)
    launch.label("start")
    launch.invoke_static(method_ref(BRIDGE, "restore", "()V"))
    launch.label("try_end")
    launch.goto("done")
    launch.label("catch")
    launch.move_exception(0)
    launch.invoke_virtual(method_ref("Ljava/lang/Throwable;", "printStackTrace", "()V"), 0)
    launch.label("done")
    launch.return_void()
    launch.protect("start", "try_end", [(None, "catch")])

    invoke_proto = Proto.parse("(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;")
    invoke = MethodBuilder(word_count(invoke_proto) + 1, word_count(invoke_proto))
    invoke.const4(0, 0)
    invoke.return_object(0)

    classes = [
        make_class(
            BRIDGE, OBJECT, ACC_PUBLIC | ACC_FINAL,
            static_fields=[FieldDef("launched", "Z", ACC_PRIVATE | ACC_STATIC,
                                    EncodedValue.boolean(False))],
            direct_methods=[
                make_method("restore", Proto.parse("()V"), ACC_PUBLIC | ACC_STATIC, restore),
                *chunk_methods,
                make_method("launch", Proto.parse("()V"),
                            ACC_PUBLIC | ACC_STATIC | ACC_SYNCHRONIZED, launch),
                make_method("invoke", Proto.parse("(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"),
                            ACC_PUBLIC | ACC_STATIC, invoke),
            ],
            source_file="Bridge.java",
        )
    ]
    if any(entry.type == METHOD for entry in fields):
        classes.append(lookup_class())
    return classes


def app_stub(parent: str, name: str = PAIRIP_APP) -> ClassDef:
    """Fallback manifest application when no real application class was found."""

    constructor = MethodBuilder(1, 1)
    constructor.invoke_direct(method_ref(parent, "<init>", "()V"), 0)
    constructor.return_void()

    launch = MethodBuilder(1, 0, 1)
    launch.invoke_static(method_ref(BRIDGE, "launch", "()V"))
    launch.return_void()

    return make_class(
        name, parent, ACC_PUBLIC,
        direct_methods=[
            make_method("<init>", Proto.parse("()V"), ACC_PUBLIC | ACC_CONSTRUCTOR, constructor),
            make_method("<clinit>", Proto.parse("()V"), ACC_STATIC | ACC_CONSTRUCTOR, launch),
        ],
        source_file="Application.java",
    )


# ---------------------------------------------------------------------------
# stubbing / injection
# ---------------------------------------------------------------------------

def _constructor_body(superclass: str, proto: Proto,
                      super_class: Optional[ClassDef]) -> MethodBuilder:
    own_ins = 1 + word_count(proto)
    super_proto = Proto.parse("()V")
    if super_class is not None:
        candidates = [m for m in super_class.all_methods() if m.name == "<init>"]
        non_private = [m for m in candidates if not m.access & ACC_PRIVATE]
        no_arg = next((m for m in non_private if not m.proto.params), None)
        if no_arg is not None:
            super_proto = no_arg.proto
        elif non_private:
            super_proto = non_private[0].proto
    args = word_count(super_proto)
    registers = own_ins + args
    b = MethodBuilder(registers, own_ins, args)
    values: List[int] = []
    for index, param in enumerate(super_proto.params):
        if param in ("J", "D"):
            b.emit("const-wide/16", index * 2, 0)
        else:
            b.const4(index, 0)
        values.append(index * 2 if param in ("J", "D") else index)
    b.invoke_direct(method_ref(superclass, "<init>", super_proto.descriptor()),
                    b.registers - own_ins, *values)
    b.return_void()
    return b


def stub_class(cls: ClassDef, known: Dict[str, ClassDef]) -> ClassDef:
    """Turn an original pairip class into a harmless placeholder."""

    superclass = cls.superclass or OBJECT
    if is_pairip(superclass):
        superclass = OBJECT
    super_class = known.get(superclass)

    interface = bool(cls.access & (ACC_INTERFACE | ACC_ANNOTATION))
    access = ACC_PUBLIC | (ACC_INTERFACE | ACC_ABSTRACT | ACC_ANNOTATION
                           if cls.access & ACC_ANNOTATION else
                           (ACC_INTERFACE | ACC_ABSTRACT if interface else 0))

    direct: List[MethodDef] = []
    virtual: List[MethodDef] = []
    for method in cls.all_methods():
        if interface:
            body = None
            method_access = (method.access | ACC_ABSTRACT) & ~(ACC_NATIVE | ACC_FINAL)
        elif method.name == "<init>":
            body = _constructor_body(superclass, method.proto, super_class).build()
            method_access = method.access & ~(ACC_NATIVE | ACC_ABSTRACT)
        else:
            method_ins = word_count(method.proto)
            if not method.access & ACC_STATIC:
                method_ins += 1
            body = default_return(method.proto, method_ins).build()
            method_access = method.access & ~(ACC_NATIVE | ACC_ABSTRACT)
        target = direct if method.is_direct else virtual
        target.append(MethodDef(method.name, method.proto, method_access, body))

    return make_class(
        cls.type, superclass, access,
        interfaces=[],
        static_fields=[FieldDef(f.name, f.type, f.access & ~ACC_FINAL)
                       for f in cls.static_fields],
        instance_fields=[FieldDef(f.name, f.type, f.access & ~ACC_FINAL)
                         for f in cls.instance_fields],
        direct_methods=direct,
        virtual_methods=virtual,
    )


_LAUNCH_REF = method_ref(BRIDGE, "launch", "()V")


def inject_launch(cls: ClassDef) -> bool:
    """Make ``<clinit>`` call ``Bridge.launch()`` before anything else."""

    launch_insn = insns.Insn(insns.NAME_TO_OPCODE["invoke-static"], (_LAUNCH_REF,))
    units = insns.encode_insn(launch_insn, lambda kind, value: 0)

    clinit = cls.find_method("<clinit>")
    if clinit is None:
        b = MethodBuilder(1, 0, 1)
        b.invoke_static(_LAUNCH_REF)
        b.return_void()
        cls.direct_methods.append(
            MethodDef("<clinit>", Proto.parse("()V"), ACC_STATIC | ACC_CONSTRUCTOR, b.build()))
        return True

    code = clinit.code
    if code is None:
        return False
    if isinstance(code, RawCode):
        new_units, new_tries = insns.insert_code(code.units, code.tries, 0, units)
        shift = len(new_units) - len(code.units)
        code.units = new_units
        code.tries = new_tries
        code.refs = [(word + shift, kind, value, width)
                     for word, kind, value, width in code.refs]
        code.refs.append((1, "method", _LAUNCH_REF, 1))
    else:
        code.items.insert(0, launch_insn)
        code.outs = max(code.outs, 1)
    return True


# ---------------------------------------------------------------------------
# dictionary helpers
# ---------------------------------------------------------------------------

def parse_dictionary(path: str) -> List[JunkField]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("dictionary must be a JSON object")

    fields: List[JunkField] = []
    for class_name, payload in data.items():
        if not isinstance(payload, dict):
            continue
        owner = class_to_descriptor(class_name)
        values = payload.get("fields", {})
        if not isinstance(values, dict):
            continue
        field_type = METHOD if str(payload.get("type", "")).endswith("Method") else STRING
        for name, value in values.items():
            fields.append(JunkField(owner, name, field_type, "" if value is None else str(value)))
    return fields
