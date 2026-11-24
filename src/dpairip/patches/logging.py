"""Logging patch.

Nothing in the original dex files is rebuilt.  The only in-place edit is
blanking the (void) PairIP integrity call; everything else lives in a fresh
appended dex plus a one-line manifest change.  That keeps the original dex
checksums and debug information intact, which matters because the protected app
often checks its own code before the VM has started.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Set, Tuple

from .. import axml, log
from ..apks import Module
from ..dex import insns, writer
from ..dex.model import (
    ACC_PUBLIC,
    ACC_STATIC,
    DexIR,
    FieldDef,
    MethodRef,
    Proto,
    RawCode,
)
from ..gen import runtime
from ..manifest import add_permission, application_class

_VERIFY = MethodRef(
    "Lcom/pairip/SignatureCheck;", "verifyIntegrity",
    Proto.parse("(Landroid/content/Context;)V"),
)

def find_junk_classes(module: Module) -> List[str]:
    """Return class descriptors that look like PairIP string dictionaries."""

    result: List[str] = []
    seen: Set[str] = set()
    for name in module.dex_names():
        for cls in module.ir(name).classes:
            if cls.type in seen:
                continue
            if cls.all_methods() or not cls.all_fields():
                continue
            if cls.superclass != "Ljava/lang/Object;" or cls.access != ACC_PUBLIC:
                continue
            valid = True
            for field in cls.all_fields():
                if field.access != ACC_STATIC | 0x1 or field.initial is not None:
                    valid = False
                    break
                if field.type not in (runtime.STRING, runtime.METHOD):
                    valid = False
                    break
            if valid:
                seen.add(cls.type)
                result.append(cls.type)
    return result


def _integrity_sites(module: Module) -> Dict[str, List[Tuple[int, int]]]:
    """Map dex name to ``(file_offset, byte_count)`` of integrity calls."""

    sites: Dict[str, List[Tuple[int, int]]] = {}
    for name in module.dex_names():
        found: Set[Tuple[int, int]] = set()
        for cls in module.ir(name).classes:
            for method in cls.all_methods():
                code = method.code
                if not isinstance(code, RawCode):
                    continue
                for word, kind, value, _width in code.refs:
                    if kind != "method" or value != _VERIFY:
                        continue
                    # the method index of both 35c and 3rc is the second unit
                    address = word - 1
                    if address < 0:
                        continue
                    size = insns.insn_size(code.units, address) * 2
                    found.add((code.offset + 16 + 2 * address, size))
        if found:
            sites[name] = sorted(found)
    return sites


def _strip_integrity(module: Module) -> int:
    patched = 0
    for name, sites in _integrity_sites(module).items():
        def blank(blob: bytearray, sites=sites) -> int:
            for offset, size in sites:
                blob[offset:offset + size] = b"\x00" * size
            return len(sites)

        patched += module.patch_raw(name, blank)
        log.info(f"removed {len(sites)} integrity call(s) from {name}")
    return patched


def apply(module: Module, *, strip_integrity: bool = True,
          non_root: bool = True, gadget_lib: Optional[str] = None) -> dict:
    """Install the dictionary dumper and return a small result summary."""

    junk = find_junk_classes(module)
    log.info(f"found {len(junk)} junk class(es)")

    if not junk:
        log.warn("no junk classes found; the dictionary will be empty")

    document = module.manifest()
    parent = "Lcom/pairip/application/Application;"
    if document is not None:
        current = application_class(document)
        if current and current != runtime.descriptor_to_class(runtime.PROXY):
            parent = runtime.class_to_descriptor(current)
    if parent == runtime.PROXY:
        parent = "Landroid/app/Application;"

    classes = [runtime.dumper_class(junk),
               runtime.proxy_application_class(parent, load_library=gadget_lib)]
    dex_name = module.add_dex(writer.write(DexIR(classes)))

    if document is not None:
        from ..axml import set_attribute_string
        app = document.element("manifest/application")
        if app is not None:
            set_attribute_string(app, document.pool, "name",
                                 runtime.descriptor_to_class(runtime.PROXY))
            if non_root:
                # debuggable lets `adb run-as` read the private copy too
                axml.set_attribute_bool_with_id(document, app, "debuggable", True,
                                                axml.RES_DEBUGGABLE)
                add_permission(document, "android.permission.WRITE_EXTERNAL_STORAGE")
                add_permission(document, "android.permission.READ_EXTERNAL_STORAGE")
            module.set_manifest(document)

    removed = _strip_integrity(module) if strip_integrity else 0
    log.build(f"added logging runtime as {dex_name}")
    return {
        "junk": junk,
        "runtime_dex": dex_name,
        "integrity_calls_removed": removed,
        "manifest_app": runtime.descriptor_to_class(runtime.PROXY),
    }
