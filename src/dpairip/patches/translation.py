"""Translation patch.

The dictionary captured from the logging run is baked into static field writes,
the protector's own classes are replaced by inert placeholders, encrypted dex
blobs found in assets are recovered and the manifest is pointed back at the
real application class.
"""

from __future__ import annotations

import io
import struct
import zipfile
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .. import log
from ..apks import Module
from ..axml import set_attribute_string
from ..dex import reader, writer
from ..dex.model import ClassDef, DexIR
from ..gen import runtime
from ..manifest import application_class, patch as patch_manifest

_IAP_HEADER = b"\x00IAP\x02"
_DEX_MAGIC = b"dex\n"


def extract_embedded_dex(data: bytes) -> List[Tuple[bytes, DexIR]]:
    """Recover dex files hidden in a PairIP asset blob.

    Two containers are understood: the classic ``00 49 41 50 02`` header with
    raw dex images at absolute offsets, and plain zip archives holding dex
    entries.  Every candidate is parsed before it is returned so garbage that
    merely starts with ``dex\\n`` is ignored.
    """

    candidates: List[bytes] = []
    if len(data) >= 117 and data[:5] == _IAP_HEADER:
        for offset in range(5, len(data) - 112 + 1):
            if data[offset:offset + 4] != _DEX_MAGIC:
                continue
            size = struct.unpack_from("<I", data, offset + 32)[0]
            if size < 112 or size > len(data) - offset:
                continue
            candidates.append(data[offset:offset + size])
    elif data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if info.filename.endswith(".dex"):
                        candidates.append(archive.read(info))
        except (OSError, ValueError, zipfile.BadZipFile):
            pass

    result: List[Tuple[bytes, DexIR]] = []
    seen: Set[bytes] = set()
    for blob in candidates:
        if blob in seen:
            continue
        seen.add(blob)
        try:
            dex = reader.parse(blob)
        except Exception:
            continue
        if dex.classes:
            result.append((blob, dex))
    return result


def _all_classes(module: Module) -> Dict[str, ClassDef]:
    known: Dict[str, ClassDef] = {}
    for name in module.dex_names():
        for cls in module.ir(name).classes:
            known.setdefault(cls.type, cls)
    return known


def _remove_pairip_defs(module: Module) -> None:
    for name in module.dex_names():
        ir = module.ir(name)
        kept = [cls for cls in ir.classes if not runtime.is_pairip(cls.type)]
        if len(kept) != len(ir.classes):
            ir.classes = kept
            module.mark_dirty(name)


def _merge_extracted(module: Module, known: Dict[str, ClassDef]) -> List[str]:
    added: List[str] = []
    existing_types = {cls.type for cls in known.values()}
    seen_types: Set[str] = set()
    raw_dexes = {entry.data for entry in module.dexes.values()}

    for name in list(module.apk.names()):
        if not name.startswith("assets/") or name.endswith("/"):
            continue
        try:
            data = module.apk.get(name)
        except KeyError:
            continue
        for blob, dex in extract_embedded_dex(data):
            if blob in raw_dexes:
                continue
            fresh = [
                cls for cls in dex.classes
                if not runtime.is_pairip(cls.type) and cls.type not in seen_types
            ]
            if not fresh:
                continue

            # An extracted class supersedes the virtualised copy in the shell.
            replaced: Set[str] = set()
            for cls in fresh:
                if cls.type not in existing_types:
                    continue
                for dex_name in module.dex_names():
                    ir = module.ir(dex_name)
                    kept = [item for item in ir.classes if item.type != cls.type]
                    if len(kept) != len(ir.classes):
                        ir.classes = kept
                        module.mark_dirty(dex_name)
                        replaced.add(cls.type)

            dex.classes = fresh
            for cls in fresh:
                seen_types.add(cls.type)
                existing_types.add(cls.type)
            new_name = module.add_dex(b"", ir=dex)
            added.append(new_name)
            log.build(f"recovered {len(fresh)} class(es) from {name} as {new_name}"
                      + (f" (replaced {len(replaced)} shell class(es))" if replaced else ""))
    return added


def _inject_launch(module: Module, target: str) -> bool:
    found = False
    for name in module.dex_names():
        ir = module.ir(name)
        for cls in ir.classes:
            if cls.type != target:
                continue
            if runtime.inject_launch(cls):
                module.mark_dirty(name)
                found = True
    return found


def apply(module: Module, dictionary: str, *, remove_native: bool = True,
          apply_manifest: bool = True) -> dict:
    fields = runtime.parse_dictionary(dictionary)
    log.info(f"dictionary contains {len(fields)} field value(s)")

    document = module.manifest()
    manifest_app = application_class(document) if document is not None else ""
    known = _all_classes(module)

    pairip_app = known.get(runtime.PAIRIP_APP)
    real_app: Optional[str] = None
    if pairip_app is not None:
        parent = pairip_app.superclass
        if parent and parent not in (runtime.OBJECT, runtime.APPLICATION):
            real_app = parent

    if real_app:
        target = real_app
    elif manifest_app:
        target = runtime.class_to_descriptor(manifest_app)
    else:
        target = runtime.PAIRIP_APP
    log.info(f"application class: {runtime.descriptor_to_class(target)}")

    extracted = _merge_extracted(module, known)
    known = _all_classes(module)

    # Build inert replacements before the originals are removed.
    stubs: Dict[str, ClassDef] = {}
    for desc, cls in known.items():
        if not runtime.is_pairip(desc) or desc == runtime.PAIRIP_APP:
            continue
        stubs[desc] = runtime.stub_class(cls, known)

    _remove_pairip_defs(module)

    runtime_classes = runtime.bridge_classes(fields)
    runtime_classes.extend(stubs.values())

    injected = _inject_launch(module, target)
    if not injected:
        log.warn(f"{target} is not present in any dex; generating a minimal stub")
        runtime_classes.append(runtime.app_stub(runtime.APPLICATION, target))
        injected = True

    runtime_name = module.add_dex(writer.write(DexIR(runtime_classes)))
    log.build(f"added translation runtime and {len(stubs)} stub(s) as {runtime_name}")

    removed_libs: List[str] = []
    if remove_native:
        removed_libs = module.apk.remove_matching(lambda name: "libpairipcore.so" in name)
        if removed_libs:
            log.build(f"removed {len(removed_libs)} native protector library(ies)")

    application_name = runtime.descriptor_to_class(target)
    if document is not None:
        if application_name != manifest_app:
            app = document.element("manifest/application")
            if app is not None:
                set_attribute_string(app, document.pool, "name", application_name)
        if apply_manifest:
            patch_manifest(document)
        module.set_manifest(document)

    return {
        "fields": len(fields),
        "stubs": len(stubs),
        "extracted_dexes": extracted,
        "runtime_dex": runtime_name,
        "removed_libraries": removed_libs,
        "application": application_name,
    }
