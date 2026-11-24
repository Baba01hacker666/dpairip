"""DEX reader: bytes -> :class:`~dpairip.dex.model.DexIR`."""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Sequence, Tuple

from . import insns
from .model import (
    Annotation,
    CallSiteRef,
    ClassDef,
    DexIR,
    EncodedValue,
    FieldDef,
    FieldRef,
    MethodDef,
    MethodHandleRef,
    MethodRef,
    Proto,
    ProtoRef,
    RawCode,
    TryBlock,
    TryHandler,
)

HEADER_SIZE = 0x70


class DexParseError(ValueError):
    pass


def is_dex(data: bytes) -> bool:
    return len(data) >= 8 and data[:4] == b"dex\n" and data[7] == 0


class _Reader:
    def __init__(self, data: bytes):
        if not is_dex(data):
            raise DexParseError("not a dex file")
        self.data = data
        (self.strings_size, self.strings_off,
         self.types_size, self.types_off,
         self.protos_size, self.protos_off,
         self.fields_size, self.fields_off,
         self.methods_size, self.methods_off,
         self.classes_size, self.classes_off) = struct.unpack_from("<12I", data, 0x38)

    # -- primitives ------------------------------------------------------
    def u1(self, off: int) -> int:
        return self.data[off]

    def u2(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def u4(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def uleb(self, off: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        while True:
            byte = self.data[off]
            off += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result, off
            shift += 7

    def sleb(self, off: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        while True:
            byte = self.data[off]
            off += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if byte & 0x40:
                    result -= 1 << shift
                return result, off

    def mutf8(self, off: int) -> Tuple[str, int]:
        _size, off = self.uleb(off)
        end = self.data.index(b"\x00", off)
        raw = self.data[off:end]
        return _decode_mutf8(raw), end + 1

    # -- pools -----------------------------------------------------------
    def load_strings(self) -> List[str]:
        return [
            self.mutf8(self.u4(self.strings_off + 4 * i))[0]
            for i in range(self.strings_size)
        ]

    def load_types(self, strings: Sequence[str]) -> List[str]:
        return [strings[self.u4(self.types_off + 4 * i)] for i in range(self.types_size)]

    def load_protos(self, types: Sequence[str]) -> List[Proto]:
        protos: List[Proto] = []
        for i in range(self.protos_size):
            base = self.protos_off + 12 * i
            return_type = types[self.u4(base + 4)]
            params_off = self.u4(base + 8)
            params: Tuple[str, ...] = ()
            if params_off:
                size = self.u4(params_off)
                params = tuple(types[self.u2(params_off + 4 + 2 * j)] for j in range(size))
            protos.append(Proto(params, return_type))
        return protos

    def load_fields(self, types: Sequence[str], strings: Sequence[str]) -> List[FieldRef]:
        out = []
        for i in range(self.fields_size):
            base = self.fields_off + 8 * i
            out.append(
                FieldRef(
                    types[self.u2(base)],
                    strings[self.u4(base + 4)],
                    types[self.u2(base + 2)],
                )
            )
        return out

    def load_methods(
        self, types: Sequence[str], strings: Sequence[str], protos: Sequence[Proto]
    ) -> List[MethodRef]:
        out = []
        for i in range(self.methods_size):
            base = self.methods_off + 8 * i
            out.append(
                MethodRef(
                    types[self.u2(base)],
                    strings[self.u4(base + 4)],
                    protos[self.u2(base + 2)],
                )
            )
        return out

    # -- encoded values --------------------------------------------------
    def read_encoded_value(self, off: int, pools: "_Pools") -> Tuple[EncodedValue, int]:
        header = self.u1(off)
        off += 1
        value_type = header & 0x1F
        arg = header >> 5

        def signed(n: int) -> int:
            raw = int.from_bytes(self.data[off:off + n + 1], "little")
            bits = (n + 1) * 8
            if raw & (1 << (bits - 1)):
                raw -= 1 << bits
            return raw

        if value_type == 0x00:
            val = signed(arg)
            return EncodedValue("byte", val), off + arg + 1
        if value_type == 0x02:
            val = signed(arg)
            return EncodedValue("short", val), off + arg + 1
        if value_type == 0x03:
            val = int.from_bytes(self.data[off:off + arg + 1], "little")
            return EncodedValue("char", val), off + arg + 1
        if value_type == 0x04:
            val = signed(arg)
            return EncodedValue("int", val), off + arg + 1
        if value_type == 0x06:
            val = signed(arg)
            return EncodedValue("long", val), off + arg + 1
        if value_type == 0x10:
            # the bit pattern is zero-extended to the right, which in a
            # little-endian file means padding the byte stream on the left
            raw = self.data[off:off + arg + 1].rjust(4, b"\x00")
            return EncodedValue("float", struct.unpack("<f", raw)[0]), off + arg + 1
        if value_type == 0x11:
            raw = self.data[off:off + arg + 1].rjust(8, b"\x00")
            return EncodedValue("double", struct.unpack("<d", raw)[0]), off + arg + 1
        if value_type == 0x15:
            idx = int.from_bytes(self.data[off:off + arg + 1], "little")
            return EncodedValue("method_type", proto=pools.protos[idx]), off + arg + 1
        if value_type == 0x16:
            idx = int.from_bytes(self.data[off:off + arg + 1], "little")
            return EncodedValue("method_handle", handle=pools.handles[idx]), off + arg + 1
        if value_type == 0x17:
            idx = int.from_bytes(self.data[off:off + arg + 1], "little")
            return EncodedValue("string", pools.strings[idx]), off + arg + 1
        if value_type == 0x18:
            idx = int.from_bytes(self.data[off:off + arg + 1], "little")
            return EncodedValue("type", type=pools.types[idx]), off + arg + 1
        if value_type == 0x19:
            idx = int.from_bytes(self.data[off:off + arg + 1], "little")
            return EncodedValue("field", field_ref=pools.fields[idx]), off + arg + 1
        if value_type == 0x1A:
            idx = int.from_bytes(self.data[off:off + arg + 1], "little")
            return EncodedValue("method", method_ref=pools.methods[idx]), off + arg + 1
        if value_type == 0x1B:
            idx = int.from_bytes(self.data[off:off + arg + 1], "little")
            return EncodedValue("enum", field_ref=pools.fields[idx]), off + arg + 1
        if value_type == 0x1C:
            size, off = self.uleb(off)
            items = []
            for _ in range(size):
                value, off = self.read_encoded_value(off, pools)
                items.append(value)
            return EncodedValue("array", array=items), off
        if value_type == 0x1D:
            annotation, off = self.read_encoded_annotation(off, pools)
            return EncodedValue("annotation", annotation=annotation), off
        if value_type == 0x1E:
            return EncodedValue("null"), off
        if value_type == 0x1F:
            return EncodedValue("boolean", bool(arg)), off
        raise DexParseError(f"unknown encoded value type {value_type:#x}")

    def read_encoded_annotation(self, off: int, pools: "_Pools") -> Tuple[Annotation, int]:
        type_idx, off = self.uleb(off)
        size, off = self.uleb(off)
        elements = []
        for _ in range(size):
            name_idx, off = self.uleb(off)
            value, off = self.read_encoded_value(off, pools)
            elements.append((pools.strings[name_idx], value))
        return Annotation(1, pools.types[type_idx], elements), off

    def read_annotation_set(self, off: int, pools: "_Pools") -> List[Annotation]:
        size = self.u4(off)
        out = []
        for i in range(size):
            item_off = self.u4(off + 4 + 4 * i)
            visibility = self.u1(item_off)
            annotation, _ = self.read_encoded_annotation(item_off + 1, pools)
            annotation.visibility = visibility
            out.append(annotation)
        return out

    # -- code ------------------------------------------------------------
    def read_code(self, off: int, pools: "_Pools") -> RawCode:
        registers, ins, outs, tries_size = struct.unpack_from("<4H", self.data, off)
        insns_size = self.u4(off + 12)
        units_off = off + 16
        units = list(struct.unpack_from(f"<{insns_size}H", self.data, units_off))
        tries: List[TryBlock] = []
        if tries_size:
            tries_off = units_off + 2 * insns_size + (insns_size % 2) * 2
            handlers_off = tries_off + 8 * tries_size
            for i in range(tries_size):
                start, count, handler_off = struct.unpack_from("<IHH", self.data, tries_off + 8 * i)
                hoff = handlers_off + handler_off
                size, hoff = self.sleb(hoff)
                handlers: List[TryHandler] = []
                for _ in range(abs(size)):
                    type_idx, hoff = self.uleb(hoff)
                    address, hoff = self.uleb(hoff)
                    handlers.append(TryHandler(pools.types[type_idx], address))
                if size <= 0:
                    address, hoff = self.uleb(hoff)
                    handlers.append(TryHandler(None, address))
                tries.append(TryBlock(start, count, handlers))
        refs = _scan_refs(units, pools)
        return RawCode(registers, ins, outs, units, tries, refs, off)


class _Pools:
    """Bundles the id pools so encoded values can resolve references."""

    def __init__(self, reader: _Reader):
        self.strings = reader.load_strings()
        self.types = reader.load_types(self.strings)
        self.protos = reader.load_protos(self.types)
        self.fields = reader.load_fields(self.types, self.strings)
        self.methods = reader.load_methods(self.types, self.strings, self.protos)
        self.handles = _load_method_handles(reader, self)
        self.call_sites = _load_call_sites(reader, self)


def _find_map_section(reader: _Reader, item_type: int) -> Tuple[int, int]:
    """Return ``(offset, count)`` of a data section described by the map list."""

    map_off = reader.u4(0x34)
    if not map_off:
        return 0, 0
    for i in range(reader.u4(map_off)):
        base = map_off + 4 + 12 * i
        if reader.u2(base) == item_type:
            return reader.u4(base + 8), reader.u4(base + 4)
    return 0, 0


def _load_call_sites(reader: _Reader, pools: _Pools) -> List[CallSiteRef]:
    offset, count = _find_map_section(reader, 0x0007)
    result: List[CallSiteRef] = []
    for i in range(count):
        array_off = reader.u4(offset + 4 * i)
        if not array_off:
            continue
        size, cursor = reader.uleb(array_off)
        values = []
        for _ in range(size):
            value, cursor = reader.read_encoded_value(cursor, pools)
            values.append(value)
        if len(values) != 3:
            continue
        handle, name, proto = values
        if (handle.kind == "method_handle" and name.kind == "string"
                and proto.kind == "method_type"):
            result.append(CallSiteRef(handle.handle, name.value, proto.proto))
    return result


def _load_method_handles(reader: _Reader, pools: _Pools) -> List[MethodHandleRef]:
    """Method handles live in the data section; locate them through the map."""
    handles: List[MethodHandleRef] = []
    map_off = reader.u4(0x34)
    if not map_off:
        return handles
    count = reader.u4(map_off)
    for i in range(count):
        item_type = reader.u2(map_off + 4 + 12 * i)
        size = reader.u4(map_off + 4 + 12 * i + 4)
        offset = reader.u4(map_off + 4 + 12 * i + 8)
        if item_type != 0x0008:  # TYPE_METHOD_HANDLE
            continue
        for j in range(size):
            kind = reader.u2(offset + 4 * j)
            member_idx = reader.u2(offset + 4 * j + 2)
            if kind <= 3:
                handles.append(MethodHandleRef(kind, pools.fields[member_idx]))
            else:
                handles.append(MethodHandleRef(kind, pools.methods[member_idx]))
    return handles


def _scan_refs(units: Sequence[int], pools: _Pools) -> List[Tuple[int, str, object, int]]:
    """Record every code unit that holds a pool index."""
    refs: List[Tuple[int, str, object, int]] = []

    def add(word: int, kind: str, value: object, width: int = 1) -> None:
        refs.append((word, kind, value, width))

    for addr, unit, size in insns.iter_instructions(units):
        if unit in (insns.PAYLOAD_PACKED_SWITCH, insns.PAYLOAD_SPARSE_SWITCH,
                    insns.PAYLOAD_ARRAY_DATA):
            continue
        op = unit & 0xFF
        name = insns.OPCODE_NAMES[op]
        fmt = insns.OPCODE_FORMATS[op]
        if fmt == "21c" or fmt == "22c":
            kind = insns.reference_kind(op)
            idx = units[addr + 1]
            add(addr + 1, _KIND_NAMES[kind], _resolve(kind, idx, pools))
        elif fmt == "31c":
            kind = insns.reference_kind(op)
            idx = units[addr + 1] | (units[addr + 2] << 16)
            add(addr + 1, _KIND_NAMES[kind], _resolve(kind, idx, pools), 2)
        elif fmt in ("35c", "3rc"):
            # AA|op BBBB ... -> the pool index lives in the second unit
            kind = insns.reference_kind(op)
            add(addr + 1, _KIND_NAMES[kind], _resolve(kind, units[addr + 1], pools))
        elif fmt in ("45cc", "4rcc"):
            add(addr + 1, "method", pools.methods[units[addr + 1]])
            add(addr + 2, "proto", pools.protos[units[addr + 2]])
    return refs


_KIND_NAMES = {
    insns.REF_STRING: "string",
    insns.REF_TYPE: "type",
    insns.REF_FIELD: "field",
    insns.REF_METHOD: "method",
    insns.REF_PROTO: "proto",
    insns.REF_METHOD_HANDLE: "method_handle",
    insns.REF_CALLSITE: "callsite",
}


def _resolve(kind: int, idx: int, pools: _Pools):
    if kind == insns.REF_STRING:
        return pools.strings[idx]
    if kind == insns.REF_TYPE:
        return pools.types[idx]
    if kind == insns.REF_FIELD:
        return pools.fields[idx]
    if kind == insns.REF_METHOD:
        return pools.methods[idx]
    if kind == insns.REF_PROTO:
        return pools.protos[idx]
    if kind == insns.REF_METHOD_HANDLE:
        return pools.handles[idx]
    if kind == insns.REF_CALLSITE:
        return pools.call_sites[idx]
    raise DexParseError(f"unsupported reference kind {kind}")


def _decode_mutf8(raw: bytes) -> str:
    # fast path: plain utf-8 without encoded NULs
    try:
        if b"\xc0\x80" not in raw:
            return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    out = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if b < 0x80:
            out.append(chr(b))
            i += 1
        elif b & 0xE0 == 0xC0:
            out.append(chr(((b & 0x1F) << 6) | (raw[i + 1] & 0x3F)))
            i += 2
        elif b & 0xF0 == 0xE0:
            out.append(chr(((b & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6) | (raw[i + 2] & 0x3F)))
            i += 3
        else:
            raise DexParseError("bad modified utf-8")
    return "".join(out)


def _read_class_data(
    reader: _Reader, off: int, pools: _Pools, class_type: str
) -> Tuple[List[FieldDef], List[FieldDef], List[Tuple[int, int, int]], List[Tuple[int, int, int]]]:
    static_count, off = reader.uleb(off)
    instance_count, off = reader.uleb(off)
    direct_count, off = reader.uleb(off)
    virtual_count, off = reader.uleb(off)

    def read_fields(count: int):
        nonlocal off
        out: List[FieldDef] = []
        field_idx = 0
        for _ in range(count):
            diff, off = reader.uleb(off)
            access, off = reader.uleb(off)
            field_idx += diff
            ref = pools.fields[field_idx]
            out.append(FieldDef(ref.name, ref.type, access))
        return out

    static_fields = read_fields(static_count)
    instance_fields = read_fields(instance_count)

    def read_methods(count: int):
        nonlocal off
        out: List[Tuple[int, int, int]] = []
        method_idx = 0
        for _ in range(count):
            diff, off = reader.uleb(off)
            access, off = reader.uleb(off)
            code_off, off = reader.uleb(off)
            method_idx += diff
            out.append((method_idx, access, code_off))
        return out

    direct_methods = read_methods(direct_count)
    virtual_methods = read_methods(virtual_count)
    return static_fields, instance_fields, direct_methods, virtual_methods


def parse(data: bytes) -> DexIR:
    """Parse ``data`` into a mutable :class:`DexIR`."""
    reader = _Reader(data)
    pools = _Pools(reader)
    ir = DexIR(version=35)
    try:
        ir.version = int(data[4:7])
    except Exception:  # pragma: no cover - defensive
        pass

    for i in range(reader.classes_size):
        base = reader.classes_off + 32 * i
        class_idx = reader.u4(base)
        access = reader.u4(base + 4)
        superclass_idx = reader.u4(base + 8)
        interfaces_off = reader.u4(base + 12)
        source_idx = reader.u4(base + 16)
        annotations_off = reader.u4(base + 20)
        class_data_off = reader.u4(base + 24)
        static_values_off = reader.u4(base + 28)

        cls = ClassDef(
            type=pools.types[class_idx],
            access=access,
            superclass=pools.types[superclass_idx] if superclass_idx != 0xFFFFFFFF else None,
            source_file=pools.strings[source_idx] if source_idx != 0xFFFFFFFF else None,
        )
        if interfaces_off:
            size = reader.u4(interfaces_off)
            cls.interfaces = [pools.types[reader.u2(interfaces_off + 4 + 2 * j)] for j in range(size)]

        if class_data_off:
            static_fields, instance_fields, direct, virtual = _read_class_data(
                reader, class_data_off, pools, cls.type
            )
            cls.static_fields = static_fields
            cls.instance_fields = instance_fields
            cls.direct_methods = [
                MethodDef(pools.methods[idx].name, pools.methods[idx].proto, acc,
                          reader.read_code(code_off, pools) if code_off else None)
                for idx, acc, code_off in direct
            ]
            cls.virtual_methods = [
                MethodDef(pools.methods[idx].name, pools.methods[idx].proto, acc,
                          reader.read_code(code_off, pools) if code_off else None)
                for idx, acc, code_off in virtual
            ]

        if static_values_off:
            _attach_static_values(reader, static_values_off, pools, cls)

        if annotations_off:
            _attach_annotations(reader, annotations_off, pools, cls)

        ir.classes.append(cls)

    return ir


def _attach_static_values(reader: _Reader, off: int, pools: _Pools, cls: ClassDef) -> None:
    size, off = reader.uleb(off)
    for i in range(size):
        value, off = reader.read_encoded_value(off, pools)
        if i < len(cls.static_fields):
            cls.static_fields[i].initial = value


def _attach_annotations(reader: _Reader, off: int, pools: _Pools, cls: ClassDef) -> None:
    class_annotations_off = reader.u4(off)
    fields_size = reader.u4(off + 4)
    methods_size = reader.u4(off + 8)
    params_size = reader.u4(off + 12)

    if class_annotations_off:
        cls.annotations = reader.read_annotation_set(class_annotations_off, pools)

    cursor = off + 16
    field_map: Dict[Tuple[str, str], FieldDef] = {
        (f.name, f.type): f for f in cls.all_fields()
    }
    for i in range(fields_size):
        idx = reader.u4(cursor + 8 * i)
        set_off = reader.u4(cursor + 8 * i + 4)
        ref = pools.fields[idx]
        target = field_map.get((ref.name, ref.type))
        if target is not None and set_off:
            target.annotations = reader.read_annotation_set(set_off, pools)

    cursor += 8 * fields_size
    method_map: Dict[Tuple[str, str], MethodDef] = {
        (m.name, m.proto.descriptor()): m for m in cls.all_methods()
    }
    for i in range(methods_size):
        idx = reader.u4(cursor + 8 * i)
        set_off = reader.u4(cursor + 8 * i + 4)
        ref = pools.methods[idx]
        target = method_map.get((ref.name, ref.proto.descriptor()))
        if target is not None and set_off:
            target.annotations = reader.read_annotation_set(set_off, pools)

    cursor += 8 * methods_size
    for i in range(params_size):
        idx = reader.u4(cursor + 8 * i)
        ref_list_off = reader.u4(cursor + 8 * i + 4)
        ref = pools.methods[idx]
        target = method_map.get((ref.name, ref.proto.descriptor()))
        if target is None or not ref_list_off:
            continue
        count = reader.u4(ref_list_off)
        target.parameter_annotations = [[] for _ in range(count)]
        for j in range(count):
            set_off = reader.u4(ref_list_off + 4 + 4 * j)
            if set_off:
                target.parameter_annotations[j] = reader.read_annotation_set(set_off, pools)


def read_file(path: str) -> DexIR:
    with open(path, "rb") as handle:
        return parse(handle.read())
