"""DEX writer: :class:`~dpairip.dex.model.DexIR` -> bytes.

The writer sorts every id pool the way the dex specification requires, so the
result is accepted by ART and by the usual dex tooling.  Debug information is
intentionally dropped: it keeps the output small and is irrelevant for a
repacked application.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import insns
from .model import (
    ACC_PRIVATE,
    ACC_STATIC,
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
    RawCode,
    SymbolicCode,
    SymbolicTry,
    TryBlock,
    TryHandler,
)

TYPE_HEADER = 0x0000
TYPE_STRING_ID = 0x0001
TYPE_CALL_SITE_ID = 0x0007
TYPE_TYPE_ID = 0x0002
TYPE_PROTO_ID = 0x0003
TYPE_FIELD_ID = 0x0004
TYPE_METHOD_ID = 0x0005
TYPE_CLASS_DEF = 0x0006
TYPE_METHOD_HANDLE = 0x0008
TYPE_MAP_LIST = 0x1000
TYPE_TYPE_LIST = 0x1001
TYPE_ANNOTATION_SET_REF_LIST = 0x1002
TYPE_ANNOTATION_SET = 0x1003
TYPE_CLASS_DATA = 0x2000
TYPE_CODE_ITEM = 0x2001
TYPE_STRING_DATA = 0x2002
TYPE_ANNOTATION_ITEM = 0x2004
TYPE_ENCODED_ARRAY = 0x2005
TYPE_ANNOTATIONS_DIRECTORY = 0x2006

VALUE_TYPES = {
    "byte": 0x00,
    "short": 0x02,
    "char": 0x03,
    "int": 0x04,
    "long": 0x06,
    "float": 0x10,
    "double": 0x11,
    "method_type": 0x15,
    "method_handle": 0x16,
    "string": 0x17,
    "type": 0x18,
    "field": 0x19,
    "method": 0x1A,
    "enum": 0x1B,
    "array": 0x1C,
    "annotation": 0x1D,
    "null": 0x1E,
    "boolean": 0x1F,
}


def _utf16_key(text: str) -> bytes:
    return text.encode("utf-16-be", "surrogatepass")


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _sleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _encode_mutf8(text: str) -> bytes:
    out = bytearray()
    for ch in text:
        code = ord(ch)
        if code == 0:
            out += b"\xc0\x80"
        elif code < 0x80:
            out.append(code)
        elif code < 0x800:
            out.append(0xC0 | (code >> 6))
            out.append(0x80 | (code & 0x3F))
        elif code < 0x10000:
            out.append(0xE0 | (code >> 12))
            out.append(0x80 | ((code >> 6) & 0x3F))
            out.append(0x80 | (code & 0x3F))
        else:
            # encode as a surrogate pair like the jvm does
            code -= 0x10000
            high = 0xD800 + (code >> 10)
            low = 0xDC00 + (code & 0x3FF)
            for unit in (high, low):
                out.append(0xE0 | (unit >> 12))
                out.append(0x80 | ((unit >> 6) & 0x3F))
                out.append(0x80 | (unit & 0x3F))
    return bytes(out)


def _utf16_length(text: str) -> int:
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def _param_words(proto: Proto) -> int:
    return sum(2 if p in ("J", "D") else 1 for p in proto.params)


class Pools:
    """Sorted id pools for one dex file."""

    def __init__(self) -> None:
        self.strings: Dict[str, int] = {}
        self.types: Dict[str, int] = {}
        self.protos: Dict[Proto, int] = {}
        self.fields: Dict[FieldRef, int] = {}
        self.methods: Dict[MethodRef, int] = {}
        self.method_handles: Dict[MethodHandleRef, int] = {}
        self.call_sites: Dict[CallSiteRef, int] = {}
        self.string_list: List[str] = []
        self.type_list: List[str] = []
        self.proto_list: List[Proto] = []
        self.field_list: List[FieldRef] = []
        self.method_list: List[MethodRef] = []
        self.method_handle_list: List[MethodHandleRef] = []
        self.call_site_list: List[CallSiteRef] = []

    def add_string(self, text: str) -> None:
        self.strings.setdefault(text, 0)

    def add_type(self, desc: str) -> None:
        self.add_string(desc)
        self.types.setdefault(desc, 0)

    def add_proto(self, proto: Proto) -> None:
        self.add_type(proto.return_type)
        for param in proto.params:
            self.add_type(param)
        self.add_string(proto.shorty())
        self.protos.setdefault(proto, 0)

    def add_field(self, ref: FieldRef) -> None:
        self.add_type(ref.owner)
        self.add_type(ref.type)
        self.add_string(ref.name)
        self.fields.setdefault(ref, 0)

    def add_method(self, ref: MethodRef) -> None:
        self.add_type(ref.owner)
        self.add_string(ref.name)
        self.add_proto(ref.proto)
        self.methods.setdefault(ref, 0)

    def add_value(self, value: Optional[EncodedValue]) -> None:
        if value is None:
            return
        if value.kind == "string":
            self.add_string(value.value)
        elif value.kind == "type":
            self.add_type(value.type)
        elif value.kind in ("field", "enum") and value.field_ref is not None:
            self.add_field(value.field_ref)
        elif value.kind == "method" and value.method_ref is not None:
            self.add_method(value.method_ref)
        elif value.kind == "method_type" and value.proto is not None:
            self.add_proto(value.proto)
        elif value.kind == "array":
            for item in value.array:
                self.add_value(item)
        elif value.kind == "annotation" and value.annotation is not None:
            self.add_annotation(value.annotation)

    def add_annotation(self, annotation: Annotation) -> None:
        self.add_type(annotation.type)
        for name, value in annotation.elements:
            self.add_string(name)
            self.add_value(value)

    def add_method_handle(self, handle: MethodHandleRef) -> None:
        if isinstance(handle.member, FieldRef):
            self.add_field(handle.member)
        else:
            self.add_method(handle.member)
        self.method_handles.setdefault(handle, 0)

    def add_callsite(self, site: CallSiteRef) -> None:
        self.add_method_handle(site.handle)
        self.add_string(site.name)
        self.add_proto(site.proto)
        self.call_sites.setdefault(site, 0)

    # -- finalisation -----------------------------------------------------
    def freeze(self) -> None:
        self.string_list = sorted(self.strings, key=_utf16_key)
        for index, text in enumerate(self.string_list):
            self.strings[text] = index
        self.type_list = sorted(self.types, key=lambda desc: self.strings[desc])
        for index, desc in enumerate(self.type_list):
            self.types[desc] = index
        self.proto_list = sorted(
            self.protos,
            key=lambda p: (self.types[p.return_type], tuple(self.types[x] for x in p.params)),
        )
        for index, proto in enumerate(self.proto_list):
            self.protos[proto] = index
        self.field_list = sorted(
            self.fields,
            key=lambda f: (self.types[f.owner], self.strings[f.name], self.types[f.type]),
        )
        for index, ref in enumerate(self.field_list):
            self.fields[ref] = index
        self.method_list = sorted(
            self.methods,
            key=lambda m: (self.types[m.owner], self.strings[m.name], self.protos[m.proto]),
        )
        for index, ref in enumerate(self.method_list):
            self.methods[ref] = index
        self.method_handle_list = sorted(
            self.method_handles,
            key=lambda handle: (handle.kind,
                                self.fields[handle.member] if isinstance(handle.member, FieldRef)
                                else self.methods[handle.member]),
        )
        for index, handle in enumerate(self.method_handle_list):
            self.method_handles[handle] = index
        self.call_site_list = sorted(
            self.call_sites,
            key=lambda site: (self.method_handles[site.handle],
                              self.strings[site.name], self.protos[site.proto]),
        )
        for index, site in enumerate(self.call_site_list):
            self.call_sites[site] = index

    # -- resolution -------------------------------------------------------
    def resolve(self, kind: str, value) -> int:
        if kind == "string":
            return self.strings[value]
        if kind == "type":
            return self.types[value]
        if kind == "field":
            return self.fields[value]
        if kind == "method":
            return self.methods[value]
        if kind == "proto":
            return self.protos[value]
        if kind == "method_handle":
            return self.method_handles[value]
        if kind == "callsite":
            return self.call_sites[value]
        raise ValueError(f"cannot resolve {kind} {value!r}")

    def resolve_insn(self, kind: int, value) -> int:
        name = {
            insns.REF_STRING: "string",
            insns.REF_TYPE: "type",
            insns.REF_FIELD: "field",
            insns.REF_METHOD: "method",
            insns.REF_PROTO: "proto",
            insns.REF_METHOD_HANDLE: "method_handle",
            insns.REF_CALLSITE: "callsite",
        }.get(kind)
        if name is None:
            raise NotImplementedError(f"instruction reference kind {kind}")
        return self.resolve(name, value)


# --------------------------------------------------------------------------
# writer
# --------------------------------------------------------------------------

class DexWriter:
    def __init__(self, ir: DexIR) -> None:
        self.ir = ir
        self.pools = Pools()
        self.buf = bytearray()
        self.map_entries: List[Tuple[int, int, int]] = []  # (type, size, offset)
        self._section_start: Dict[int, int] = {}
        self._section_count: Dict[int, int] = {}
        self.code_offsets: Dict[Tuple[str, str, str], int] = {}
        self._collect()

    # -- collection -------------------------------------------------------
    def _collect(self) -> None:
        pools = self.pools
        for cls in self.ir.classes:
            pools.add_type(cls.type)
            if cls.superclass:
                pools.add_type(cls.superclass)
            for interface in cls.interfaces:
                pools.add_type(interface)
            if cls.source_file:
                pools.add_string(cls.source_file)
            for annotation in cls.annotations:
                pools.add_annotation(annotation)
            for field in cls.all_fields():
                pools.add_field(FieldRef(cls.type, field.name, field.type))
                pools.add_value(field.initial)
                for annotation in field.annotations:
                    pools.add_annotation(annotation)
            for method in cls.all_methods():
                pools.add_method(MethodRef(cls.type, method.name, method.proto))
                pools.add_type(method.proto.return_type)
                for param in method.proto.params:
                    pools.add_type(param)
                pools.add_string(method.proto.shorty())
                for annotation in method.annotations:
                    pools.add_annotation(annotation)
                for group in method.parameter_annotations:
                    for annotation in group:
                        pools.add_annotation(annotation)
                code = method.code
                if isinstance(code, RawCode):
                    for _word, kind, value, _width in code.refs:
                        self._add_kind(kind, value)
                    for block in code.tries:
                        for handler in block.handlers:
                            if handler.type:
                                pools.add_type(handler.type)
                elif isinstance(code, SymbolicCode):
                    for item in code.items:
                        if not isinstance(item, insns.Insn):
                            continue
                        kind = insns.reference_kind(item.opcode)
                        ref = item.operands[-1] if item.operands else None
                        if kind == insns.REF_STRING:
                            pools.add_string(ref)
                        elif kind == insns.REF_TYPE:
                            pools.add_type(ref)
                        elif kind == insns.REF_FIELD:
                            pools.add_field(ref)
                        elif kind == insns.REF_METHOD:
                            pools.add_method(ref)
                        elif kind == insns.REF_PROTO:
                            pools.add_proto(ref.proto if hasattr(ref, "proto") else ref)
                        elif kind == insns.REF_METHOD_HANDLE:
                            pools.add_method_handle(ref)
                        elif kind == insns.REF_CALLSITE:
                            pools.add_callsite(ref)
                    for block in code.tries:
                        for handler in block.handlers:
                            ctype = handler[0] if isinstance(handler, tuple) else handler.type
                            if ctype:
                                pools.add_type(ctype)
        self.pools.freeze()

    def _add_kind(self, kind: str, value) -> None:
        if kind == "string":
            self.pools.add_string(value)
        elif kind == "type":
            self.pools.add_type(value)
        elif kind == "field":
            self.pools.add_field(value)
        elif kind == "method":
            self.pools.add_method(value)
        elif kind == "proto":
            self.pools.add_proto(value)
        elif kind == "method_handle":
            self.pools.add_method_handle(value)
        elif kind == "callsite":
            self.pools.add_callsite(value)
        else:
            raise NotImplementedError(kind)

    # -- low level --------------------------------------------------------
    def align(self, boundary: int = 4) -> None:
        while len(self.buf) % boundary:
            self.buf.append(0)

    def u1(self, value: int) -> None:
        self.buf.append(value & 0xFF)

    def u2(self, value: int) -> None:
        self.buf += struct.pack("<H", value & 0xFFFF)

    def u4(self, value: int) -> None:
        self.buf += struct.pack("<I", value & 0xFFFFFFFF)

    def raw(self, data: bytes) -> None:
        self.buf += data

    def _note(self, item_type: int, offset: int) -> None:
        if item_type not in self._section_start:
            self._section_start[item_type] = offset
            self._section_count[item_type] = 0
        self._section_count[item_type] += 1

    # -- size planning ----------------------------------------------------
    def _layout(self) -> None:
        strings = len(self.pools.string_list)
        types = len(self.pools.type_list)
        protos = len(self.pools.proto_list)
        fields = len(self.pools.field_list)
        methods = len(self.pools.method_list)
        classes = len(self.ir.classes)

        self.strings_off = 0x70
        self.types_off = self.strings_off + 4 * strings
        self.protos_off = self.types_off + 4 * types
        self.fields_off = self.protos_off + 12 * protos
        self.methods_off = self.fields_off + 8 * fields
        self.classes_off = self.methods_off + 8 * methods
        end = self.classes_off + 32 * classes
        self.data_off = (end + 3) & ~3

        self.string_ids_size = strings
        self.types_size = types
        self.protos_size = protos
        self.fields_size = fields
        self.methods_size = methods
        self.classes_size = classes

    # -- value encoding ---------------------------------------------------
    def _encode_value(self, value: EncodedValue) -> bytes:
        pool = self.pools
        kind = value.kind
        vtype = VALUE_TYPES[kind]
        if kind == "null":
            return bytes([vtype])
        if kind == "boolean":
            return bytes([vtype | ((1 if value.value else 0) << 5)])
        if kind in ("byte", "short", "int", "long"):
            raw = _minimal_signed(int(value.value))
            return bytes([vtype | ((len(raw) - 1) << 5)]) + raw
        if kind == "char":
            raw = _minimal_unsigned(int(value.value))
            return bytes([vtype | ((len(raw) - 1) << 5)]) + raw
        if kind == "float":
            return bytes([vtype | (3 << 5)]) + struct.pack("<f", float(value.value))
        if kind == "double":
            return bytes([vtype | (7 << 5)]) + struct.pack("<d", float(value.value))
        if kind == "string":
            raw = _minimal_unsigned(pool.strings[value.value])
            return bytes([vtype | ((len(raw) - 1) << 5)]) + raw
        if kind == "type":
            raw = _minimal_unsigned(pool.types[value.type])
            return bytes([vtype | ((len(raw) - 1) << 5)]) + raw
        if kind in ("field", "enum"):
            raw = _minimal_unsigned(pool.fields[value.field_ref])
            return bytes([vtype | ((len(raw) - 1) << 5)]) + raw
        if kind == "method":
            raw = _minimal_unsigned(pool.methods[value.method_ref])
            return bytes([vtype | ((len(raw) - 1) << 5)]) + raw
        if kind == "method_type":
            raw = _minimal_unsigned(pool.protos[value.proto])
            return bytes([vtype | ((len(raw) - 1) << 5)]) + raw
        if kind == "method_handle":
            raw = _minimal_unsigned(pool.method_handles[value.handle])
            return bytes([vtype | ((len(raw) - 1) << 5)]) + raw
        if kind == "array":
            out = bytearray(_uleb128(len(value.array)))
            for item in value.array:
                out += self._encode_value(item)
            return bytes([vtype]) + bytes(out)
        if kind == "annotation":
            assert value.annotation is not None
            return bytes([vtype]) + self._encode_annotation(value.annotation)
        raise NotImplementedError(kind)

    def _encode_annotation(self, annotation: Annotation) -> bytes:
        out = bytearray()
        out += _uleb128(self.pools.types[annotation.type])
        out += _uleb128(len(annotation.elements))
        for name, value in annotation.elements:
            out += _uleb128(self.pools.strings[name])
            out += self._encode_value(value)
        return bytes(out)

    # -- code -------------------------------------------------------------
    def _emit_symbolic(self, code: SymbolicCode):
        assembled, labels = _assemble(code)

        def resolve(kind: int, value) -> int:
            return self.pools.resolve_insn(kind, value)

        units: List[int] = []
        for item in assembled:
            units.extend(insns.encode_insn(item, resolve))
        if len(units) != sum(item.size for item in assembled):
            raise ValueError("instruction encoding produced an unexpected size")

        tries: List[TryBlock] = []
        for entry in code.tries:
            if isinstance(entry, SymbolicTry):
                handlers = [
                    TryHandler(ctype, labels[address] if isinstance(address, str) else address)
                    for ctype, address in entry.handlers
                ]
                start = labels[entry.start]
                end = labels[entry.end]
                tries.append(TryBlock(start, end - start, handlers))
            else:
                tries.append(entry)

        outs = code.outs
        for item in assembled:
            if 0x6E <= item.opcode <= 0x78:  # invoke-*
                if item.format == "35c":
                    outs = max(outs, len(item.operands) - 1)
                elif item.format == "3rc":
                    outs = max(outs, int(item.operands[1]))
        return units, tries, code.registers, code.ins, outs

    def _emit_raw(self, code: RawCode) -> Tuple[List[int], List[TryBlock], int, int, int]:
        units = list(code.units)
        for word, kind, value, width in code.refs:
            index = self.pools.resolve_insn(
                {
                    "string": insns.REF_STRING,
                    "type": insns.REF_TYPE,
                    "field": insns.REF_FIELD,
                    "method": insns.REF_METHOD,
                    "proto": insns.REF_PROTO,
                    "method_handle": insns.REF_METHOD_HANDLE,
                    "callsite": insns.REF_CALLSITE,
                }[kind],
                value,
            )
            units[word] = index & 0xFFFF
            if width == 2:
                units[word + 1] = index >> 16
        return units, code.tries, code.registers, code.ins, code.outs

    def _emit_code_item(self, units: Sequence[int], tries: Sequence[TryBlock],
                        registers: int, ins: int, outs: int) -> None:
        self.align(4)
        offset = len(self.buf)
        self._note(TYPE_CODE_ITEM, offset)
        self.u2(registers)
        self.u2(ins)
        self.u2(outs)
        self.u2(len(tries))
        self.u4(0)  # debug info
        self.u4(len(units))
        for unit in units:
            self.u2(unit)
        if not tries:
            return
        if len(units) % 2:
            self.u2(0)
        # encode handlers first so their offsets are known
        handlers_blob = bytearray()
        handler_offsets: List[int] = []
        prefix = _uleb128(len(tries))
        for block in tries:
            handler_offsets.append(len(prefix) + len(handlers_blob))
            typed = [h for h in block.handlers if h.type is not None]
            catch_all = next((h for h in block.handlers if h.type is None), None)
            handlers_blob += _sleb128(-len(typed) if catch_all else len(typed))
            for handler in typed:
                handlers_blob += _uleb128(self.pools.types[handler.type])
                handlers_blob += _uleb128(handler.address)
            if catch_all is not None:
                handlers_blob += _uleb128(catch_all.address)
        tries_off = len(self.buf)
        for block, handler_off in zip(tries, handler_offsets):
            self.u4(block.start)
            self.u2(block.count)
            self.u2(handler_off)
        # handler offsets are relative to the handler list header (the uleb count)
        self.raw(prefix)
        self.raw(bytes(handlers_blob))

    # -- main -------------------------------------------------------------
    def build(self) -> bytes:
        self._layout()
        self.buf = bytearray(b"\x00" * self.data_off)

        # 1. type lists (proto parameters and interfaces)
        proto_params: Dict[Proto, int] = {}
        for proto in self.pools.proto_list:
            if not proto.params:
                proto_params[proto] = 0
                continue
            self.align(4)
            offset = len(self.buf)
            self._note(TYPE_TYPE_LIST, offset)
            proto_params[proto] = offset
            self.u4(len(proto.params))
            for param in proto.params:
                self.u2(self.pools.types[param])
        interface_offsets: Dict[str, int] = {}
        for cls in self.ir.classes:
            if not cls.interfaces:
                continue
            self.align(4)
            offset = len(self.buf)
            self._note(TYPE_TYPE_LIST, offset)
            interface_offsets[cls.type] = offset
            self.u4(len(cls.interfaces))
            for interface in cls.interfaces:
                self.u2(self.pools.types[interface])

        # 1b. method handles and call sites (dex 038+)
        if self.pools.method_handle_list:
            self.align(4)
            self._note(TYPE_METHOD_HANDLE, len(self.buf))
            for handle in self.pools.method_handle_list:
                member = handle.member
                index = (self.pools.fields[member] if isinstance(member, FieldRef)
                         else self.pools.methods[member])
                self.u2(handle.kind)
                self.u2(0)
                self.u2(index)
                self.u2(0)
        if self.pools.call_site_list:
            self.align(4)
            self._note(TYPE_CALL_SITE_ID, len(self.buf))
            table = len(self.buf)
            self.buf += bytearray(4 * len(self.pools.call_site_list))
            for index, site in enumerate(self.pools.call_site_list):
                struct.pack_into("<I", self.buf, table + 4 * index, len(self.buf))
                self.raw(_uleb128(3))
                self.raw(_encoded_index(0x16, self.pools.method_handles[site.handle]))
                self.raw(_encoded_index(0x17, self.pools.strings[site.name]))
                self.raw(_encoded_index(0x15, self.pools.protos[site.proto]))

        # 2. annotation items
        annotation_offsets: Dict[int, int] = {}

        def emit_annotation(annotation: Annotation) -> int:
            key = id(annotation)
            if key in annotation_offsets:
                return annotation_offsets[key]
            offset = len(self.buf)
            self._note(TYPE_ANNOTATION_ITEM, offset)
            self.u1(annotation.visibility)
            self.raw(self._encode_annotation(annotation))
            annotation_offsets[key] = offset
            return offset

        # 3. annotation sets
        set_offsets: Dict[Tuple[int, ...], int] = {}

        def set_key(annotations: Sequence[Annotation]) -> Tuple[int, ...]:
            return tuple(sorted(id(a) for a in annotations))

        def emit_set(annotations: Sequence[Annotation]) -> int:
            if not annotations:
                return 0
            key = set_key(annotations)
            if key in set_offsets:
                return set_offsets[key]
            for annotation in annotations:
                emit_annotation(annotation)
            self.align(4)
            offset = len(self.buf)
            self._note(TYPE_ANNOTATION_SET, offset)
            set_offsets[key] = offset
            ordered = sorted(annotations, key=lambda a: self.pools.types[a.type])
            self.u4(len(ordered))
            for annotation in ordered:
                self.u4(annotation_offsets[id(annotation)])
            return offset

        # every set is materialised before the structures that point at it
        for cls in self.ir.classes:
            emit_set(cls.annotations)
            for field in cls.all_fields():
                emit_set(field.annotations)
            for method in cls.all_methods():
                emit_set(method.annotations)
                for group in method.parameter_annotations:
                    emit_set(group)

        # 4. annotation set ref lists (method parameters)
        param_ref_offsets: Dict[Tuple[int, ...], int] = {}
        for cls in self.ir.classes:
            for method in cls.all_methods():
                if not any(method.parameter_annotations):
                    continue
                key = tuple(id(a) for group in method.parameter_annotations for a in group)
                if key in param_ref_offsets:
                    continue
                self.align(4)
                offset = len(self.buf)
                self._note(TYPE_ANNOTATION_SET_REF_LIST, offset)
                param_ref_offsets[key] = offset
                self.u4(len(method.parameter_annotations))
                for group in method.parameter_annotations:
                    self.u4(emit_set(group))

        # 5. annotation directories
        directory_offsets: Dict[str, int] = {}
        for cls in self.ir.classes:
            field_entries = [
                (self.pools.fields[FieldRef(cls.type, f.name, f.type)], f.annotations)
                for f in cls.all_fields() if f.annotations
            ]
            method_entries = [
                (self.pools.methods[MethodRef(cls.type, m.name, m.proto)], m.annotations)
                for m in cls.all_methods() if m.annotations
            ]
            param_methods = [
                (self.pools.methods[MethodRef(cls.type, m.name, m.proto)], m.parameter_annotations)
                for m in cls.all_methods() if any(m.parameter_annotations)
            ]
            if not (cls.annotations or field_entries or method_entries or param_methods):
                continue
            self.align(4)
            offset = len(self.buf)
            self._note(TYPE_ANNOTATIONS_DIRECTORY, offset)
            directory_offsets[cls.type] = offset
            self.u4(emit_set(cls.annotations))
            self.u4(len(field_entries))
            self.u4(len(method_entries))
            self.u4(len(param_methods))
            for index, annotations in sorted(field_entries, key=lambda item: item[0]):
                self.u4(index)
                self.u4(emit_set(annotations))
            for index, annotations in sorted(method_entries, key=lambda item: item[0]):
                self.u4(index)
                self.u4(emit_set(annotations))
            for index, params in sorted(param_methods, key=lambda item: item[0]):
                key = tuple(id(a) for group in params for a in group)
                self.u4(index)
                self.u4(param_ref_offsets[key])

        # 6. static values
        static_value_offsets: Dict[str, int] = {}
        for cls in self.ir.classes:
            fields = sorted(cls.static_fields, key=lambda f: self.pools.fields[FieldRef(cls.type, f.name, f.type)])
            last = -1
            for i, field in enumerate(fields):
                if field.initial is not None:
                    last = i
            if last < 0:
                continue
            offset = len(self.buf)
            self._note(TYPE_ENCODED_ARRAY, offset)
            static_value_offsets[cls.type] = offset
            self.raw(_uleb128(last + 1))
            for field in fields[: last + 1]:
                self.raw(self._encode_value(field.initial or EncodedValue.null()))

        # 7. code items
        for cls in self.ir.classes:
            for method in cls.all_methods():
                code = method.code
                if code is None:
                    continue
                if isinstance(code, RawCode):
                    units, tries, registers, ins, outs = self._emit_raw(code)
                else:
                    units, tries, registers, ins, outs = self._emit_symbolic(code)
                self.align(4)
                self.code_offsets[(cls.type, method.name, method.proto.descriptor())] = len(self.buf)
                self._emit_code_item(units, tries, registers, ins, outs)

        # 8. class data
        class_data_offsets: Dict[str, int] = {}
        for cls in self.ir.classes:
            if not (cls.static_fields or cls.instance_fields or cls.direct_methods or cls.virtual_methods):
                continue
            offset = len(self.buf)
            self._note(TYPE_CLASS_DATA, offset)
            class_data_offsets[cls.type] = offset
            static_fields = sorted(
                cls.static_fields,
                key=lambda f: self.pools.fields[FieldRef(cls.type, f.name, f.type)],
            )
            instance_fields = sorted(
                cls.instance_fields,
                key=lambda f: self.pools.fields[FieldRef(cls.type, f.name, f.type)],
            )
            direct = sorted(
                [m for m in cls.all_methods() if m.is_direct],
                key=lambda m: self.pools.methods[MethodRef(cls.type, m.name, m.proto)],
            )
            virtual = sorted(
                [m for m in cls.all_methods() if not m.is_direct],
                key=lambda m: self.pools.methods[MethodRef(cls.type, m.name, m.proto)],
            )
            self.raw(_uleb128(len(static_fields)))
            self.raw(_uleb128(len(instance_fields)))
            self.raw(_uleb128(len(direct)))
            self.raw(_uleb128(len(virtual)))
            for group in (static_fields, instance_fields):
                index = 0
                for field in group:
                    delta = self.pools.fields[FieldRef(cls.type, field.name, field.type)] - index
                    index += delta
                    self.raw(_uleb128(delta))
                    self.raw(_uleb128(field.access))
            for group in (direct, virtual):
                index = 0
                for method in group:
                    delta = self.pools.methods[MethodRef(cls.type, method.name, method.proto)] - index
                    index += delta
                    self.raw(_uleb128(delta))
                    self.raw(_uleb128(method.access))
                    code_off = self.code_offsets.get(
                        (cls.type, method.name, method.proto.descriptor()), 0
                    )
                    if code_off and code_off < self.data_off:
                        raise ValueError("code offset outside of the data section")
                    self.raw(_uleb128(code_off))

        # 9. string data
        string_offsets: List[int] = []
        for text in self.pools.string_list:
            string_offsets.append(len(self.buf))
            self.raw(_uleb128(_utf16_length(text)))
            self.raw(_encode_mutf8(text))
            self.u1(0)

        # 10. map list
        self.align(4)
        map_off = len(self.buf)
        sections = dict(self._section_start)
        counts = dict(self._section_count)
        fixed = [
            (TYPE_HEADER, 1, 0),
            (TYPE_STRING_ID, self.string_ids_size, self.strings_off),
            (TYPE_TYPE_ID, self.types_size, self.types_off),
            (TYPE_PROTO_ID, self.protos_size, self.protos_off),
            (TYPE_FIELD_ID, self.fields_size, self.fields_off),
            (TYPE_METHOD_ID, self.methods_size, self.methods_off),
            (TYPE_CLASS_DEF, self.classes_size, self.classes_off),
        ]
        for item_type, offset in sections.items():
            fixed.append((item_type, counts[item_type], offset))
        fixed.append((TYPE_MAP_LIST, 1, map_off))
        entries = sorted(fixed, key=lambda item: item[2])
        self.u4(len(entries))
        for item_type, size, offset in entries:
            self.u2(item_type)
            self.u2(0)
            self.u4(size)
            self.u4(offset)
        self.map_off = map_off

        # 11. fixed sections
        self._write_ids(proto_params, interface_offsets, class_data_offsets,
                        static_value_offsets, directory_offsets, string_offsets, map_off)
        self._write_header()
        return bytes(self.buf)

    def _write_ids(self, proto_params, interface_offsets, class_data_offsets,
                   static_value_offsets, directory_offsets, string_offsets, map_off) -> None:
        buf = self.buf
        pools = self.pools

        for i, text in enumerate(pools.string_list):
            struct.pack_into("<I", buf, self.strings_off + 4 * i, string_offsets[i])

        for i, desc in enumerate(pools.type_list):
            struct.pack_into("<I", buf, self.types_off + 4 * i, pools.strings[desc])

        for i, proto in enumerate(pools.proto_list):
            base = self.protos_off + 12 * i
            struct.pack_into("<I", buf, base, pools.strings[proto.shorty()])
            struct.pack_into("<I", buf, base + 4, pools.types[proto.return_type])
            struct.pack_into("<I", buf, base + 8, proto_params[proto])

        for i, ref in enumerate(pools.field_list):
            base = self.fields_off + 8 * i
            struct.pack_into("<H", buf, base, pools.types[ref.owner])
            struct.pack_into("<H", buf, base + 2, pools.types[ref.type])
            struct.pack_into("<I", buf, base + 4, pools.strings[ref.name])

        for i, ref in enumerate(pools.method_list):
            base = self.methods_off + 8 * i
            struct.pack_into("<H", buf, base, pools.types[ref.owner])
            struct.pack_into("<H", buf, base + 2, pools.protos[ref.proto])
            struct.pack_into("<I", buf, base + 4, pools.strings[ref.name])

        classes = sorted(self.ir.classes, key=lambda c: pools.types[c.type])
        self.classes_size = len(classes)
        for i, cls in enumerate(classes):
            base = self.classes_off + 32 * i
            struct.pack_into("<I", buf, base, pools.types[cls.type])
            struct.pack_into("<I", buf, base + 4, cls.access)
            superclass = pools.types[cls.superclass] if cls.superclass else 0xFFFFFFFF
            struct.pack_into("<I", buf, base + 8, superclass)
            struct.pack_into("<I", buf, base + 12, interface_offsets.get(cls.type, 0))
            source = pools.strings[cls.source_file] if cls.source_file else 0xFFFFFFFF
            struct.pack_into("<I", buf, base + 16, source)
            struct.pack_into("<I", buf, base + 20, directory_offsets.get(cls.type, 0))
            struct.pack_into("<I", buf, base + 24, class_data_offsets.get(cls.type, 0))
            struct.pack_into("<I", buf, base + 28, static_value_offsets.get(cls.type, 0))

    def _write_header(self) -> None:
        buf = self.buf
        version = min(max(getattr(self.ir, "version", 35), 35), 41)
        if self.pools.call_site_list or self.pools.method_handle_list:
            version = max(version, 38)
        buf[0:8] = f"dex\n{version:03d}\x00".encode("ascii")
        struct.pack_into("<I", buf, 32, len(buf))
        struct.pack_into("<I", buf, 36, 0x70)
        struct.pack_into("<I", buf, 40, 0x12345678)
        struct.pack_into("<I", buf, 44, 0)  # link_size
        struct.pack_into("<I", buf, 48, 0)  # link_off
        struct.pack_into("<I", buf, 52, self.map_off)
        struct.pack_into("<I", buf, 56, self.string_ids_size)
        struct.pack_into("<I", buf, 60, self.strings_off)
        struct.pack_into("<I", buf, 64, self.types_size)
        struct.pack_into("<I", buf, 68, self.types_off)
        struct.pack_into("<I", buf, 72, self.protos_size)
        struct.pack_into("<I", buf, 76, self.protos_off)
        struct.pack_into("<I", buf, 80, self.fields_size)
        struct.pack_into("<I", buf, 84, self.fields_off)
        struct.pack_into("<I", buf, 88, self.methods_size)
        struct.pack_into("<I", buf, 92, self.methods_off)
        struct.pack_into("<I", buf, 96, self.classes_size)
        struct.pack_into("<I", buf, 100, self.classes_off)
        struct.pack_into("<I", buf, 104, len(buf) - self.data_off)
        struct.pack_into("<I", buf, 108, self.data_off)

        # Signatures cover everything from file_size onwards, and the adler32
        # covers the signature as well, so both must be written last.
        buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
        struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)


def _minimal_signed(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    for size in range(1, 9):
        try:
            raw = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            continue
        if value.to_bytes(8, "little", signed=True)[:size] == raw:
            return raw
    return value.to_bytes(8, "little", signed=True)


def _minimal_unsigned(value: int) -> bytes:
    size = 1
    while value >> (8 * size):
        size += 1
    return value.to_bytes(size, "little")


def _encoded_index(value_type: int, index: int) -> bytes:
    raw = _minimal_unsigned(index)
    return bytes([value_type | ((len(raw) - 1) << 5)]) + raw


def _assemble(code: SymbolicCode):
    from .insns import CodeBuffer

    buffer = CodeBuffer(code.registers, code.ins, code.outs)
    buffer.items = list(code.items)
    buffer.tries = []
    return buffer.assemble()


def write(ir: DexIR) -> bytes:
    return DexWriter(ir).build()
