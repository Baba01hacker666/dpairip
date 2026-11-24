"""Reader/writer for Android's binary XML (``AndroidManifest.xml``).

The format is a sequence of chunks: a string pool, an optional resource map and
a flat list of XML nodes.  Nodes keep their original string indices, so editing
(other than appending strings) never disturbs the rest of the document.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Sequence

CHUNK_NULL = 0x0000
CHUNK_STRING_POOL = 0x0001
CHUNK_XML = 0x0003
CHUNK_RESOURCE_MAP = 0x0180
CHUNK_START_NAMESPACE = 0x0100
CHUNK_END_NAMESPACE = 0x0101
CHUNK_START_ELEMENT = 0x0102
CHUNK_END_ELEMENT = 0x0103
CHUNK_CDATA = 0x0104

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

NO_ENTRY = 0xFFFFFFFF
UTF8_FLAG = 0x00000100

# android resource ids used by the manifest patcher
RES_DEBUGGABLE = 0x0101000B
RES_EXTRACT_NATIVE_LIBS = 0x010104EA
RES_NAME = 0x01010003
RES_REQUIRED_SPLIT_TYPES = 0x0101058B
RES_SPLIT_TYPES = 0x0101058C
RES_IS_SPLIT_REQUIRED = 0x01010591
RES_IS_FEATURE_SPLIT = 0x0101055B
RES_REQUIRED = 0x0101028E


class AxmlError(ValueError):
    pass


@dataclass
class StringPool:
    strings: List[str] = field(default_factory=list)
    styles: List[bytes] = field(default_factory=list)
    flags: int = 0

    def index_of(self, text: str, create: bool = True) -> int:
        try:
            return self.strings.index(text)
        except ValueError:
            if not create:
                return NO_ENTRY
            self.strings.append(text)
            return len(self.strings) - 1

    def get(self, index: int) -> str:
        if index == NO_ENTRY or index >= len(self.strings):
            return ""
        return self.strings[index]


@dataclass
class Attribute:
    ns: int
    name: int
    raw_value: int
    data_type: int
    data: int
    resource_id: Optional[int] = None


@dataclass
class Node:
    type: int
    line: int = 0
    comment: int = NO_ENTRY


@dataclass
class Namespace(Node):
    prefix: int = NO_ENTRY
    uri: int = NO_ENTRY


@dataclass
class Element(Node):
    ns: int = NO_ENTRY
    name: int = NO_ENTRY
    attributes: List[Attribute] = field(default_factory=list)
    children: List["Element"] = field(default_factory=list)
    parent: Optional["Element"] = None
    namespace_start: Optional[Namespace] = None
    namespace_end: Optional[Namespace] = None
    id_index: int = 0
    class_index: int = 0
    style_index: int = 0

    # -- navigation -------------------------------------------------------
    def child(self, tag: str, pool: StringPool) -> Optional["Element"]:
        for child in self.children:
            if pool.get(child.name) == tag:
                return child
        return None

    def children_named(self, tag: str, pool: StringPool) -> List["Element"]:
        return [child for child in self.children if pool.get(child.name) == tag]

    def attribute(
        self, pool: StringPool, name: Optional[str] = None, resource_id: Optional[int] = None
    ) -> Optional[Attribute]:
        for attribute in self.attributes:
            if resource_id is not None and attribute.resource_id == resource_id:
                return attribute
            if name is not None and pool.get(attribute.name) == name:
                return attribute
        return None

    def attribute_value(self, pool: StringPool, attribute: Attribute) -> str:
        if attribute.data_type == TYPE_STRING:
            return pool.get(attribute.data)
        return pool.get(attribute.raw_value) if attribute.raw_value != NO_ENTRY else ""

    def remove(self) -> None:
        if self.parent is not None:
            self.parent.children = [c for c in self.parent.children if c is not self]
            self.parent = None


@dataclass
class CData(Node):
    text: int = NO_ENTRY


@dataclass
class Document:
    pool: StringPool
    root: Optional[Element] = None
    resource_map: List[int] = field(default_factory=list)
    trailing_namespaces: List[Namespace] = field(default_factory=list)

    # convenience ---------------------------------------------------------
    def element(self, path: str) -> Optional[Element]:
        parts = path.strip("/").split("/")
        node = self.root
        if node is None or self.pool.get(node.name) != parts[0]:
            return None
        for part in parts[1:]:
            node = node.child(part, self.pool)
            if node is None:
                return None
        return node

    def to_bytes(self) -> bytes:
        return _write_document(self)


def _decode_utf8(data: bytes, offset: int) -> str:
    # length prefix: one or two bytes of char count, then byte count
    length = data[offset]
    offset += 1
    if length & 0x80:
        length = ((length & 0x7F) << 8) | data[offset]
        offset += 1
    byte_len = data[offset]
    offset += 1
    if byte_len & 0x80:
        byte_len = ((byte_len & 0x7F) << 8) | data[offset]
        offset += 1
    return data[offset:offset + byte_len].decode("utf-8", "replace")


def _decode_utf16(data: bytes, offset: int) -> str:
    length = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", data, offset)[0]
        offset += 2
    return data[offset:offset + 2 * length].decode("utf-16-le", "replace")


def _encode_utf8(text: str) -> bytes:
    raw = text.encode("utf-8")
    units = len(text.encode("utf-16-le")) // 2
    out = bytearray()
    if units > 0x7F:
        out += bytes([0x80 | (units >> 8), units & 0xFF])
    else:
        out.append(units)
    if len(raw) > 0x7F:
        out += bytes([0x80 | (len(raw) >> 8), len(raw) & 0xFF])
    else:
        out.append(len(raw))
    return bytes(out) + raw + b"\x00"


def _encode_utf16(text: str) -> bytes:
    raw = text.encode("utf-16-le")
    units = len(raw) // 2
    out = bytearray()
    if units > 0x7FFF:
        out += struct.pack("<HH", 0x8000 | (units >> 16), units & 0xFFFF)
    else:
        out += struct.pack("<H", units)
    return bytes(out) + raw + b"\x00\x00"


def parse(data: bytes) -> Document:
    if len(data) < 8:
        raise AxmlError("file too small")
    chunk_type, header_size, size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != CHUNK_XML:
        raise AxmlError(f"not a binary XML document ({chunk_type:#x})")

    offset = header_size
    pool: Optional[StringPool] = None
    resource_map: List[int] = []
    root: Optional[Element] = None
    stack: List[Element] = []
    pending_namespaces: List[Namespace] = []
    trailing_namespaces: List[Namespace] = []

    while offset + 8 <= len(data):
        node_type, node_header, node_size = struct.unpack_from("<HHI", data, offset)
        if node_size < 8:
            break
        if node_type == CHUNK_STRING_POOL:
            pool = _parse_string_pool(data, offset)
        elif node_type == CHUNK_RESOURCE_MAP:
            count = (node_size - node_header) // 4
            resource_map = list(struct.unpack_from(f"<{count}I", data, offset + node_header))
        elif node_type == CHUNK_START_NAMESPACE:
            line, comment = struct.unpack_from("<II", data, offset + 8)
            prefix, uri = struct.unpack_from("<II", data, offset + node_header)
            pending_namespaces.append(
                Namespace(CHUNK_START_NAMESPACE, line, comment, prefix, uri)
            )
        elif node_type == CHUNK_END_NAMESPACE:
            line, comment = struct.unpack_from("<II", data, offset + 8)
            prefix, uri = struct.unpack_from("<II", data, offset + node_header)
            namespace = Namespace(CHUNK_END_NAMESPACE, line, comment, prefix, uri)
            if stack:
                stack[-1].namespace_end = namespace
            else:
                trailing_namespaces.append(namespace)
        elif node_type == CHUNK_START_ELEMENT:
            line, comment = struct.unpack_from("<II", data, offset + 8)
            (
                ns, name, attr_start, attr_size, attr_count,
                id_index, class_index, style_index,
            ) = struct.unpack_from("<IIHHHHHH", data, offset + 16)
            element = Element(
                CHUNK_START_ELEMENT, line, comment, ns, name,
                id_index=id_index, class_index=class_index, style_index=style_index,
            )
            cursor = offset + 16 + attr_start
            for _ in range(attr_count):
                a_ns, a_name, a_raw, a_size, a_res0, a_type, a_data = struct.unpack_from(
                    "<IIIHBBI", data, cursor
                )
                element.attributes.append(Attribute(a_ns, a_name, a_raw, a_type, a_data))
                cursor += attr_size
            if stack:
                element.parent = stack[-1]
                stack[-1].children.append(element)
            else:
                root = element
            if pending_namespaces:
                element.namespace_start = pending_namespaces[0]
                pending_namespaces = []
            stack.append(element)
        elif node_type == CHUNK_END_ELEMENT:
            if stack:
                stack.pop()
        offset += node_size

    if pool is None:
        raise AxmlError("missing string pool")

    # attach resource ids to attributes
    for element in _walk(root):
        for attribute in element.attributes:
            if attribute.name < len(resource_map):
                attribute.resource_id = resource_map[attribute.name] or None

    return Document(pool, root, resource_map, trailing_namespaces)


def _walk(element: Optional[Element]) -> Iterator[Element]:
    if element is None:
        return
    yield element
    for child in list(element.children):
        yield from _walk(child)


def _parse_string_pool(data: bytes, offset: int) -> StringPool:
    header_size, = struct.unpack_from("<H", data, offset + 2)
    chunk_size, = struct.unpack_from("<I", data, offset + 4)
    count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", data, offset + 8
    )
    offsets = struct.unpack_from(f"<{count}I", data, offset + header_size)
    base = offset + strings_start
    decode = _decode_utf8 if flags & UTF8_FLAG else _decode_utf16
    strings = [decode(data, base + item) for item in offsets]
    styles: List[bytes] = []
    if style_count and styles_start:
        style_offsets = struct.unpack_from(f"<{style_count}I", data, offset + header_size + 4 * count)
        for item in style_offsets:
            start = offset + styles_start + item
            styles.append(data[start:start + 8])
    return StringPool(strings, styles, flags)


def _write_document(document: Document) -> bytes:
    pool = document.pool
    body = bytearray()

    # nodes are written depth first; namespaces follow their element
    def write_node(element: Element) -> None:
        if element.namespace_start is not None:
            body.extend(_namespace_chunk(element.namespace_start, CHUNK_START_NAMESPACE))
        attr_blob = bytearray()
        for attribute in element.attributes:
            attr_blob += struct.pack(
                "<IIIHBBI",
                attribute.ns,
                attribute.name,
                attribute.raw_value,
                8,
                0,
                attribute.data_type,
                attribute.data,
            )
        header = struct.pack(
            "<HHI", CHUNK_START_ELEMENT, 16, 36 + len(attr_blob)
        )
        header += struct.pack("<II", element.line, element.comment)
        header += struct.pack(
            "<IIHHHHHH",
            element.ns,
            element.name,
            20,
            20,
            len(element.attributes),
            element.id_index,
            element.class_index,
            element.style_index,
        )
        body.extend(header)
        body.extend(attr_blob)
        for child in element.children:
            write_node(child)
        end = struct.pack("<HHI", CHUNK_END_ELEMENT, 16, 24)
        end += struct.pack("<II", element.line, element.comment)
        end += struct.pack("<II", element.ns, element.name)
        body.extend(end)
        if element.namespace_end is not None:
            body.extend(_namespace_chunk(element.namespace_end, CHUNK_END_NAMESPACE))

    if document.root is not None:
        write_node(document.root)
    for namespace in document.trailing_namespaces:
        body.extend(_namespace_chunk(namespace, CHUNK_END_NAMESPACE))

    pool_chunk = _write_string_pool(pool)
    resource_chunk = _write_resource_map(document.resource_map)
    total = 8 + len(pool_chunk) + len(resource_chunk) + len(body)
    out = bytearray(struct.pack("<HHI", CHUNK_XML, 8, total))
    out += pool_chunk
    out += resource_chunk
    out += body
    return bytes(out)


def _namespace_chunk(namespace: Namespace, kind: int) -> bytes:
    out = struct.pack("<HHI", kind, 16, 24)
    out += struct.pack("<II", namespace.line, namespace.comment)
    out += struct.pack("<II", namespace.prefix, namespace.uri)
    return out


def _write_string_pool(pool: StringPool) -> bytes:
    encode = _encode_utf8 if pool.flags & UTF8_FLAG else _encode_utf16
    data = bytearray()
    offsets: List[int] = []
    for text in pool.strings:
        offsets.append(len(data))
        data += encode(text)
    while len(data) % 4:
        data.append(0)
    header_size = 28
    strings_start = header_size + 4 * len(pool.strings)
    size = strings_start + len(data)
    out = bytearray(struct.pack("<HHI", CHUNK_STRING_POOL, header_size, size))
    out += struct.pack(
        "<IIIII", len(pool.strings), 0, pool.flags, strings_start, 0
    )
    for offset in offsets:
        out += struct.pack("<I", offset)
    out += data
    return bytes(out)


def _write_resource_map(resource_map: Sequence[int]) -> bytes:
    if not resource_map:
        return b""
    out = bytearray(struct.pack("<HHI", CHUNK_RESOURCE_MAP, 8, 8 + 4 * len(resource_map)))
    for value in resource_map:
        out += struct.pack("<I", value)
    return bytes(out)


# --------------------------------------------------------------------------
# editing helpers
# --------------------------------------------------------------------------

def set_attribute_string(element: Element, pool: StringPool, name: str, value: str) -> None:
    attribute = element.attribute(pool, name=name)
    index = pool.index_of(value)
    if attribute is None:
        element.attributes.append(
            Attribute(NO_ENTRY, pool.index_of(name), index, TYPE_STRING, index)
        )
        return
    attribute.data_type = TYPE_STRING
    attribute.data = index
    attribute.raw_value = index


def set_attribute_bool(
    element: Element, pool: StringPool, name: str, value: bool, resource_id: Optional[int] = None
) -> None:
    attribute = element.attribute(pool, name=name, resource_id=resource_id)
    data = 0xFFFFFFFF if value else 0
    if attribute is None:
        element.attributes.append(
            Attribute(0x01000000, pool.index_of(name), NO_ENTRY, TYPE_INT_BOOLEAN, data)
        )
        return
    attribute.data_type = TYPE_INT_BOOLEAN
    attribute.data = data
    attribute.raw_value = NO_ENTRY


def set_attribute_bool_with_id(
    document: Document,
    element: Element,
    name: str,
    value: bool,
    resource_id: int,
) -> None:
    """Set a framework attribute, adding it to the string pool/resource map."""

    index = document.pool.index_of(name)
    while len(document.resource_map) < len(document.pool.strings):
        document.resource_map.append(0)
    document.resource_map[index] = resource_id
    set_attribute_bool(element, document.pool, name, value, resource_id)


def bool_value(pool: StringPool, attribute: Attribute) -> Optional[bool]:
    if attribute.data_type != TYPE_INT_BOOLEAN:
        return None
    return attribute.data != 0


def remove_attributes(
    element: Element,
    pool: StringPool,
    names: Sequence[str] = (),
    resource_ids: Sequence[int] = (),
) -> int:
    wanted_ids = set(resource_ids)
    wanted_names = set(names)
    before = len(element.attributes)
    element.attributes = [
        attribute
        for attribute in element.attributes
        if not (
            (attribute.resource_id is not None and attribute.resource_id in wanted_ids)
            or pool.get(attribute.name) in wanted_names
        )
    ]
    return before - len(element.attributes)
