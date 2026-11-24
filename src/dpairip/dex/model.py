"""Name based intermediate representation of a DEX file.

Everything is keyed by descriptor strings (``Ljava/lang/String;``) instead of
pool indices.  That keeps the transforms readable and makes a full rebuild
possible: parse -> mutate -> write.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple, Union

# access flags
ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_SYNCHRONIZED = 0x0020
ACC_VOLATILE = 0x0040
ACC_BRIDGE = 0x0040
ACC_TRANSIENT = 0x0080
ACC_VARARGS = 0x0080
ACC_NATIVE = 0x0100
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400
ACC_STRICT = 0x0800
ACC_SYNTHETIC = 0x1000
ACC_ANNOTATION = 0x2000
ACC_ENUM = 0x4000
ACC_CONSTRUCTOR = 0x10000
ACC_DECLARED_SYNCHRONIZED = 0x20000

PRIMITIVES = frozenset("VZBSCIJFD")


def descriptor_to_name(desc: str) -> str:
    """``Lcom/foo/Bar;`` -> ``com.foo.Bar`` (arrays/primitives returned as-is)."""
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")
    return desc


def name_to_descriptor(name: str) -> str:
    """``com.foo.Bar`` -> ``Lcom/foo/Bar;`` (leaves descriptors untouched)."""
    if name.startswith(("L", "[")) and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


@dataclass(frozen=True)
class Proto:
    params: Tuple[str, ...] = ()
    return_type: str = "V"

    def descriptor(self) -> str:
        return "(" + "".join(self.params) + ")" + self.return_type

    def shorty(self) -> str:
        def one(t: str) -> str:
            while t.startswith("["):
                t = t[1:]
            return t if t in PRIMITIVES else "L"

        return one(self.return_type) + "".join(one(p) for p in self.params)

    @classmethod
    def parse(cls, descriptor: str) -> "Proto":
        if not descriptor.startswith("("):
            raise ValueError(f"bad proto: {descriptor}")
        params: List[str] = []
        i = 1
        while descriptor[i] != ")":
            start = i
            while descriptor[i] == "[":
                i += 1
            if descriptor[i] == "L":
                i = descriptor.index(";", i) + 1
            else:
                i += 1
            params.append(descriptor[start:i])
        return cls(tuple(params), descriptor[i + 1:])


@dataclass(frozen=True)
class FieldRef:
    owner: str
    name: str
    type: str


@dataclass(frozen=True)
class MethodRef:
    owner: str
    name: str
    proto: Proto

    def descriptor(self) -> str:
        return self.owner + "->" + self.name + self.proto.descriptor()


@dataclass(frozen=True)
class ProtoRef:
    """Reference to a proto (only used by ``const-method-type``)."""

    proto: Proto


@dataclass(frozen=True)
class MethodHandleRef:
    kind: int
    member: Union[FieldRef, MethodRef]


@dataclass(frozen=True)
class CallSiteRef:
    """A ``invoke-custom`` call site (bootstrap handle, name and proto)."""

    handle: MethodHandleRef
    name: str
    proto: Proto


@dataclass
class EncodedValue:
    """A dex ``encoded_value``."""

    kind: str
    value: object = None
    type: Optional[str] = None
    field_ref: Optional[FieldRef] = None
    method_ref: Optional[MethodRef] = None
    proto: Optional[Proto] = None
    handle: Optional[MethodHandleRef] = None
    array: List["EncodedValue"] = field(default_factory=list)
    annotation: Optional["Annotation"] = None

    # convenience constructors -------------------------------------------------
    @staticmethod
    def null() -> "EncodedValue":
        return EncodedValue("null")

    @staticmethod
    def boolean(value: bool) -> "EncodedValue":
        return EncodedValue("boolean", bool(value))

    @staticmethod
    def integer(value: int, kind: str = "int") -> "EncodedValue":
        return EncodedValue(kind, int(value))

    @staticmethod
    def string(value: str) -> "EncodedValue":
        return EncodedValue("string", value)

    @staticmethod
    def type_value(desc: str) -> "EncodedValue":
        return EncodedValue("type", type=desc)

    @staticmethod
    def field(field_ref: FieldRef) -> "EncodedValue":
        return EncodedValue("field", field_ref=field_ref)

    @staticmethod
    def method(method_ref: MethodRef) -> "EncodedValue":
        return EncodedValue("method", method_ref=method_ref)

    @staticmethod
    def enum(field_ref: FieldRef) -> "EncodedValue":
        return EncodedValue("enum", field_ref=field_ref)


@dataclass
class Annotation:
    visibility: int  # 0 build, 1 runtime, 2 system
    type: str
    elements: List[Tuple[str, EncodedValue]] = field(default_factory=list)


@dataclass
class TryHandler:
    type: Optional[str]  # None == catch-all
    address: int


@dataclass
class TryBlock:
    start: int
    count: int
    handlers: List[TryHandler]


@dataclass
class RawCode:
    """Method body kept as raw code units plus a list of pool references."""

    registers: int
    ins: int
    outs: int
    units: List[int]
    tries: List[TryBlock] = field(default_factory=list)
    refs: List[Tuple[int, str, object, int]] = field(default_factory=list)
    offset: int = 0  # file offset of the code item, for surgical patches


@dataclass
class SymbolicTry:
    """Try/catch block of a generated method, addressed by labels."""

    start: str
    end: str
    handlers: List[Tuple[Optional[str], str]] = field(default_factory=list)


@dataclass
class SymbolicCode:
    """Method body produced by the assembler."""

    registers: int
    ins: int
    outs: int
    items: list  # Insn / str labels
    tries: List[TryBlock] = field(default_factory=list)


Code = Union[RawCode, SymbolicCode]


@dataclass
class FieldDef:
    name: str
    type: str
    access: int
    initial: Optional[EncodedValue] = None
    annotations: List[Annotation] = field(default_factory=list)


@dataclass
class MethodDef:
    name: str
    proto: Proto
    access: int
    code: Optional[Code] = None
    annotations: List[Annotation] = field(default_factory=list)
    parameter_annotations: List[List[Annotation]] = field(default_factory=list)

    @property
    def is_direct(self) -> bool:
        return bool(
            self.access
            & (ACC_STATIC | ACC_PRIVATE | ACC_CONSTRUCTOR)
        )


@dataclass
class ClassDef:
    type: str
    access: int
    superclass: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    source_file: Optional[str] = None
    annotations: List[Annotation] = field(default_factory=list)
    static_fields: List[FieldDef] = field(default_factory=list)
    instance_fields: List[FieldDef] = field(default_factory=list)
    direct_methods: List[MethodDef] = field(default_factory=list)
    virtual_methods: List[MethodDef] = field(default_factory=list)

    # -- helpers ---------------------------------------------------------
    def all_fields(self) -> List[FieldDef]:
        return self.static_fields + self.instance_fields

    def all_methods(self) -> List[MethodDef]:
        return self.direct_methods + self.virtual_methods

    def find_method(self, name: str, proto: Optional[Proto] = None) -> Optional[MethodDef]:
        for method in self.all_methods():
            if method.name == name and (proto is None or method.proto == proto):
                return method
        return None

    def add_method(self, method: MethodDef) -> None:
        if method.is_direct:
            self.direct_methods.append(method)
        else:
            self.virtual_methods.append(method)

    def sort_members(self) -> None:
        """Keep fields/methods in the order the dex format expects."""

        def field_key(f: FieldDef):
            return (f.name, f.type)

        def method_key(m: MethodDef):
            return (m.name, m.proto.descriptor())

        self.static_fields.sort(key=field_key)
        self.instance_fields.sort(key=field_key)
        self.direct_methods.sort(key=method_key)
        self.virtual_methods.sort(key=method_key)


@dataclass
class DexIR:
    classes: List[ClassDef] = field(default_factory=list)
    version: int = 35

    def find_class(self, desc: str) -> Optional[ClassDef]:
        for cls in self.classes:
            if cls.type == desc:
                return cls
        return None
