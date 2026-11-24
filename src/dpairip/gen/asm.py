"""A very small symbolic assembler used to synthesise runtime classes.

The DEX writer understands :class:`~dpairip.dex.model.SymbolicCode`, which is a
flat instruction list where pool references stay symbolic and branches carry
labels.  This module wraps that into something readable so the generated
classes do not have to be written as raw code unit dumps.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple, Union

from ..dex import insns
from ..dex.model import (
    ACC_ABSTRACT,
    ACC_CONSTRUCTOR,
    ACC_FINAL,
    ACC_NATIVE,
    ACC_PRIVATE,
    ACC_PUBLIC,
    ACC_STATIC,
    ACC_SYNCHRONIZED,
    ClassDef,
    FieldDef,
    FieldRef,
    MethodDef,
    MethodRef,
    Proto,
    SymbolicCode,
    SymbolicTry,
)


def method_ref(owner: str, name: str, descriptor: str) -> MethodRef:
    return MethodRef(owner, name, Proto.parse(descriptor))


def field_ref(owner: str, name: str, type_: str) -> FieldRef:
    return FieldRef(owner, name, type_)


def word_count(proto: Proto) -> int:
    """Registers consumed by the argument list (wide values take two)."""

    return sum(2 if param in ("J", "D") else 1 for param in proto.params)


class MethodBuilder:
    """Accumulates a method body."""

    def __init__(self, registers: int, ins: int = 0, outs: int = 0) -> None:
        self.registers = registers
        self.ins = ins
        self.outs = outs
        self.items: List[object] = []
        self.tries: List[SymbolicTry] = []

    # -- raw emission -----------------------------------------------------
    def label(self, name: str) -> "MethodBuilder":
        self.items.append(name)
        return self

    def emit(self, name: str, *operands) -> "MethodBuilder":
        self.items.append(insns.Insn(insns.NAME_TO_OPCODE[name], tuple(operands)))
        return self

    def branch(self, name: str, *operands) -> "MethodBuilder":
        label = operands[-1]
        assert isinstance(label, str)
        return self.emit(name, *operands[:-1], insns.Branch(label))

    def protect(
        self, start: str, end: str, handlers: Sequence[Tuple[Optional[str], str]]
    ) -> "MethodBuilder":
        self.tries.append(SymbolicTry(start, end, list(handlers)))
        return self

    def build(self) -> SymbolicCode:
        return SymbolicCode(self.registers, self.ins, self.outs, self.items, self.tries)

    # -- calls ------------------------------------------------------------
    def invoke(self, kind: str, ref: MethodRef, *registers: int) -> "MethodBuilder":
        names = {
            "static": "invoke-static",
            "virtual": "invoke-virtual",
            "direct": "invoke-direct",
            "interface": "invoke-interface",
            "super": "invoke-super",
        }
        if len(registers) > 5 or any(reg > 0xF for reg in registers):
            return self.invoke_range(kind, ref, registers[0], len(registers)) if registers else \
                self.emit(names[kind], ref)
        self.outs = max(self.outs, len(registers))
        return self.emit(names[kind], *registers, ref)

    def invoke_range(
        self, kind: str, ref: MethodRef, first: int, count: int
    ) -> "MethodBuilder":
        names = {
            "static": "invoke-static/range",
            "virtual": "invoke-virtual/range",
            "direct": "invoke-direct/range",
            "interface": "invoke-interface/range",
            "super": "invoke-super/range",
        }
        self.outs = max(self.outs, count)
        return self.emit(names[kind], first, count, ref)

    def invoke_static(self, ref: MethodRef, *registers: int) -> "MethodBuilder":
        return self.invoke("static", ref, *registers)

    def invoke_virtual(self, ref: MethodRef, *registers: int) -> "MethodBuilder":
        return self.invoke("virtual", ref, *registers)

    def invoke_direct(self, ref: MethodRef, *registers: int) -> "MethodBuilder":
        return self.invoke("direct", ref, *registers)

    # -- common idioms ----------------------------------------------------
    def const4(self, register: int, value: int) -> "MethodBuilder":
        return self.emit("const/4", register, value)

    def const16(self, register: int, value: int) -> "MethodBuilder":
        return self.emit("const/16", register, value)

    def const_string(self, register: int, text: str) -> "MethodBuilder":
        # jumbo form keeps working even when the string pool is large
        return self.emit("const-string/jumbo", register, text)

    def const_class(self, register: int, desc: str) -> "MethodBuilder":
        return self.emit("const-class", register, desc)

    def new_instance(self, register: int, desc: str) -> "MethodBuilder":
        return self.emit("new-instance", register, desc)

    def move_result(self, register: int) -> "MethodBuilder":
        return self.emit("move-result", register)

    def move_result_object(self, register: int) -> "MethodBuilder":
        return self.emit("move-result-object", register)

    def move_result_wide(self, register: int) -> "MethodBuilder":
        return self.emit("move-result-wide", register)

    def move_object(self, dest: int, src: int) -> "MethodBuilder":
        return self.emit("move-object", dest, src)

    def sget_object(self, register: int, ref: FieldRef) -> "MethodBuilder":
        return self.emit("sget-object", register, ref)

    def sput_object(self, register: int, ref: FieldRef) -> "MethodBuilder":
        return self.emit("sput-object", register, ref)

    def sget_boolean(self, register: int, ref: FieldRef) -> "MethodBuilder":
        return self.emit("sget-boolean", register, ref)

    def sput_boolean(self, register: int, ref: FieldRef) -> "MethodBuilder":
        return self.emit("sput-boolean", register, ref)

    def if_eqz(self, register: int, label: str) -> "MethodBuilder":
        return self.branch("if-eqz", register, label)

    def if_nez(self, register: int, label: str) -> "MethodBuilder":
        return self.branch("if-nez", register, label)

    def if_ge(self, first: int, second: int, label: str) -> "MethodBuilder":
        return self.branch("if-ge", first, second, label)

    def goto(self, label: str) -> "MethodBuilder":
        # goto/32 has no practical range limit, which keeps generated code safe
        return self.branch("goto/32", label)

    def add_int_lit8(self, dest: int, src: int, literal: int) -> "MethodBuilder":
        return self.emit("add-int/lit8", dest, src, literal)

    def array_length(self, dest: int, array: int) -> "MethodBuilder":
        return self.emit("array-length", dest, array)

    def aget_object(self, dest: int, array: int, index: int) -> "MethodBuilder":
        return self.emit("aget-object", dest, array, index)

    def check_cast(self, register: int, desc: str) -> "MethodBuilder":
        return self.emit("check-cast", register, desc)

    def move_exception(self, register: int) -> "MethodBuilder":
        return self.emit("move-exception", register)

    def return_void(self) -> "MethodBuilder":
        return self.emit("return-void")

    def return_object(self, register: int) -> "MethodBuilder":
        return self.emit("return-object", register)

    def nop(self) -> "MethodBuilder":
        return self.emit("nop")


def default_return(proto: Proto, ins: int = 0) -> MethodBuilder:
    """Body that returns the zero value of ``proto``."""

    builder = MethodBuilder(ins + 1, ins)
    result = proto.return_type
    if result == "V":
        builder.return_void()
    elif result in ("J", "D"):
        builder.emit("const-wide/16", 0, 0)
        builder.emit("return-wide", 0)
    elif result in ("F",):
        builder.emit("const/4", 0, 0)
        builder.emit("return", 0)
    elif result in ("Z", "B", "S", "C", "I"):
        builder.emit("const/4", 0, 0)
        builder.emit("return", 0)
    else:
        builder.const4(0, 0)
        builder.return_object(0)
    return builder


def make_method(
    name: str,
    proto: Proto,
    access: int,
    builder: MethodBuilder,
    annotations=None,
) -> MethodDef:
    return MethodDef(
        name=name,
        proto=proto,
        access=access,
        code=builder.build(),
        annotations=list(annotations or []),
    )


def make_class(
    desc: str,
    superclass: Optional[str] = "Ljava/lang/Object;",
    access: int = ACC_PUBLIC,
    interfaces: Sequence[str] = (),
    static_fields: Sequence[FieldDef] = (),
    instance_fields: Sequence[FieldDef] = (),
    direct_methods: Sequence[MethodDef] = (),
    virtual_methods: Sequence[MethodDef] = (),
    source_file: Optional[str] = None,
) -> ClassDef:
    return ClassDef(
        type=desc,
        access=access,
        superclass=superclass,
        interfaces=list(interfaces),
        source_file=source_file,
        static_fields=list(static_fields),
        instance_fields=list(instance_fields),
        direct_methods=list(direct_methods),
        virtual_methods=list(virtual_methods),
    )
