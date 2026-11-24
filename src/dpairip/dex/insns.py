"""Dalvik instruction tables, encoding helpers and branch fix-ups.

Only the pieces needed by the packer/unpacker are implemented here, but the
tables cover the complete opcode range so that arbitrary methods can be
disassembled, shifted around and re-emitted without losing information.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

# --------------------------------------------------------------------------
# opcode table
# --------------------------------------------------------------------------

# name, format  (index of the tuple in the list == opcode value)
_OPCODE_ROWS: List[Tuple[str, str]] = [
    ("nop", "10x"),
    ("move", "12x"),
    ("move/from16", "22x"),
    ("move/16", "32x"),
    ("move-wide", "12x"),
    ("move-wide/from16", "22x"),
    ("move-wide/16", "32x"),
    ("move-object", "12x"),
    ("move-object/from16", "22x"),
    ("move-object/16", "32x"),
    ("move-result", "11x"),
    ("move-result-wide", "11x"),
    ("move-result-object", "11x"),
    ("move-exception", "11x"),
    ("return-void", "10x"),
    ("return", "11x"),
    ("return-wide", "11x"),
    ("return-object", "11x"),
    ("const/4", "11n"),
    ("const/16", "21s"),
    ("const", "31i"),
    ("const/high16", "21h"),
    ("const-wide/16", "21s"),
    ("const-wide/32", "31i"),
    ("const-wide", "51l"),
    ("const-wide/high16", "21h"),
    ("const-string", "21c"),
    ("const-string/jumbo", "31c"),
    ("const-class", "21c"),
    ("monitor-enter", "11x"),
    ("monitor-exit", "11x"),
    ("check-cast", "21c"),
    ("instance-of", "22c"),
    ("array-length", "12x"),
    ("new-instance", "21c"),
    ("new-array", "22c"),
    ("filled-new-array", "35c"),
    ("filled-new-array/range", "3rc"),
    ("fill-array-data", "31t"),
    ("throw", "11x"),
    ("goto", "10t"),
    ("goto/16", "20t"),
    ("goto/32", "30t"),
    ("packed-switch", "31t"),
    ("sparse-switch", "31t"),
    ("cmpl-float", "23x"),
    ("cmpg-float", "23x"),
    ("cmpl-double", "23x"),
    ("cmpg-double", "23x"),
    ("cmp-long", "23x"),
    ("if-eq", "22t"),
    ("if-ne", "22t"),
    ("if-lt", "22t"),
    ("if-ge", "22t"),
    ("if-gt", "22t"),
    ("if-le", "22t"),
    ("if-eqz", "21t"),
    ("if-nez", "21t"),
    ("if-ltz", "21t"),
    ("if-gez", "21t"),
    ("if-gtz", "21t"),
    ("if-lez", "21t"),
    ("unused-3e", "10x"),
    ("unused-3f", "10x"),
    ("unused-40", "10x"),
    ("unused-41", "10x"),
    ("unused-42", "10x"),
    ("unused-43", "10x"),
    ("aget", "23x"),
    ("aget-wide", "23x"),
    ("aget-object", "23x"),
    ("aget-boolean", "23x"),
    ("aget-byte", "23x"),
    ("aget-char", "23x"),
    ("aget-short", "23x"),
    ("aput", "23x"),
    ("aput-wide", "23x"),
    ("aput-object", "23x"),
    ("aput-boolean", "23x"),
    ("aput-byte", "23x"),
    ("aput-char", "23x"),
    ("aput-short", "23x"),
    ("iget", "22c"),
    ("iget-wide", "22c"),
    ("iget-object", "22c"),
    ("iget-boolean", "22c"),
    ("iget-byte", "22c"),
    ("iget-char", "22c"),
    ("iget-short", "22c"),
    ("iput", "22c"),
    ("iput-wide", "22c"),
    ("iput-object", "22c"),
    ("iput-boolean", "22c"),
    ("iput-byte", "22c"),
    ("iput-char", "22c"),
    ("iput-short", "22c"),
    ("sget", "21c"),
    ("sget-wide", "21c"),
    ("sget-object", "21c"),
    ("sget-boolean", "21c"),
    ("sget-byte", "21c"),
    ("sget-char", "21c"),
    ("sget-short", "21c"),
    ("sput", "21c"),
    ("sput-wide", "21c"),
    ("sput-object", "21c"),
    ("sput-boolean", "21c"),
    ("sput-byte", "21c"),
    ("sput-char", "21c"),
    ("sput-short", "21c"),
    ("invoke-virtual", "35c"),
    ("invoke-super", "35c"),
    ("invoke-direct", "35c"),
    ("invoke-static", "35c"),
    ("invoke-interface", "35c"),
    ("unused-73", "10x"),
    ("invoke-virtual/range", "3rc"),
    ("invoke-super/range", "3rc"),
    ("invoke-direct/range", "3rc"),
    ("invoke-static/range", "3rc"),
    ("invoke-interface/range", "3rc"),
    ("unused-79", "10x"),
    ("unused-7a", "10x"),
    ("neg-int", "12x"),
    ("not-int", "12x"),
    ("neg-long", "12x"),
    ("not-long", "12x"),
    ("neg-float", "12x"),
    ("neg-double", "12x"),
    ("int-to-long", "12x"),
    ("int-to-float", "12x"),
    ("int-to-double", "12x"),
    ("long-to-int", "12x"),
    ("long-to-float", "12x"),
    ("long-to-double", "12x"),
    ("float-to-int", "12x"),
    ("float-to-long", "12x"),
    ("float-to-double", "12x"),
    ("double-to-int", "12x"),
    ("double-to-long", "12x"),
    ("double-to-float", "12x"),
    ("int-to-byte", "12x"),
    ("int-to-char", "12x"),
    ("int-to-short", "12x"),
    ("add-int", "23x"),
    ("sub-int", "23x"),
    ("mul-int", "23x"),
    ("div-int", "23x"),
    ("rem-int", "23x"),
    ("and-int", "23x"),
    ("or-int", "23x"),
    ("xor-int", "23x"),
    ("shl-int", "23x"),
    ("shr-int", "23x"),
    ("ushr-int", "23x"),
    ("add-long", "23x"),
    ("sub-long", "23x"),
    ("mul-long", "23x"),
    ("div-long", "23x"),
    ("rem-long", "23x"),
    ("and-long", "23x"),
    ("or-long", "23x"),
    ("xor-long", "23x"),
    ("shl-long", "23x"),
    ("shr-long", "23x"),
    ("ushr-long", "23x"),
    ("add-float", "23x"),
    ("sub-float", "23x"),
    ("mul-float", "23x"),
    ("div-float", "23x"),
    ("rem-float", "23x"),
    ("add-double", "23x"),
    ("sub-double", "23x"),
    ("mul-double", "23x"),
    ("div-double", "23x"),
    ("rem-double", "23x"),
    ("add-int/2addr", "12x"),
    ("sub-int/2addr", "12x"),
    ("mul-int/2addr", "12x"),
    ("div-int/2addr", "12x"),
    ("rem-int/2addr", "12x"),
    ("and-int/2addr", "12x"),
    ("or-int/2addr", "12x"),
    ("xor-int/2addr", "12x"),
    ("shl-int/2addr", "12x"),
    ("shr-int/2addr", "12x"),
    ("ushr-int/2addr", "12x"),
    ("add-long/2addr", "12x"),
    ("sub-long/2addr", "12x"),
    ("mul-long/2addr", "12x"),
    ("div-long/2addr", "12x"),
    ("rem-long/2addr", "12x"),
    ("and-long/2addr", "12x"),
    ("or-long/2addr", "12x"),
    ("xor-long/2addr", "12x"),
    ("shl-long/2addr", "12x"),
    ("shr-long/2addr", "12x"),
    ("ushr-long/2addr", "12x"),
    ("add-float/2addr", "12x"),
    ("sub-float/2addr", "12x"),
    ("mul-float/2addr", "12x"),
    ("div-float/2addr", "12x"),
    ("rem-float/2addr", "12x"),
    ("add-double/2addr", "12x"),
    ("sub-double/2addr", "12x"),
    ("mul-double/2addr", "12x"),
    ("div-double/2addr", "12x"),
    ("rem-double/2addr", "12x"),
    ("add-int/lit16", "22s"),
    ("rsub-int", "22s"),
    ("mul-int/lit16", "22s"),
    ("div-int/lit16", "22s"),
    ("rem-int/lit16", "22s"),
    ("and-int/lit16", "22s"),
    ("or-int/lit16", "22s"),
    ("xor-int/lit16", "22s"),
    ("add-int/lit8", "22b"),
    ("rsub-int/lit8", "22b"),
    ("mul-int/lit8", "22b"),
    ("div-int/lit8", "22b"),
    ("rem-int/lit8", "22b"),
    ("and-int/lit8", "22b"),
    ("or-int/lit8", "22b"),
    ("xor-int/lit8", "22b"),
    ("shl-int/lit8", "22b"),
    ("shr-int/lit8", "22b"),
    ("ushr-int/lit8", "22b"),
    ("unused-e3", "10x"),
    ("unused-e4", "10x"),
    ("unused-e5", "10x"),
    ("unused-e6", "10x"),
    ("unused-e7", "10x"),
    ("unused-e8", "10x"),
    ("unused-e9", "10x"),
    ("unused-ea", "10x"),
    ("unused-eb", "10x"),
    ("unused-ec", "10x"),
    ("unused-ed", "10x"),
    ("unused-ee", "10x"),
    ("unused-ef", "10x"),
    ("unused-f0", "10x"),
    ("unused-f1", "10x"),
    ("unused-f2", "10x"),
    ("unused-f3", "10x"),
    ("unused-f4", "10x"),
    ("unused-f5", "10x"),
    ("unused-f6", "10x"),
    ("unused-f7", "10x"),
    ("unused-f8", "10x"),
    ("unused-f9", "10x"),
    ("invoke-polymorphic", "45cc"),
    ("invoke-polymorphic/range", "4rcc"),
    ("invoke-custom", "35c"),
    ("invoke-custom/range", "3rc"),
    ("const-method-handle", "21c"),
    ("const-method-type", "21c"),
]

OPCODE_NAMES: Tuple[str, ...] = tuple(row[0] for row in _OPCODE_ROWS)
OPCODE_FORMATS: Tuple[str, ...] = tuple(row[1] for row in _OPCODE_ROWS)
NAME_TO_OPCODE: Dict[str, int] = {name: code for code, name in enumerate(OPCODE_NAMES)}

FORMAT_SIZE: Dict[str, int] = {
    "10x": 1, "12x": 1, "11n": 1, "11x": 1, "10t": 1,
    "20t": 2, "22x": 2, "21t": 2, "21s": 2, "21h": 2, "21c": 2,
    "23x": 2, "22b": 2, "22t": 2, "22s": 2, "22c": 2, "20bc": 2, "22cs": 2,
    "30t": 3, "32x": 3, "31i": 3, "31t": 3, "31c": 3, "35c": 3, "3rc": 3,
    "45cc": 4, "4rcc": 4, "51l": 5,
}

# pseudo instructions (payloads) - the low byte is the real opcode, the high
# byte identifies the payload kind.
PAYLOAD_PACKED_SWITCH = 0x0100
PAYLOAD_SPARSE_SWITCH = 0x0200
PAYLOAD_ARRAY_DATA = 0x0300

BRANCH_FORMATS = frozenset({"10t", "20t", "30t", "21t", "22t", "31t"})
# payload reference instructions store an absolute code-unit offset
PAYLOAD_REF_NAMES = frozenset(
    {"packed-switch", "sparse-switch", "fill-array-data"}
)

# reference kinds used by the assembler when resolving operands
REF_NONE = 0
REF_STRING = 1
REF_TYPE = 2
REF_FIELD = 3
REF_METHOD = 4
REF_PROTO = 5
REF_CALLSITE = 6
REF_METHOD_HANDLE = 7

_TYPE_REF_OPS = {
    "const-class", "check-cast", "new-instance", "new-array", "instance-of",
    "filled-new-array", "filled-new-array/range",
}
_PROTO_REF_OPS = {"const-method-type"}
_CALL_SITE_OPS = {"invoke-custom", "invoke-custom/range"}
_FIELD_REF_OPS = {
    "iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte",
    "iget-char", "iget-short", "iput", "iput-wide", "iput-object",
    "iput-boolean", "iput-byte", "iput-char", "iput-short", "sget",
    "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char",
    "sget-short", "sput", "sput-wide", "sput-object", "sput-boolean",
    "sput-byte", "sput-char", "sput-short",
}
_METHOD_REF_OPS = {
    "invoke-virtual", "invoke-super", "invoke-direct", "invoke-static",
    "invoke-interface", "invoke-virtual/range", "invoke-super/range",
    "invoke-direct/range", "invoke-static/range", "invoke-interface/range",
    "invoke-polymorphic", "invoke-polymorphic/range",
}
_STRING_REF_OPS = {"const-string", "const-string/jumbo"}


def reference_kind(opcode: int) -> int:
    """Return the pool kind referenced by ``opcode`` (REF_* constant)."""
    name = OPCODE_NAMES[opcode]
    if name in _STRING_REF_OPS:
        return REF_STRING
    if name in _TYPE_REF_OPS:
        return REF_TYPE
    if name in _FIELD_REF_OPS:
        return REF_FIELD
    if name in _METHOD_REF_OPS:
        return REF_METHOD
    if name in _PROTO_REF_OPS:
        return REF_PROTO
    if name in _CALL_SITE_OPS:
        return REF_CALLSITE
    if name == "const-method-handle":
        return REF_METHOD_HANDLE
    return REF_NONE


# --------------------------------------------------------------------------
# instruction sizes / scanning
# --------------------------------------------------------------------------

def insn_size(insns: Sequence[int], addr: int) -> int:
    """Size in code units of the instruction starting at ``addr``."""
    unit = insns[addr]
    if unit in (PAYLOAD_PACKED_SWITCH, PAYLOAD_SPARSE_SWITCH, PAYLOAD_ARRAY_DATA):
        return payload_size(insns, addr)
    return FORMAT_SIZE[OPCODE_FORMATS[unit & 0xFF]]


def payload_size(insns: Sequence[int], addr: int) -> int:
    kind = insns[addr]
    if kind == PAYLOAD_PACKED_SWITCH:
        size = insns[addr + 1]
        return 4 + size * 2
    if kind == PAYLOAD_SPARSE_SWITCH:
        size = insns[addr + 1]
        return 2 + size * 4
    if kind == PAYLOAD_ARRAY_DATA:
        width = insns[addr + 1]
        count = insns[addr + 2] | (insns[addr + 3] << 16)
        return 4 + (width * count + 1) // 2
    raise ValueError(f"not a payload at {addr:#x}: {kind:#06x}")


def iter_instructions(insns: Sequence[int]) -> Iterable[Tuple[int, int, int]]:
    """Yield ``(address, opcode_unit, size)`` for every instruction."""
    addr = 0
    end = len(insns)
    while addr < end:
        size = insn_size(insns, addr)
        yield addr, insns[addr], size
        addr += size


# --------------------------------------------------------------------------
# symbolic instructions used when generating new code
# --------------------------------------------------------------------------

@dataclass
class Branch:
    """Relative branch target inside the method being built."""

    label: str
    offset: int = 0

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"Branch({self.label})"


@dataclass
class Insn:
    """A symbolic instruction.

    ``operands`` are plain integers or pool references that the dex writer
    resolves.  Branches may still be unresolved when the instruction is
    created; :func:`assemble` fills in their offsets.
    """

    opcode: int
    operands: Tuple[Union[int, object], ...] = ()
    size: int = 0
    addr: int = 0

    @property
    def format(self) -> str:
        return OPCODE_FORMATS[self.opcode]

    @property
    def name(self) -> str:
        return OPCODE_NAMES[self.opcode]


@dataclass
class CodeBuffer:
    """Collects instructions, labels and try/catch data for one method.

    The buffer is later assembled into a concrete :class:`CodeItem` once
    every pool index is known.
    """

    registers: int
    ins: int
    outs: int = 2
    items: List[Union[Insn, str]] = field(default_factory=list)
    tries: List[Tuple[int, int, List[Tuple[Optional[str], str]]]] = field(
        default_factory=list
    )
    debug: Optional[bytes] = None

    # -- emission helpers -------------------------------------------------
    def label(self, name: str) -> "CodeBuffer":
        self.items.append(name)
        return self

    def emit(self, name: str, *operands) -> "CodeBuffer":
        try:
            opcode = NAME_TO_OPCODE[name]
        except KeyError:  # pragma: no cover - programming error
            raise ValueError(f"unknown opcode {name!r}") from None
        self.items.append(Insn(opcode, tuple(operands)))
        return self

    def branch(self, name: str, *operands_with_label) -> "CodeBuffer":
        last = operands_with_label[-1]
        assert isinstance(last, str), "last operand of a branch must be a label"
        buf = self.emit(name, *operands_with_label[:-1], Branch(last))
        return buf

    def try_block(self, start: str, end: str, handlers: List[Tuple[Optional[str], str]]):
        self.items.append(("try", start, end, handlers))
        return self

    # -- layout -----------------------------------------------------------
    def assemble(self) -> Tuple[List[Insn], Dict[str, int]]:
        # pass 1: sizes + label addresses
        labels: Dict[str, int] = {}
        addr = 0
        sized: List[Insn] = []
        for item in self.items:
            if isinstance(item, str):
                labels[item] = addr
            elif isinstance(item, tuple):
                continue
            else:
                item.size = FORMAT_SIZE[item.format]
                item.addr = addr
                addr += item.size
                sized.append(item)
        # pass 2: resolve branch offsets
        for insn in sized:
            for i, operand in enumerate(insn.operands):
                if isinstance(operand, Branch):
                    target = labels[operand.label]
                    operand.offset = target - insn.addr
        return sized, labels


def encode_insn(insn: Insn, resolve) -> List[int]:
    """Encode a symbolic instruction into code units.

    ``resolve(kind, reference)`` must return the pool index for pool
    references and the unit index for payload references.
    """
    fmt = insn.format
    op = insn.opcode
    o = tuple(operand.offset if isinstance(operand, Branch) else operand
              for operand in insn.operands)

    if fmt == "10x":
        return [op]
    if fmt == "12x":
        return [op | (o[0] << 8) | (o[1] << 12)]
    if fmt == "11n":
        return [op | (o[0] << 8) | ((o[1] & 0xF) << 12)]
    if fmt == "11x":
        return [op | (o[0] << 8)]
    if fmt == "10t":
        return [op | ((o[0] & 0xFF) << 8)]
    if fmt == "20t":
        return [op, o[0] & 0xFFFF]
    if fmt == "22x":
        return [op | (o[0] << 8), o[1]]
    if fmt == "21t":
        return [op | (o[0] << 8), o[1] & 0xFFFF]
    if fmt == "21s":
        return [op | (o[0] << 8), o[1] & 0xFFFF]
    if fmt == "21h":
        return [op | (o[0] << 8), o[1] & 0xFFFF]
    if fmt == "21c" or fmt == "31c":
        idx = resolve(reference_kind(op), o[1])
        if fmt == "21c":
            return [op | (o[0] << 8), idx]
        return [op | (o[0] << 8), idx & 0xFFFF, (idx >> 16) & 0xFFFF]
    if fmt == "23x":
        return [op | (o[0] << 8), o[1] | (o[2] << 8)]
    if fmt == "22b":
        return [op | (o[0] << 8), o[1] | ((o[2] & 0xFF) << 8)]
    if fmt == "22t":
        return [op | (o[0] << 8) | (o[1] << 12), o[2] & 0xFFFF]
    if fmt == "22s":
        return [op | (o[0] << 8) | (o[1] << 12), o[2] & 0xFFFF]
    if fmt == "22c":
        return [op | (o[0] << 8) | (o[1] << 12), resolve(reference_kind(op), o[2])]
    if fmt == "32x":
        return [op, o[0], o[1]]
    if fmt == "30t":
        off = o[0] & 0xFFFFFFFF
        return [op, off & 0xFFFF, off >> 16]
    if fmt == "31i":
        v = o[1] & 0xFFFFFFFF
        return [op | (o[0] << 8), v & 0xFFFF, v >> 16]
    if fmt == "31t":
        off = o[1] & 0xFFFFFFFF
        return [op | (o[0] << 8), off & 0xFFFF, off >> 16]
    if fmt == "35c":
        # A|G|op BBBB F|E|D|C -- the first four registers live in the low
        # nibble pairs of the third unit; G is the *fifth* register.
        regs = list(o[:-1])
        idx = resolve(reference_kind(op), o[-1])
        count = len(regs)
        word0 = op | (count << 12)
        word2 = 0
        for i, reg in enumerate(regs[:4]):
            word2 |= (reg & 0xF) << (4 * i)
        if count == 5:
            word0 |= (regs[4] & 0xF) << 8
        return [word0, idx, word2]
    if fmt == "3rc":
        first = o[0]
        count = o[1]
        idx = resolve(reference_kind(op), o[2])
        return [op | (count << 8), idx, first]
    if fmt == "45cc":
        raise NotImplementedError("invoke-polymorphic is not supported")
    if fmt == "4rcc":
        raise NotImplementedError("invoke-polymorphic/range is not supported")
    if fmt == "51l":
        v = o[1] & 0xFFFFFFFFFFFFFFFF
        return [op | (o[0] << 8), v & 0xFFFF, (v >> 16) & 0xFFFF,
                (v >> 32) & 0xFFFF, (v >> 48) & 0xFFFF]
    raise ValueError(f"unsupported format {fmt}")


# --------------------------------------------------------------------------
# branch fix-ups for in-place edits of existing methods
# --------------------------------------------------------------------------

TryHandler = Tuple[Optional[str], int]
TryBlock = Tuple[int, int, List[TryHandler]]


def _signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def _payload_addresses(insns: Sequence[int]) -> List[int]:
    return [
        addr
        for addr, unit, _size in iter_instructions(insns)
        if unit in (PAYLOAD_PACKED_SWITCH, PAYLOAD_SPARSE_SWITCH, PAYLOAD_ARRAY_DATA)
    ]


def _reshift(
    insns: Sequence[int],
    tries: Sequence[TryBlock],
    at: int,
    delta: int,
    insert: Optional[Sequence[int]] = None,
) -> Tuple[List[int], List[TryBlock]]:
    """Apply a size delta at ``at`` and rewrite every code reference.

    ``delta`` is positive for insertions and negative for removals.  Branch
    offsets, switch/array payload offsets and try/catch ranges are all
    recomputed so that the resulting method stays verifiable.
    """
    old = list(insns)
    total = delta

    # payloads must stay aligned to an even code-unit boundary
    if delta > 0 and delta % 2 == 1:
        if any(addr >= at for addr in _payload_addresses(old)):
            total = delta + 1

    if delta > 0:
        block = list(insert if insert is not None else [0] * delta)
        block.extend([0] * (total - len(block)))

        def remap(addr: int) -> int:
            return addr + total if addr >= at else addr

        new = old[:at] + block + old[at:]
    else:
        cut = -delta

        def remap(addr: int) -> int:
            if addr < at:
                return addr
            if addr < at + cut:
                return at
            return addr - cut

        new = old[:at] + old[at + cut:]

    # relative branches
    for addr, unit, size in iter_instructions(old):
        fmt = OPCODE_FORMATS[unit & 0xFF]
        if fmt not in ("10t", "20t", "30t", "21t", "22t"):
            continue
        if fmt == "10t":
            target = addr + _signed(unit >> 8, 8)
        elif fmt == "20t":
            target = addr + _signed(old[addr + 1], 16)
        elif fmt == "30t":
            target = addr + _signed(old[addr + 1] | (old[addr + 2] << 16), 32)
        else:  # 21t / 22t
            target = addr + _signed(old[addr + 1], 16)

        new_addr = remap(addr)
        offset = remap(target) - new_addr

        if fmt == "10t":
            if not -128 <= offset <= 127:
                raise ValueError("goto offset no longer fits in 8 bits")
            new[new_addr] = (unit & 0xFF) | ((offset & 0xFF) << 8)
        elif fmt == "20t":
            if not -32768 <= offset <= 32767:
                raise ValueError("goto/16 offset out of range")
            new[new_addr + 1] = offset & 0xFFFF
        elif fmt == "30t":
            new[new_addr + 1] = offset & 0xFFFF
            new[new_addr + 2] = (offset >> 16) & 0xFFFF
        else:
            if not -32768 <= offset <= 32767:
                raise ValueError("branch offset out of range")
            new[new_addr + 1] = offset & 0xFFFF

    # absolute payload references
    for addr, unit, size in iter_instructions(old):
        if unit not in (PAYLOAD_PACKED_SWITCH, PAYLOAD_SPARSE_SWITCH, PAYLOAD_ARRAY_DATA):
            continue

    for addr, unit, size in iter_instructions(old):
        if OPCODE_NAMES[unit & 0xFF] not in PAYLOAD_REF_NAMES:
            continue
        target = _signed(old[addr + 1] | (old[addr + 2] << 16), 32)
        new_addr = remap(addr)
        value = remap(target) & 0xFFFFFFFF
        new[new_addr + 1] = value & 0xFFFF
        new[new_addr + 2] = (value >> 16) & 0xFFFF

    # try/catch ranges
    new_tries: List[TryBlock] = []
    for start, count, handlers in tries:
        new_start = remap(start)
        new_end = remap(start + count)
        if new_end <= new_start:
            new_end = new_start + 1
        new_handlers = [(ctype, remap(haddr)) for ctype, haddr in handlers]
        new_tries.append((new_start, new_end - new_start, new_handlers))

    return new, new_tries


def insert_code(
    insns: Sequence[int], tries: Sequence[TryBlock], at: int, units: Sequence[int]
) -> Tuple[List[int], List[TryBlock]]:
    """Insert ``units`` at code unit ``at`` and fix all references."""
    return _reshift(insns, tries, at, len(units), insert=units)


def remove_code(
    insns: Sequence[int], tries: Sequence[TryBlock], at: int, count: int
) -> Tuple[List[int], List[TryBlock]]:
    """Remove ``count`` code units starting at ``at`` and fix all references."""
    return _reshift(insns, tries, at, -count)


def patch_unit(insns: List[int], addr: int, index: int, value: int) -> None:
    """Overwrite one code unit of an existing instruction."""
    insns[addr + index] = value & 0xFFFF
