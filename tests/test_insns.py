from dpairip.dex import insns
from dpairip.dex.model import MethodRef, Proto


def test_opcode_tables_are_complete():
    assert len(insns.OPCODE_NAMES) == 256
    assert len(insns.OPCODE_FORMATS) == 256
    for code, fmt in enumerate(insns.OPCODE_FORMATS):
        assert fmt in insns.FORMAT_SIZE, (code, fmt)
    assert insns.NAME_TO_OPCODE["invoke-virtual"] == 0x6E
    assert insns.NAME_TO_OPCODE["invoke-custom"] == 0xFC


def test_35c_register_layout():
    ref = MethodRef("La;", "b", Proto.parse("(I)V"))
    insn = insns.Insn(insns.NAME_TO_OPCODE["invoke-static"], (2, 3, ref))
    units = insns.encode_insn(insn, lambda kind, value: 7)
    assert units[0] & 0xFF == 0x71
    assert units[0] >> 12 == 2          # argument count
    assert units[0] & 0xF00 == 0        # G only used for the fifth register
    assert units[1] == 7
    assert units[2] == 0x32             # registers C=2, D=3

    five = insns.Insn(insns.NAME_TO_OPCODE["invoke-virtual"], (1, 2, 3, 4, 5, ref))
    units = insns.encode_insn(five, lambda kind, value: 0)
    assert (units[0] >> 8) & 0xF == 5   # G is the fifth register
    assert units[2] == 0x4321


def test_insert_and_remove_fix_branches():
    # goto/16 -1 at unit 1; after inserting two units before it the target
    # (unit 0) is three units behind the branch
    code = [0x0000, 0x0029, 0xFFFF, 0x0000, 0x000E]
    new, _ = insns.insert_code(code, [], 1, [0x0000, 0x0000])
    assert new[1:3] == [0, 0]
    assert new[3] == 0x0029
    assert new[4] == 0xFFFD
    restored, _ = insns.remove_code(new, [], 1, 2)
    assert restored == code


def test_iter_instructions_handles_payload():
    # const/4, fill-array-data payload with two 4-byte entries
    code = [0x0012, 0x0300, 0x0004, 0x0002, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000]
    addresses = [addr for addr, _unit, _size in insns.iter_instructions(code)]
    assert addresses == [0, 1]
    assert insns.insn_size(code, 1) == 8
