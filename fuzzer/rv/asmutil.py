# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import DO_ASSERT
import random
import numpy as np

MAX_32b = 0xFFFFFFFF
MAX_64b = 0xFFFFFFFFFFFFFFFF



def get_another_random_reg_id(forbidden_reg: int, x0_allowed: bool):
    if DO_ASSERT:
        assert 0 <= forbidden_reg
        assert forbidden_reg < 32
    if x0_allowed:
        ret = (forbidden_reg + random.randrange(1, 32)) & 0x1F
        if DO_ASSERT:
            assert 0 <= ret
    else:
        if DO_ASSERT:
            assert 0 < forbidden_reg
        ret = ((forbidden_reg - 1 + random.randrange(1, 31)) % 31) + 1
        if DO_ASSERT:
            assert 0 < ret
    if DO_ASSERT:
        assert ret < 32
        assert ret != forbidden_reg
    return ret

# Generates a section that will contain a typically pseudo-random 8-byte data.
# @param sectionname. It should not have duplicates. Typically 'randdata0' or 'randdata1' or 'randdata2'.
# @param contentval must be nonnegative and fit on 8 bytes.
# @return a list of gnuasm lines that create the section and feed it with the provided data.
def gen_val_section(sectionname: str, contentval: int):
    if DO_ASSERT:
        assert contentval >= 0 and contentval < 0x10000000000000000
    return [
        f'.section ".{sectionname}","ax",@progbits',
        # .align 2  <-- alignment is already enforced by the linker script.
        f'  .8byte {hex(contentval)}'
    ]

# @param val_section_id the section id so that different registers get potentially different values (and do not point to the same)
# @return a list of asm lines that put the random val into the designated register.
def put_random_value_into_reg_if_not_x0(val_section_id: int, tgt_reg_id: int, is_design_32bit: bool, interm_reg: int = None, forbidden_interms = set()):
    if tgt_reg_id == 0:
        return []

    if DO_ASSERT:
        assert 0 <= tgt_reg_id
        assert tgt_reg_id < 32

    # Generate and check the intermediate register.
    while interm_reg is None or interm_reg in forbidden_interms:
        interm_reg = get_another_random_reg_id(tgt_reg_id, False) # Load the symbol using any other symbol
    if DO_ASSERT:
        assert 0 < interm_reg
        assert interm_reg < 32
        assert interm_reg not in forbidden_interms
        assert tgt_reg_id != interm_reg

    # Load a word or a double, depending on bit width of the CPU ISA.
    if is_design_32bit:
        load_opcode = 'lw'
    else:
        load_opcode = 'ld'

    return [
        f"la x{interm_reg}, randdata{val_section_id}",
        f"{load_opcode} x{tgt_reg_id}, (x{interm_reg})"
    ]

# Helper function that generates assembly lines to load random data into a floating point register
# @param val_section_id the section id so that different registers get potentially different values (and do not point to the same)
# @param tgt_reg_id the id of the register to be assigned, must be included between 0 and 31.
# @param interm_reg the intermediate register id. Leave None for a constrained random choice.
# @return a list of assembly lines.
def put_random_value_into_floating_double_reg(val_section_id: int, tgt_reg_id: int, interm_reg: int = None, forbidden_interms = set()):
    if DO_ASSERT:
        assert 0 <= tgt_reg_id
        assert tgt_reg_id < 32

    # Generate and check the intermediate register.
    while interm_reg is None or interm_reg in forbidden_interms:
        interm_reg = random.randrange(1, 32) # Load the symbol using any other symbol
    if DO_ASSERT:
        assert 0 < interm_reg
        assert interm_reg < 32
        assert interm_reg not in forbidden_interms
    # For a target floating register, the reg id can be the same as the interm (because one is floating is one is integer)
    # assert tgt_reg_id != interm_reg

    # Load a word or a double, depending on bit width of the CPU ISA.
    load_opcode = 'fld'

    return [
        f"la x{interm_reg}, randdata{val_section_id}",
        f"{load_opcode} f{tgt_reg_id}, (x{interm_reg})"
    ]

# This function sets the value of the given register using an lui+addi sequence.
# @param do_check_bounds if True, will check that the value is not too big to fit in 31 bits (i.e., in 32 bits but without being sign-extended to 64 bits). DO_ASSERT must be True for it to be effective.
# @return pair (lui_imm: int, addi_imm: int)
def li_into_reg(val_unsigned: int, do_check_bounds: bool = True):
    if DO_ASSERT:
        assert val_unsigned >= 0
        if do_check_bounds:
            assert val_unsigned < 0x80000000, f"For the destination address `{hex(val_unsigned)}`, we will need to manage sign extension, which is not yet implemented here."

    # Check whether the MSB of the addi would be 1. In this case, we will add 1 to the lui
    is_sign_extend_ones = (val_unsigned >> 11) & 1

    addi_imm = val_unsigned & 0xFFF
    # Make it negative properly
    if is_sign_extend_ones:
        addi_imm = -((~addi_imm) & 0xFFF) - 1
    lui_imm  = (int(is_sign_extend_ones) + (val_unsigned >> 12)) & 0xFFFFF
    return lui_imm, addi_imm

# From an unsigned int coded on 32 or 64 bits, returns the signed value when interpreting the value as signed
def twos_complement(val_unsigned: int, is_design_64bit: bool):
    if is_design_64bit:
        if DO_ASSERT:
            assert val_unsigned >= 0, f"{hex(val_unsigned)} < 0"
            assert val_unsigned < 1 << 64,  f"{hex(val_unsigned)} >= 2**64"
        return val_unsigned - (((val_unsigned >> 63) & 1) << 64)
    else:
        if DO_ASSERT:
            assert val_unsigned >= 0, f"{hex(val_unsigned)} < 0"
            assert val_unsigned < 1 << 32,  f"{hex(val_unsigned)} >= 2**32"
        return val_unsigned - (((val_unsigned >> 31) & 1) << 32)

# From a signed int, returns an unsigned version.
# This should be a reciprocal function of twos_complement.
def to_unsigned(val_signed: int, is_design_64bit: bool):
    if is_design_64bit:
        if DO_ASSERT:
            assert val_signed < 1 << 63
        return (((val_signed >> 63) & 1) << 64) + val_signed
    else:
        if DO_ASSERT:
            assert val_signed < 1 << 32
        return (((val_signed >> 31) & 1) << 32) + val_signed


def add(a: int, b: int,  is_design_64bit: bool):
    return a + b

def add_t0(a: int, a_t0: int, b: int, b_t0: int,  is_design_64bit: bool):
    # Compute the smallest possible result
    a_and_not_a_t0 = a&~a_t0
    b_and_not_b_t0 = b&~b_t0
    a_plus_b_not_t0 = a_and_not_a_t0 + b_and_not_b_t0

    # Compute the largest possible result
    a_or_a_t0 = a | a_t0
    b_or_b_t0 = b | b_t0
    a_plus_b_or_t0 = a_or_a_t0 + b_or_b_t0

    # Compute the polarization term.
    polarization = a_plus_b_not_t0 ^ a_plus_b_or_t0

    # Compute the transportability term.
    transport = a_t0 | b_t0

    return polarization | transport

def sub(a: int, b: int,  is_design_64bit: bool):
    return a - b

def sub_t0(a: int, a_t0: int, b: int, b_t0: int,  is_design_64bit: bool):
    a_and_not_a_t0 = a&~a_t0
    b_and_not_b_t0 = b&~b_t0

    a_or_a_t0 = a | a_t0
    b_or_b_t0 = b | b_t0

    # Compute the result where a is largets and b is smallest
    a_max_minus_b_min = a_or_a_t0 - b_and_not_b_t0
    # Compute the result where b is largets and a is smallest
    a_min_minus_b_max = a_and_not_a_t0 - b_or_b_t0

    # Compute the polarization term.
    polarization = a_max_minus_b_min ^ a_min_minus_b_max

    # Compute the transportability term.
    transport = a_t0 | b_t0

    return (polarization | transport)

def sll(a: int, b: int,  is_design_64bit: bool):
    shamt = b & 0x1F
    return a<<shamt

def sll_t0_imprecise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    if b_t0 and (a or a_t0):
        return MAX_64b if is_design_64bit else MAX_32b
    elif b_t0 and not (a or a_t0):
        return 0x0
    else:
        return sll(a_t0, b, is_design_64bit)

def sll_t0_precise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    # The first cell of the decomposition shifts a and a_t0 by b_0 (i.e. b&~b_t0)
    a_p = a<<(b&~b_t0)
    a_p_t0 = a_t0<<(b&~b_t0)

    # The second cell of the decomposition inputs a_p and b_p = b&b_t0 .
    b_p = b&b_t0
    y_t0 = a_p_t0
    for k in range((b_p &~b_t0) & (2**5-1), (b_p | b_t0) & (2**5-1)):
        left_side = b_t0 | ~(k ^ b_p) # k is a reachable by modifying tainted bits in b_p
        left_side &= MAX_64b if is_design_64bit else MAX_32b
        right_side = (a_p_t0 << k) | (a_p ^ (a_p<<k)) # Bit i can either be tainted by a of a tainted bit in a by k or by a difference in the bit value between shamts b and k
        y_t0 |= left_side&right_side
    
    y_t0 &= MAX_64b if is_design_64bit else MAX_32b

    return y_t0

def slt(a: int, b: int, is_design_64bit: bool):
    return twos_complement(a,is_design_64bit) < twos_complement(b, is_design_64bit)

def slt_t0(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    a_signed = twos_complement(a, is_design_64bit)
    b_signed = twos_complement(b, is_design_64bit)
    a_t0_signed = twos_complement(a_t0, is_design_64bit)
    b_t0_signed = twos_complement(b_t0, is_design_64bit)
    return slt_t0(a_signed, a_t0_signed, b_signed, b_t0_signed, is_design_64bit)
    
def sltu(a: int, b: int,  is_design_64bit: bool):
    return a < b

def sltu_t0(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    # print(f"a: {hex(a)}, a_t0: {hex(a_t0)}, b: {hex(b)}, b_t0: {hex(b_t0)}")

    a_and_not_a_t0 = a&~a_t0
    b_and_not_b_t0 = b&~b_t0

    assert a_and_not_a_t0 >= 0
    assert b_and_not_b_t0 >= 0

    a_or_a_t0 = a | a_t0
    b_or_b_t0 = b | b_t0

    assert a_or_a_t0 >= 0
    assert b_or_b_t0 >= 0
    # Compute the result where a is largest and b is smallest
    a_max_lt_b_min = a_or_a_t0 < b_and_not_b_t0
    # Compute the result where b is largest and a is smallest
    a_min_lt_b_max = a_and_not_a_t0 < b_or_b_t0

    # print(f"a_max_lt_b_min: {hex(a_max_lt_b_min)}, a_min_lt_b_max: {hex(a_min_lt_b_max)}")

    # Compute the polarization term.
    polarization = a_max_lt_b_min ^ a_min_lt_b_max

    # print(f"pol: {hex(polarization)}")

    return polarization


def slt_t0(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    # print(f"a: {hex(a)}, a_t0: {hex(a_t0)}, b: {hex(b)}, b_t0: {hex(b_t0)}")

    a_and_not_a_t0 = a&~a_t0
    b_and_not_b_t0 = b&~b_t0

    a_or_a_t0 = a | a_t0
    b_or_b_t0 = b | b_t0

    msb_mask = 1<<63 if is_design_64bit else 1<<31
    exclude_msb_mask = MAX_64b^msb_mask if is_design_64bit else MAX_32b^msb_mask

    # For maximal value set msb to 0, for minimal set msb to 1 it bit tainted. 
    min_a_msb = a_or_a_t0&msb_mask
    min_b_msb = b_or_b_t0&msb_mask
    max_a_msb = a_and_not_a_t0&msb_mask
    max_b_msb = b_and_not_b_t0&msb_mask
    
    # Compute the result where a is largest and b is smallest
    a_min = (a_and_not_a_t0&exclude_msb_mask)|min_a_msb
    b_min = (b_and_not_b_t0&exclude_msb_mask)|min_b_msb
    a_max = (a_or_a_t0&exclude_msb_mask)|max_a_msb
    b_max = (b_or_b_t0&exclude_msb_mask)|max_b_msb

    a_min = twos_complement(a_min,is_design_64bit)
    a_max = twos_complement(a_max,is_design_64bit)
    b_max = twos_complement(b_max,is_design_64bit)
    b_min = twos_complement(b_min,is_design_64bit)

    # print(f"a_min: {a_min}, a_max: {a_max}, b_min: {b_min}, b_max: {b_max}")
    
    # Compute the result where b is largest and a is smallest
    a_min_lt_b_max = a_min < b_max
    a_max_lt_b_min = a_max < b_min

    # print(f"a_max_lt_b_min: {hex(a_max_lt_b_min)}, a_min_lt_b_max: {hex(a_min_lt_b_max)}")

    # Compute the polarization term.
    polarization = a_max_lt_b_min ^ a_min_lt_b_max
    # print(f"pol: {hex(polarization)}")
    return polarization

def xor(a: int, b: int,  is_design_64bit: bool):
    return a ^ b

def xor_t0(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    return a_t0 | b_t0

def srl(a: int, b: int,  is_design_64bit: bool):
    shamt = b & 0x1F
    return a>>shamt

def srl_t0_imprecise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    if b_t0 and (a or a_t0):
        return MAX_64b if is_design_64bit else MAX_32b
    elif b_t0 and not (a or a_t0):
        return 0x0
    else:
        return srl(a_t0,b, is_design_64bit)

def srl_t0_precise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    # The first cell of the decomposition shifts the a_t0 by b_0 (i.e. b&~b_t0)
    a_p = a>>(b&~b_t0)
    a_p_t0 = a_t0>>(b&~b_t0)

    # The second cell of the decomposition inputs a_p and b_p = b&b_t0 .
    b_p = b&b_t0
    y_t0 = a_p_t0
    for k in range((b_p &~b_t0) & (2**5-1), (b_p | b_t0) & (2**5-1)):
        left_side = b_t0 | ~(k ^ b_p) # k is a reachable by modifying tainted bits in b_p
        right_side = (a_p_t0 >> k) | (a_p ^ (a_p>>k)) # Bit i can either be tainted by a of a tainted bit in a by k or by a difference in the bit value between shamts b and k
        y_t0 |= left_side&right_side

    # print(f"a: {a}, a_t0: {a_t0}, b: {b}, b_t0: {b_t0}, y_t0: {y_t0}")
    y_t0 &= MAX_64b if is_design_64bit else MAX_32b
    return y_t0


def sra(a: int, b: int, is_design_64bit: bool):
    n_bits = 64 if is_design_64bit else 32
    msb = (a>>(n_bits-1))&1
    shamt = b&0x1F
    mask = MAX_32b<<(n_bits-shamt)
    mask &= MAX_32b
    return (a >> shamt) | (mask*msb)


def sra_t0(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    if b_t0:
        return MAX_64b if is_design_64bit else MAX_32b
    else:
        return sra(a_t0, b, is_design_64bit)

def or_(a: int, b: int, is_design_64bit: bool):
    return a | b

def or_t0(a: int, a_t0: int, b: int, b_t0: int,  is_design_64bit: bool):
    a_and_b_t0 = a_t0 & b_t0 # Can change value since both sides tainted
    
    # Can change value since one side is zero while other is tainted.
    a_t0_and_not_b = a_t0 & ~b
    b_t0_and_not_a = b_t0 & ~a

    a_t0_and_not_b_or_reverse = a_t0_and_not_b | b_t0_and_not_a

    return a_and_b_t0 | a_t0_and_not_b_or_reverse

def and_(a: int, b: int, is_design_64bit: bool):
    return a & b

def and_t0(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    a_and_b_t0 = a_t0 & b_t0 # Can change value since both sides tainted
    
    # Can change value since one side is one while other is tainted.
    a_t0_and_b = a_t0 & b
    b_t0_and_a = b_t0 & a

    a_t0_and_b_or_reverse = a_t0_and_b | b_t0_and_a

    return (a_and_b_t0 | a_t0_and_b_or_reverse)

## IMMEDIATE OPERATIONS ##
def addi(a: int, imm: int, is_design_64bit: bool):
    return a + to_unsigned(imm, is_design_64bit)

def addi_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit):
    uimm = to_unsigned(imm, is_design_64bit)
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit)
    return add_t0(a,a_t0,uimm,uimm_t0,is_design_64bit)

def slli(a: int, imm: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    return sll(a,uimm,is_design_64bit)

def slli_t0_precise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit)
    return sll_t0_precise(a,a_t0,uimm,uimm_t0,is_design_64bit)


def slli_t0_imprecise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit)
    return sll_t0_imprecise(a,a_t0,uimm,uimm_t0,is_design_64bit)

def slti(a: int, imm: int, is_design_64bit: bool):
    return twos_complement(a,is_design_64bit) < imm

def slti_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    a_signed = twos_complement(a, is_design_64bit)
    a_t0_signed = twos_complement(a_t0, is_design_64bit)
    return slt_t0(a_signed, a_t0_signed, imm, imm_t0, is_design_64bit)

def sltiu(a: int, imm: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    return sltu(a, uimm, is_design_64bit)

def sltiu_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit)
    return slti_t0(a,a_t0,uimm,uimm_t0,is_design_64bit)

def xori(a: int, imm: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    return xor(a,uimm,is_design_64bit)

def xori_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit)
    return xor_t0(a, a_t0, uimm, uimm_t0, is_design_64bit)

def srli(a: int, imm: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    return srl(a,uimm, is_design_64bit)

def srli_t0_precise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit)
    return srl_t0_precise(a, a_t0, uimm, uimm_t0, is_design_64bit)

def srli_t0_imprecise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit)
    return srl_t0_imprecise(a, a_t0, uimm, uimm_t0, is_design_64bit)

def srai(a: int, imm: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    return sra(a, uimm, is_design_64bit)

def srai_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit)
    return sra_t0(a, a_t0, uimm, uimm_t0, is_design_64bit)

def ori(a: int, imm: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    return or_(a, uimm, is_design_64bit)

def ori_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: int):
    uimm = to_unsigned(imm, is_design_64bit)
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit)
    return or_t0(a, a_t0, uimm, uimm_t0, is_design_64bit)

def andi(a: int, imm: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit)
    return and_(a, uimm, is_design_64bit)

def andi_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: int):
    uimm = to_unsigned(imm, is_design_64bit)
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit)
    return and_t0(a, a_t0, uimm, uimm_t0, is_design_64bit)

def lui(pc: int, imm: int, is_design_64bit: bool):
    return to_unsigned(imm, is_design_64bit)<<12

def lui_t0(pc: int, pc_t0: int,  imm: int, imm_t0: int, is_design_64bit: bool):
    return lui(0x0, imm_t0, is_design_64bit)

def auipc(pc: int, imm: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit) & 0xFFFFF # 20 bit immediate
    n_bits = 64 if is_design_64bit else 32
    mask = (MAX_64b<<n_bits)&MAX_64b # extend to 64 bits
    uimm = (uimm & 0xFFFFF) << 12
    res = pc+uimm
    msb = (res>>(n_bits-1))&1
    return res | (mask*msb)

def auipc_t0(pc: int, pc_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit) & 0xFFFFF # 20 bit immediate
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit) & 0xFFFFF # 20 bit immediate
    n_bits = 64 if is_design_64bit else 32
    mask = (MAX_64b<<n_bits)&MAX_64b # extend to 64 bits
    uimm = (uimm & 0xFFFFF) << 12
    uimm_t0 = (uimm_t0 & 0xFFFFF) << 12
    res_t0 = add_t0(pc, pc_t0, uimm, uimm_t0, is_design_64bit)
    msb = (res_t0>>(n_bits-1))&1
    return (res_t0 | (mask*msb))

## JAL and JALR ##
def jal(pc: int, imm: int, is_design_64bit: bool):
    return pc+4

def jal_t0(pc: int, pc_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    # return addi_t0(pc, 0x0, 0x0, 0x0, is_design_64bit)
    return 0x0 # always returns 0 since pc is never tainted and jal computes pc+4

def jalr(pc: int, imm: int, is_design_64bit: bool):
    return pc+4

def jalr_t0(pc: int, pc_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    # return addi_t0(pc, 0x0, 0x0, 0x0, is_design_64bit)
    return 0x0 # always returns 0 since pc is never tainted and jalr computes pc+4



INSTR_FUNCS = {
    # register instructions
    "add": add,
    "sub": sub,
    "sll": sll,
    "slt": slt,
    "sltu": sltu,
    "xor": xor,
    "srl": srl,
    "sra": sra,
    "or": or_,
    "and": and_,
    # immediate instructions
    "addi": addi,
    "slli": slli,
    "slti": slti,
    "sltiu": sltiu,
    "xori": xori,
    "srli": srli,
    "srai": srai,
    "ori": ori,
    "andi": andi,
    "lui": lui,
    "auipc": auipc,
    # jal and jalr
    "jal": jal,
    "jalr": jalr,
    # placeholder instructions
    "lui (PlaceholderProducerInstr0)": lui,
    "addi (PlaceholderProducerInstr1)": addi,
    "and (PlaceholderPreConsumerInstr)": and_,
    "xor (PlaceholderConsumerInstr)": xor,
    # load and store instructions
    "sw": addi, # to compute the address
    "lw": addi, # to compute the address
    # unimplemented instructions
    "csrw": None,
    "csrrw": None,
    "csrrwi": None,
    "csrrs": None,
    "fence": None,
    "bne": None
}

INSTR_FUNCS_T0 = {
    # register instructions
    "add": add_t0,
    "sub": sub_t0,
    "sll": sll_t0_precise,
    "slt": slt_t0,
    "sltu": sltu_t0,
    "xor": xor_t0,
    "srl": srl_t0_precise,
    "sra": sra_t0,
    "or": or_t0,
    "and": and_t0,
    # immediate instructions
    "addi": addi_t0,
    "slli": slli_t0_precise,
    "slti": slti_t0,
    "sltiu": sltiu_t0,
    "xori": xori_t0,
    "srli": srli_t0_precise,
    "srai": srai_t0,
    "ori": ori_t0,
    "andi": andi_t0,
    "lui": lui_t0,
    "auipc": auipc_t0,
    # jal and jalr
    "jal": jal_t0,
    "jalr": jalr_t0,
    # placeholder instructions
    "lui (PlaceholderProducerInstr0)": lui_t0,
    "addi (PlaceholderProducerInstr1)": addi_t0,
    "and (PlaceholderPreConsumerInstr)": and_t0,
    "xor (PlaceholderConsumerInstr)": xor_t0,
    # load and store instructions
    "sw": None, # we don't allow tainted addresses
    "lw": None, # we don't allow tainted addresses
    # unimplemented instructions
    "csrw": None,
    "csrrw": None,
    "csrrwi": None,
    "csrrs": None,
    "fence": None,
    "bne": None
}




