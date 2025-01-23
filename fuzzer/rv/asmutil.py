# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import DO_ASSERT
from params.celliftparams import *
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

# Sign-extends a number of specified bit-width to either 64 or 32 bit.
def sign_extend(a,n_bit,is_design_64bit):
    msb = (a>>(n_bit-1))&1
    mask = 2**n_bit-1
    return a | (((MAX_64b if is_design_64bit else MAX_32b)^mask))*msb

def add(a: int, b: int,  is_design_64bit: bool):
    return a + b

def addw(a: int, b: int,  is_design_64bit: bool):
    res32 = add(a&MAX_32b,b&MAX_32b,is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def subw(a: int, b: int,  is_design_64bit: bool):
    res32 = sub(a&MAX_32b,b&MAX_32b,is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

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

def addw_t0(a: int, a_t0: int, b: int, b_t0: int,  is_design_64bit: bool):
    res32 =  add_t0(a&MAX_32b,a_t0&MAX_32b,b&MAX_32b,b_t0&MAX_32b,is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def sub(a: int, b: int,  is_design_64bit: bool):
    return a - b

def sub_t0(a: int, a_t0: int, b: int, b_t0: int,  is_design_64bit: bool):
    a_and_not_a_t0 = a&~a_t0
    b_and_not_b_t0 = b&~b_t0

    a_or_a_t0 = a|a_t0
    b_or_b_t0 = b|b_t0

    a_max_min_b_min = a_or_a_t0 - b_and_not_b_t0 
    a_min_min_b_max = a_and_not_a_t0 - b_or_b_t0

    # Compute the polarization term.
    polarization = a_max_min_b_min ^ a_min_min_b_max

    # Compute the transportability term.
    transport = a_t0 | b_t0
    res = polarization | transport
    # if a_t0 == 0 or b_t0 == 0:
    # print(f"SUB: a={hex(a)} a_t0={hex(a_t0)} b={hex(b)} b_t0={hex(b_t0)} a_max_min_b_min={hex(a_max_min_b_min)} a_min_min_b_max={hex(a_min_min_b_max)} res={hex(res&0xFFFFFFFF)}")
        
    # return add_t0(a, a_t0, ~b+1, b_t0, is_design_64bit)
    return res


def sll(a: int, b: int,  is_design_64bit: bool):
    shamt = b & 0x3F if is_design_64bit else b & 0x1F
    return a<<shamt

def sllw(a: int, b: int,  is_design_64bit: bool):
    res32 = sll(a&MAX_32b, b&0x1f, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def sll_t0_imprecise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    # if b_t0&(0x3f if is_design_64bit else 0x1f):
    if b_t0: # overaproximate
        return MAX_64b if is_design_64bit else MAX_32b
    else:
        return sll(a_t0, b, is_design_64bit)

def sllw_t0_imprecise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    res32 = sll_t0_imprecise(a&MAX_32b, a_t0&MAX_32b, b&0x1F, b_t0&0x1F, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def sll_t0_precise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    # The first cell of the decomposition shifts a and a_t0 by b_0 (i.e. b&~b_t0)
    a_p = a<<((b&~b_t0)&0x1F)
    a_p_t0 = a_t0<<((b&~b_t0)&0x1F)

    # The second cell of the decomposition inputs a_p and b_p = b&b_t0.
    b_p = b&b_t0
    y_t0 = a_p_t0
    for k in range((b_p &~b_t0) & (2**5-1), (b_p | b_t0) & (2**5-1)):
        left_side = b_t0 | ~(k ^ b_p) # k is a reachable by modifying tainted bits in b_p
        left_side &= MAX_64b if is_design_64bit else MAX_32b
        right_side = (a_p_t0 << k) | (a_p ^ (a_p<<k)) # Bit i can either be tainted by a of a tainted bit in a by k or by a difference in the bit value between shamts b and k
        y_t0 |= left_side&right_side
    
    y_t0 &= MAX_64b if is_design_64bit else MAX_32b
    # print(f"a: {hex(a)}, a_t0: {hex(a_t0)}, b: {hex(b)}, b_t0: {hex(b_t0)}")
    return y_t0

def sllw_t0_precise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    res32 = sll_t0_precise(a&MAX_32b, a_t0&MAX_32b, b&0x1f, b_t0&0x1f, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)


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

    # print(f"a:{hex(a)}, a_t0: {hex(a_t0)}, b: {hex(b)}, b_t0: {hex(b_t0)}, a_max_lt_b_min: {hex(a_max_lt_b_min)}, a_min_lt_b_max: {hex(a_min_lt_b_max)}")

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
    shamt = b & 0x3F if is_design_64bit else b & 0x1F
    return a>>shamt

def srlw(a: int, b: int,  is_design_64bit: bool):
    res32 = srl(a&MAX_32b, b&0x1f, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)
    
def srl_t0_imprecise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    # if b_t0&(0x3f if is_design_64bit else 0x1f):
    if b_t0: # overaproximate
        return MAX_64b if is_design_64bit else MAX_32b
    else:
        return srl(a_t0,b, is_design_64bit)

def srlw_t0_imprecise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    res32 = srl_t0_imprecise(a&MAX_32b, a_t0&MAX_32b, b&MAX_32b, b_t0&MAX_32b, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)


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

def srlw_t0_precise(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    res32 = srl_t0_precise(a&MAX_32b, a_t0&MAX_32b, b&MAX_32b, b_t0&MAX_32b, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def sra(a: int, b: int, is_design_64bit: bool):
    n_bits = 64 if is_design_64bit else 32
    msb = (a>>(n_bits-1))&1
    shamt = b & 0x3F if is_design_64bit else b & 0x1F
    mask = (MAX_64b if is_design_64bit else MAX_32b)<<(n_bits-shamt)
    mask &= (MAX_64b if is_design_64bit else MAX_32b)
    return (a >> shamt) | (mask*msb)

def sraw(a: int, b: int, is_design_64bit: bool):
    n_bits = 32
    msb = ((a&MAX_32b)>>(n_bits-1))&1
    shamt = b & 0x1F
    mask = MAX_32b<<(n_bits-shamt)
    mask &= MAX_32b
    res32 =  (((a&MAX_32b) >> shamt) | (mask*msb))&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def sra_t0(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    # if b_t0&(0x3F if is_design_64bit else 0x1F):
    if b_t0: # overaproximate
        return MAX_64b if is_design_64bit else MAX_32b
    else:
        return sra(a_t0, b, is_design_64bit)

def sraw_t0(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    return sra_t0(a&MAX_32b, a_t0&MAX_32b, b&MAX_32b, b_t0&MAX_32b, is_design_64bit)&MAX_32b

def or_(a: int, b: int, is_design_64bit: bool):
    return a | b

def conj(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    return sign_extend(a_t0,32,is_design_64bit) | sign_extend(b_t0,32,is_design_64bit)

def conji(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    return sign_extend(a_t0,32,is_design_64bit) | sign_extend(imm_t0,12,is_design_64bit)

# Used for div/mul, precise IFT rules not implemented yet.
def allones(a: int, a_t0: int, b: int, b_t0: int, is_design_64bit: bool):
    if a_t0 or b_t0:
        return MAX_64b if is_design_64bit else MAX_32b
    else:
        return 0

def or_t0(a: int, a_t0: int, b: int, b_t0: int,  is_design_64bit: bool):
    a_t0_and_b_t0 = a_t0 & b_t0 # Can change value since both sides tainted
    # print(f"a={hex(a)}, a_t0={hex(a_t0)}, b={hex(b)}, b_t0={hex(b_t0)}")
    # Can change value since one side is zero while other is tainted.
    a_t0_and_not_b = a_t0 & ~b
    b_t0_and_not_a = b_t0 & ~a
    # print(f"a_t0_and_not_b={hex(a_t0_and_not_b)}")
    # print(f"b_t0_and_not_a={hex(b_t0_and_not_a)}")

    a_t0_and_not_b_or_reverse = a_t0_and_not_b | b_t0_and_not_a
    # print(f"a_t0_and_not_b_or_reverse={hex(a_t0_and_not_b_or_reverse)}")
    # print(f"conjunctive: {hex(or_(a_t0,b_t0,is_design_64bit))}")
    return a_t0_and_b_t0 | a_t0_and_not_b_or_reverse
    # return or_(a_t0,b_t0,is_design_64bit)

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
    imm = sign_extend(imm,12,is_design_64bit)
    return a + imm

def addiw(a: int, imm: int, is_design_64bit: bool):
    res32 = addi(a&MAX_32b, imm, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def addi_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit):
    imm = sign_extend(imm,12,is_design_64bit)
    imm_t0 = sign_extend(imm_t0,12,is_design_64bit)
    return add_t0(a,a_t0,imm,imm_t0,is_design_64bit)

def addiw_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit):
    res32 = addi_t0(a&MAX_32b, a_t0&MAX_32b, imm, imm_t0, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def slli(a: int, imm: int, is_design_64bit: bool):
    return sll(a,imm,is_design_64bit)

def slliw(a: int, imm: int, is_design_64bit: bool):
    assert (imm>>5)&1 == 0
    res32 = sll(a&MAX_32b, imm, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def slli_t0_precise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    return sll_t0_precise(a,a_t0,imm,imm_t0,is_design_64bit)

def slliw_t0_precise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    res32 = slli_t0_precise(a&MAX_32b, a_t0&MAX_32b, imm, imm_t0,is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def slli_t0_imprecise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    return sll_t0_imprecise(a,a_t0,imm,imm_t0,is_design_64bit)

def slliw_t0_imprecise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    res32 =  slli_t0_imprecise(a&MAX_32b, a_t0&MAX_32b, imm, imm_t0, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def slti(a: int, imm: int, is_design_64bit: bool):
    return twos_complement(a,is_design_64bit) < sign_extend(imm, 12,is_design_64bit)

def slti_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    a_signed = twos_complement(a, is_design_64bit)
    a_t0_signed = twos_complement(a, is_design_64bit)
    return slt_t0(a_signed, a_t0_signed, imm, imm_t0, is_design_64bit)

def sltiu(a: int, imm: int, is_design_64bit: bool):
    uimm = to_unsigned(sign_extend(imm,12,is_design_64bit), is_design_64bit)
    return sltu(a, uimm, is_design_64bit)

def sltiu_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    uimm = to_unsigned(sign_extend(imm,12,is_design_64bit), is_design_64bit)
    uimm_t0 = to_unsigned(sign_extend(imm_t0,12,is_design_64bit), is_design_64bit)
    return slti_t0(a,a_t0,uimm,uimm_t0,is_design_64bit)

def xori(a: int, imm: int, is_design_64bit: bool):
    imm = sign_extend(imm,12,is_design_64bit)
    return xor(a,imm,is_design_64bit)

def xori_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    imm = sign_extend(imm,12,is_design_64bit)
    imm_t0 = sign_extend(imm_t0,12,is_design_64bit)
    return xor_t0(a, a_t0, imm, imm_t0, is_design_64bit)

def srli(a: int, imm: int, is_design_64bit: bool):
    return srl(a,imm, is_design_64bit)

def srliw(a: int, imm: int, is_design_64bit: bool):
    assert (imm>>5)&1 == 0
    res32 = srli(a&MAX_32b, imm, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def srli_t0_precise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    return srl_t0_precise(a, a_t0, imm, imm_t0, is_design_64bit)

def srliw_t0_precise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    res32 = srli_t0_precise(a&MAX_32b, a_t0&MAX_32b, imm, imm_t0, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def srli_t0_imprecise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    return srl_t0_imprecise(a, a_t0, imm, imm_t0, is_design_64bit)

def srliw_t0_imprecise(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    res32 = srli_t0_imprecise(a&MAX_32b, a_t0&MAX_32b, imm, imm_t0, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def srai(a: int, imm: int, is_design_64bit: bool):
    return sra(a, imm, is_design_64bit)

def sraiw(a: int, imm: int, is_design_64bit: bool):
    assert (imm>>5)&1 == 0
    return sraw(a&MAX_32b, imm&0x1F, is_design_64bit)

def srai_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    return sra_t0(a, a_t0, imm, imm_t0, is_design_64bit)

def sraiw_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    res32 = srai_t0(sign_extend(a,32,False), sign_extend(a_t0,32,False), imm, imm_t0, is_design_64bit)&MAX_32b
    return sign_extend(res32, 32, is_design_64bit)

def ori(a: int, imm: int, is_design_64bit: bool):
    imm = sign_extend(imm,12,is_design_64bit)
    return or_(a, imm, is_design_64bit)

def ori_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: int):
    imm = sign_extend(imm,12,is_design_64bit)
    imm_t0 = sign_extend(imm_t0,12,is_design_64bit)
    return or_t0(a, a_t0, imm, imm_t0, is_design_64bit)

def andi(a: int, imm: int, is_design_64bit: bool):
    imm = sign_extend(imm,12,is_design_64bit)
    return and_(a, imm, is_design_64bit)

def andi_t0(a: int, a_t0: int, imm: int, imm_t0: int, is_design_64bit: int):
    imm = sign_extend(imm,12,is_design_64bit)
    imm_t0 = sign_extend(imm_t0,12,is_design_64bit)
    return and_t0(a, a_t0, imm, imm_t0, is_design_64bit)

def lui(pc: int, imm: int, is_design_64bit: bool):
    res = to_unsigned(imm, is_design_64bit)<<12
    if is_design_64bit:
        msb = (res>>31)&1
        res |= (MAX_64b^MAX_32b)*msb
    return res&(MAX_64b if is_design_64bit else MAX_32b)
    
def lui_t0(pc: int, pc_t0: int,  imm: int, imm_t0: int, is_design_64bit: bool):
    return lui(0x0, imm_t0, is_design_64bit)

def auipc(pc: int, imm: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit) & 0xFFFFF # 20 bit immediate
    uimm = uimm << 12
    if is_design_64bit:
        msb = (uimm>>31)&1
        uimm |= (MAX_64b^MAX_32b)*msb
    res = pc+uimm
    return res

def auipc_t0(pc: int, pc_t0: int, imm: int, imm_t0: int, is_design_64bit: bool):
    uimm = to_unsigned(imm, is_design_64bit) & 0xFFFFF # 20 bit immediate
    uimm = uimm << 12
    uimm_t0 = to_unsigned(imm_t0, is_design_64bit) & 0xFFFFF # 20 bit immediate
    uimm_t0 = uimm_t0 << 12
    if is_design_64bit:
        msb_t0 = (uimm_t0>>31)&1
        uimm_t0 |= (MAX_64b^MAX_32b)*msb_t0
        msb= (uimm>>31)&1
        uimm |= (MAX_64b^MAX_32b)*msb

    res_t0 = add_t0(pc, pc_t0, uimm, uimm_t0, is_design_64bit)
    return res_t0

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


def csrrs(rs1_val: int, csr_val: int, is_design_64bit: bool):
    return csr_val | rs1_val

def csrrc(rs1_val: int, csr_val: int, is_design_64bit: bool):
    return csr_val & ~rs1_val

def csrrw(rs1_val: int, csr_val: int, is_design_64bit: bool):
    return rs1_val


def csrrsi(uimm: int, csr_val: int, is_design_64bit: bool):
    return csr_val | uimm

def csrrci(uimm: int, csr_val: int, is_design_64bit: bool):
    return csr_val & ~uimm

def csrrwi(uimm: int, csr_val: int, is_design_64bit: bool):
    return uimm


def csrrs_t0(rs1_val: int, rs1_val_t0: int, csr_val: int, csr_val_t0: int, is_design_64bit: bool):
    return or_t0(rs1_val,rs1_val_t0,csr_val,csr_val_t0, is_design_64bit)

def csrrc_t0(rs1_val: int, rs1_val_t0: int, csr_val: int, csr_val_t0: int, is_design_64bit: bool):
    return and_t0(csr_val,csr_val_t0, ~rs1_val, rs1_val_t0, is_design_64bit)

def csrrw_t0(rs1_val: int, rs1_val_t0: int, csr_val: int, csr_val_t0: int, is_design_64bit: bool):
    return rs1_val_t0


def csrrsi_t0(uimm: int, uimm_t0: int, csr_val: int, csr_val_t0: int, is_design_64bit: bool):
    return ori_t0(uimm,uimm_t0,csr_val,csr_val_t0)

def csrrci_t0(uimm: int, uimm_t0: int, csr_val: int, csr_val_t0: int, is_design_64bit: bool):
    return andi_t0(uimm,uimm_t0,~csr_val,csr_val_t0)

def csrrwi_t0(uimm: int, uimm_t0: int, csr_val: int, csr_val_t0: int, is_design_64bit: bool):
    return uimm_t0

def lb(a, is_design_64bit: bool):
    return sign_extend(a,8,is_design_64bit)

def lh(a, is_design_64bit: bool):
    return sign_extend(a,16,is_design_64bit)

def lw(a, is_design_64bit: bool):
    return sign_extend(a,32,is_design_64bit)

def lbu(a, is_design_64bit: bool):
    return a&0xFF

def lhu(a, is_design_64bit: bool):
    return a&0xFFFF

def lwu(a, is_design_64bit: bool):
    return a&MAX_32b

def ld(a, is_design_64bit: bool):
    return sign_extend(a,64,is_design_64bit)

def lb_t0(a, is_design_64bit: bool):
    return sign_extend(a,8,is_design_64bit)

def lh_t0(a, is_design_64bit: bool):
    return sign_extend(a,16,is_design_64bit)

def lw_t0(a, is_design_64bit: bool):
    return sign_extend(a,32,is_design_64bit)

def lbu_t0(a, is_design_64bit: bool):
    return a&0xFF

def lhu_t0(a, is_design_64bit: bool):
    return a&0xFFFF

def lwu_t0(a, is_design_64bit: bool):
    return a&MAX_32b

def ld_t0(a, is_design_64bit: bool):
    return sign_extend(a,64,is_design_64bit)

def mul(a, b, is_design_64bit: bool):
    return (a*b)&(MAX_64b if is_design_64bit else MAX_32b)

def mulh(a, b, is_design_64bit: bool):
    mult_res = twos_complement(a,is_design_64bit)*twos_complement(b,is_design_64bit)
    ret =  (mult_res&(MAX_64b<<64)) >> 64 if is_design_64bit else (mult_res&(MAX_64b<<32)) >> 32
    return ret

def mulhu(a, b, is_design_64bit: bool):
    mult_res = a*b
    ret =  (mult_res&(MAX_64b<<64)) >> 64 if is_design_64bit else (mult_res&(MAX_64b<<32)) >> 32
    return ret

def mulhsu(a, b, is_design_64bit: bool):
    mult_res = twos_complement(a,is_design_64bit)*b
    ret =  (mult_res&(MAX_64b<<64)) >> 64 if is_design_64bit else (mult_res&(MAX_64b<<32)) >> 32
    return ret

def mulw(a, b, is_design_64bit: bool):
    return sign_extend(((a&MAX_32b)*(b&MAX_32b))&MAX_32b,32,is_design_64bit)

# C-like division to match spike
def _div_c(a, b):
    if (a >= 0) != (b >= 0) and a % b:
        return a // b + 1
    else:
        return a // b

def div(a, b, is_design_64bit: bool):
    if b & (MAX_64b if is_design_64bit else MAX_32b) == 0:
        return MAX_64b if is_design_64bit else MAX_32b
    elif a == (1 << 63 if is_design_64bit else 1<<31) and b == (MAX_64b if is_design_64bit else MAX_32b):
        return a
    else:
        return _div_c(twos_complement(a, is_design_64bit),twos_complement(b, is_design_64bit))&(MAX_64b if is_design_64bit else MAX_32b)

def rem(a,b, is_design_64bit: bool):
    if b & (MAX_64b if is_design_64bit else MAX_32b) == 0:
        return a
    elif a == (1 << 63 if is_design_64bit else 1<<31) and b == (MAX_64b if is_design_64bit else MAX_32b):
        return 0
    else:
        div_res = div(a,b,is_design_64bit)
        return a-div_res*b

def divu(a, b, is_design_64bit: bool):
    if b & (MAX_64b if is_design_64bit else MAX_32b) == 0:
        return MAX_64b if is_design_64bit else MAX_32b
    else:
        return abs(_div_c(a&(MAX_64b if is_design_64bit else MAX_32b),b&(MAX_64b if is_design_64bit else MAX_32b)))&(MAX_64b if is_design_64bit else MAX_32b)

def remu(a,b, is_design_64bit: bool):
    if b & (MAX_64b if is_design_64bit else MAX_32b) == 0:
        return a
    else:
        div_res = divu(a,b,is_design_64bit)
        return a-div_res*b

def divw(a, b, is_design_64bit: bool):
    if b & MAX_32b == 0:
        return MAX_64b if is_design_64bit else MAX_32b
    elif a&MAX_32b == (1<<31) and b&MAX_32b == MAX_32b:
        return sign_extend((1<<31), 32, is_design_64bit)
    else:
        return  sign_extend(_div_c(twos_complement(a&MAX_32b, False),twos_complement(b&MAX_32b, False))&MAX_32b, 32, is_design_64bit)

def remw(a, b, is_design_64bit: bool):
    if b & MAX_32b == 0:
        res = sign_extend(a&MAX_32b,32,is_design_64bit)
    elif a&MAX_32b == (1<<31) and b&MAX_32b == MAX_32b:
        res =  0
    else:
        div_res = divw(a,b,is_design_64bit)
        res = sign_extend(((a&MAX_32b)-div_res*(b&MAX_32b))&MAX_32b,32,is_design_64bit)
    return res

def divuw(a, b, is_design_64bit: bool):
    if b&MAX_32b == 0:
        res32 = MAX_32b
    else:
        res32 = abs(_div_c(a&MAX_32b, b&MAX_32b))
    return sign_extend(res32, 32, is_design_64bit)

def remuw(a, b, is_design_64bit: bool):
    if b&MAX_32b == 0:
        return sign_extend(a&MAX_32b,32,is_design_64bit)
    else:
        div_res = divuw(a,b,is_design_64bit)
        return sign_extend(((a&MAX_32b)-div_res*(b&MAX_32b))&MAX_32b,32,is_design_64bit)


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
    "lb": lb,
    "lh": lh,
    "lw": lw,
    "lbu": lbu,
    "lhu": lhu,
    "lwu": lwu,
    "ld": ld,
    "sb": None,
    "sh": None,
    "sw": None,
    "sd": None,
    # csr instructions
    "csrw": csrrw, # csrw is a pseudo instruction, rd=zero
    "csrrw": csrrw,
    "csrr": csrrs,  # csrw is a pseudo instruction, rs1=zero
    "csrrs": csrrs,
    "csrrc": csrrc,
    "csrwi": csrrwi, # csrw is a pseudo instruction, rd=zero
    "csrrwi": csrrwi,
    "csrri": csrrsi,  # csrw is a pseudo instruction, rs1=zero
    "csrrsi": csrrsi,
    "csrrci": csrrci,
    # Branches don't effect the dataflow.
    "beq": None,
    "bne": None,
    "blt": None,
    "bge": None,
    "bltu": None,
    "bgeu": None,
    # environment calls,
    "ecall": None,
    "ebreak": None,
    # unimplemented instructions
    "fence": None,
    "fence.i": None,
    "sfence.vma": None,
    # wrapper instructions
    "TvecWriterInstruction": None,
    "EPCWriterInstruction": None,
    "GenericCSRWriterInstruction": None,
    "ExceptionInstruction": None,
    "SpeculativeInstructionEncapsulator": None,
    # mret and sret have no function
    "mret": None,
    "sret": None,
    "sfence.vma": None,
    # compressed
    "c.add": add,
    "c.mv" : add,
    "c.and": and_,
    "c.or": or_,
    "c.xor": xor,
    "c.sub": sub,
    "c.lui": lui,
    "c.slli": slli,
    "c.srli": srli,
    "c.srai": srai,
    "c.andi": andi,
    "c.addi": addi,
    "c.li":addi,
    "c.addi16sp":addi,
    "c.addi4spn":addi,
    "c.j": jal,
    "c.jal": jal,
    "c.jalr": jalr,
    "c.jr": jalr,
    "c.beqz" : None,
    "c.bnez" : None,
    "c.lsdp":ld,
    "c.ld": ld,
    "c.lwsp":lw,
    "c.lw": lw,
    "c.addiw": addiw,
    "c.addw": addw,
    "c.subw": subw,
    "c.sd": None,
    "c.sdsp": None,
    "c.sw": None,
    "c.swsp": None,
    # alu64
    "addiw": addiw,
    "slliw": slliw,
    "srliw": srliw,
    "sraiw": sraiw,
    "addw": addw,
    "subw": subw,
    "sllw": sllw,
    "srlw": srlw,
    "sraw": sraw,
    # muldiv
    "divw": divw,
    "divuw": divuw,
    "remw": remw,
    "remuw":remuw,
    "mul": mul,
    "mulw":mulw,
    "div": div,
    "divu": divu,
    "rem": rem,
    "remu": remu,
    "mulh": mulh,
    "mulhsu":mulhsu,
    "mulhu":mulhu

}

INSTR_FUNCS_T0 = {
    # register instructions
    "add": add_t0 if not ADD_CONJ else conj,
    "sub": allones,
    "sll": sll_t0_imprecise if SLL_IMPRECISE else conj if SLL_IMPRECISE else sll_t0_precise,
    "slt": allones,
    "sltu": allones,
    "xor": xor_t0 if not XOR_CONJ else conj,
    "srl": srl_t0_imprecise if SRL_IMPRECISE else conj if SRL_CONJ else srl_t0_precise,
    "sra": sra_t0 if not SRA_CONJ else conj,
    "or": or_t0 if not OR_CONJ else conj,
    "and": and_t0 if not AND_CONJ else conj,
    # immediate instructions
    "addi": addi_t0 if not ADDI_CONJ else conji,
    "slli": slli_t0_imprecise if SLL_IMPRECISE else conji if SLL_CONJ else slli_t0_precise,
    "slti": allones,
    "sltiu": allones,
    "xori": xori_t0 if not XORI_CONJ else conji,
    "srli": srli_t0_imprecise if SRL_IMPRECISE else conji if SRL_IMPRECISE else srl_t0_precise,
    "srai": srai_t0 if not SRAI_CONJ else conji,
    "ori": ori_t0 if not ORI_CONJ else conji,  
    "andi": andi_t0 if not ANDI_CONJ else conji,
    "lui": lui_t0,
    "auipc": auipc_t0,
    # jal and jalr
    "jal": jal_t0,
    "jalr": jalr_t0,
    # placeholder instructions
    "lui (PlaceholderProducerInstr0)": lui_t0,
    "addi (PlaceholderProducerInstr1)": addi_t0 if not ADDI_CONJ else conji,
    "and (PlaceholderPreConsumerInstr)": and_t0 if not AND_CONJ else conji,
    "xor (PlaceholderConsumerInstr)": xor_t0 if not XOR_CONJ else conji,
    # load and store instructions, no taint function as we dont allow tainted operands for address computation.
    "lb": lb_t0,
    "lh": lh_t0,
    "lw": lw_t0,
    "lbu": lbu_t0,
    "lhu": lhu_t0,
    "lwu": lwu_t0,
    "ld": ld_t0,
    "sb": None,
    "sh": None,
    "sw": None,
    "sd": None,    
    # csr instructions
    "csrw": csrrw_t0, # csrw is a pseudo instruction, rd=zero
    "csrrw": csrrw_t0,
    "csrr": csrrs_t0,  # csrw is a pseudo instruction, rs1=zero
    "csrrs": csrrs_t0,
    "csrrc": csrrc_t0,
    "csrwi": csrrwi_t0, # csrw is a pseudo instruction, rd=zero
    "csrrwi": csrrwi_t0,
    "csrri": csrrsi_t0,  # csrw is a pseudo instruction, rs1=zero
    "csrrsi": csrrsi_t0,
    "csrrci": csrrci_t0,
    # Branches
    "beq": None,
    "bne": None,
    "blt": None,
    "bge": None,
    "bltu": None,
    "bgeu": None,
    # environment calls,
    "ecall": None,
    "ebreak": None,
    # unimplemented instructions
    "fence": None,
    "fence.i": None,
    "sfence.vma": None,
    # wrapper instructions
    "TvecWriterInstruction": None,
    "EPCWriterInstruction": None,
    "GenericCSRWriterInstruction": None,
    "ExceptionInstruction": None,
    "SpeculativeInstructionEncapsulator": None,
    # mret and sret have no function
    "mret": None,
    "sret": None,
    "sfence.vma": None,
    # rvc
    "c.add": add_t0,
    "c.mv" : add_t0,
    "c.and": and_t0,
    "c.or": conj,
    "c.xor": xor_t0,
    "c.sub": allones,
    "c.lui": lui_t0,
    "c.slli": slli_t0_imprecise if SLL_IMPRECISE else conji if SLL_CONJ else slli_t0_precise,
    "c.srli": srli_t0_imprecise if SRL_IMPRECISE else conji if SRL_IMPRECISE else srl_t0_precise,
    "c.srai": srai_t0,
    "c.andi": andi_t0,
    "c.addi": addi_t0,
    "c.li":addi_t0,
    "c.addi16sp":addi_t0,
    "c.addi4spn":addi_t0,
    "c.j": jal_t0,
    "c.jal": jal_t0,
    "c.jalr": jalr_t0,
    "c.jr": jalr_t0,
    "c.beqz" : None,
    "c.bnez" : None,
    "c.lsdp":ld_t0,
    "c.ld": ld_t0,
    "c.lwsp":lw_t0,
    "c.lw": lw_t0,
    "c.addiw": addiw_t0,
    "c.addw": addw_t0,
    "c.subw": allones,
    "c.sd": None,
    "c.sdsp": None,
    "c.sw": None,
    "c.swsp": None,
    # alu64
    "addiw": addiw_t0,
    "slliw": slliw_t0_imprecise if SLL_IMPRECISE else conji if SLL_CONJ else slliw_t0_precise,
    "srliw": srliw_t0_imprecise if SRL_IMPRECISE else conji if SRL_IMPRECISE else srlw_t0_precise,
    "sraiw": allones,
    "addw": addw_t0,
    "subw": allones,
    "sllw": sllw_t0_imprecise if SLL_IMPRECISE else conj if SLL_IMPRECISE else sllw_t0_precise,
    "srlw": allones,
    "sraw": allones,
    # muldiv
    "divw": allones,
    "divuw": allones,
    "remw": allones,
    "remuw":allones,
    "mul": allones,
    "mulw": allones,
    "div": allones,
    "divu": allones,
    "rem": allones,
    "remu": allones,
    "mulh":allones,
    "mulhsu":allones,
    "mulhu":allones

}




