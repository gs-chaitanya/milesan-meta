# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module is dedicated to transforming bytes to ELF files.
# The script is not super robust, but sufficient for Cascade.

from params.runparams import DO_ASSERT
from makeelf.elf import *
import os
import subprocess

# @param inbytes the bytes to put into the ELF file. Be careful that they must be in little endian format already.
# @param section_addr may be None
# @return None
def gen_elf(inbytes: bytes, start_addr: int, section_addr: int, destination_path: str, is_64bit: bool, add_tohost_fromhost: bool = True, tohost_addr: int = None) -> None:
    if DO_ASSERT:
        assert destination_path

    elf = ELF(e_machine=EM.EM_RISCV, e_data=ELFDATA.ELFDATA2LSB, e_entry=start_addr)

    # Create the .text.init section
    SH_FLAGS = 0x6 # Loadable and executable
    section_id = elf.append_section('.text.init', inbytes, start_addr, sh_flags=SH_FLAGS, sh_addralign=4)
    # p_offset=0 is a placeholder; we fix it below after bytes() computes the real layout.
    elf.append_segment(section_id, addr=start_addr, p_offset=0)

    # Add .tohost section and tohost/fromhost symbols for HTIF/fesvr graceful exit.
    # fesvr requires BOTH tohost and fromhost symbols to enable polling.
    if tohost_addr is not None:
        fromhost_addr = tohost_addr + 8
        tohost_data = b'\x00' * 16  # 16 bytes: 8 for tohost + 8 for fromhost
        tohost_section_id = elf.append_section(
            '.tohost', tohost_data, tohost_addr,
            sh_flags=0x3,          # SHF_WRITE | SHF_ALLOC
            sh_addralign=8
        )
        elf.append_symbol(
            'tohost',
            tohost_section_id,   # sym_section
            tohost_addr,         # sym_offset (value)
            8,                   # sym_size
            sym_binding=STB.STB_GLOBAL,
            sym_type=STT.STT_OBJECT,
        )
        elf.append_symbol(
            'fromhost',
            tohost_section_id,   # sym_section
            fromhost_addr,       # sym_offset (value)
            8,                   # sym_size
            sym_binding=STB.STB_GLOBAL,
            sym_type=STT.STT_OBJECT,
        )

    # First serialize: bytes() has side-effects that compute section offsets.
    # We need these to fix the program header's p_offset.
    _ = bytes(elf)
    elf.Elf.Phdr_table[0].p_offset = elf.Elf.Shdr_table[section_id].sh_offset
    # Re-serialize with the corrected p_offset
    elf_bytes = bytes(elf)

    # Sanity check
    assert len(elf.Elf.Phdr_table) == 1, "Expected only a single program header"
    assert elf.Elf.Phdr_table[0].p_offset == elf.Elf.Shdr_table[section_id].sh_offset, "In ELF: offset mismatch between Phdr and Shdr."

    # Write the ELF
    with open(destination_path, 'wb') as f:
        f.write(elf_bytes)

    # Relocate sections and fix sign-extension for 64-bit.
    # objcopy 32→64 conversion sign-extends addresses with bit 31 set
    # (e.g. 0x80100000 → 0xFFFFFFFF80100000). --change-section-address forces
    # the correct 64-bit address.
    objcopy = f"riscv{os.environ['MILESAN_RISCV_BITWIDTH']}-unknown-elf-objcopy"
    tohost_fixup = ['--change-section-address', f".tohost={hex(tohost_addr)}"] if (tohost_addr is not None and is_64bit) else []

    if section_addr is not None:
        if is_64bit:
            subprocess.run([objcopy, '--change-section-address', f".text.init={hex(section_addr)}"] + tohost_fixup + ['-I', 'elf32-littleriscv', '-O', 'elf64-littleriscv', destination_path], check=True)
        else:
            subprocess.run([objcopy, '--change-section-address', f".text.init={hex(section_addr)}", destination_path], check=True)
    else:
        if is_64bit:
            subprocess.run([objcopy] + tohost_fixup + ['-I', 'elf32-littleriscv', '-O', 'elf64-littleriscv', destination_path], check=True)
