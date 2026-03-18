# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module is dedicated to transforming bytes to ELF files.
# The script is not super robust, but sufficient for Cascade.

from params.runparams import DO_ASSERT
from makeelf.elf import *
import os
import subprocess
import tempfile

# @param inbytes the bytes to put into the ELF file. Be careful that they must be in little endian format already.
# @param section_addr may be None
# @return None
def gen_elf(inbytes: bytes, start_addr: int, section_addr: int, destination_path: str, is_64bit: bool) -> None:
    if DO_ASSERT:
        assert destination_path

    elf = ELF(e_machine=EM.EM_RISCV, e_data=ELFDATA.ELFDATA2LSB, e_entry=start_addr)

    # Create the section
    SH_FLAGS = 0x6 # Loadable and executable
    section_id = elf.append_section('.text.init', inbytes, start_addr, sh_flags=SH_FLAGS, sh_addralign=4)
    elf.append_segment(section_id, addr=start_addr, p_offset=0xe2) # Very hacky, we hardcode the section offset.
    
    elf_bytes = bytes(elf) # We first cast to bytes, since casting to bytes has side-effects (such as offset computation) on the ELF object, that are taken into account just before the bytes are generated.

    # Check that the offsets in the program header and in the section header match
    assert len(elf.Elf.Phdr_table) == 1, "Expected only a single program header"
    assert elf.Elf.Phdr_table[0].p_offset == elf.Elf.Shdr_table[-1].sh_offset, "In ELF: offset mismatch between Phdr and Shdr. Maybe the hack with makeelf did not work this time."

    # Finally, write the bytes into the ELF object
    with open(destination_path, 'wb') as f:
        f.write(elf_bytes)

    # Relocate the section
    if section_addr is not None:
        if is_64bit:
            subprocess.run([f"riscv{os.environ['MILESAN_RISCV_BITWIDTH']}-unknown-elf-objcopy", '--change-section-address', f".text.init={hex(section_addr)}", '-I', 'elf32-littleriscv', '-O', 'elf64-littleriscv', destination_path], check=True)
        else:
            subprocess.run([f"riscv{os.environ['MILESAN_RISCV_BITWIDTH']}-unknown-elf-objcopy", '--change-section-address', f".text.init={hex(section_addr)}", destination_path], check=True)
    else:
        if is_64bit:
            subprocess.run([f"riscv{os.environ['MILESAN_RISCV_BITWIDTH']}-unknown-elf-objcopy", '-I', 'elf32-littleriscv', '-O', 'elf64-littleriscv', destination_path], check=True)

    # Add .tohost section with tohost/fromhost symbols for HTIF (fesvr) communication.
    # fesvr looks up "tohost" and "fromhost" ELF symbols by name (htif.cc:179-181).
    # Address 0x80200000 is 2MB after boot (0x80000000), well clear of max 1MB program.
    TOHOST_ADDR = 0x80200000
    fd, tohost_zero_file = tempfile.mkstemp(suffix='.bin', dir=os.path.dirname(destination_path))
    try:
        os.write(fd, b'\x00' * 128)
        os.close(fd)
        objcopy = f"riscv{os.environ['MILESAN_RISCV_BITWIDTH']}-unknown-elf-objcopy"
        subprocess.run([
            objcopy,
            '--add-section', f'.tohost={tohost_zero_file}',
            '--set-section-flags', '.tohost=alloc,contents,load,data',
            '--change-section-address', f'.tohost={hex(TOHOST_ADDR)}',
            '--add-symbol', f'tohost=.tohost:0,global,object',
            '--add-symbol', f'fromhost=.tohost:64,global,object',
            destination_path
        ], check=True)
    finally:
        os.remove(tohost_zero_file)
