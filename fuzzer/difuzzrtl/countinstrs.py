# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import DO_ASSERT, NO_REMOVE_TMPFILES, PATH_TO_TMP
from common.spike import SPIKE_STARTADDR, get_spike_timeout_seconds
import os
import subprocess
from pathlib import Path


def countinstrs_milesan_fromelf(elf_id: int, elfpath: str, rvflags: str, final_addr: int) -> int:
    # Generate the spike debug commands file
    path_to_debug_file = __gen_spike_dbgcmd_file_for_count_instrs(identifier_str=f"milesan_countinstrs{elf_id}", startpc=SPIKE_STARTADDR, endpc=final_addr)

    # Second, run the Spike command
    spike_shell_command = (
        "spike",
        "-d",
        f"--debug-cmd={path_to_debug_file}",
        f"--isa={rvflags}",
        f"--pc={SPIKE_STARTADDR}",
        elfpath
    )

    try:
        spike_out = subprocess.run(spike_shell_command, capture_output=True, text=True, timeout=get_spike_timeout_seconds()).stderr
    except Exception as e:
        raise Exception(f"Spike timeout (A) for identifier str: difuzzrtl_patched{elf_id}. Command: {' '.join(filter(lambda s: '--debug-cmd' not in s, spike_shell_command))}  Debug file: {path_to_debug_file}")
    # print('run_trace_regs_at_pc_locs done')
    if not NO_REMOVE_TMPFILES:
        os.remove(path_to_debug_file)
        del path_to_debug_file

    return len(list(filter(lambda s: s.startswith('core   0: 0x'), spike_out.split('\n'))))


def countinstrs_milesan(elf_id: int) -> int:
    rvflags = 'rv64g'
    design_name = 'rocket'
    # elfpath = os.path.join(PATH_TO_TMP, 'manyelfs_modelsim', f"{design_name}_{elf_id}.elf")
    # final_addr_path = os.path.join(PATH_TO_TMP, 'manyelfs_modelsim', f"{design_name}_{elf_id}_finaladdr.txt")

    # with open(final_addr_path, 'r') as file:
    #     content = file.read()
    # final_addr = SPIKE_STARTADDR + int(content, 16)

    # return countinstrs_milesan_fromelf(elf_id, elfpath, rvflags, final_addr)

    # Actually, we just take the pre-computed number of instructions
    num_instrs_path = os.path.join(PATH_TO_TMP, 'manyelfs_modelsim', f"{design_name}_{elf_id}_numinstrs.txt")
    with open(num_instrs_path, 'r') as file:
        content = file.read()
    return int(content, 16)

def countinstrs_difuzzrtl(elf_id: int) -> int:
    rvflags = 'rv64g'
    elfpath = os.path.join(PATH_TO_TMP, 'difuzzrtl_elfs_patched', f"id_{elf_id}.elf")

    assert elfpath is not None, "elfpath is None"
    assert 'difuzzrtl_elfs_patched' in elfpath, "elfpath is not a patched difuzzrtl elf"

    # Get the final pc
    final_addr_str = subprocess.check_output([f"nm {elfpath} | grep write_tohost"], shell=True, text=True)
    final_addr = int(final_addr_str.split()[0], 16)

    # Generate the spike debug commands file
    path_to_debug_file = __gen_spike_dbgcmd_file_for_count_instrs(identifier_str=f"difuzzrtl_patched{elf_id}", startpc=SPIKE_STARTADDR, endpc=final_addr)

    # Second, run the Spike command
    spike_shell_command = (
        "spike",
        "-d",
        f"--debug-cmd={path_to_debug_file}",
        f"--isa={rvflags}",
        f"--pc={SPIKE_STARTADDR}",
        elfpath
    )

    try:
        spike_out = subprocess.run(spike_shell_command, capture_output=True, text=True, timeout=get_spike_timeout_seconds()).stderr
    except Exception as e:
        raise Exception(f"Spike timeout (A) for identifier str: difuzzrtl_patched{elf_id}. Command: {' '.join(filter(lambda s: '--debug-cmd' not in s, spike_shell_command))}  Debug file: {path_to_debug_file}")
    # print('run_trace_regs_at_pc_locs done')
    if not NO_REMOVE_TMPFILES:
        os.remove(path_to_debug_file)
        del path_to_debug_file

    return len(list(filter(lambda s: s.startswith('core   0: 0x'), spike_out.split('\n'))))

def __gen_spike_dbgcmd_file_for_count_instrs(identifier_str: str, startpc: int, endpc: int):
    path_to_debug_file = os.path.join(PATH_TO_TMP, 'dbgcmds', f"cmds_count_instrs_{identifier_str}")
    # if not os.path.exists(path_to_debug_file):
    Path(os.path.dirname(path_to_debug_file)).mkdir(parents=True, exist_ok=True)
    spike_debug_commands = [
        f"until pc 0 0x{startpc:x}",
        f"untiln pc 0 0x{endpc:x}",
        f"q\n",
    ]
    spike_debug_commands_str = '\n'.join(spike_debug_commands)

    with open(path_to_debug_file, 'w') as f:
        f.write(spike_debug_commands_str)

    return path_to_debug_file
