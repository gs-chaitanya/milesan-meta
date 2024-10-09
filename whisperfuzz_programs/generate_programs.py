#%%
import sys
sys.path.append("../")
import os
import re
import pandas as pd
import subprocess
import seaborn as sns
import matplotlib.pyplot as plt
from fuzzer.common.designcfgs import get_design_stop_sig_addr, get_design_reg_dump_addr, get_design_cascade_path
#%%%
DUTS = ["cva6-test"]
SECTION_STR = ".section \".text.init\",\"ax\",@progbits\n\t.globl _start\n\t.align 2\n_start:\n"
INSTR_STRS = ["mv","add","and","or","xor","sub","addw","subw"]
# INSTR_STRS = ["divuw"]
CINSTR_STR = [f"c.{inst}" for inst in INSTR_STRS] 
CINSTR_STR= [] 
# IMMS = [0] + [1<<i for i in range(20)]
IMMS = [0,2047]
CWD =  "/mnt/cascade-meta/whisperfuzz_programs/"
SRCDIR = "/mnt/cascade-meta/whisperfuzz_programs/src"
BUILDDIR = "/mnt/cascade-meta/whisperfuzz_programs/build"
#%%
def generate_program(inst_str: str, imm: int, stopsig_addr: int, regdump_addr: int, clear_csr = bool):
    prog_str = SECTION_STR
    prog_str += f"li a4, {imm}\n"
    prog_str += f"li a7, 0\n"
    if clear_csr:
        prog_str += "csrr t1, mcycle\n"
    prog_str += f"{inst_str} t3, a4\n" if "mv" in inst_str or "c" in inst_str else  f"{inst_str} t3, t3, a4\n"
    prog_str += "csrr ra, mcycle\n"
    prog_str += f"sub ra, ra, t1\n"
    prog_str += f"li a0, {regdump_addr}\n"
    prog_str += "sd ra, 0(a0)\n"
    prog_str += f"li a0, {stopsig_addr}\n"
    prog_str += f"sd a0, 0(a0)\n"
    return prog_str
#%%
os.makedirs(SRCDIR,exist_ok=True)
targets = []
instr_strs = []
imms = []
clear_csrs = [] 
for dut in DUTS:
    stopsig_addr = get_design_stop_sig_addr(dut)
    regdump_addr = get_design_reg_dump_addr(dut)
    for instr_str in ["c.add"]:
        for imm in IMMS:
            for clear_csr in [True]:
                prog = generate_program(instr_str, imm, stopsig_addr, regdump_addr,clear_csr)
                # with open(f"{SRCDIR}/{instr_str}_{imm}_{int(clear_csr)}.S", "w") as f:
                    # f.write(prog)
                targets += [f"build/{instr_str}_{imm}_{int(clear_csr)}.elf"]
                instr_strs += [instr_str]
                imms += [imm]
                clear_csrs += [int(clear_csr)]
# %%
env = os.environ.copy()
env["TARGETS"] = f"\"{' '.join(targets)}\""
# subprocess.run(["make","clean"],cwd=CWD,env=env)
subprocess.run(["make","all"],cwd=CWD,env=env)

# %%
env = os.environ.copy()
env["SIMLEN"] = "1000"
mcycle_df = pd.DataFrame()
for dut in DUTS:
    for target,instr,imm,clear_csr in zip(targets,instr_strs,imms,clear_csrs):
        env["SIMSRAMELF"] = f"{CWD}/{target}"
        cmd = ["make","run_vanilla_notrace"]
        output = subprocess.run(cmd,cwd=get_design_cascade_path(dut),env=env, capture_output=True)
        mcycles = int(re.findall("Dump of reg x01:\s*0x[0-9a-zA-Z]+",str(output))[0].split(":")[-1].strip(),16)
        row = {
            "target":target,
            "instr": instr,
            "imm":imm,
            "mcycles":mcycles,
            "iscompressed": "c" in instr,
            "clear_csr":clear_csr
        }
        mcycle_df = pd.concat([mcycle_df,pd.DataFrame([row])])

# %%
fig, ax = plt.subplots()
sns.scatterplot(data=mcycle_df[(mcycle_df["iscompressed"] == True) & (mcycle_df["clear_csr"] == 0) ], x="imm",y="mcycles",hue="instr",ax=ax)
ax.set_xscale("log",base=2)
# %%
fig, ax = plt.subplots()
sns.scatterplot(data=mcycle_df[(mcycle_df["iscompressed"] == False) & (mcycle_df["clear_csr"] == 0) & (mcycle_df["instr"] == "div")], x="imm",y="mcycles",hue="instr",ax=ax)
ax.set_xscale("log",base=2)
ax.set_ylim([270,280])