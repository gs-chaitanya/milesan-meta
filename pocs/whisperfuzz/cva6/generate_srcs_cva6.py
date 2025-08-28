
import os
#%%%
DUTS = ["cva6"]
SECTION_STR = ".section \".text.init\",\"ax\",@progbits\n\t.globl _start\n\t.align 2\n_start:\n"
INSTR_STRS = ["mv","add","and","or","xor","sub","addw","subw"]

INSTR_STRS += [f"c.{inst}" for inst in INSTR_STRS] 
INSTR_STRS += ["divuw","remu"]
IMMS = [2047]
cwd = os.getcwd()
SRCDIR = cwd + '/src'
BUILDIR = cwd + '/build'
STOPSIG_ADDR = 0x0
REGDUMP_ADDR = 0x10
#%%
def generate_program(inst_str: str, imm: int, stopsig_addr: int, regdump_addr: int):
    prog_str = SECTION_STR
    prog_str += f"li a0, {imm}\n"
    prog_str += f"li a1, 0\n"
    prog_str += "csrr t1, mcycle\n"

    prog_str += f"{inst_str} a1, a0\n" if "mv" in inst_str or "c" in inst_str else  f"{inst_str} a1, a1,a0\n"

    prog_str += "csrr t2, mcycle\n"
    prog_str += f"sub t1, t2, t1\n"

    prog_str += f"li t0, {regdump_addr}\n"
    prog_str += "sd t1, 0(t0)\n"
    prog_str += f"li t0, {stopsig_addr}\n"
    prog_str += f"sd t0, 0(t0)\n"
    return prog_str

if __name__ == "__main__":
    os.makedirs(SRCDIR,exist_ok=True)
    targets = []
    instr_strs = []
    for instr_str in INSTR_STRS:
        for imm in IMMS:
                prog = generate_program(instr_str, imm, STOPSIG_ADDR, REGDUMP_ADDR)
                with open(f"{SRCDIR}/{instr_str}.S", "w") as f:
                    f.write(prog)
                targets += [f"build/{instr_str}.elf"]
                instr_strs += [instr_str]

# # %%
# env = os.environ.copy()
# env["TARGETS"] = f"\"{' '.join(targets)}\""
# # subprocess.run(["make","clean"],cwd=CWD,env=env)
# subprocess.run(["make","all"],cwd=CWD,env=env)

# # %%
# env = os.environ.copy()
# env["SIMLEN"] = "1000"
# mcycle_df = pd.DataFrame()
# for dut in DUTS:
#     for target,instr,imm,clear_csr in zip(targets,instr_strs):
#         env["SIMSRAMELF"] = f"{CWD}/{target}"
#         cmd = ["make","run_vanilla_notrace"]
#         output = subprocess.run(cmd,cwd=get_design_milesan_path(dut),env=env, capture_output=True)
#         mcycles = int(re.findall("Dump of reg x01:\s*0x[0-9a-zA-Z]+",str(output))[0].split(":")[-1].strip(),16)
#         row = {
#             "target":target,
#             "instr": instr,
#             "imm":imm,
#             "mcycles":mcycles,
#             "iscompressed": "c" in instr,
#             "clear_csr":clear_csr
#         }
#         mcycle_df = pd.concat([mcycle_df,pd.DataFrame([row])])

# # %%
# fig, ax = plt.subplots()
# sns.scatterplot(data=mcycle_df[(mcycle_df["iscompressed"] == True) & (mcycle_df["clear_csr"] == 0) ], x="imm",y="mcycles",hue="instr",ax=ax)
# ax.set_xscale("log",base=2)
# # %%
# fig, ax = plt.subplots()
# sns.scatterplot(data=mcycle_df[(mcycle_df["iscompressed"] == False) & (mcycle_df["clear_csr"] == 0) & (mcycle_df["instr"] == "div")], x="imm",y="mcycles",hue="instr",ax=ax)
# ax.set_xscale("log",base=2)
# ax.set_ylim([270,280])
# %%
