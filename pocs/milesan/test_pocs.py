import json
import glob
import subprocess
import os
import sys
import time
cwd = os.getcwd()
ELFS_PATH = cwd + "/build/elfs/pocs"
NOMMUELFS_PATH = cwd + "/build/nommuelfs/pocs"
TAINT_PATH = cwd + "/taint/"
REGDUMP_PATH =  "/scratch/tkovats/ssh_mnt/milesan-data/regdump.json"
elfs = glob.glob(ELFS_PATH + "/*.riscv")


env = os.environ.copy()
env["REGDUMP_PATH"] = REGDUMP_PATH
c = {}


if os.path.isfile(REGDUMP_PATH):
    os.remove(REGDUMP_PATH)


def check_leak():
    while not os.path.isfile(REGDUMP_PATH):
        print(f"Waiting for {REGDUMP_PATH}")
        time.sleep(1)
    with open(REGDUMP_PATH, "r") as f:
        regdumps = json.load(f)
    os.remove(REGDUMP_PATH)
    for regdump in regdumps:
        if int(regdump["value_t0"],16):
            return True
    return False

for elf in elfs:
    taint = TAINT_PATH + elf.split("/")[-1].split(".")[0] + ".txt"
    cmd = [
        "make",
        "rerun_drfuzz_mem_notrace_modelsim"
    ]
    nommuelf = elf.replace("elfs","nommuelfs")
    assert os.path.isfile(nommuelf)
    assert os.path.isfile(taint)
    env["SIMSRAMTAINT"] = taint
    env["SIMSRAMELF"] = elf
    
    # print(f"{elf} - {nommuelf} {taint}")
    subprocess.run(cmd, env=env, cwd=sys.argv[1], capture_output=True)
    leak = check_leak()
    if leak:
        print(f"{elf.split('/')[-1]} leaks with MMU on")
    else:
        print(f"{elf.split('/')[-1]} does not leak with MMU on")
    c[elf] = leak
    env["SIMSRAMELF"] = nommuelf
    ret = subprocess.run(cmd, env=env, cwd=sys.argv[1],capture_output=True)    
    leak = check_leak()
    if leak:
        print(f"{elf.split('/')[-1]} leaks with MMU off")
    else:
        print(f"{elf.split('/')[-1]} does not leak with MMU off")

    c[nommuelf] = leak


# for i,j in c.items():
#     print(f"{i}: {j}")

