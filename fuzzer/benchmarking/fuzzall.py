import sys
sys.path.append("../")

import subprocess
import os
import json

def load_fuzzconfigs(path: str):
    with open(path, "r") as f:
        cfgs = json.load(f)
    return cfgs

if __name__ == '__main__':
    if "CASCADE_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")
    
    if len(sys.argv) < 1:
        raise Exception("Usage: python3 fuzzall.py <path_to_config_json>")


    if len(sys.argv) > 1:
        cfgs_path = sys.argv[1]
    
    cfgs = load_fuzzconfigs(cfgs_path)
    env = os.environ.copy()
    cmd = []
    for cfg in cfgs:
        for design_name in cfg["duts"]:
            env["USE_MMU"] = str(int(cfg["use_mmu"]))
            env["TAINT_IN_PRIVS"] = cfg["taint_in_privs"]
            env["TAINT_IMMRD_IMM"] = str(int(cfg["taint_immrd_imm"]))
            env["TAINT_REGIMM_IMM"] = str(int(cfg["taint_regimm_imm"]))
            env["TAINT_NONTAKEN_BRANCHES"] = str(int(cfg["taint_nontaken_branches"]))
            datadir = os.path.join(os.environ["CASCADE_DATADIR"],cfg["name"])
            env["CASCADE_DATADIR"] = datadir
            os.makedirs(datadir, exist_ok=True)
            try:
                cmd = [
                    "python",
                    "do_check_isa_sim.py",
                    design_name,
                    str(cfg["n_threads"]),
                    str(cfg["n_tests"]),
                    "0",
                    str(cfg["timeout"])
                ]
                subprocess.run(cmd, env=env, cwd="/mnt/cascade-meta/fuzzer/")
                log_file = os.path.join(datadir, "logs", f"{design_name}.taint_mismatch.log")
                cmd = [
                    "python",
                    "do_reducemany.py",
                    design_name,
                    str(cfg["n_threads"]),
                    f"--log-file={log_file}"
                ]
                subprocess.run(cmd, env=env, cwd="/mnt/cascade-meta/fuzzer/")
            except Exception as e:
                print(f"Failed running {' '.join(cmd)}")

            exit(0)

else:
    raise Exception("This module must be at the toplevel.")

