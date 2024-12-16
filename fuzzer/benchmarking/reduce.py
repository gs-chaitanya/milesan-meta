import sys
sys.path.append("../")

import subprocess
import os
import json
TIMEOUT_REDUCE=7200
USE_MODELSIM = None

def load_fuzzconfigs(path: str):
    with open(path, "r") as f:
        cfgs = json.load(f)
    return cfgs

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")
    
    if len(sys.argv) < 2:
        raise Exception("Usage: python3 reduce.py <path_to_config_json>")


    if len(sys.argv) > 1:
        cfgs_path = sys.argv[1]
    
    cfgs = load_fuzzconfigs(cfgs_path)
    env = os.environ.copy()
    assert not "TRACE_EN" in env or env["TRACE_EN"] == "0", f"This is a bad idea."
    cmd = []
    for cfg in cfgs:
        print(f"Fuzzing {cfg}")
        for design_name in cfg["DUTS"]: 
            cfg_cpy = cfg.copy()
            cfg_cpy.pop("DUTS")
            env.update(cfg_cpy) 
            if USE_MODELSIM is not None:
                env["USE_MODELSIM"] = str(int(USE_MODELSIM))
            datadir = os.path.join(os.environ["MILESAN_DATADIR"],cfg["NAME"])
            env["MILESAN_DATADIR"] = datadir
            os.makedirs(datadir, exist_ok=True)
            
            try:
                log_file = os.path.join(datadir, "logs", f"{design_name}.taint_mismatch.log")
                if not os.path.exists(log_file):
                    print(f"Log-file not found: {log_file}")
                    continue

                cmd = [
                    "python",
                    "do_reducemany.py",
                    design_name,
                    str(cfg["N_THREADS"]),
                    f"--log-file={log_file}"
                ]
                subprocess.run(cmd, env=env, cwd="/mnt/milesan-meta/fuzzer/", timeout=TIMEOUT_REDUCE)
            except Exception as e:
                print(f"Failed running {' '.join(cmd)}: {e}")


else:
    raise Exception("This module must be at the toplevel.")

