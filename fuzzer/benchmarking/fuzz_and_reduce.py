import sys
sys.path.append("../")

import subprocess
import os
import json
TIMEOUT_REDUCE=7200
FUZZ=True
REDUCE_RTL_TIMEOUT=True
REDUCE_VALUE_MISMATCH=True
REDUCE_TAINT_MISMATCH=True
def load_fuzzconfigs(path: str):
    with open(path, "r") as f:
        cfgs = json.load(f)
    return cfgs

if __name__ == '__main__':
    if "CASCADE_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")
    
    if len(sys.argv) < 1:
        raise Exception("Usage: python3 fuzz_and_reduce.py <path_to_config_json>")


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
            datadir = os.path.join(os.environ["CASCADE_DATADIR"],cfg["NAME"])
            env["CASCADE_DATADIR"] = datadir
            os.makedirs(datadir, exist_ok=True)
            if FUZZ:
                with open(os.path.join(datadir,"config.json"), "w") as f:
                    json.dump(cfg,f)
                try:
                    cmd = [
                        "python",
                        "do_check_isa_sim.py",
                        design_name,
                        str(cfg["N_THREADS"]),
                        str(cfg["N_TESTS"]),
                        str(cfg["SEED_OFFSET"]) if "SEED_OFFSET" in cfg else str(0),
                        str(cfg["TIMEOUT"])
                    ]

                    subprocess.run(cmd, env=env, cwd="/mnt/cascade-meta/fuzzer/")

                except Exception as e:
                    print(f"Failed running {' '.join(cmd)}: {e}")

            if REDUCE_TAINT_MISMATCH:
                try:
                    log_file = os.path.join(datadir, "logs", f"{design_name}.taint_mismatch.log")
                    if not os.path.exists(log_file):
                        print(f"Log-file not found: {log_file}")
                        
                    else:
                        print(f"Reducing {log_file}")
                        cmd = [
                            "python",
                            "do_reducemany.py",
                            design_name,
                            str(cfg["N_THREADS"]),
                            f"--log-file={log_file}"
                        ]
                        subprocess.run(cmd, env=env, cwd="/mnt/cascade-meta/fuzzer/", timeout=TIMEOUT_REDUCE)

                except Exception as e:
                    print(f"Failed running {' '.join(cmd)}: {e}")


            if REDUCE_RTL_TIMEOUT:
                try:
                    log_file = os.path.join(datadir, "logs", f"{design_name}.rtl_timeout.log")
                    if not os.path.exists(log_file):
                        print(f"Log-file not found: {log_file}")
                        continue
                    else:
                        print(f"Reducing {log_file}")
                        cmd = [
                            "python",
                            "do_reducemany.py",
                            design_name,
                            str(cfg["N_THREADS"]),
                            f"--log-file={log_file}"
                        ]
                        subprocess.run(cmd, env=env, cwd="/mnt/cascade-meta/fuzzer/", timeout=TIMEOUT_REDUCE)

                except Exception as e:
                    print(f"Failed running {' '.join(cmd)}: {e}")


            if REDUCE_VALUE_MISMATCH:
                try:
                    log_file = os.path.join(datadir, "logs", f"{design_name}.value_mismatch.log")
                    if not os.path.exists(log_file):
                        print(f"Log-file not found: {log_file}")
                        continue
                    else:
                        print(f"Reducing {log_file}")
                        cmd = [
                            "python",
                            "do_reducemany.py",
                            design_name,
                            str(cfg["N_THREADS"]),
                            f"--log-file={log_file}"
                        ]
                        subprocess.run(cmd, env=env, cwd="/mnt/cascade-meta/fuzzer/", timeout=TIMEOUT_REDUCE)

                except Exception as e:
                    print(f"Failed running {' '.join(cmd)}: {e}")



else:
    raise Exception("This module must be at the toplevel.")

