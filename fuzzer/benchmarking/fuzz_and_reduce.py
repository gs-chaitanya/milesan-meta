import sys
sys.path.append("../")

import subprocess
import os
import json
from time import gmtime, strftime
import argparse 
import git

SHA = git.Repo(search_parent_directories=True).head.object.hexsha
TIMEOUT_REDUCE=3600*24 # 24h
FUZZ = True
REDUCE_TAINT_MISMATCH = False
REDUCE_RTL_TIMEOUT = False
REDUCE_VALUE_MISMATCH = False
def load_fuzzconfigs(path: str):
    with open(path, "r") as f:
        cfgs = json.load(f)
    return cfgs

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Milesan environment must be sourced prior to running the Python recipes.")
    
    if len(sys.argv) < 1:
        raise Exception("Usage: python3 fuzz_and_reduce.py <path_to_config_json> [--reduce=taint,value,timeout] [--reduce-only]")

    parser = argparse.ArgumentParser(prog="fuzz_and_reduce,py",description="Fuzz and reduce with some config.")
    parser.add_argument("cfg_path")
    parser.add_argument("-r","--reduce",choices = ["taint","value","timeout"],help="Enable reduction for specific mismatch. Ignored when --fuzz-only is used.",default="taint")
    parser.add_argument("-ro","--reduce-only",dest="reduce_only",action="store_true", help="Skip fuzzing and only reduce. Requires existing log file from previous fuzzing round.")
    parser.add_argument("-fo","--fuzz-only",dest="fuzz_only",action="store_true", help="Skip reduction and only fuzz.")

    args = parser.parse_args()
    cfgs = load_fuzzconfigs(args.cfg_path)
    env = os.environ.copy()
    assert not "TRACE_EN" in env or env["TRACE_EN"] == "0", f"This is a bad idea."
    cmd = []
    for cfg in cfgs:
        cfg_cpy = cfg.copy()
        cfg_cpy.pop("DUTS")
        env = os.environ.copy()
        env.update(cfg_cpy)                
        datadir = os.path.join(os.environ["MILESAN_DATADIR"],cfg["NAME"])
        env["MILESAN_DATADIR"] = datadir
        os.makedirs(datadir, exist_ok=True)
        metadir = os.path.join(datadir,"meta")
        os.makedirs(metadir, exist_ok=True)
        print(f"Fuzzing {cfg}")
        with open(os.path.join(metadir,"config.json"), "w") as f:
            json.dump(cfg,f)
        with open(os.path.join(metadir,"env.sh"), "w") as f:
            f.write('\n'.join([f"export {varname}={varval}" for varname, varval in env.items()]))
        with open(os.path.join(metadir,"commithash.txt"), "w") as f:
            f.write(SHA)
        for design_name in cfg["DUTS"]: 
            if not args.reduce_only:
                try:
                    cmd = [
                        "python",
                        "do_check_isa_sim.py",
                        design_name,
                        str(cfg["N_THREADS"]) if "N_THREADS" in cfg else 40,
                        str(cfg["N_TESTS"]) if "N_TESTS" in cfg else str(-1),
                        str(cfg["SEED_OFFSET"]) if "SEED_OFFSET" in cfg else str(0),
                    ]
                    if "TIMEOUT" in cfg:
                        cmd += [str(cfg["TIMEOUT"])]

                    subprocess.run(cmd, env=env, cwd="/mnt/milesan-meta/fuzzer/")

                except Exception as e:
                    print(f"Failed running {' '.join(cmd)}: {e}")
            
            if args.fuzz_only:
                continue
            
            if "taint" in args.reduce:
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
                            str(cfg["N_THREADS"]) if "N_THREADS" in cfg else 40,
                            f"--log-file={log_file}"
                        ]
                        subprocess.run(cmd, env=env, cwd="/mnt/milesan-meta/fuzzer/", timeout=TIMEOUT_REDUCE)

                except Exception as e:
                    print(f"Failed running {' '.join(cmd)}: {e}")


            if "timeout" in args.reduce:
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
                            str(cfg["N_THREADS"]) if "N_THREADS" in cfg else 40,
                            f"--log-file={log_file}"
                        ]
                        subprocess.run(cmd, env=env, cwd="/mnt/milesan-meta/fuzzer/", timeout=TIMEOUT_REDUCE)

                except Exception as e:
                    print(f"Failed running {' '.join(cmd)}: {e}")


            if "value" in args.reduce:
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
                            str(cfg["N_THREADS"]) if "N_THREADS" in cfg else 40,
                            f"--log-file={log_file}"
                        ]
                        subprocess.run(cmd, env=env, cwd="/mnt/milesan-meta/fuzzer/", timeout=TIMEOUT_REDUCE)

                except Exception as e:
                    print(f"Failed running {' '.join(cmd)}: {e}")



else:
    raise Exception("This module must be at the toplevel.")

