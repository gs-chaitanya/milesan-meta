import os
import sys
import time
import subprocess
import threading
import multiprocessing as mp
import atexit
import json

PRINT_THREAD_STATUS = True
MAX_N_THREADS = 30
MUTE = False
TRACE_EN = False
callback_lock = threading.Lock()
n_finished_threads = 0

def test_done_callback(ret):
    global n_finished_threads
    with callback_lock:
        n_finished_threads += 1
        if ret is not None:
            if PRINT_THREAD_STATUS:
                print(f"Finished {n_finished_threads} threads.")


def modelsim_worker(new_req_path):
    if PRINT_THREAD_STATUS:
        print(f"Found new design req at {new_req_path}")

    with open(new_req_path, "r") as f:
        req_env = json.load(f)

    os.remove(new_req_path)

    assert "SIMSRAMELF" in req_env,  "SIMSRAMELF not found in req!"
    assert "SIMSRAMTAINT" in req_env,  "SIMSRAMTAINT not found in req!"
    assert "DESIGN_DIR" in req_env, "DESIGN_DIR not found in req!"
    assert "REGDUMP_PATH" in req_env, "REGDUMP_PATH not found in req!"
    assert "REGSTREAM_PATH" in req_env, "REGSTREAM_PATH not found in req!"
    assert not TRACE_EN or "TRACEFILE" in req_env, "TRACEFILE not found in req!"
    assert "SIMLEN" in req_env, "SIMLEN not foun din req!"

    simsramelf = req_env["SIMSRAMELF"]
    simsramtaint = req_env["SIMSRAMTAINT"]

    design_dir = req_env["DESIGN_DIR"]

    while(not os.path.exists(simsramelf)):
        time.sleep(2)
        print(f"Waiting for {simsramelf}")

    while(not os.path.exists(simsramtaint)):
        time.sleep(1)
        print(f"Waiting for {simsramtaint}")
    
    assert os.path.exists(design_dir), f"Design directory does not exists! {design_dir}"

    print(f"Running {simsramelf} with {simsramtaint} in {design_dir}")
    env = os.environ.copy()
    env.update(req_env)
    cmd = [
        "make",
        "rerun_drfuzz_mem_notrace_modelsim" if not TRACE_EN else "rerun_drfuzz_mem_trace_modelsim"
    ]
    subprocess.run(cmd, cwd=design_dir, env=env, capture_output=MUTE)
    if PRINT_THREAD_STATUS:
        print(f"Finished processing design req at {new_req_path}")
    return new_req_path


if __name__ == '__main__':
    if len(sys.argv) > 2:
        raise Exception("Usage: python3 do_run_modelsim.py [path_to_req]")

    if len(sys.argv) > 1:
        path_to_req = sys.argv[1]
        modelsim_worker(path_to_req)
    else:
        assert "MODELSIM_REQ_DIR" in os.environ, f"MODELSIM_REQ_DIR not set. Did you source cascade-meta/env.sh?"
        req_dir = os.environ["MODELSIM_REQ_DIR"]
        assert os.path.exists(req_dir)
        initiated_reqs = []
        with mp.Pool(processes=MAX_N_THREADS) as pool:
            while(1):
                time.sleep(2)
                all_reqs = []
                for rootdir, dirs, files in os.walk(req_dir):
                    for file in files:
                        if file.endswith(".modelsim_req.json"):
                            req_path = os.path.join(rootdir,file)
                            all_reqs += [req_path]
                if not len(all_reqs):
                    if PRINT_THREAD_STATUS:
                        print("Waiting for requests...")
                    continue
                if PRINT_THREAD_STATUS:
                    print(f"Waiting for requests at {req_dir}...\n started: {len(initiated_reqs)} threads, {len(all_reqs)} pending requests in directory")

                new_reqs = [req for req in all_reqs if req not in initiated_reqs]

                for i, new_req in enumerate(new_reqs):
                    initiated_reqs += [new_req]
                    if PRINT_THREAD_STATUS:
                        print(f"Starting thread for {new_req}.")
                    pool.apply_async(modelsim_worker, args=(new_req,),callback=test_done_callback)

            
