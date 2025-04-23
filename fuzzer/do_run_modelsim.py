import os
import sys
import time
import subprocess
import threading
import multiprocessing as mp
import json
from signal import *
import sys, time
import shutil
import psutil

PRINT_THREAD_STATUS = True
LOG_THREAD_STATUS = True
MAX_N_THREADS = 60 # This is a cap for the request throughput.
MUTE = True
DELETE_REQS = True
KILL_THREADS = True
WAIT_UNTIL_FINISHED = True
callback_lock = threading.Lock()
n_finished_threads = 0


def clean(*args):
    assert "MODELSIM_REQ_DIR" in os.environ, f"MODELSIM_REQ_DIR not set. Did you source milesan-meta/env.sh?"
    if DELETE_REQS:
        with callback_lock: # Use the lock so we don't run this for every thread.
            req_dir = os.environ["MODELSIM_REQ_DIR"]
            if os.path.isdir(req_dir):
                print(f"Deleting {req_dir} for cleanup before exit.")
                shutil.rmtree(req_dir)
                subprocess.run(["pkill","-f","-9","vsimk"],capture_output=True)
                subprocess.run(["pkill","-f","-9","vish"], capture_output=True)
    sys.exit(0)

def test_done_callback(ret):
    global n_finished_threads
    with callback_lock:
        n_finished_threads += 1
        if ret is not None:
            if PRINT_THREAD_STATUS:
                print(f"Finished {n_finished_threads} threads.")
            if LOG_THREAD_STATUS:
                with open("run_modelsim.log","a") as f:
                    f.write(f"({'Success' if ret[1] else 'Failed'}): Finished thread for {ret[0]} after {ret[1]}s")
                
def modelsim_worker(new_req_path):
    if PRINT_THREAD_STATUS:
        print(f"Found new req at {new_req_path}")

    with open(new_req_path, "r") as f:
        req_env = json.load(f)

    if DELETE_REQS:
        os.remove(new_req_path)

    assert "SIMSRAMELF" in req_env,  "SIMSRAMELF not found in req!"
    assert "SIMSRAMTAINT" in req_env,  "SIMSRAMTAINT not found in req!"
    assert "DESIGN_DIR" in req_env, "DESIGN_DIR not found in req!"
    assert "REGDUMP_PATH" in req_env, "REGDUMP_PATH not found in req!"
    assert "REGSTREAM_PATH" in req_env, "REGSTREAM_PATH not found in req!"
    assert "TRACE_EN" in req_env, "TRACE_EN not found in req!"
    assert "COV_EN" in req_env, "COV_EN not found in req!"
    assert "TRACE_FST" in req_env, "TRACE_FST not found in req!"
    assert "TRACEFILE" in req_env, "TRACEFILE not found in req!"
    assert "SIMLEN" in req_env, "SIMLEN not found in req!"
    assert "MODELSIM_TIMEOUT" in req_env, "MODELSIM_TIMEOUT not found in req!"
    assert "PCDUMP_PATH" in req_env, "PCDUMP_PATH not found in req!"
    assert "STOP_AT_PC_TAINT" in req_env, "STOP_AT_PC_TAIN not found in req!"

    simsramelf = req_env["SIMSRAMELF"]
    simsramtaint = req_env["SIMSRAMTAINT"]
    design_dir = req_env["DESIGN_DIR"]
    msim_timeout = int(req_env["MODELSIM_TIMEOUT"])
    trace_en = req_env["TRACE_EN"]
    cov_en = req_env["COV_EN"]
    trace_fst = req_env["TRACE_FST"]
    del req_env["TRACE_EN"]
    del req_env["TRACE_FST"]
    del req_env["COV_EN"]
    del req_env["USE_VANILLA"]
    assert not trace_fst, f"FST tracing not implemented in modelsim yet."
    while(not os.path.exists(simsramelf)):
        time.sleep(1)
        if PRINT_THREAD_STATUS:
            print(f"Waiting for {simsramelf}")

    while(not os.path.exists(simsramtaint)):
        time.sleep(1)
        if PRINT_THREAD_STATUS:
            print(f"Waiting for {simsramtaint}")
    
    assert os.path.exists(design_dir), f"Design directory does not exists! {design_dir}"

    env = os.environ.copy()
    env.update(req_env)
    cmd = [
        "make",
        "rerun_drfuzz_mem_notrace_modelsim" if not cov_en else "rerun_drfuzz_mem_muxcov_notrace_modelsim"
    ]
    start_time = time.time()

    p = subprocess.Popen(cmd, cwd=design_dir, env=env, stdout=subprocess.DEVNULL if MUTE else None)
    finished = False
    if not WAIT_UNTIL_FINISHED:
        while(p.poll() is None):
            try:
                with open(req_env["REGDUMP_PATH"], "rb") as f:
                    json.load(f)
                    finished = True
                    print(f"Found register dumps after {time.time() - start_time}s. Early stop.")
                    break
            except Exception:
                time.sleep(1)
                if time.time() - start_time >= msim_timeout:
                    break
        # killing the processes might create problems with the lockfile when it is not properly released...
        if KILL_THREADS:
            for child in psutil.Process(p.pid).children(recursive=True):
                child.kill()
            p.kill()
    else:
        p.wait()
        finished = True
    total_time = time.time() - start_time
    if not finished:
        assert total_time >= msim_timeout, f"Modelsim finished prematurely after {total_time}s: {str(p.stderr)}"
        if PRINT_THREAD_STATUS: 
            print(f"Timed out process with pid {p.pid} for request at {new_req_path} after {total_time}s > {msim_timeout}s.")
        with open(req_env["REGDUMP_PATH"], "w") as f:
            json.dump([{"timeout": total_time}],f) # Write an empty json to signal to the container that this instance timed out.
    
    else: 
        if PRINT_THREAD_STATUS:
            print(f"Finished request at {new_req_path} after {total_time}s.")

    return (new_req_path,total_time,finished)


if __name__ == '__main__':
    if len(sys.argv) > 2:
        raise Exception("Usage: python3 do_run_modelsim.py [path_to_req]")

    for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
        signal(sig, clean)
    printed_status = False
    if len(sys.argv) > 1:
        path_to_req = sys.argv[1]
        modelsim_worker(path_to_req)
    else:
        assert "MODELSIM_REQ_DIR" in os.environ, f"MODELSIM_REQ_DIR not set. Did you source milesan-meta/env.sh?"
        req_dir = os.environ["MODELSIM_REQ_DIR"]
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
                if PRINT_THREAD_STATUS and not printed_status:
                    print(f"Waiting for requests at {req_dir}...\n\tstarted {len(initiated_reqs)}, finished {n_finished_threads}, pending {len(all_reqs)} requests.")
                    printed_status = True
                new_reqs = [req for req in all_reqs if req not in initiated_reqs]

                for i, new_req in enumerate(new_reqs):
                    initiated_reqs += [new_req]
                    if PRINT_THREAD_STATUS:
                        print(f"Starting thread for {new_req}.")
                        printed_status = False
                    pool.apply_async(modelsim_worker, args=(new_req,),callback=test_done_callback)

            
