import os
import sys
import time
import subprocess
import threading
import multiprocessing as mp

PRINT_THREAD_STATUS = True
MAX_N_THREADS = 30
MUTE = False
callback_lock = threading.Lock()
n_finished_threads = 0

def test_done_callback(ret):
    global n_finished_threads
    with callback_lock:
        n_finished_threads += 1
        if ret is not None:
            if PRINT_THREAD_STATUS:
                print(f"Finished {n_finished_threads} threads.")


def modelsim_worker(new_source):
    if PRINT_THREAD_STATUS:
        print(f"Found new design source at {new_source}")
    for root, dirs, files in os.walk(new_source):
        for file in files: 
            if file.startswith("rtl") and file.endswith(".elf"):
                rtl_elf_path = root+'/'+str(file)
            elif file.startswith(f"rtl") and file.endswith(".simsramtaint.txt"):
                simsramtaint_path =  root+'/'+str(file)


    env = os.environ.copy()
    env["SIMSRAMELF"] = rtl_elf_path
    env["REGDUMP_PATH"] = f"{new_source}/regdump.json"
    env["REGSTREAM_PATH"] = f"{new_source}/regstream.json"
    env["SIMSRAMTAINT"] = simsramtaint_path
    env["TRACEFILE"] = rtl_elf_path.split(".")[0]+".trace.vcd"

    cmd = [
        "make",
        "rerun_drfuzz_mem_notrace_modelsim"
    ]
    subprocess.run(cmd, cwd=design_dir, env=env, capture_output=MUTE)
    if PRINT_THREAD_STATUS:
        print(f"Finished processing design source at {new_source}")
    return new_source


if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise Exception("Usage: python3 do_run_modelsim.py <design-dir> <design-run-source>")
    
    design_dir = sys.argv[1]
    source = sys.argv[2]
    assert os.path.exists(source)
    processed_sources = []
    with mp.Pool(processes=MAX_N_THREADS) as pool:
        while(1):
            time.sleep(2)
            # all_sources = [os.path.join(source,i) for i in os.listdir(source)]
            all_sources = []
            for rootdir, dirs, files in os.walk(source):
                for subdir in dirs:
                    if "cva6" in subdir:
                        all_sources += [os.path.join(rootdir,subdir)]
            if not len(all_sources):
                if PRINT_THREAD_STATUS:
                    print("Waiting for sources...")
                continue
            if PRINT_THREAD_STATUS:
                print(f"Waiting for new design sources at {source}...\n started: {len(processed_sources)} threads, total: {len(all_sources)} in directory")

            new_sources = [source for source in all_sources if source not in processed_sources]

            for i, new_source in enumerate(new_sources):
                processed_sources += [new_source]
                if PRINT_THREAD_STATUS:
                    print(f"Starting thread for {new_source}.")
                pool.apply_async(modelsim_worker, args=(new_source,),callback=test_done_callback)

