from common.designcfgs import get_design_milesan_path
from common.timeout import timeout
from params.runparams import PATH_TO_TMP, PATH_TO_COV
from common.threads import capture_process_output
from milesan.fuzzfromdescriptor import NUM_MAX_BBS_UPPERBOUND, gen_fuzzerstate_elf_expectedvals, gen_fuzzerstate_interm_elf, gen_new_test_instance
from common.profiledesign import profile_get_medeleg_mask
from milesan.fuzzsim import runtest_verilator_fordrfuzz_mem, runtest_verilator_forrfuzz_mem
from milesan.fuzzerstate import FuzzerState
from milesan.genelf import gen_elf_from_bbs

import os

import time
import multiprocessing as mp
from tqdm import tqdm
import threading
import subprocess

elf_tuples = []
lock = threading.Lock()
rfuzz_times = []
drfuzz_times = []
n_new_workers_done = 0

# @return a pair (rfuzz_coverage_mask, duration in seconds)
@timeout(seconds=60*60*10)
def _run_drfuzz_mem_worker(memsize: int, design_name: str, randseed: int, nmax_bbs: int, authorize_privileges: bool):
    try:
        start_time = time.time()
        fuzzerstate, elfpath, _, _ ,_,_= gen_fuzzerstate_elf_expectedvals(memsize, design_name, randseed, nmax_bbs, authorize_privileges, True)

        cov_dir = os.path.join(PATH_TO_COV, fuzzerstate.design_name,'drfuzz_mem', fuzzerstate.instance_to_str())
        os.makedirs(cov_dir)
        simsramtaint =  os.path.join(PATH_TO_TMP, f'{fuzzerstate.instance_to_str()}.taint.txt') # this path is also computed in the gen_initial_basic_block function which is sorta bad.

        print(f"SIMSRAMELF set to {elfpath}")
        print(f"SIMSRAMTAINT set to {simsramtaint}")
        print(f"COV_DIR set to {cov_dir}")
        rfuzz_coverage_mask = runtest_verilator_fordrfuzz_mem(fuzzerstate, elfpath, cov_dir, simsramtaint)
        return rfuzz_coverage_mask, time.time() - start_time
    except Exception as e:
        print(f"Ignored failed instance with tuple: ({memsize}, {design_name}, {randseed}, {nmax_bbs})")
        print(f"Exception: {e}")
        return 0, -1


def run_drfuzz_mem(design_name: str, num_cores: int, num_testcases: int, timeout: int):
    num_workers = min(num_cores, num_testcases)
    assert num_workers > 0


    profile_get_medeleg_mask(design_name)

    print(f"Starting mux select coverage testing with DrFUZZ_MEM of `{design_name}` on {num_workers} processes.")

    pool = mp.Pool(processes=num_workers)
    process_instance_id = 0
    # First, apply the function to all the workers.
    for process_id in range(num_workers):
        pool.apply_async(_run_drfuzz_mem_worker, args=(*gen_new_test_instance(design_name, process_instance_id, True),))
        process_instance_id += 1  
    time.sleep(timeout)  


@timeout(seconds=60*60*10)
def _run_rfuzz_mem_worker(memsize: int, design_name: str, randseed: int, nmax_bbs: int, authorize_privileges: bool):
    try:
        start_time = time.time()
        fuzzerstate, elfpath, _, _ ,_,_= gen_fuzzerstate_elf_expectedvals(memsize, design_name, randseed, nmax_bbs, authorize_privileges, True)

        cov_dir = os.path.join(PATH_TO_COV, fuzzerstate.design_name, 'rfuzz_mem', fuzzerstate.instance_to_str())
        os.makedirs(cov_dir)
        simsramtaint =  os.path.join(PATH_TO_TMP, f'{fuzzerstate.instance_to_str()}.taint.txt') # this path is also computed in the gen_initial_basic_block function which is sorta bad.

        print(f"SIMSRAMELF set to {elfpath}")
        print(f"SIMSRAMTAINT set to {simsramtaint}")
        print(f"COV_DIR set to {cov_dir}")
        rfuzz_coverage_mask = runtest_verilator_forrfuzz_mem(fuzzerstate, elfpath, cov_dir, simsramtaint)
        return rfuzz_coverage_mask, time.time() - start_time
    except Exception as e:
        print(f"Ignored failed instance with tuple: ({memsize}, {design_name}, {randseed}, {nmax_bbs})")
        print(f"Exception: {e}")
        return 0, -1


def run_rfuzz_mem(design_name: str, num_cores: int, num_testcases: int, timeout: int):
    num_workers = min(num_cores, num_testcases)
    assert num_workers > 0


    profile_get_medeleg_mask(design_name)

    print(f"Starting mux select coverage testing with DrFUZZ_MEM of `{design_name}` on {num_workers} processes.")

    pool = mp.Pool(processes=num_workers)
    process_instance_id = 0
    # First, apply the function to all the workers.
    for process_id in range(num_workers):
        pool.apply_async(_run_rfuzz_mem_worker, args=(*gen_new_test_instance(design_name, process_instance_id, True),))
        process_instance_id += 1  
    time.sleep(timeout)  


@timeout(seconds=60*60*10)
def _gen_elf_worker(memsize: int, design_name: str, randseed: int, nmax_bbs: int, authorize_privileges: bool):
    try:
        fuzzerstate, rtl_elfpath, interm_elfpath, _, _, _, _  = gen_fuzzerstate_elf_expectedvals(memsize, design_name, randseed, nmax_bbs, authorize_privileges, True)
        cov_dir_rfuzz = os.path.join(PATH_TO_COV,fuzzerstate.design_name,'rfuzz_mem',fuzzerstate.instance_to_str())
        cov_dir_drfuzz = os.path.join(PATH_TO_COV,fuzzerstate.design_name,'drfuzz_mem',fuzzerstate.instance_to_str())

        fuzzerstate.simsramtaint_path =  os.path.join(PATH_TO_TMP, f'{fuzzerstate.instance_to_str()}.taint.txt') # this path is also computed in the gen_initial_basic_block function which is sorta bad.
        fuzzerstate.expected_regvals_path = os.path.join(PATH_TO_TMP, f'{fuzzerstate.instance_to_str()}.expected_regvals.json')
        print(f"COV_DIR for drfuzz: {cov_dir_drfuzz}")
        print(f"COV_DIR for rfuzz: {cov_dir_rfuzz}")
        print(f"SIMSRAMELF for final set to {rtl_elfpath}")
        print(f"SIMSRAMELF for intermediate set to {interm_elfpath}")
        print(f"SIMSRAMTAINT set to {fuzzerstate.simsramtaint_path}")

        return fuzzerstate, rtl_elfpath, interm_elfpath, fuzzerstate.simsramtaint_path, cov_dir_drfuzz, cov_dir_rfuzz # todo: move these into fuzzerstate
    except Exception as e:
        print(f"Ignored failed elf generation for instance with ID: ({fuzzerstate.instance_to_str()})")
        print(f"Exception: {e}")
        return 0, -1

def gen_elf_callback(gen_elf_tuple: str):
    global n_new_workers_done
    global elf_tuples
    with lock:
        if gen_elf_tuple is None:
            return
        elf_tuples += [gen_elf_tuple]
        n_new_workers_done += 1

def rfuzz_callback(inst_time_tuple: str):
    print(f"rfuzz exec done with {inst_time_tuple[0]} after {inst_time_tuple[1]}s")
    global rfuzz_times
    global n_new_workers_done
    with lock:
        if time is None:
            return
        rfuzz_times += [time]
        n_new_workers_done += 1


def drfuzz_callback(inst_time_tuple: str):
    print(f"drfuzz exec done with {inst_time_tuple[0]} after {inst_time_tuple[1]}s")
    global drfuzz_times
    global n_new_workers_done
    with lock:
        if time is None:
            return
        drfuzz_times += [time]
        n_new_workers_done += 1

@timeout(seconds=60*60*10)
def _run_rfuzz_with_existing_elf_worker(fuzzerstate: FuzzerState, rtl_elfpath,interm_elfpath, simsramtaint, cov_dir_drfuzz, cov_dir_rfuzz, use_interm:bool=False):
    try:
        if use_interm:
            cov_dir_rfuzz_cov = f"{cov_dir_rfuzz}/interm/cov/"
            fuzzerstate.reg_mismatch_dir = f"{cov_dir_rfuzz}/interm/reg_mismatch/"
            fuzzerstate.timeout_dir = f"{cov_dir_rfuzz}/interm/timeout/"
            print(f"COV_DIR for rfuzz_mem set to {cov_dir_rfuzz_cov}")
            os.makedirs(cov_dir_rfuzz_cov)
            os.makedirs(fuzzerstate.reg_mismatch_dir)
            os.makedirs(fuzzerstate.timeout_dir)
            start = time.time()
            runtest_verilator_forrfuzz_mem(fuzzerstate, interm_elfpath, cov_dir_rfuzz_cov, simsramtaint)
        else:
            cov_dir_rfuzz_cov = f"{cov_dir_rfuzz}/final/cov/"
            fuzzerstate.reg_mismatch_dir = f"{cov_dir_rfuzz}/final/reg_mismatch/"
            fuzzerstate.timeout_dir = f"{cov_dir_rfuzz}/final/timeout/"
            print(f"COV_DIR for rfuzz_mem set to {cov_dir_rfuzz_cov}")
            os.makedirs(cov_dir_rfuzz_cov)
            os.makedirs(fuzzerstate.reg_mismatch_dir)
            os.makedirs(fuzzerstate.timeout_dir)
            start = time.time()
            runtest_verilator_forrfuzz_mem(fuzzerstate, rtl_elfpath, cov_dir_rfuzz_cov, simsramtaint)
        return fuzzerstate.instance_to_str(), time.time() - start, 
    except Exception as e:
        print(f"Ignored failed rfuzz instance with ID: ({fuzzerstate.instance_to_str()})")
        print(f"Exception: {e}")
        return 0, -1


@timeout(seconds=60*60*10)
def _run_drfuzz_with_existing_elf_worker(fuzzerstate: FuzzerState, rtl_elfpath,interm_elfpath, simsramtaint, cov_dir_drfuzz, cov_dir_rfuzz, use_interm:bool = False):
    try:
        if use_interm:
            cov_dir_drfuzz_cov = f"{cov_dir_drfuzz}/interm/cov/"
            fuzzerstate.reg_mismatch_dir = f"{cov_dir_drfuzz}/interm/reg_mismatch/"
            fuzzerstate.timeout_dir = f"{cov_dir_drfuzz}/interm/timeout/"
            print(f"COV_DIR for drfuzz_mem set to {cov_dir_drfuzz_cov}")
            os.makedirs(cov_dir_drfuzz_cov)
            os.makedirs(fuzzerstate.reg_mismatch_dir)
            os.makedirs(fuzzerstate.timeout_dir)
            start = time.time()
            runtest_verilator_fordrfuzz_mem(fuzzerstate, interm_elfpath, cov_dir_drfuzz_cov, simsramtaint)
        else:
            cov_dir_drfuzz_cov = f"{cov_dir_drfuzz}/final/cov/"
            fuzzerstate.reg_mismatch_dir = f"{cov_dir_drfuzz}/final/reg_mismatch/"
            fuzzerstate.timeout_dir = f"{cov_dir_drfuzz}/final/timeout/"
            print(f"COV_DIR for drfuzz_mem set to {cov_dir_drfuzz_cov}")
            os.makedirs(cov_dir_drfuzz_cov)
            os.makedirs(fuzzerstate.reg_mismatch_dir)
            os.makedirs(fuzzerstate.timeout_dir)
            start = time.time()
            runtest_verilator_fordrfuzz_mem(fuzzerstate, rtl_elfpath, cov_dir_drfuzz_cov, simsramtaint)
        return fuzzerstate.instance_to_str(), time.time() - start, 
    except Exception as e:
        print(f"Ignored failed drfuzz instance with ID: ({fuzzerstate.instance_to_str()})")
        print(f"Exception: {e}")
        return 0, -1


def recompile_rfuzz_and_drfuzz_mem(design_name):
    for inst in ['rfuzz_mem','drfuzz_mem']:
        print(f"Recompiling {design_name} for {inst} in {get_design_milesan_path(design_name)}")
        cmd = ['make', '-C', f"{get_design_milesan_path(design_name)}", f'recompile_{inst}_notrace']
        subprocess.run(cmd)


def run_rfuzz_and_drfuzz_mem(design_name: str, num_cores: int, num_testcases: int, timeout: int, use_final_elf:bool, use_interm_elf: bool, run_rfuzz, run_drfuzz):
    global n_new_workers_done
    global elf_tuples
    global rfuzz_times
    global drfuzz_times


    elf_tuples.clear()
    rfuzz_times.clear()
    drfuzz_times.clear()
    n_new_workers_done = 0
        
    num_workers = min(num_cores, num_testcases)
    assert num_workers > 0

    profile_get_medeleg_mask(design_name)

    print(f"Generating {num_testcases} ELFs for {design_name} on {num_workers} processes.")
        
    process_instance_id = 0

    with  mp.Pool(processes=num_workers) as pool:
        for _ in range(num_workers):
            pool.apply_async(_gen_elf_worker, args=(*gen_new_test_instance(design_name, process_instance_id, True),), callback=gen_elf_callback)
            process_instance_id += 1

        with tqdm(total=num_testcases) as pbar:
            while len(elf_tuples) < num_testcases:
                # Yield the execution
                time.sleep(0.1)
                # Check whether we received new coverage paths
                with lock:
                    if n_new_workers_done > 0:
                        pbar.update(n_new_workers_done)
                        if len(elf_tuples) >= num_testcases:
                            print(f"Collected enough ELFs.")
                            break
                        for _ in range(n_new_workers_done):
                            pool.apply_async(_gen_elf_worker, args=(*gen_new_test_instance(design_name, process_instance_id, True),), callback=gen_elf_callback)
                            process_instance_id += 1
                        n_new_workers_done = 0

    return
    step = 2 if run_rfuzz and run_drfuzz else 1
    num_workers = min(num_cores, step*num_testcases) # 2x num_testcased for rfuzz and drfuzz
    if use_final_elf:
        print(f"Starting RFUZZ and DrFUZZ on collected final elfs.")
        n_new_workers_done = 0
        elf_id = 0
        with  mp.Pool(processes=num_workers) as pool:
            for _ in range(0,num_workers,step):
                if run_rfuzz: pool.apply_async(_run_rfuzz_with_existing_elf_worker, args=(*elf_tuples[elf_id],False), callback= rfuzz_callback)
                if run_drfuzz: pool.apply_async(_run_drfuzz_with_existing_elf_worker, args=(*elf_tuples[elf_id],False), callback= drfuzz_callback)
                elf_id += 1

            t = 0
            with tqdm(total=timeout) as pbar:
                while True:
                    # Yield the execution
                    time.sleep(1)
                    t+=1
                    pbar.update(1)
                    with lock:
                        if n_new_workers_done > step-1:
                            if elf_id < num_testcases:
                                for _ in range(0,n_new_workers_done,step):
                                    print("Scheduling another two runs")
                                    if run_rfuzz: pool.apply_async(_run_rfuzz_with_existing_elf_worker, args=(*elf_tuples[elf_id],False), callback= rfuzz_callback)
                                    if run_drfuzz: pool.apply_async(_run_drfuzz_with_existing_elf_worker, args=(*elf_tuples[elf_id],False), callback= drfuzz_callback)
                                    elf_id += 1
                                n_new_workers_done = 0
                    if(t >= timeout): 
                        print(f"Stopping RFUZZ and DrFUZZ after timeout {t}s>={timeout}s")
                        break

                    if((len(rfuzz_times) >= num_testcases) and (len(drfuzz_times) >= num_testcases)):
                        print("All RFUZZ and DrFUZZ executions finished")
                        break
    
    if use_interm_elf:
        print(f"Starting RFUZZ and DrFUZZ on collected intermediate elfs.")
        n_new_workers_done = 0
        elf_id = 0
        with  mp.Pool(processes=num_workers) as pool:
            for _ in range(0,num_workers,step):
                if run_rfuzz: pool.apply_async(_run_rfuzz_with_existing_elf_worker, args=(*elf_tuples[elf_id],True), callback= rfuzz_callback)
                if run_drfuzz: pool.apply_async(_run_drfuzz_with_existing_elf_worker, args=(*elf_tuples[elf_id],True), callback= drfuzz_callback)
                elf_id += 1

            t = 0
            with tqdm(total=timeout) as pbar:
                while True:
                    time.sleep(1)
                    t+=1
                    pbar.update(1)
                    with lock:
                        if n_new_workers_done > 1:
                            if elf_id < num_testcases:
                                for _ in range(0,n_new_workers_done,step):
                                    print("Scheduling another two runs")
                                    if run_rfuzz: pool.apply_async(_run_rfuzz_with_existing_elf_worker, args=(*elf_tuples[elf_id],True), callback= rfuzz_callback)
                                    if run_drfuzz: pool.apply_async(_run_drfuzz_with_existing_elf_worker, args=(*elf_tuples[elf_id],True), callback= drfuzz_callback)
                                    elf_id += 1
                                n_new_workers_done = 0
                    if(t >= timeout): 
                        print(f"Stopping RFUZZ and DrFUZZ after timeout {t}s>={timeout}s")
                        break

                    if((len(rfuzz_times) >= (2*num_testcases) if (use_interm_elf and use_final_elf) else num_testcases) and (len(drfuzz_times) >= (2*num_testcases) if (use_interm_elf and use_final_elf) else num_testcases)):
                        print("All RFUZZ and DrFUZZ executions finished")

    

