from common import designcfgs
import subprocess
import os
def recompile_design(design_name: str, en_taint: bool, single_fuzz: bool):
    cascadedir = designcfgs.get_design_cascade_path(design_name)
    env = os.environ.copy()
    if single_fuzz:
        env["CPPFLAGS"] = "-DSINGLE_FUZZ"
    cmd = [
        "make",
        "recompile_drfuzz_mem_notrace" if en_taint else "recompile_rfuzz_mem_notrace"]
    
    subprocess.run(cmd,cwd=cascadedir,env=env,capture_output=False,check=True)
