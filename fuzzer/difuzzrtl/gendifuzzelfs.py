import os
import subprocess

docker_img_name = 'difuzzrtl-img'

# Around 1000 ELFs will be produced (1000 minus some potential DifuzzRTL failures)
def gen_many_difuzzrtl_elfs():
    # Generate the elfs
    command = f"docker run -it -v {os.environ['MILESAN_DOCKER_MNT_DIR']}:/difuzzrtl {docker_img_name} bash -c 'cd /difuzzrtl && bash gen_difuzzrtl_elfs.sh'"
    subprocess.run(command, shell=True, check=True)
