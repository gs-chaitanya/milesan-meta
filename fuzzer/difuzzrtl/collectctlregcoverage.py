# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from common.threads import capture_process_output
import subprocess
import os

docker_img_name = 'difuzzrtl-img'

duration_seconds = 100 # TODO 55 * 3600

def collect_control_register_coverage(is_difuzzrtl: bool):
    if is_difuzzrtl:
        command = f"docker run -it -v {os.environ['MILESAN_DOCKER_MNT_DIR']}:/difuzzrtl {docker_img_name} bash -c 'cd /difuzzrtl && bash fuzz_difuzzrtl.sh'"
    else:
        command = f"docker run -it -v {os.environ['MILESAN_DOCKER_MNT_DIR']}:/difuzzrtl {docker_img_name} bash -c 'cd /difuzzrtl && bash fuzz_milesan.sh'"

    ret_content = capture_process_output(command, duration_seconds)

    with open('retlines.log', 'w') as f:
        f.write(ret_content)
