# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# absolute path we are executing from


if [ "$0" != "$BASH_SOURCE" -a "$BASH_SOURCE" ]
then  # sourced in bash
	myroot=$(dirname $(realpath -- $BASH_SOURCE))
else
	myroot=$(cd $(dirname $0) && pwd -P)
fi

echo "milesan metarepo root: $myroot"

# Set meta repo root
export MILESAN_META_ROOT=$myroot

PWD=$(pwd)
if [[ "${PWD}" == *"tkovats"* ]];
then
echo "Running natively."
export LOCAL_MNT=/scratch/tkovats/ssh_mnt
export PATH=$PATH:/usr/local/questa-2022-03/questasim/bin
export VSIM=/usr/local/questa-2023-04/questasim/linux_x86_64/vsim
source $LOCAL_MNT/cellift-meta/env.sh
else
echo "Running inside container."
export LOCAL_MNT=/mnt
export LM_LICENSE_FILE=8161@lic-mentor.ethz.ch
export PATH_FROM_MODELSIM_TO_MNT=/scratch/tkovats/ssh_mnt
source $LOCAL_MNT/cellift-meta/env.sh
fi

export MODELSIM_REQ_DIR=$LOCAL_MNT/modelsim_req

# Where are the design submodules located
export MILESAN_DESIGN_PROCESSING_ROOT=$MILESAN_META_ROOT/design-processing

# Do not select any design by default
unset MILESAN_DESIGN

# Defaults

# Where to install the binaries and other files of all the tools
# (compiler toolchain, verilator, sv2v, etc.)
export PREFIX_MILESAN=$HOME/prefix-milesan

# How many parallel jobs would you like to have issued?
export MILESAN_JOBS=250 # Feel free to change this

# Where to store a lot of data?
export MILESAN_DATADIR=$MILESAN_META_ROOT/experimental-data # Feel free to change this

export MILESAN_META_COMMON=$MILESAN_DESIGN_PROCESSING_ROOT/common
# Where the common HDL processing Python scripts are located.
export MILESAN_PYTHON_COMMON=$MILESAN_DESIGN_PROCESSING_ROOT/common/python_scripts

# If you would like to customize some of the settings, add another
# $USER test clause like the one below.

export MILESAN_RISCV_BITWIDTH=32

# Modelsim
# export MODELSIM_VERSION=questa-2022.3
export MODELSIM_VERSION=

export PATH_TO_INSTANCELIMIT_PY=$LOCAL_MNT/gits/instancelimit/instancelimit.py
export MODELSIM_MAX_INSTANCES=100
export MODELSIM_WORKROOT=$LOCAL_MNT/modelsim_workroot


# export MODELSIM_VLOG_COVERFLAG=+cover
# export MODELSIM_VSIM_COVERFLAG=-coverage
export MODELSIM_VSIM_COVERPATH=cover.ucdb

HOSTNAME=$(hostname)
if [[ "${HOSTNAME}" == *"eda3"* ]]; # ETHZ EDA server
then
    # Example customization
    export MILESAN_JOBS=14

    ulimit -n 4096 # many FD's
    export MILESAN_DATADIR=/data/"${USER}"/data-eda3
    # export MILESAN_DATADIR=/home/flsolt/milesan-data
elif [[ "${HOSTNAME}" == *"cn112"* ]]; # ETHZ cn112
then
    # Example customization
    export MILESAN_JOBS=14

    ulimit -n 4096 # many FD's
    export MILESAN_DATADIR=/data/"${USER}"/data
    export MODELSIM_VERSION=
    export MODELSIM_WORKROOT=/data/"${USER}"/modelsimfuzz
elif [[ "${HOSTNAME}" == *"cn106"* ]]; # ETHZ cn106
then
    # Example customization
    export MILESAN_JOBS=250
    export MILESAN_DOCKER_MNT_DIR=/scratch/"${USER}"/shareddir
    export MODELSIM_MAX_INSTANCES=256
    export MILESAN_RISCV_BITWIDTH=32

    ulimit -n 10000 # many FD's
    export MILESAN_DATADIR=/scratch/"${USER}"/data/python-tmp
    export MODELSIM_VERSION=
    # export MODELSIM_WORKROOT=//"${USER}"/modelsimfuzz
elif [[ "${HOSTNAME}" == *"cn107"* ]]; # ETHZ cn107
then
    # Example customization
    export MILESAN_JOBS=250
    export MODELSIM_MAX_INSTANCES=256

    ulimit -n 4096 # many FD's
    export MILESAN_DATADIR=/scratch/"${USER}"/data
    export MODELSIM_VERSION=
    export MODELSIM_WORKROOT=/scratch/"${USER}"/modelsimfuzz
elif [ "$USER" = flsolt ] # ETHZ Flavien big server
then
    # Example customization
    export MILESAN_JOBS=250
    export MODELSIM_MAX_INSTANCES=256

    ulimit -n 10000 # many FD's
    export MILESAN_DATADIR=/scratch/"${USER}"/data
    export MODELSIM_VERSION=
    export MODELSIM_WORKROOT=/scratch/"${USER}"/modelsimfuzz
elif [ "$USER" = user ] # ETHZ Flavien laptop
then
    export MILESAN_JOBS=10

    ulimit -n 10000 # many FD's
    export MILESAN_DATADIR=/home/"${USER}"/milesan-data
elif [ -z ${IS_DOCKER+x} ]
then
    export MILESAN_JOBS=250

    ulimit -n 10000 # many FD's
    export MILESAN_DATADIR=/mnt/milesan-data
fi

# Where should our python venv be?
export MILESAN_PYTHON_VENV=$PREFIX_MILESAN/python-venv

# RISCV toolchain location
export RISCV=$PREFIX_MILESAN/riscv

# Have we been sourced?
export MILESAN_ENV_SOURCED=yes

# Rust settings
export CARGO_HOME=$PREFIX_MILESAN/.cargo
export RUSTUP_HOME=$PREFIX_MILESAN/.rustup

# If we add more variables, let consumers
# of these variables detect it
export MILESAN_ENV_VERSION=1

# Set opentitan path (for Ibex)
export OPENTITAN_ROOT=$myroot/external-dependencies/milesan-opentitan

# Set yosys scripts location
export MILESAN_YS=$MILESAN_DESIGN_PROCESSING_ROOT/common/yosys

# use which compiler?
export MILESAN_GCC=riscv32-unknown-elf-gcc
export MILESAN_OBJDUMP=riscv32-unknown-elf-objdump

# use libstdc++ in this prefix
export LD_LIBRARY_PATH=$PREFIX_MILESAN/lib64:$LD_LIBRARY_PATH

export MPLCONFIGDIR=$PREFIX_MILESAN/matplotlib
mkdir -p $MPLCONFIGDIR


# Make configuration usable; prioritize our tools
PATH=/mnt/verilator/bin:$PATH
# PATH=$PREFIX_MILESAN/miniconda/bin:$PATH
PATH=$PREFIX_MILESAN/bin:$PATH
PATH=$PREFIX_MILESAN/bin:$CARGO_HOME/bin:$PREFIX_MILESAN/python-venv/bin/:$PATH
PATH=$RISCV/bin:$PATH
# For cooperative Modelsim locking
export MODELSIM_LOCKFILE=$MILESAN_META_ROOT/tmp/modelsim_lock

# RISC-V proxy kernel
export MILESAN_PK64=$RISCV/riscv32-unknown-elf/bin/pk

# TODO Remove, not really a milesan thing, just used to eval DifuzzRTL
# PATH=/data/flsolt/opt/elf2hex:$PATH

export MILESAN_PATH_TO_FIGURES=$MILESAN_META_ROOT/figures

export MILESAN_PATH_TO_DIFUZZRTL_ELFS=/milesan-difuzzrtl/docker/shareddir/savedockerdifuzzrtl/Fuzzer/outdir/illegal/elf/
# export MILESAN_PATH_TO_DIFUZZRTL_ELFS=/scratch/flsolt/shareddir/Fuzzer/outdir1000/illegal/elf


export COVDUMP_DIR=$LOCAL_MNT/cov_dump

# Generous timeouts. Shorter timeouts may be enforced from python runparams when using the modelsim server.
export MODELSIM_TIMEOUT=600
export MODELSIM_TIMEOUT_TRACE_EN=1200

# cd $MILESAN_META_ROOT/fuzzer