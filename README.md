# MileSan
This repository contains the main components of MileSan and RandOS. It works in conjunction with the milesan-design repositories [milesan-kronos](https://github.com/comsec-group/milesan-kronos), [milesan-chipyard](https://github.com/comsec-group/milesan-chipyard), [milesan-cva6]() and [milesan-openc910](https://github.com/comsec-group/milesan-openc910), which contain the sources required for RTL simulation. We recommend using the [docker image](https://github.com/comsec-group/milesan-docker).
## Docker Setup
When using the [MileSan docker image](https://github.com/comsec-group/milesan-docker), start it with
```
docker run -it -v [path_to_mnt]:/mnt milesan-docker-ccs bash
```
where *[path_to_mnt]* is a directory to be shared between the host and the docker. This is required when using ModelSim from the host system.
Finally, move all contents of */tmp_mnt* to */mnt* to make them available to ModelSim in the host system:
```
mv /tmp_mnt/* /mnt/
```
## Basic Usage
To setup the environment variables run
```
source env.sh
```
NOTE: When using natively, the username and environment variables (LOCAL_MNT, VSIM) in *env.sh* need to be adjusted accordingly beforehand.


### Using ModelSim or Verilator
Since the setup is meant to be used from a docker container and ModelSim is usually not avaiable, we provide a ModelSim server that runs on the host system and interfaces with the docker container through a mounted directory. For this purpose, run:
```
cd fuzzer
python do_run_modelsim.py
```
which starts the ModelSim server which waits for requests in the MODELSIM_REQ_DIR directory, as set from *env.sh*.
### Compiling the DUTs
You can compile the designs ([milesan-kronos](https://github.com/comsec-group/milesan-kronos), [milesan-chipyard](https://github.com/comsec-group/milesan-chipyard), [milesan-cva6]() and [milesan-openc910](https://github.com/comsec-group/milesan-openc910)) individually in their respective *milesan/* directories by running
```
make run_vanilla_notrace && make run_drfuzz_mem_notrace
```
When using ModelSim, additionally navigate to the mounted design directory on the host system and run
```
make run_drfuzz_mem_notrace_modelsim
```

### Fuzzing
First, cd into the *fuzzer/* directory
```
cd /mnt/fuzzer
```
To fuzz a core, run the following
```
python do_check_isa_sim.py [DUT] [N_CORES] [N_SEEDS] [SEED_OFFSET]
```
e.g., to test the Rocket core with a single RandOS program, run
```
python do_check_isa_sim.py rocket 1 1 0
```
This will generate a RandOS program according to the standard configuration in *fuzzer/params/fuzzparams_default.py*. You can use environment variables to change these parameters, e.g.,
```
USE_MODELSIM=0 TAINT_SOURCE_PRIVS=S TAINT_SINK_PRIVS=U python do_check_isa_sim.py rocket 1 1 0
```
to generate an executable where taint is only allowed in S-mode (i.e., S-mode is the taint-source privilege), and run it using Verilator, instead of ModelSim.

### Reduction
To reduce a test case, run
```
python do_reduce_single.py [DUT] [SEED_OFFSET]
```
E.g., to reduce the test program generated with seed 2499 on Boom, run
```
python do_reduce_single.py boom 2499
```
which will reduce the test case using the standard configuration from *fuzzer/params/reduceparams_default.py*. You can change the parameters using environment variables. E.g., to disable taint reduction, run
```
REDUCE_TAINT=0 python do_reduce_single.py boom 2499
```


## Evaluation
### Benchmarking
To perform benchmarking, cd into the */mnt/milesan-meta/fuzzer/benchmarking* directory.
The *fuzz_and_reduce.py* script allows fuzzing a set of DUTs with various configurations and subsequently reducing the leaking programs while collecting performance stats etc.
To perform benchmarking of the transient vulnerabilities discovered on BOOM, run
```
python fuzz_and_reduce.py fuzzconfigs/trans-plots-boom.json
```
which will fuzz and reduce. However, you can skipp fuzzing or reducing by providing the *--fuzz-only* or *--reduce-only* flags. E.g.,
```
python fuzz_and_reduce.py fuzzconfigs/trans-plots-boom.json --reduce-only
```
will only perform reduction and raise an error if no fuzzing with the respective configurtation was performed beforehand. You can pass parameters for fuzzing or reduction through environment variables as above.

### Plotting
We provide plotting facilities in the *plotting/* directory to reproduce the plots from the paper. 
#### Plotting the data used in the paper
We provide the benchmarking data (obtained from several days of fuzzing using Modelsim) plotted in the paper to exactly reproduce the plots. Run
```
 ./gen_plots_and_tables.sh --cached
```
to retrieve all data and store the plots and tables in the *plots/* and *tables/* directories.
#### Plotting new data
To plot new data, you will need to perform benchmarking accordingly for each plot. In the *fuzzer/benchmarking* directory, run
```
./run_all_benchmarks.sh
```
to run the benchmarking as required. This will perform fuzzing campaigns for
1) the BOOM TTEs (Figure 11),
2) the OpenC910 and CVA6 TTEs (Figure 10 and 12),
3) the reduction performance breakdown (Figure 8) and
4) the fuzzing throughput (Figure 9).

**CAUTION:** Performing all these experiments might consume considerable computing resources and take a few days to complete.

Afterwards, in the *plotting/* directory, run
```
 ./gen_plots_and_tables.sh
```
to plot the data. Note that the obtained data and plots might deviate from the original paper due to smaller sample size and system variations.

## Testing PoCs
To test PoCs from this and prior work, look at the README in the *pocs/* directory for further instructions.