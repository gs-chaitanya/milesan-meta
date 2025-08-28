## CVA6 PoCs from WhisperFuzz
### Generating the PoCs
Run 
```
./gen_pocs.sh
```
to generate the sources in *src/* and corresponding executables (including the their disassemblies) in *build/*. 
### Testing the PoCs
#### Building the DUT
If you have not built the verilator/modelsim DUT, you can do so using
```
make run_drfuzz_mem_notrace
```
for verilator or
```
make build_drfuzz_mem_notrace_modelsim
```
for modelsim. We recommend using modelsim for this experiment as we have encountered false positives when using verilator with CVA6 due to a bug in verilator.
Note that if you are using modelsim from your native host system and are otherwise using the docker environment, you can run the build command for modelsim first in the docker until it fails to generate the sources and the re-run in from the host system in the same directory.
#### Running the DUT with the PoC
Set the environment variables SIMSRAMELF and SIMSRAMTAINT, e.g.
```
export SIMSRAMELF=/mnt/milesan-meta/pocs/whisperfuzz/cva6/build/add.elf
export SIMSRAMTAINT=/mnt/milesan-meta/pocs/whisperfuzz/cva6/simsramtaint.txt
```
The simsramtaint.txt file taints the bits of the immediate in the 
and then run
```
make rerun_drfuzz_mem_notrace[_modelsim]
````
in the *milesan/* directory of CVA6 to test the PoC using verilator or modelsim. Note that when using modelsim, you will need to run the command from the host system in respective mounted directory and set the environment variables accordinly.

#### Interpreting the outputs
The authors of the original paper measure the latency of each instruction by substracting the value of MCYCLES CSR after the instruction was executed with the one before. Each executable thus terminates with a the values and taints of the register that contains the diff printed to the console. A PoC that triggers a constant-time violation should this taint the MCYCLES CSR and the register holding the diff. Thus, we can detect whether a constant-time violation occured by checking the taint pattern of the dumped register.
E.g., the PoC below triggers a constant-time violation:
```
export SIMSRAMELF=/scratch/tkovats/ssh_mnt/milesan-meta/pocs/whisperfuzz/cva6/build/remu.elf
export SIMSRAMTAINT=/scratch/tkovats/ssh_mnt/milesan-meta/pocs/whisperfuzz/cva6/simsramtaint.txt
make rerun_drfuzz_mem_notrace_modelsim

...
Dump of reg x 1: 0x0000000000000003, 0xffffffffffffffff
...
```

however, the PoC below does not not:
```
export SIMSRAMELF=/scratch/tkovats/ssh_mnt/milesan-meta/pocs/whisperfuzz/cva6/build/add.elf
export SIMSRAMTAINT=/scratch/tkovats/ssh_mnt/milesan-meta/pocs/whisperfuzz/cva6/simsramtaint.txt
make rerun_drfuzz_mem_notrace_modelsim
...
Dump of reg x 1: 0x0000000000000003, 0x0000000000000000
...
```