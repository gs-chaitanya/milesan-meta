## BOOM PoCs from WhisperFuzz
### Generating the PoCs
Run
```
make
```
to build the corresponding executable (including the their disassemblies) in *build/*. 
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
for modelsim.
Note that if you are using modelsim from your native host system and are otherwise using the docker environment, you can run the build command for modelsim first in the docker until it fails to generate the sources and the re-run in from the host system in the same directory.
#### Running the DUT with the PoC
Set the environment variables SIMSRAMELF and SIMSRAMTAINT, e.g.
```
export SIMSRAMELF=/mnt/milesan-meta/pocs/whisperfuzz/boom/build/divuw.elf
export SIMSRAMTAINT=/mnt/milesan-meta/pocs/whisperfuzz/boom/simsramtaint.txt
```
The simsramtaint.txt file taints the bits of the immediate in the 
and then run
```
make rerun_drfuzz_mem_notrace[_modelsim]
````
in the *milesan/* directory of BOOM to test the PoC using verilator or modelsim. Note that when using modelsim, you will need to run the command from the host system in respective mounted directory and set the environment variables accordinly.

#### Interpreting the outputs
Each executable terminates with a the values and taints of a register printed to the console. A PoC that triggers a constant-time violation taints the PC and causes a taint explosion, which taints all elements in the CPU within a few cycles. Thus, we can detect whether a constant-time violation occured by checking the taint pattern of the dumped register.
E.g., the PoC below triggers a constant-time violation:
```
export SIMSRAMELF=[path_to_mount]/milesan-meta/pocs/whisperfuzz/boom/build/divuw.elf
export SIMSRAMTAINT=[path_to_mount]/milesan-meta/pocs/whisperfuzz/boom/simsramtaint.txt
make rerun_drfuzz_mem_notrace_modelsim

...
Dump of reg x 1: 0x0000000000000003, 0xffffffffffffffff
...
```

however, the PoC of CVA6 below does not not:
```
export SIMSRAMELF=[path_to_mount]/milesan-meta/pocs/whisperfuzz/cva6/build/add.elf
export SIMSRAMTAINT=[path_to_mount]/milesan-meta/pocs/whisperfuzz/cva6/simsramtaint.txt
make rerun_drfuzz_mem_notrace_modelsim
...
Dump of reg x 1: 0x0000000000000003, 0x0000000000000000
...
```