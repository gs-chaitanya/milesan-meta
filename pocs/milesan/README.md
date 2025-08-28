# PoCs of MileSan
## TLBLeed PoC exploit
For details on reproducing the TLBLeed exploit see the README in the *tlbleed* directory.

## Building the remaining PoCs
Run
```
make
```
to build all remaining PoCs. The executables are the in the *build/* folders. Note that this includes some modified PoCs from Phantom Trails used for testing.
## Testing the PoCs
Set the environment variables SIMSRAMELF and SIMSRAMTAINT, e.g.
```
export SIMSRAMELF=[path_to_mount]/milesan-meta/pocs/milesan/build/elfs/openc910/milesan/divfff.riscv
export SIMSRAMTAINT=[path_to_mount]/milesan-meta/pocs/milesan/taint/udata_openc910.txt
```
The simsramtaint.txt file taints the secret data to be leaked.
```
make rerun_drfuzz_mem_notrace[_modelsim]
````
in the *milesan/* directory of the respective DUT to test the PoC using verilator or modelsim. Note that when using modelsim, you will need to run the command from the host system in respective mounted directory and set the environment variables accordinly.

#### Interpreting the outputs
Each executable terminates with a the values and taints of a register printed to the console. A PoC that triggers a constant-time violation taints the PC and causes a taint explosion, which taints all elements in the CPU within a few cycles. Thus, we can detect whether a constant-time violation occured by checking the taint pattern of the dumped register.
E.g., the PoC below triggers a constant-time violation:
```
export SIMSRAMELF=[path_to_mount]/milesan-meta/pocs/milesan/build/elfs/openc910/milesan/divfff.riscv
export SIMSRAMTAINT=[path_to_mount]/milesan-meta/pocs/milesan/taint/udata_openc910.txt
make rerun_drfuzz_mem_notrace_modelsim

...
Dump of reg x 1: 0x0000000000000000, 0xffffffffffffffff
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