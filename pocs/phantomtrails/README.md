# Phantom Trails PoCs
## Building the PoCs
Run 
```
make
```
to build all PoCs.
## Testing the PoCs
Using modelsim, you can test all PoCs and determine the leakage channel by running
```
python test_pocs.py [path_to_mount]/milesan-designs/milesan-chipyard/milesan-boom/
```
Alternatively, you can manually select the executable and taint and run the simulation in the *milesan/* directory of the DUT. E.g.,
```
export SIMSRAMELF=[path_to_mount]/milesan-meta/pocs/phantomtrails/build/elfs/pocs/spectrev4-stl.riscv
export SIMSRAMTAINT=[path_to_mount]/milesan-meta/pocs/phantomtrails/taint/spectrev4-stl.txt
make rerun_drfuzz_mem_notrace_modelsim
```