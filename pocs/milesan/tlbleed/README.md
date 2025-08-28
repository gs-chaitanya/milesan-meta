# PoC TLBLeed exploit
## Building
Run
```
make
```
to build the PoC.
## Running
To run it, use the stock verilator simulation and provide the path to the executable:
```
cd /mnt/milesan-designs/milesan-chipyard/sims/verilator
CONFIG=MediumBoomConfig make
./simulator-chipyard-MediumBoomConfig /mnt/milesan-meta/pocs/milesan/tlbleed/Template/tlb-exploit.riscv
```