RISCV_PREFIX = riscv64-unknown-elf


RV_ARCH_FLAGS ?= -march=rv64gc -mabi=lp64
# RISCV_GCC_OPTS ?= $(RV_ARCH_FLAGS) -DPREALLOCATE=1 -mcmodel=medany -static -std=gnu99 -O0 -ffast-math -fno-common -fno-builtin-printf -fno-tree-loop-distribute-patterns -gdwarf-2
RISCV_GCC_OPTS ?= -mcmodel=medany -I -std=gnu99 -O0 -g -fno-common -Wall -Wno-unused-function -Wno-unused-variable
LDFLAGS = -Tlink.ld -static -nostdlib -nostartfiles -lm -lgcc
RISCV_OBJDUMP ?= $(RISCV_PREFIX)-objdump -d
CC = $(RISCV_PREFIX)-gcc
CADD_0 = /mnt/cascade-meta/whisperfuzz_programs/poc/build/cadd_t3_a4_0_0.elf
CADD_2047 = /mnt/cascade-meta/whisperfuzz_programs/poc/build/cadd_t3_a4_2047_0.elf

build/%.elf: %.c link.ld | build
	$(CC) $(RISCV_GCC_OPTS) $< -o $@ $(LDFLAGS)
	$(RISCV_OBJDUMP) -M no-aliases $@ > $@.dump

build:
	mkdir -p build

all: $(patsubst %, build/%, $(patsubst %.c,%.elf,$(wildcard *.c)))

run: all
	cd /mnt/cascade-designs/cascade-cva6/cascade && SIMSRAMELF=$(CADD_0) make run_vanilla_notrace
	cd /mnt/cascade-designs/cascade-cva6/cascade &&SIMSRAMELF=$(CADD_2047) make run_vanilla_notrace

.PHONY: clean all
clean:
	rm -rf build
