RISCV_PREFIX = riscv64-unknown-elf
RV_ARCH_FLAGS ?= -march=rv64gc -mabi=lp64
RISCV_GCC_OPTS ?= $(RV_ARCH_FLAGS) -DPREALLOCATE=1 -mcmodel=medany -static -std=gnu99 -O0 -ffast-math -fno-common -fno-builtin-printf -fno-tree-loop-distribute-patterns -gdwarf-2
LDFLAGS = -Tlink.ld -static -nostdlib -nostartfiles -lm -lgcc
RISCV_OBJDUMP ?= $(RISCV_PREFIX)-objdump -d
CC = $(RISCV_PREFIX)-gcc
GEN_SRC_PY=generate_programs_cva6.py
S_SRCS=$(wildcard src/*.S)
C_SRCS=$(wildcard src/*.c)
TARGETS=$(patsubst src%, build%, $(patsubst %.S,%.elf,$(S_SRCS))) $(patsubst src%, build%, $(patsubst %.c,%.elf,$(C_SRCS)))


all: $(TARGETS)

build/%.elf: src/%.S link.ld | build 
	$(CC) $(RISCV_GCC_OPTS) $< -o $@ $(LDFLAGS)
	$(RISCV_OBJDUMP) -M no-aliases $@ > $@.dump

build/%.elf: src/%.c link.ld | build
	$(CC) $(RISCV_GCC_OPTS) src/startup.S $<  -o $@ $(LDFLAGS)
	$(RISCV_OBJDUMP) -M no-aliases $@ > $@.dump

build:
	mkdir -p build

run_$(CPU)_$(POC): all
	cd /mnt/milesan-designs/$(CPU)/milesan && SIMSRAMELF=$(POC) make rerun_drfuzz_mem_notrace

.PHONY: clean all

clean:
	rm -rf build
	rm -rf src
