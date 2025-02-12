RISCV_PREFIX = riscv32-unknown-elf


RV_ARCH_FLAGS ?= -march=rv64g -mabi=lp64
RISCV_GCC_OPTS ?= $(RV_ARCH_FLAGS) -DPREALLOCATE=1 -mcmodel=medany -static -std=gnu99 -O0 -ffast-math -fno-common -fno-builtin-printf -fno-tree-loop-distribute-patterns -gdwarf-2
LDFLAGS = -Tlink.ld -static -nostdlib -nostartfiles -lm -lgcc
RISCV_OBJDUMP ?= $(RISCV_PREFIX)-objdump -d
CC = $(RISCV_PREFIX)-gcc
CADD_0_CVA6 = /mnt/milesan-meta/whisperfuzz_programs/build/c.add_0_1_cva6.elf
CADD_2047_CVA6 = /mnt/milesan-meta/whisperfuzz_programs/build/c.add_2047_1_cva6.elf
CADD_0_BOOM = /mnt/milesan-meta/whisperfuzz_programs/build/c.add_0_1_boom.elf
CADD_2047_BOOM = /mnt/milesan-meta/whisperfuzz_programs/build/c.add_2047_1_boom.elf

# # Edit the rounding mode
# build/app.elf: build/app_nobbe.elf
# 	bbe -e 's/\xd3\x82\x00\xd2/\xd3\xa2\x00\xd2/g' $< -o $@
# 	$(RISCV_OBJDUMP) $@ > $@.dump

build/%.elf: src/%.S link.ld | build
	$(CC) $(RISCV_GCC_OPTS) $< -o $@ $(LDFLAGS)
	$(RISCV_OBJDUMP) -M no-aliases $@ > $@.dump

build:
	mkdir -p build

all: $(patsubst src%, build%, $(patsubst %.S,%.elf,$(wildcard src/*.S)))

run_cva6: all
	cd /mnt/milesan-designs/cva6-test/milesan && SIMSRAMELF=$(CADD_0_CVA6) make rerun_vanilla_notrace
	cd /mnt/milesan-designs/cva6-test/milesan && SIMSRAMELF=$(CADD_2047_CVA6) make run_vanilla_notrace

run_boom: all
	cd /mnt/milesan-designs/milesan-chipyard-rvc/milesan-boom && SIMSRAMELF=$(CADD_0_BOOM) TRACFILE=$(CADD_0_BOOM).trace.vcd make rerun_vanilla_notrace
	cd /mnt/milesan-designs/milesan-chipyard-rvc/milesan-boom && SIMSRAMELF=$(CADD_2047_BOOM)  TRACFILE=$(CADD_2047_BOOM).trace.vcd make rerun_vanilla_notrace

.PHONY: clean all
clean:
	rm -rf build
