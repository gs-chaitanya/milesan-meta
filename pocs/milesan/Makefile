RISCV_GCC:=riscv64-unknown-elf-gcc
RISCV_FLAGS:=-O0 -static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles -fno-pic  -I. -I./include -T./link.ld  -march=rv64g -mabi=lp64
RISCV_OBJDUMP:=riscv64-unknown-elf-objdump --disassemble-all --disassemble-zeroes -D
RISCV_OBJCOPY:=riscv64-unknown-elf-objcopy
REMOVE_SECTIONS=.riscv.attributes
ELF2HEX:=./smartelf2hex.sh
HEX2BIN:=/mnt/phantom-trails/BOOM/scripts/hex2bin

RISCV_FLAGS:=$(RISCV_FLAGS) -DREGDUMP_ADDR=0x10 -DSTOPSIG_ADDR=0x8 # OpenC910
# RISCV_FLAGS:=$(RISCV_FLAGS) -DREGDUMP_ADDR=0x10 -DSTOPSIG_ADDR=0x0 # CVA6
# RISCV_FLAGS:=$(RISCV_FLAGS) -DREGDUMP_ADDR=0x60000010 -DSTOPSIG_ADDR=0x60000000 # BOOM

BUILDDIR = build/.tmp
BINDIR = build/bins
DUMPDIR = build/dumps
NODATADIR = build/nodata
SRCDIR = src
ELFDIR = build/elfs
NOMMUELFDIR = build/nommuelfs
#Programs to compile
SOURCES = $(wildcard src/**/*.S)
DUMPS = $(patsubst $(SRCDIR)/%.S,$(DUMPDIR)/%.asm,$(SOURCES))
BINS = $(patsubst $(SRCDIR)/%.S,$(BINDIR)/%.bin,$(SOURCES))
ELFS = $(patsubst $(SRCDIR)/%.S,$(ELFDIR)/%.riscv,$(SOURCES))
NOMMUELFS = $(patsubst $(SRCDIR)/%.S,$(NOMMUELFDIR)/%.riscv,$(SOURCES))
NODATABINS = $(patsubst $(SRCDIR)/%.S,$(NODATADIR)/%.bin,$(SOURCES))
# BOOT = boot/bootrom.S
INIT = init/init.S

.PHONY: all
all: elfs

bin: $(BINS)
# nodata: $(NODATABINS)
dumps: $(DUMPS)
elfs: $(ELFS) $(NOMMUELFS)



$(BINDIR)/%.bin: $(BUILDDIR)/%.hex
	mkdir -p `dirname $@`
	$(HEX2BIN) $< $@

$(BUILDDIR)/%.hex: $(BUILDDIR)/%.riscv
	$(ELF2HEX) $< > $@

$(DUMPDIR)/%.asm: $(BUILDDIR)/%.riscv
	mkdir -p `dirname $@`
	$(RISCV_OBJDUMP) $< > $@

$(ELFDIR)/%.riscv: $(SRCDIR)/%.S
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS) $< -o $@
	$(RISCV_OBJCOPY) -R $(REMOVE_SECTIONS) $@ $@
	$(RISCV_OBJDUMP) $@ > $@.dump

$(NOMMUELFDIR)/%.riscv: $(SRCDIR)/%.S
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS)  -DNO_MMU $< -o $@
	$(RISCV_OBJCOPY) -R $(REMOVE_SECTIONS) $@ $@
	$(RISCV_OBJDUMP) $@ > $@.dump


.PHONY: clean

clean:
	rm -rf  build
	mkdir -p build
