RISCV_GCC:=riscv64-unknown-elf-gcc
RISCV_FLAGS:=-O0 -static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles -fno-pic  -I. -I./include -T./link.ld  -march=rv64g -mabi=lp64 -Tboot/linker.ld -Tinit/link.ld
RISCV_OBJDUMP:=riscv64-unknown-elf-objdump --disassemble-all --disassemble-zeroes -D
ELF2HEX:=./smartelf2hex.sh
HEX2BIN:=/mnt/phantom-trails/BOOM/scripts/hex2bin

# RISCV_FLAGS:=$(RISCV_FLAGS) -DREGDUMP_ADDR=0x10 -DSTOPSIG_ADDR=0x8 # OpenC910
RISCV_FLAGS:=$(RISCV_FLAGS) -DREGDUMP_ADDR=0x60000010 -DSTOPSIG_ADDR=0x60000000 # BOOM

BUILDDIR = build/.tmp
BINDIR = build/bins
DUMPDIR = build/dumps
NODATADIR = build/nodata
SRCDIR = src
ELFDIR = build/elfs
NOMMUELFDIR = build/nommuelfs
NODEPLOADELFDIR = build/nodeploadelfs
#Programs to compile
SOURCES = $(wildcard src/**/*.S)
DUMPS = $(patsubst $(SRCDIR)/%.S,$(DUMPDIR)/%.asm,$(SOURCES))
BINS = $(patsubst $(SRCDIR)/%.S,$(BINDIR)/%.bin,$(SOURCES))
ELFS = $(patsubst $(SRCDIR)/%.S,$(ELFDIR)/%.riscv,$(SOURCES))
NOMMUELFS = $(patsubst $(SRCDIR)/%.S,$(NOMMUELFDIR)/%.riscv,$(SOURCES))
NODEPLOADELFS = $(patsubst $(SRCDIR)/%.S,$(NODEPLOADELFDIR)/%.riscv,$(SOURCES))
NODATABINS = $(patsubst $(SRCDIR)/%.S,$(NODATADIR)/%.bin,$(SOURCES))
BOOT = boot/bootrom.S
INIT = init/init.S

.PHONY: all
all: elfs

bin: $(BINS)
# nodata: $(NODATABINS)
dumps: $(DUMPS)
elfs: $(ELFS) $(NOMMUELFS) $(NODEPLOADELFS)



$(BINDIR)/%.bin: $(BUILDDIR)/%.hex
	mkdir -p `dirname $@`
	$(HEX2BIN) $< $@

$(BUILDDIR)/%.hex: $(BUILDDIR)/%.riscv
	$(ELF2HEX) $< > $@

$(DUMPDIR)/%.asm: $(BUILDDIR)/%.riscv
	mkdir -p `dirname $@`
	$(RISCV_OBJDUMP) $< > $@

$(ELFDIR)/%.riscv: $(SRCDIR)/%.S $(INIT)
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS)  $(INIT) $< -o $@
	$(RISCV_OBJDUMP) $@ > $@.dump

$(NOMMUELFDIR)/%.riscv: $(SRCDIR)/%.S  $(INIT)
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS)  -DNO_MMU  $(INIT) $< -o $@
	$(RISCV_OBJDUMP) $@ > $@.dump


$(NODEPLOADELFDIR)/%.riscv: $(SRCDIR)/%.S  $(INIT)
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS)  -DDISABLE_DEP_LOAD  $(INIT) $< -o $@
	$(RISCV_OBJDUMP) $@ > $@.dump



.PHONY: clean

clean:
	rm -rf  build
	mkdir -p build
