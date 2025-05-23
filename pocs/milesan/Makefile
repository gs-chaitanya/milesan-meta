RISCV_GCC:=riscv64-unknown-elf-gcc
RISCV_FLAGS:=-O0 -static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles -fno-pic  -I. -march=rv64g -mabi=lp64 -I./include
RISCV_OBJDUMP:=riscv64-unknown-elf-objdump --disassemble-all --disassemble-zeroes -D
RISCV_OBJCOPY:=riscv64-unknown-elf-objcopy
REMOVE_SECTIONS=.riscv.attributes
ELF2HEX:=./smartelf2hex.sh
HEX2BIN:=/mnt/phantom-trails/BOOM/scripts/hex2bin

# RISCV_FLAGS:=$(RISCV_FLAGS) -DREGDUMP_ADDR=0x10 -DSTOPSIG_ADDR=0x8 # OpenC910
# RISCV_FLAGS:=$(RISCV_FLAGS) -DREGDUMP_ADDR=0x10 -DSTOPSIG_ADDR=0x0 # CVA6
# RISCV_FLAGS:=$(RISCV_FLAGS) -DREGDUMP_ADDR=0x60000010 -DSTOPSIG_ADDR=0x60000000 # BOOM
TARGETS=cva6 openc910 chipyard
BUILDDIR = build/.tmp
BINDIR = build/bins
DUMPDIR = build/dumps
NODATADIR = build/nodata
SRCDIR = src
ELFDIR = build/elfs
NOMMUELFDIR = build/nommuelfs

DUMPDIRS_TARGETS = $(patsubst %,$(DUMPDIR)/%, $(TARGETS))
NODATADIRS_TARGETS = $(patsubst %,$(NODATADIR)/%, $(TARGETS))
ELFDIRS_TARGETS = $(patsubst %, $(ELFDIR)/%, $(TARGETS))
NOMMUELFDIRS_TARGETS = $(patsubst %, $(NOMMUELFDIR)/%, $(TARGETS))
BINDIRS_TARGETS = $(patsubst %, $(BINDIR)/%, $(TARGETS))

#Programs to compile
SOURCES = $(wildcard src/**/*.S)
DUMPS =$(foreach dir, $(DUMPDIRS_TARGETS), $(patsubst $(SRCDIR)/%.S,$(dir)/%.asm,$(SOURCES)))
BINS = $(foreach dir, $(BINDIR), $(patsubst $(SRCDIR)/%.S,$(dir)/%.bin,$(SOURCES)))
NODATABINS = $(foreach dir, $(NODATADIRS_TARGETS), $(patsubst $(SRCDIR)/%.S,$(dir)/%.bin,$(SOURCES)))
ELFS = $(foreach dir, $(ELFDIRS_TARGETS), $(patsubst $(SRCDIR)/%.S,$(dir)/%.riscv,$(SOURCES)))
NOMMUELFS = $(foreach dir, $(NOMMUELFDIRS_TARGETS), $(patsubst $(SRCDIR)/%.S,$(dir)/%.riscv,$(SOURCES)))
# BOOT = boot/bootrom.S
INIT = init/init.S

.PHONY: all
all: elfs
bin: $(BINS)
# nodata: $(NODATABINS)
dumps: $(DUMPS)
elfs: $(ELFS) $(NOMMUELFS)



$(BINDIR)/cva6/%.bin: $(BUILDDIR)/%.hex
	mkdir -p `dirname $@`
	$(HEX2BIN) $< $@

$(BUILDDIR)/cva6/%.hex: $(BUILDDIR)/%.riscv
	$(ELF2HEX) $< > $@

$(DUMPDIR)/cva6/%.asm: $(BUILDDIR)/%.riscv
	mkdir -p `dirname $@`
	$(RISCV_OBJDUMP) $< > $@

$(ELFDIR)/cva6/%.riscv: $(SRCDIR)/%.S
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS) -Tlink/link_cva6.ld -DCVA6 $< -o $@
	$(RISCV_OBJCOPY) -R $(REMOVE_SECTIONS) $@ $@
	$(RISCV_OBJDUMP) $@ > $@.dump

$(NOMMUELFDIR)/cva6/%.riscv: $(SRCDIR)/%.S
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS) -Tlink/link_cva6.ld -DCVA6 -DNO_MMU $< -o $@
	$(RISCV_OBJCOPY) -R $(REMOVE_SECTIONS) $@ $@
	$(RISCV_OBJDUMP) $@ > $@.dump


$(BINDIR)/openc910/%.bin: $(BUILDDIR)/%.hex
	mkdir -p `dirname $@`
	$(HEX2BIN) $< $@

$(BUILDDIR)/openc910/%.hex: $(BUILDDIR)/%.riscv
	$(ELF2HEX) $< > $@

$(DUMPDIR)/openc910/%.asm: $(BUILDDIR)/%.riscv
	mkdir -p `dirname $@`
	$(RISCV_OBJDUMP) $< > $@

$(ELFDIR)/openc910/%.riscv: $(SRCDIR)/%.S
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS) -Tlink/link_openc910.ld -DOPENC910 $< -o $@
	$(RISCV_OBJCOPY) -R $(REMOVE_SECTIONS) $@ $@
	$(RISCV_OBJDUMP) $@ > $@.dump

$(NOMMUELFDIR)/openc910/%.riscv: $(SRCDIR)/%.S
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS)   -Tlink/link_openc910.ld -DOPENC910 -DNO_MMU $< -o $@
	$(RISCV_OBJCOPY) -R $(REMOVE_SECTIONS) $@ $@
	$(RISCV_OBJDUMP) $@ > $@.dump


$(BINDIR)/chipyard/%.bin: $(BUILDDIR)/%.hex
	mkdir -p `dirname $@`
	$(HEX2BIN) $< $@

$(BUILDDIR)/chipyard/%.hex: $(BUILDDIR)/%.riscv
	$(ELF2HEX) $< > $@

$(DUMPDIR)/chipyard/%.asm: $(BUILDDIR)/%.riscv
	mkdir -p `dirname $@`
	$(RISCV_OBJDUMP) $< > $@

$(ELFDIR)/chipyard/%.riscv: $(SRCDIR)/%.S
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS)  -Tlink/link_chipyard.ld -DCHIPYARD $< -o $@
	$(RISCV_OBJCOPY) -R $(REMOVE_SECTIONS) $@ $@
	$(RISCV_OBJDUMP) $@ > $@.dump

$(NOMMUELFDIR)/chipyard/%.riscv: $(SRCDIR)/%.S
	mkdir -p `dirname $@`
	$(RISCV_GCC) $(RISCV_FLAGS)  -Tlink/link_chipyard.ld -DCHIPYARD   -DNO_MMU $< -o $@
	$(RISCV_OBJCOPY) -R $(REMOVE_SECTIONS) $@ $@
	$(RISCV_OBJDUMP) $@ > $@.dump


.PHONY: clean

clean:
	rm -rf  build
	mkdir -p build
