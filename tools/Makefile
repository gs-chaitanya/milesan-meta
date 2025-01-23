# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

PYTHON=python3.9

RUSTEXEC=$(CARGO_HOME)/bin/rustc
RUSTUPEXEC=$(CARGO_HOME)/bin/rustup
CARGOEXEC=$(CARGO_HOME)/bin/cargo

LOGFILES=log

installtools: install_verilator install_morty install_rust install_bender install_fusesoc install_sv2v install_milesan_python install_yosys install_miniconda install_toolchain install_spike install_makeelf

install_verilator: | log
	( unset VERILATOR_ROOT && cd verilator && autoconf && ./configure --prefix=$(PREFIX_MILESAN) && make -j$(MILESAN_JOBS) && make install ) >$(LOGFILES)/verilator.log 2>&1

install_sv2v: $(PREFIX_MILESAN)/bin/stack | log
	( cd sv2v && make -j$(MILESAN_JOBS) && mkdir -p $(PREFIX_MILESAN)/bin/ && cp bin/sv2v $(PREFIX_MILESAN)/bin/ ) >$(LOGFILES)/sv2v.log 2>&1

$(PREFIX_MILESAN)/bin/stack: | log
	sh stack/gethaskellstack.sh -d $(PREFIX_MILESAN)/bin

install_yosys: | log
	( cd milesan-yosys && make config-gcc && make PREFIX=$(PREFIX_MILESAN) -j$(MILESAN_JOBS) && make PREFIX=$(PREFIX_MILESAN) install ) >$(LOGFILES)/yosys.log 2>&1

install_rust: $(RUSTEXEC)

install_milesan_python: $(MILESAN_PYTHON_VENV) | log
	(  \
		set -e; \
		$(MILESAN_PYTHON_VENV)/bin/pip install -r ../design-processing/python-requirements.txt; \
		$(MILESAN_PYTHON_VENV)/bin/pip install ninja==1.10.2 \
	)  >$(LOGFILES)/milesan-python.log 2>&1

$(RUSTEXEC): | log
	( CARGO_HOME=\$CARGO_HOME RUSTUP_HOME=\$RUSTUP_HOME curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y ) >$(LOGFILES)/rust.log 2>&1

install_morty: $(RUSTEXEC) | log
ifdef DO_INSTALL_OLD_VERSIONS
	$(CARGOEXEC) install --force --path morty --root $(PREFIX_MILESAN) >$(LOGFILES)/morty.log 2>&1
else
	$(CARGOEXEC) install --force morty --root $(PREFIX_MILESAN)
endif

install_bender: $(RUSTEXEC) | log
ifdef DO_INSTALL_OLD_VERSIONS
	$(CARGOEXEC) install --force --path bender --root $(PREFIX_MILESAN) >$(LOGFILES)/bender.log 2>&1
else
	$(CARGOEXEC) install --force bender --root $(PREFIX_MILESAN)
endif

install_fusesoc: $(MILESAN_PYTHON_VENV) | log
	$(MILESAN_PYTHON_VENV)/bin/pip install fusesoc >$(LOGFILES)/fusesoc.log 2>&1

install_miniconda: $(MILESAN_PYTHON_VENV) | log
	mkdir -p miniconda
	( wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O miniconda/miniconda.sh \
		&& cd miniconda/ && bash miniconda.sh -u -b -p $(PREFIX_MILESAN)/miniconda \
		&& $(PREFIX_MILESAN)/miniconda/bin/conda update -y -n base -c defaults conda \
		&& $(PREFIX_MILESAN)/miniconda/bin/conda config --add channels conda-forge \
		&& $(PREFIX_MILESAN)/miniconda/bin/conda config --set channel_priority strict \
		) >$(LOGFILES)/miniconda.log 2>&1

install_toolchain: $(PREFIX_MILESAN)/riscv | log
	# make also does install
	( cd riscv-gnu-toolchain/ && ./configure --prefix=$(PREFIX_MILESAN)/riscv --with-arch=rv32imc --with-cmodel=medlow --enable-multilib && make -j $(MILESAN_JOBS) ) >$(LOGFILES)/toolchain.log 2>&1

install_spike: $(PREFIX_MILESAN)/riscv | log
	(cd riscv-isa-sim && mkdir -p build && cd build && ../configure --prefix=$(PREFIX_MILESAN)/riscv && make -j $(MILESAN_JOBS) && make install) >$(LOGFILES)/spike.log 2>&1

install_makeelf: | log
	(cd makeelf && git checkout finercontrol && $(PYTHON) setup.py install) >$(LOGFILES)/makeelf.log 2>&1

$(MILESAN_PYTHON_VENV): | log
	$(PYTHON) -mvenv $(MILESAN_PYTHON_VENV)

cleantools:
	@echo "This is a fairly destructive recipe. Really know what's going to happen?"
	@echo "If so, press enter. Otherwise, press ^C."
	@echo -n "  >  "
	@read line
	set -x; for x in riscv-isa-sim bender morty riscv-gnu-toolchain sv2v verilator; do ( cd $$x && git clean -xfd ); done
	rm -rf $(PREFIX_MILESAN)
	rm -f $(LOGFILES)/*.log

$(PREFIX_MILESAN)/riscv log:
	mkdir -p $@
