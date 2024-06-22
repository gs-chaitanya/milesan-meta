// Copyright 2022 Flavien Solt, ETH Zurich.
// Licensed under the General Public License, Version 3.0, see LICENSE for details.
// SPDX-License-Identifier: GPL-3.0-only

#ifndef TESTBENCH_H
#define TESTBENCH_H

#include <iostream>
#include <stdlib.h>
#include <deque>



#if VM_TRACE
#if VM_TRACE_FST
#include <verilated_fst_c.h>
typedef VerilatedFstC VMTraceType;
#else
#include <verilated_vcd_c.h>
typedef  VerilatedVcdC VMTraceType;
#endif // VM_TRACE_FST
#endif  // VM_TRACE

#include "verilated.h"
#include "dtypes.h"
#include "helperfuncs.h"
#include "def_tb.h"

#include "svdpi.h"


// This class implements elementary interaction with the design under test.
class Testbench {

	private:
        #if VM_TRACE
        VMTraceType *trace_;
        #endif // VM_TRACE

        void apply_vinput(uint32_t* inputs);
        void read_vcoverage(uint32_t* outputs);
        void read_vasserts(uint32_t* asserts);
        void apply_vtaints(uint32_t* taints);
        void read_vtaints(uint32_t* asserts);


	public:
        std::deque<doutput_t *> outputs;
        std::deque<tick_req_t *> tick_reqs;
        std::deque<tick_req_t *> reg_stream;
        vluint32_t tick_count_;
        std::unique_ptr<Module> module_;
        std::chrono::_V2::steady_clock::time_point start_time;
        std::map<uint32_t, Instruction*> intercept_instructions;
        bool intercepted;
        bool got_stop_req;

        Testbench(const std::string &trace_filename = ""): module_(new Module), tick_count_(0l){
            #if VM_TRACE
            trace_ = new VMTraceType;
            module_->trace(trace_, TRACE_LEVEL);
            trace_->open(trace_filename.c_str());
            #endif // VM_TRACE
            this->start_time = std::chrono::steady_clock::now();
            this->got_stop_req = false;
            this->intercepted = false;
        }
        ~Testbench(){
            close_trace();
        }

		void reset(void);
        #ifdef META_RESTET_EN
		void meta_reset();
        #endif
        #ifdef RESET_MEM_EN
        void reset_memory();
        #ifdef TAINT_EN
        void reset_memory_t();
        #endif
        #endif
		void close_trace(void);
        void clear_outputs();
        #ifdef MUXCOV_EN
		int get_coverage_amount();
		void print_last_output();
        #endif
        void read_new_output();
        void dump_memory();
        #ifdef TAINT_EN
        bool is_output_tainted();
        void meta_reset_t0();
        void meta_reset_pc_t0();
        void check_got_stop_req();
        #endif // TAINT_EN
        void print_outputs();
        std::deque<doutput_t *> *pop_outputs();
        void push_instructions(std::deque<Instruction *> *instructions);
        void push_instruction(Instruction * instruction);
        std::deque<Instruction *> *pop_instructions();
        int check_all_inst_retired();
        void clear_instructions();
		tick_req_t *tick(int num_ticks = 1, bool false_tick = false);
        std::deque<tick_req_t *> *pop_tick_reqs();
        std::deque<tick_req_t *> *pop_reg_stream();

		
};

#endif // TESTBENCH_H
