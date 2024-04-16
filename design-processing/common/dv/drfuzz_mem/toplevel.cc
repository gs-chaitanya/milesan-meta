// Copyright 2022 Flavien Solt and Tobias Kovats, ETH Zurich.
// Licensed under the General Public License, Version 3.0, see LICENSE for details.
// SPDX-License-Identifier: GPL-3.0-only
#include <sys/stat.h>
#include <stdlib.h> 
#include <map>
#include <math.h> 


#include "testbench.h"
#include "def_tb.h"
#include "ticks.h"
#include "macros.h"
#include "dtypes.h"
#include "helperfuncs.h"
#include "queue.h"
#include "corpus.h"
#include "mutator.h"
#include "progressbar.h"


void fuzz_once(Testbench *tb, int simlen, bool reset = false) {
	if (reset){
		tb->meta_reset();
		#ifdef TAINT_EN
		tb->meta_reset_t0();
		#endif // TAINT_EN
		tb->reset();
		tb->clear_outputs();
	}

	int remaining_before_stop = N_TICKS_AFTER_STOP;
	Queue *q = new Queue();
	size_t step_id = 1;
	for (; step_id < simlen; step_id++) {
		tick_req_t *tick_req = tb->tick(1,false);
		if(tick_req->type == REQ_FLOATREGDUMP || tick_req->type == REQ_INTREGDUMP){
			#ifdef PRINT_REG_REQ
			tick_req->print();
			#endif
			tb->tick_reqs.push_back(tick_req);
		}
		// Check whether stop has been requested.
		if(tick_req->type == REQ_REGSTREAM){
			#ifdef PRINT_REG_REQ
			tick_req->print();
			#endif
			tb->reg_stream.push_back(tick_req);
		}

		if (!tb->got_stop_req && tick_req->type == REQ_STOP) {
			#ifdef PRINT_STOP_REQ
			std::cout << "Found a stop request. Stopping the benchmark after " << N_TICKS_AFTER_STOP << " more ticks, total tickcount was " << step_id << std::endl;
			#endif
			tb->got_stop_req = true;
		}
		// Decrement the chrono and maybe stop if stop request has been detected.
		if (tb->got_stop_req)
			if (remaining_before_stop-- == 0)
				break;

		// "Natural" stop since SIMLEN has been reached
		#ifdef PRINT_STOP_REQ
		if (step_id == simlen-1)
			std::cout << "Reached SIMLEN (" << simlen << " cycles). Stopping." << std::endl;
		#endif
		#ifdef TAINT_EN
		if(tb->module_->pc_probe_t0){
			#ifdef PRINT_TAINT_PC
			std::cout << "PC tainted\n";
			#endif
			#ifdef STOP_TAINT_PC
			break;
			#endif
			#ifdef RESET_TAINT_PC
			Queue *q = new_queue(nullptr,false);
			q->push_tb_outputs(tb->pop_outputs());
			q->push_tb_instructions(tb->pop_instructions());
			q->print_accumulated_output();
			#ifdef DUMP_COVERAGE
			q->dump(tb);
			#endif
			tb->meta_reset_t0();
			// tb->meta_reset_pc_t0();
			#endif
			// tb->module_->block_fadein_t0 = 1;
				// break;

			// tb->tick(1,false);
			// tb->module_->block_fadein_t0 = 0;
		}
		#endif // TAINT_EN

		#ifdef DUMP_COV_OVER_TICKS
		if(tb->intercepted){
			q->push_tb_outputs(tb->pop_outputs());
			q->dump_acc(tb);

		}
		#endif // DUMP_COV_OVER_TICKS
	}	
	}

long fuzz(size_t simlen, bool prune = true){
	auto start = std::chrono::steady_clock::now();

	Testbench *tb = new Testbench(cl_get_tracefile());

	tb->reset();
	// Queue *seed = new_queue(nullptr,true);
	Queue *seed = new Queue();
	Queue *reg_stream = new Queue();

	// tb->push_instructions(seed->pop_tb_instructions());
	fuzz_once(tb, simlen, true );
	seed->push_tb_tick_reqs(tb->pop_tick_reqs());
	seed->dump_tick_reqs();

	reg_stream->push_tb_tick_reqs(tb->pop_reg_stream());
	reg_stream->dump_reg_stream();
	// tb->check_all_inst_retired();
	seed->push_tb_outputs(tb->pop_outputs());
	seed->push_tb_tick_reqs(tb->pop_tick_reqs());
	// seed->push_tb_instructions(tb->pop_instructions());

	tb->clear_outputs();
	tb->clear_instructions();
	seed->print_accumulated_output();
	// #ifdef DUMP_QUEUES
	// seed->dump(tb);
	// #endif
	// seed->get_accumulated_output()->dump(tb);

	

				
	std::cout << "SEED COVERAGE:\n" << std::dec << seed->get_coverage_amount() << "/" << N_COV_POINTS << "\n";


	#ifdef CHECK_OVERTAINT
	seed->check_tick_reqs_taint();
	#endif
	#ifdef CHECK_GOT_STOP_REQ
	tb->check_got_stop_req();
	#endif
	#ifdef CHECK_REG_REQ
	seed->check_reg_reqs();
	#endif

	#ifdef SINGLE_FUZZ
	exit(0);
	#endif
	// #ifdef CHECK_REG_REQ
	// if(!reg_dumps.size()){
	// 	std::cout << "Invalid seed with ID " << get_id() <<  ": did not receive register requests!\n";
	// 	exit(-1);
	// }
	// #endif  // CHECK_REG_REQ

	Corpus *corpus = new Corpus();

	Queue *prev_q;
	Queue *q;
	Queue *min_hw_q = seed->copy();
	
	if(corpus->is_interesting(seed)){
		#ifdef TAINT_EN
		size_t n_untoggled_and_tainted_mux = seed->get_accumulated_output()->get_untoggled_taintcount();
		if(n_untoggled_and_tainted_mux == 0){
			std::cout << "Seed did not taint any untoggled mux.\n"; // TODO do this for only untoggled mux
			// exit(0);
		}
		std::cout << "Seed is interesting and taints " << std::dec << n_untoggled_and_tainted_mux << " untoggled mux.\n";
		#else
		std::cout << "Seed is interesting\n";
		#endif // TAINT_EN
		corpus->add_q(seed);
	}
	else{
		std::cerr << "Seed is not interesting.\n";
		exit(0);
	} 
	#ifdef DUMP_COVERAGE
	corpus->dump_current_cov(tb);
	#endif

	// exit(0);
	while(!corpus->empty()){
		q = corpus->pop_q(); // generate mutated children of q here and apply each to tb, discard q since we dont need the tests after fuzzing
		#ifdef TAINT_EN
		prev_q = q->copy();
		#endif
		size_t max;
		max = q->compute_inst_taint_hw();
		std::deque<Mutator *> *mutators = get_all_mutators(max);

		while(mutators->size()){
			Mutator *mut = mutators->front();
			mutators->pop_front();
			mut->print();
			while(!mut->is_done()){
				#ifdef TAINT_EN
				if(!corpus->taints_any_untoggled_mux(q)){
					std::cout << "Queue exhausted, skipping.\n";
					// q->print_accumulated_output();
					break; // q does not taint anything interesting anymore so no point in mutating it
				}
				#endif
				Queue *mut_q = mut->apply_next(q);
				#ifdef TAINT_EN
				if(prev_q != nullptr){ // is only true when previously taints was reduced and still toggled all interesting mux
					mut_q->reduce_instruction_taints(prev_q);
				} 
				#endif
				#ifdef PRINT_TESTS
				std::cout << "*** Fuzzing instructions ***\n";
				mut_q->print_instructions();
				std::cout << "****************************\n";
				#endif
				tb->push_instructions(mut_q->pop_tb_instructions());

				fuzz_once(tb, simlen, true);

				// #ifdef CHECK_REG_REQ
				// tb->check_all_inst_retired();
				// if(reg_dumps.size() == 0){ // killed the control flow, so was a bug or invalid mutation
				// 	std::cout << "Killed CF, triggered bug or invalid mutation:\n";
				// 	// mut_q->push_tb_instructions(tb->pop_instructions());
				// 	// mut_q->print_instructions();
				// 	// mut_q->push_tb_outputs(tb->pop_outputs());
				// 	// mut_q->print_accumulated_output();
				// 	// exit(0);
				// 	delete mut_q;
				// 	continue;
				// }
				// #endif // CHECK_REG_REQ
				
				mut_q->push_tb_outputs(tb->pop_outputs());
				mut_q->push_tb_instructions(tb->pop_instructions());
				#ifdef PRINT_COVERAGE
				mut_q->print_accumulated_output();
				#endif
				tb->clear_outputs();
				tb->clear_instructions();

				#ifdef TAINT_EN
				size_t n_untainted_mux = corpus->get_n_untoggled_and_untainted_mux(mut_q);
				#endif
				if(corpus->is_interesting(mut_q)){		
					#ifdef DUMP_QUEUES
					mut_q->dump(tb);
					#endif			
					#ifdef TAINT_EN
					if(!corpus->taints_all_untoggled_mux(mut_q) && prev_q != nullptr){
						mut_q->revert_taints(prev_q); // untainted bit toggled a mux so must still be interesting to fuzz, so taint it again
					}
					#endif
					corpus->add_q(mut_q);
					#ifdef DUMP_COVERAGE
					corpus->dump_current_cov(tb);
					#endif
				}
				#ifdef TAINT_EN
				// for bit flip mutator: if untainting that bit did not change reachibility of untoggled mux, keep it untainted
				else if (n_untainted_mux <= MUX_UNTAINT_TH){
					#ifdef PRINT_N_UNTAINTS
					std::cout << "Untainted " << std::dec << n_untainted_mux << " <= MUX_UNTAINT_TH (" << MUX_UNTAINT_TH << "). Keeping taints.\n";
					#endif
					// untainting that bit still leaves all untoggled coverage points tainted, so lets untaint it and reduce
					// fuzzing instruction space for subsequent mutations -> change q accordingly
					if(prev_q != nullptr) delete prev_q;
					prev_q = mut_q;
				}
				#endif
				else{ // nothing interesting happend
					#ifdef PRINT_N_UNTAINTS
					std::cout << "Untainted " << std::dec << n_untainted_mux << " > MUX_UNTAINT_TH (" << MUX_UNTAINT_TH << "). Reverting taints.\n";
					#endif
					#ifdef TAINT_EN
					if(prev_q != nullptr){
						mut_q->revert_taints(prev_q); // untainted bit toggled a mux so must still be interesting to fuzz, so taint it again
						delete prev_q; // delete because otherwise we double reduce the mut_q
						prev_q = mut_q;
					}
					#else
					if(prev_q != nullptr) delete prev_q; // delete because otherwise we double reduce the mut_q
					prev_q = nullptr;
					#endif
					// if(prev_q != nullptr) delete prev_q;
					// prev_q = mut_q;
				}
				// corpus->print_acc_coverage();
				// std::cout << std::endl;

				if(mut_q->inst_taint_hw<min_hw_q->inst_taint_hw){
					delete min_hw_q;
					min_hw_q = mut_q->copy();
				}
			}
		}
		mutators->clear();
	}
	// TAINT_FUZZ:
	PRINT("**********\n");
	PRINT(INST << "max possible coverage: " << std::dec << N_COV_POINTS << std::endl);
	PRINT(INST << " achieved coverage: " << std::dec << corpus->get_coverage_amount() << std::endl);
	PRINT(INST << " total number of cycles: "  << std::dec << tb->tick_count_ << std::endl);
	PRINT(INST << " coverage map: \n");
	corpus->print_acc_coverage();

	#ifdef TAINT_EN
	if(!corpus->taints_any_untoggled_mux(min_hw_q)){
		PRINT("Skipping bruteforce because min_hw_q exhaused. Exiting.");
	}
	#endif
	PRINT("Starting brute force fuzzing on " << min_hw_q->inst_taint_hw << " tainted instruction bits\n");
	PRINT("Taint mask derived from instruction:\n");
	min_hw_q->print_instructions();
	min_hw_q->print_accumulated_output();
	if(min_hw_q->inst_taint_hw > sizeof(size_t)*8){
		PRINT("HW too large to fit into queue->index of type size_t\n");
		exit(-1);
	}
	Mutator *bf_mut = new DetBruteForceMutator(min_hw_q->inst_taint_hw);
	// Mutator *bf_mut = new EndlessRandomMutator(min_hw_q->inst_taint_hw);
	while(!bf_mut->is_done()){
		Queue *mut_q = bf_mut->apply_next(min_hw_q);
		
		#ifdef PRINT_TESTS
		mut_q->print_instructions();
		#endif

		tb->push_instructions(mut_q->pop_tb_instructions());

		fuzz_once(tb, simlen, true);

		mut_q->push_tb_outputs(tb->pop_outputs());
		mut_q->push_tb_instructions(tb->pop_instructions());
		#ifdef PRINT_COVERAGE
		mut_q->print_accumulated_output();
		#endif

		tb->clear_outputs();
		tb->clear_instructions();

		
		if(corpus->is_interesting(mut_q)){
			// nothing more to gain from min_hw_q, does not taint any untoggled mux anymore
			corpus->add_q(mut_q);
			#ifdef TAINT_EN
			if(!corpus->get_accumulated_output()->get_n_untoggled_by_this_and_tainted_by_other(mut_q->get_accumulated_output())){
				std::cout << "MIN_HW_Q exhausted.\n";
				break;
			}		
			#endif
			#ifdef DUMP_COVERAGE
			corpus->dump_current_cov(tb);
			#endif
		}
		else{
			delete mut_q;
		}
	}

	PRINT("**********\n");
	PRINT("DRFUZZ max possible coverage: " << std::dec << N_COV_POINTS << std::endl);
	PRINT("DRFUZZ achieved coverage: " << std::dec << corpus->get_coverage_amount() << std::endl);
	PRINT("DRFUZZ total number of cycles: \n" << std::dec << tb->tick_count_ << std::endl);
	PRINT("DRFUZZ final coverage map: \n");
	corpus->print_acc_coverage();


	auto stop = std::chrono::steady_clock::now();
	long ret = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();

	return ret;

}


void test_mutators(){
	Queue *q = new_queue(nullptr, true);




	size_t n_taints = q->compute_inst_taint_hw();

	std::cout << "n taints: " << std::dec << n_taints << std::endl;
	std::deque<Mutator *> *mutators = get_all_mutators(n_taints);
	while(mutators->size()){
		Queue *prev_q = nullptr;
		printf("Max %i\n", n_taints);
		Mutator *mut = mutators->front();
		mut->print();
		mutators->pop_front();
		while(!mut->is_done()){
			Queue *mut_q = mut->apply_next(q);
			#ifdef TAINT_EN
			if(prev_q != nullptr) mut_q->reduce_instruction_taints(prev_q);
			#endif
			mut_q->print_instructions();
			std::cout << std::endl;

			// if(!mut_q->compute_inst_taint_hw()) break;
			prev_q = mut_q;
		}
		break;
	}

}



void test_ISA_fuzz(size_t simlen){
	Testbench *tb = new Testbench(cl_get_tracefile());

	Queue *seed1;
	Queue *seed2;
	// seed->rand_words();
	// seed->taint_all();

	std::cout << "FIRST RUN\n";
	// seed->print_instructions();
	// seed->print_instructions_binary();

	// seed->dump_instructions();
	// recompute_elf();
	std::map<std::string, uint64_t> reg_dumps;
	seed1 = new_queue();
	tb->reset_memory();
	tb->reset_memory_t();

	fuzz_once(tb, simlen, true);
	seed1->push_tb_outputs(tb->pop_outputs());
	tb->clear_outputs();
	seed1->print_accumulated_output();
	seed2 = new_queue();

	for(int i=IMMI_BIT; i<31; i++){

		// seed2->push_tb_instruction(new I_Instruction(0xca4,0x0091e1b3,0x7<<i));
		seed2->push_tb_instruction(new RegImmInstruction(0xcb8,0x97b38393,0x1<<i,""));
		tb->push_instructions(seed2->pop_tb_instructions());

		fuzz_once(tb, simlen, true);
		seed2->push_tb_outputs(tb->pop_outputs());
		tb->clear_outputs();
		tb->clear_instructions();

		// seed2->print_accumulated_output();
		std::cout << "seed1 size " << std::dec << seed1->size() << ", seed2 size " << seed2->size() << std::dec <<  std::endl;
		// seed2->get_accumulated_output()->print_diff(seed1->get_accumulated_output());
		seed1->get_accumulated_output()->print_increase(seed2->get_accumulated_output());
		seed2->clear_tb_outputs();
		// return;

	}
	

	// return;
	// if(reg_dumps.size() == 0){
	// 	std::cout << "timeout detected\n"; 
	// 	dump_regs(get_new_timeout_path(), reg_dumps, seed);
	// }
	// else if(!check_regs(reg_dumps)){
	// 	std::cout << "reg mismatch detected\n"; 
	// 	dump_regs(get_new_reg_mismatch_path(), reg_dumps, seed);
	// }

	// seed->push_tb_outputs(tb->pop_outputs());
	// tb->clear_outputs();
	// seed->clear_tb_outputs();
	// return;

	// std::cout << "SECOND RUN\n";
	// seed->rand_words();
	// seed->untaint();


	// seed->print_instructions();

	// seed->dump_instructions();
	// recompute_elf();
	// tb->reset_memory();
	// tb->reset_memory_t();
	// reg_dumps = fuzz_once(tb, simlen, true);

	// if(reg_dumps.size() == 0){
	// 		std::cout << "timeout detected\n"; 
	// 		dump_regs(get_new_timeout_path(), reg_dumps, seed);
	// 	}
	// else if(!check_regs(reg_dumps)){
	// 	std::cout << "reg mismatch detected\n"; 
	// 	dump_regs(get_new_reg_mismatch_path(), reg_dumps, seed);
	// }

	// seed->push_tb_outputs(tb->pop_outputs());
	// tb->clear_outputs();
	// seed->print_accumulated_output();

}

void test_load_ins(){
	Queue *q = new Queue();
	q->load_instructions();
	q->print_instructions();

	uint32_t mask;
	mask = IMMI_MASK<<IMMI_BIT;
	std::cout << "eq: " << q->instructions.front()->equals(new R12DInstruction(0x281c,0xb7f47493,mask,"")) << std::endl;

}


int main(int argc, char **argv, char **env) {
	Verilated::commandArgs(argc, argv);
	Verilated::traceEverOn(VM_TRACE);
	srand(SEED);

	#if defined DUMP_COVERAGE || defined DUMP_COV_OVER_TICKS
	if(std::string(COV_DIR) == get_cov_dir()){ // create directories if no environment variable was set
		std::cout << "Creating standard directories in " << DUMP_DIR << std::endl;
		mkdir(DUMP_DIR,PERMISSIONS);
		mkdir(DUT_DIR,PERMISSIONS);
		mkdir(INST_DIR,PERMISSIONS);
		mkdir(SEED_DIR,PERMISSIONS);
		mkdir(COV_DIR,PERMISSIONS);
		mkdir(REG_MISMATCH_DIR,PERMISSIONS);
		mkdir(TIMEOUT_DIR,PERMISSIONS);
		mkdir(Q_DIR,PERMISSIONS);
	}
	#endif

	#ifndef SINGLE_MEM
    #ifndef DUAL_MEM
    assert(0);
    #endif
    #endif

	size_t simlen = get_sim_length_cycles(LEADTICKS);
	// srand(get_seed());
	// test_mem_reset(simlen);
	// test_tb(simlen);	
	fuzz(simlen,false);
	// test_load_ins();
	// test_ISA_fuzz(simlen);
	// test_simlen(simlen);

	// test_mutators();
	exit(0);
}
