// Copyright 2022 Flavien Solt, ETH Zurich.
// Licensed under the General Public License, Version 3.0, see LICENSE for details.
// SPDX-License-Identifier: GPL-3.0-only
#include <iostream>
#include <verilated_fst_c.h>
#include <sys/stat.h>
#include <errno.h> 

#include "testbench.h"
#include "queue.h"
#include "ticks.h"
#include "dtypes.h"
#include "corpus.h"
#include "mutator.h"
#include "log.h"
#include "macros.h"

// run one input that is split into a temporal sequence of inputs
static inline void fuzz_once(Testbench *tb, bool reset = true, bool print = false) {
	tb->init();

	if (reset){
		tb->meta_reset();
		tb->reset();
		assert(tb->outputs.size() == 0);
	}

	while(tb->has_another_input()){
		if(print){
			std::cout << "TB INPUT\n";
			 tb->print_next_input();
		}
		tb->apply_next_input();
		tb->tick();
		tb->read_new_output();
		if(print){
			std::cout << "TB OUTPUT\n";
			tb->print_last_output();
		}
	}

	tb->finish();
}

static long fuzz(){
	auto start = std::chrono::steady_clock::now();
	
	Testbench *tb = new Testbench(cl_get_tracefile());
	Corpus *corpus = new Corpus();

	Queue *seed = new_queue();
	seed->seed();

	#ifdef WRITE_QUEUES
	seed->dump(tb);
	#endif // WRITE_QUEUES

	std::cout << "***SEED***\n";
	std::cout << "INPUT:\n";
	seed->print_inputs();

	tb->push_inputs(seed->pop_tb_inputs());
	fuzz_once(tb, true);
	seed->push_tb_outputs(tb->pop_outputs());
	std::cout << "OUTPUT: \n";
	seed->print_outputs();
	std::cout << "ACCUMULATED OUTPUT:\n";
	seed->get_accumulated_output()->print();
	std::cout << "COVERAGE:\n" << seed->get_coverage_amount() << "\n";
	
	if(seed->get_accumulated_output()->failed()){
		std::cout << "Invalid input seed!\n";
		exit(-1);
	}

	unsigned long milliseconds_since_epoch = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
	std::cout << "TIMESTAMP START: " << milliseconds_since_epoch << std::endl;

	seed->push_tb_inputs(tb->pop_retired_inputs());
	std::cout << "**********\n";
	std::cout << "***CORPUS***\n";
	Queue *prev_q;
	Queue *q;
	Queue *min_hw_q = new_queue();
	min_hw_q->seed(); // values dont matter, just need all bits tainted to have max HW
	corpus->add_q(seed);
	while(!corpus->empty()){
		q = corpus->pop_q(); // generate mutated children of q here and apply each to tb, discard q since we dont need the tests after fuzzing
		#ifdef TAINT_EN
		if(q->compute_input_hw()<min_hw_q->compute_input_hw()){
			delete min_hw_q;
			min_hw_q = q->copy();
		}
		#endif // TAINT_EN
		#ifdef PRINT_TESTS
		std::cout << "NEXT TEST\n";
		q->print_inputs();
		#endif
		#ifdef TAINT_EN
		std::deque<Mutator *> *mutators = get_all_mutators(q->compute_input_hw());
		#else
		std::deque<Mutator *> *mutators = get_all_mutators(q->size());
		#endif
		while(mutators->size()){
			prev_q = nullptr;
			Mutator *mut = mutators->front();
			mutators->pop_front();
			mut->print();
			while(!mut->is_done()){
				#ifdef WRITE_COVERAGE
				corpus->dump_current_cov(tb);
				#endif
				
				Queue *mut_q = mut->apply_next(q);

				#ifdef TAINT_EN
				if(prev_q != nullptr){ // is only true when previously taints was reduced and still toggled all interesting mux
					mut_q->reduce_input_taints(prev_q);
				} 
				#endif

				tb->push_inputs(mut_q->pop_tb_inputs());
				fuzz_once(tb, true);
				mut_q->push_tb_outputs(tb->pop_outputs());
				mut_q->push_tb_inputs(tb->pop_retired_inputs()); // retrieve inputs back into q
				

				if(corpus->is_interesting(mut_q)){
					#ifdef TAINT_EN
					if(!corpus->taints_all_untoggled_mux(mut_q)){
						mut->revert_taints(mut_q); // untainted bit toggled a mux so must still be interesting to fuzz, so taint it again
					}
					#endif
					
					#ifdef WRITE_QUEUES
					mut_q->dump(tb);
					#endif // WRITE_QUEUES
				
					corpus->add_q(mut_q);
				}
				#ifdef TAINT_EN
				// for bit flip mutator: if untainting that bit did not change reachibility of untoggled mux, keep it untainted
				else if(corpus->taints_all_untoggled_mux(mut_q)){
					// untainting that bit still leaves all untoggled coverage points tainted, so lets untaint it and reduce
					// fuzzing input space for subsequent mutations -> change q accoringly
					// std::cout << "INPUT STILL TAINTED ALL INTERESTING MUX:\n";
					if(prev_q != nullptr) delete prev_q;
					prev_q = mut_q;
				}
				else{ // nothing interesting happend
					delete mut_q;
					if(prev_q != nullptr) delete prev_q; // delete because otherwise we double reduce the mut_q
					prev_q = nullptr;
				}
				#else
				else{
					delete mut_q;
				}
				#endif // TAINT_EN
			}
			// delete mut;
		}
		// corpus->add_q(q); // readd it to corpus
		// delete q; // delete it since all deterministic mutations were covered and random unsignificant
	}

	unsigned long milliseconds_since_epoch_stop = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
	std::cout << "TIMESTAMP STOP: " << milliseconds_since_epoch_stop << std::endl;

	
	PRINT("**********\n");
	PRINT(INST << "max possible coverage: " << N_COV_POINTS << std::endl);
	PRINT(INST << " achieved coverage: " << corpus->get_coverage_amount() << std::endl);
	PRINT(INST << " total number of cycles: " << tb->tick_count_ << std::endl);
	PRINT(INST << " final coverage map: \n");
	corpus->print_acc_coverage();

	#ifdef TAINT_EN
	PRINT("Starting random fuzzing on" << min_hw_q->compute_input_hw() << " tainted input bits\n");
	PRINT("Taint mask derived from input:\n");
	min_hw_q->print_inputs();

	Mutator *rand_mut = new EndlessRandomMutator(min_hw_q->compute_input_hw());

	while(!rand_mut->is_done()){
		Queue *mut_q = rand_mut->apply_next(min_hw_q);
		#ifdef PRINT_TESTS
		std::cout << "NEXT TEST\n";
		mut_q->print_inputs(); 
		#endif
		DEBUG("**********\n");
		#ifdef WRITE_COVERAGE
		corpus->dump_current_cov(tb);
		#endif // WRITE_COVERAGE
		tb->push_inputs(mut_q->pop_tb_inputs());
		fuzz_once(tb, true);
		mut_q->push_tb_outputs(tb->pop_outputs());
		#if DEBUG_LVL > 2
		DEBUG("OUTPUT\n");
		mut_q->print_outputs(); 
		DEBUG("ACCUMULATED OUTPUT\n");
		mut_q->print_accumulated_output(); 
		DEBUG("CORPUS:\n");
		corpus->print_acc_coverage();
		#endif // DEBUG_LVL
		mut_q->push_tb_inputs(tb->pop_retired_inputs()); // retrieve inputs back into q
		if(corpus->is_interesting(mut_q)){
			corpus->add_q(mut_q);
			#ifdef WRITE_QUEUES
			mut_q->dump(tb);
			#endif // WRITE_QUEUES
		}
		else{
			tb->free_retired_inputs();
			delete mut_q;
		}
	}

	PRINT("**********\n");
	PRINT("DRFUZZ max possible coverage: " << N_COV_POINTS << std::endl);
	PRINT("DRFUZZ achieved coverage: " << corpus->get_coverage_amount() << std::endl);
	PRINT("DRFUZZ total number of cycles: \n" << tb->tick_count_ << std::endl);
	PRINT("DRFUZZ final coverage map: \n");
	corpus->print_acc_coverage();
	#endif // TAINT_EN


	auto stop = std::chrono::steady_clock::now();
	long ret = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();

	return ret;
}
#ifdef TAINT_EN
void test_mutators(){
	Queue *q = new_queue();
	q->seed();
	int i=0;
	std::deque<Mutator *> *mutators = get_det_mutators(q->compute_input_hw());
	while(mutators->size()){
		Mutator *mut = mutators->front();
		mutators->pop_front();
		std::cout << mut->name << " max: " << mut->max << std::endl;
		Queue *mut_q_prev = nullptr;
		while(!mut->is_done()){
			Queue *mut_q = mut->apply_next(q);
			if(mut_q_prev != nullptr) mut_q->reduce_input_taints(mut_q_prev);
			std::cout << "input:\n";
			mut_q->print_inputs();
			mut_q_prev = mut_q->copy();
			std::cout << mut->name << " max: " << mut->max << std::endl;
			std::cout << "idx: " << mut->idx << std::endl;

		}
	}
	PRINT("SEED\n");
	q->print_inputs();
	Mutator *rand_mut = new EndlessRandomMutator(q->compute_input_hw());
	PRINT("INPUT HW " << q->compute_input_hw() <<  std::endl);
	PRINT("RANDMUT MAX " << rand_mut->max << std::endl);
	PRINT("b8 MAX " << b8(q->compute_input_hw()) << std::endl);

	// exit(0);
	while(!rand_mut->is_done()){
		Queue *mut_q = rand_mut->apply_next(q);
		PRINT("NEXT INPUT\n");
		mut_q->print_inputs(); 
	}

}

void test_corpus(){
	
	Corpus *corpus = new Corpus();
	Queue *q = new_queue();
	q->seed();
	Mutator *mut = new DetSingleByteFlipMutator(q->compute_input_hw());
	Queue *mut_q_prev = nullptr;
	while(!mut->is_done()){
		Queue *mut_q = mut->apply_next(q);
		if(mut_q_prev != nullptr) mut_q->reduce_input_taints(mut_q_prev);
		std::cout << "input:\n";
		mut_q->print_inputs();
		mut_q_prev = mut_q->copy();
		std::cout << mut->name << " max: " << mut->max << std::endl;
		std::cout << "idx: " << mut->idx << std::endl;
		corpus->add_q(mut_q);
		}
	corpus->sort_qs();
	// for(auto &q: corpus->qs){
	// 	q->print_inputs();
	// 	std::cout << std::endl;
	// }

}
#endif

int main(int argc, char **argv, char **env) {

	Verilated::commandArgs(argc, argv);
	Verilated::traceEverOn(VM_TRACE);
	#ifdef WRITE_COVERAGE
	mkdir(DUMP_DIR,PERMISSIONS);
	mkdir(DUT_DIR,PERMISSIONS);
	mkdir(INST_DIR,PERMISSIONS);
	mkdir(SEED_DIR,PERMISSIONS);
	mkdir(Q_DIR,PERMISSIONS);
	mkdir(COV_DIR,PERMISSIONS);
	#endif
	// Testbench *tb = new Testbench(cl_get_tracefile());
	// Queue *q = new_queue();
	// Queue *qx = new_queue(q);
	// q->dump(tb);
	// qx->dump(tb);
	long duration = fuzz();
	// test_mutators();
	// test_corpus();

	

}
