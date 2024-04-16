#ifndef QUEUE_H
#define QUEUE_H

#include <deque>

#include "macros.h"
#include "dtypes.h"
#include "testbench.h"
#include "instructions.h"

// This Queue class represents a set of instructions and the resulting coverage and taints.
class Queue {
    private:
        doutput_t *acc_output;
        doutput_t *ini_output;

    public:
        size_t ID;
        size_t parent_ID;
        std::deque<doutput_t *> outputs; // mux toggle outputs from DUT, FIFO
        std::deque<tick_req_t *> tick_reqs;
        std::deque<Instruction *> instructions; // instructions and taints that we intercept to mutate
        size_t inst_taint_hw;
        std::string mutator;

        void load_instructions();
        void seed();
        void init_instructions();
        void print_instructions();
        void print_instructions_binary();
        void rand_words(){};
        void zero_words(){};
        void clear_instructions();
        void deadbeef(){};
        void accumulate_output(doutput_t *);
        bool has_another_instruction();
        void dump(Testbench *tb); // dumps the queue to the queue dir
        void dump_tick_reqs();
        void dump_reg_stream();
        void dump_acc(Testbench *tb); // dumps the accumulated corpus queue to the cov dir
        std::string get_instructions_json_str();
        void push_tb_instruction(Instruction *tb_instruction);
        void push_tb_instructions(std::deque<Instruction *> *instructions);
        std::deque<Instruction *> *pop_tb_instructions();
        void push_tb_output(doutput_t *tb_output);
        void push_tb_outputs(std::deque<doutput_t *> *outputs);
        void push_tb_tick_req(tick_req_t *tb_tick_req);
        void push_tb_tick_reqs(std::deque<tick_req_t *> *tb_tick_reqs);
        void clear_tb_outputs();
        void print_outputs();
        void print_accumulated_output();
        doutput_t *get_accumulated_output();
        void clear_accumulated_output();
        int get_coverage_amount();
        Queue *copy();
        size_t size();
        void print_diff(Queue *other);
        void print_increase(Queue *other);
        std::deque<size_t> get_toggles();
        std::deque<size_t> get_new_toggles(Queue *q);
        ~Queue(){
            this->clear_tb_outputs();
            if(this->acc_output != nullptr) free(this->acc_output);
            if(this->ini_output != nullptr) free(this->ini_output);
            this->instructions.clear();
        }
        Queue(){
            this->acc_output = nullptr;
            this->ini_output = nullptr;
            this->inst_taint_hw = 0;
        }
        bool failed();
        size_t compute_inst_taint_hw();
        void recompute_inst_taint_hw();
        void decode_instructions();
        void accumulate(Queue *other);
        #ifdef TAINT_EN
        // void invert_tainted_bits();
        // void check_taint_progess();
        size_t compute_min_simlen();
        void reduce_instruction_taints(Queue *other);
        void taint_all();
        void rand_taints();
        void untaint();
        void revert_taints(Queue *other);
        bool taints_all_untoggled_mux(Queue *other);
        bool taints_any_untoggled_mux(Queue *other);
        size_t get_n_untoggled_and_untainted_mux(Queue *other);
        void check_tick_reqs_taint();
        void check_reg_reqs();
        #endif // TAINT_EN
};

Queue * new_queue(Queue *parent_q = nullptr,bool load_instructions = false);

#endif // QUEUE_H