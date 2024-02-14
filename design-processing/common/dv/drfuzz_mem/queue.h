#ifndef QUEUE_H
#define QUEUE_H

#include <deque>

#include "macros.h"
#include "dtypes.h"
#include "testbench.h"
#include "instructions.h"

// this Queue class represents a set of instruction register values and the resulting DUT outputs collected during execution
class Queue {
    private:
        doutput_t *acc_output;
        doutput_t *ini_output;

    public:
        size_t ID;
        size_t parent_ID;
        std::deque<doutput_t *> outputs; // mux toggle outputs from DUT, FIFO
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
        void dump(Testbench *tb);
        std::string get_instructions_json_str();
        void push_tb_instruction(Instruction *tb_instruction);
        void push_tb_instructions(std::deque<Instruction *> *instructions);
        std::deque<Instruction *> *pop_tb_instructions();
        void push_tb_output(doutput_t *tb_output);
        void push_tb_outputs(std::deque<doutput_t *> *outputs);
        void clear_tb_outputs();
        void print_outputs();
        void print_accumulated_output();
        doutput_t *get_accumulated_output();
        void clear_accumulated_output();
        int get_coverage_amount();
        Queue *copy();
        size_t size();
        void print_diff(Queue *other);
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

        #ifdef TAINT_EN
        // void invert_tainted_bits();
        // void check_taint_progess();
        size_t compute_min_simlen();
        void reduce_instruction_taints(Queue *other);
        void taint_all();
        void rand_taints();
        void untaint();
        void revert_taints(Queue *other);
        #endif // TAINT_EN
};

Queue * new_queue(Queue *parent_q = nullptr,bool load_instructions = false);

#endif // QUEUE_H