#ifndef QUEUE_H
#define QUEUE_H

#include <deque>

#include "macros.h"
#include "dtypes.h"
#include "testbench.h"

// this Queue class represents one set of inputs to be applied in succession to the DUT
class Queue {
    private:
        dinput_t *last_input;
        doutput_t *last_output;
        doutput_t *acc_output;
        doutput_t *ini_output;
        void accumulate_output(doutput_t *);

    public:
        size_t ID;
        size_t parent_ID;
        std::string mutator;
        std::deque<dinput_t *> inputs; // inputs to DUT, FIFO
        std::deque<doutput_t *> outputs; // outputs from DUT, FIFO
        size_t input_hw;

        
        bool has_another_input();
        dinput_t *pop_tb_input();
        std::deque<dinput_t *> *pop_tb_inputs();
        void push_tb_output(doutput_t *tb_output);
        void push_tb_outputs(std::deque<doutput_t *> *outputs);
        void push_tb_input(dinput_t *tb_input);
        void push_tb_inputs(std::deque<dinput_t *> *inputs);
        void clear_tb_outputs();
        void clear_tb_inputs();
        void generate_inputs(bool taint = true, int n_inputs = N_MAX_INPUTS);
        void seed();
        void print_inputs();
        void print_outputs();
        void print_accumulated_output();
        doutput_t *get_accumulated_output();
        void clear_accumulated_output();
        int get_coverage_amount();
        Queue *copy();
        size_t size();
        bool is_equal(Queue* other);
        void print_diff(Queue *other);
        ~Queue(){
            this->clear_tb_inputs();
            this->clear_tb_outputs();
            free(this->acc_output);
            free(this->ini_output);
        }
        bool failed();
        
        #ifdef TAINT_EN
        void invert_tainted_bits();
        void check_taint_progess();
        size_t compute_input_hw();
        void recompute_input_hw();
        void reduce_input_taints(Queue *other);
        #endif // TAINT_EN

        #ifdef WRITE_COVERAGE
        void dump(Testbench *tb);
        #endif // WRITE_COVERAGE

};

Queue * new_queue(Queue *q = nullptr);

#endif // QUEUE_H