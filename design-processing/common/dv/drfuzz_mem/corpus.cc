#include <cstring>

#include "corpus.h"

Corpus::Corpus(){
    #ifdef DUMP_COVERAGE
    this->t_last_dump = std::chrono::steady_clock::now();
    #endif // COV_DUMP
    this->acc_queue = nullptr;
}
void Corpus::add_q(Queue *q){
    this->qs.push_back(q);
    if(this->acc_queue == nullptr) this->acc_queue = q->copy();
    else this->acc_queue->accumulate(q);
    assert(this->qs.size());
}

void Corpus::dump_current_cov(Testbench *tb){
    static bool is_first_call = true;
    #ifdef DUMP_COVERAGE
    std::chrono::_V2::steady_clock::time_point now = std::chrono::steady_clock::now();
    long t_since_last_dump = std::chrono::duration_cast<std::chrono::seconds>(now - this->t_last_dump).count();
    #ifdef EN_COV_QUANTIZATION
    if(t_since_last_dump < T_DELTA_COV_DUMP && !is_first_call) return; 
    is_first_call = false;
    #endif
    this->acc_queue->dump_acc(tb);
    this->t_last_dump = now;
    #else
    std::cout << "enable DUMP_COVERAGE compile flag!\n";
    #endif
}

size_t Corpus::size(){
    return this->qs.size();
}

Queue *Corpus::pop_q(){
    assert(this->qs.size());
    #ifdef TAINT_EN
    this->sort_qs();
    // std::cout << "sorted\n";
    // for(auto &q: this->qs){
    //     q->print_instructions();
    //     std::cout << "HW: " << q->inst_taint_hw << std::endl;
    // }
    #endif // TAINT_EN
    Queue *front = this->qs.front();
    assert(front != nullptr);
    this->qs.pop_front();
    return front;
}
#ifdef TAINT_EN
bool is_smaller(Queue *q1, Queue *q2){
    return q1->inst_taint_hw < q2->inst_taint_hw;
}
void Corpus::sort_qs(){
    std::sort(this->qs.begin(), this->qs.end(), is_smaller);
}
#endif

bool Corpus::empty(){
    return this->qs.size()==0;
}

void Corpus::accumulate_output(Queue *q){ // we don't need initial coverage here since all the queues are already accumulated
    this->acc_queue->accumulate(q);
}

bool Corpus::is_interesting(Queue *q){
    bool is_interesting = false;
    if(!q->get_coverage_amount()) return false;
    std::deque<size_t> new_toggles_idx;
    if(this->acc_queue==nullptr){
        new_toggles_idx = q->get_toggles();
        is_interesting = true;
    }
    else{
        new_toggles_idx = this->acc_queue->get_new_toggles(q);
        if(new_toggles_idx.size()) is_interesting = true;
    }

    if(is_interesting){
        std::cout << "***NEW TEST FOUND***\n";
        q->print_instructions();
        std::cout << "Toggled " << std::dec << new_toggles_idx.size() << " new coverage point(s): [";
        for(auto &mux: new_toggles_idx){
            std::cout << std::dec << mux;
            if(mux != new_toggles_idx.back()) std::cout << ",";
        }
        std::cout << "]\n";
        if(this->acc_queue != nullptr){
            std::cout << "New total coverage: " << std::dec << this->get_coverage_amount() + new_toggles_idx.size() << "/" << N_COV_POINTS << std::endl;
            this->acc_queue->print_increase(q);
        }
        else{
            std::cout << "Seed coverage: " << std::dec << new_toggles_idx.size() << "/" << N_COV_POINTS << std::endl;
            q->print_accumulated_output();
        }
        std::cout << "********************\n";

    }
    return is_interesting;
}
#ifdef TAINT_EN
bool Corpus::taints_all_untoggled_mux(Queue *q){
    return this->acc_queue->taints_all_untoggled_mux(q);
}

bool Corpus::taints_any_untoggled_mux(Queue *q){
    return this->acc_queue->taints_any_untoggled_mux(q);
}

size_t Corpus::get_n_untoggled_and_untainted_mux(Queue *q){
    return this->acc_queue->get_n_untoggled_and_untainted_mux(q);
}
#endif


int Corpus::get_coverage_amount() {
    return this->acc_queue->get_coverage_amount();
}

void Corpus::print_acc_coverage(){
    this->get_accumulated_output()->print();
}

doutput_t *Corpus::get_accumulated_output(){
    return this->acc_queue->get_accumulated_output();
}

