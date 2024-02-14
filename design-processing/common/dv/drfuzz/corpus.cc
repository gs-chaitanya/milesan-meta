#include <cstring>

#include "corpus.h"

Corpus::Corpus(){
    #ifdef WRITE_COVERAGE
    this->t_last_dump = std::chrono::steady_clock::now();
    #endif // COV_DUMP
}
void Corpus::add_q(Queue *q){
    this->qs.push_back(q);
    this->accumulate_output(q);
    assert(this->qs.size());
}

void Corpus::dump_current_cov(Testbench *tb){
    #ifdef WRITE_COVERAGE
    std::chrono::_V2::steady_clock::time_point now = std::chrono::steady_clock::now();
    long t_since_last_dump = std::chrono::duration_cast<std::chrono::seconds>(now - this->t_last_dump).count();
    if(t_since_last_dump < 1) return;
    this->acc_output->dump(tb);
    this->t_last_dump = now;
    #else
    std::cout << "enable WRITE_COVERAGE compile flag!\n";
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
    //     q->print_inputs();
    //     std::cout << std::endl;
    // }
    #endif // TAINT_EN
    Queue *front = this->qs.front();
    assert(front != nullptr);
    this->qs.pop_front();
    return front;
}
#ifdef TAINT_EN
bool is_smaller(Queue *q1, Queue *q2){
    return q1->input_hw < q2->input_hw;
}
void Corpus::sort_qs(){
    std::sort(this->qs.begin(), this->qs.end(), is_smaller);
}
#endif

bool Corpus::empty(){
    return this->qs.size()==0;
}

void Corpus::accumulate_output(Queue *q){ // we don't need initial coverage here since all the queues are already accumulated
    doutput_t *output = q->get_accumulated_output();
    if(output == nullptr) return;
    if(this->acc_output == nullptr){
        this->acc_output = (doutput_t *) malloc(sizeof(doutput_t));
        memcpy(this->acc_output, output, sizeof(doutput_t));
    }
    else{
        for(int i=0; i<N_COV_POINTS_b32; i++){
            this->acc_output->coverage[i] |= this->acc_output->coverage[i] ^ output->coverage[i];
        }

        #ifdef TAINT_EN
        for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
            this->acc_output->taints[i] |= output->taints[i];
        }
        #endif // TAINT_EN

        for(int i=0; i<N_ASSERTS_b32; i++){
            this->acc_output->asserts[i] |= output->asserts[i];
        }
        this->acc_output->check();
    }
}

bool Corpus::is_interesting(Queue *q){
    bool is_interesting = false;
    if(this->acc_output==nullptr) return true;
    doutput_t *new_output = q->get_accumulated_output();
    std::deque<size_t> new_toggles_idx;;
    for(int i=0; i<N_COV_POINTS_b32; i++){ // TODO: modifiy this to include taints
        uint32_t check = (~this->acc_output->coverage[i]) & new_output->coverage[i];
        if(check != 0){
            is_interesting = true;
            for(int j=0; j<32; j++){
                if(check & (1<<j)){
                    new_toggles_idx.push_back(31-j+i*N_COV_POINTS_b32*sizeof(uint32_t)); // maybe need the indices sometime later
                }
            }
        } 
    }
    if(is_interesting){
        std::cout << "Toggled " << new_toggles_idx.size() << " new coverage point(s) \n";
        unsigned long milliseconds_since_epoch = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
        std::cout << "TIMESTAMP TOGGLE: " << milliseconds_since_epoch << std::endl;
        std::cout << "New total coverage: " << this->get_coverage_amount() + new_toggles_idx.size() << std::endl;
        #ifdef PRINT_COVERAGE
        this->acc_output->print_increase(new_output);
        #endif // PRINT_COVERAGE
    }
    return is_interesting;
}
#ifdef TAINT_EN
bool Corpus::taints_all_untoggled_mux(Queue *q){
    if(this->acc_output==nullptr) return true;
    doutput_t *new_output = q->get_accumulated_output();
    assert(N_COV_POINTS_b32 == N_TAINT_OUTPUTS_b32);

    for(int i=0; i<N_COV_POINTS_b32; i++){ // TODO: modifiy this to include taints
        int trail = 32;
        if(i == N_COV_POINTS_b32-1) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            if(((this->acc_output->coverage[i] & (1<<j)) == 0) && ((this->acc_output->taints[i] & (1<<j)))){ // untoggled but tainted coverage points
                if(!(new_output->taints[i] & (1<<j))){ // is not tainted by queue
                    return false;
                } 

            }
        }
    }
    return true;
}
#endif


int Corpus::get_coverage_amount() {
    assert((this->acc_output->coverage[N_COV_POINTS_b32-1] & ~COV_MASK) == 0);
    // Count the bits equal to 1.
    int ret = 0;
    for (int i = 0; i < N_COV_POINTS_b32; i++) {
        ret += __builtin_popcount(this->acc_output->coverage[i]);
    }
    assert(ret >= 0);
    assert(ret <= N_COV_POINTS);
    return ret;
}

void Corpus::print_acc_coverage(){
    this->acc_output->print();
}

doutput_t *Corpus::get_accumulated_output(){
    return this->acc_output;
}

