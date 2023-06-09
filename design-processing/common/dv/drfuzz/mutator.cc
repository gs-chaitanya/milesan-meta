#include "mutator.h"
#include "corpus.h"

#include <cstring>
#include <deque>

#ifdef TAINT_EN
TaintMutator::TaintMutator(Corpus *corpus){
    this->acc_output.init();
    this->done = false;
    this->corpus = corpus;
    this->candidate_score = 0;
    this->candidate_weight = 0;
    this->ini_candidate_weight = 0;
    this->done = false;
    this->n_untainted_bits = 0; // keep track of the number of taint bits we flipped to 0

}

void TaintMutator::reduce(Queue *q){
    size_t n_tainted_bits = 0;

    q->clear_accumulated_output();
    q->clear_tb_outputs();
    assert(q->outputs.size() ==0);

    // if(P_UNTAINT == 0) return;  
    for(auto &inp: q->inputs){
        for(int i=0; i<N_TAINT_INPUTS_b32; i++){
            for(int j=0; j<32; j++){
                if(inp->taints[i] & (1<<j)){ // bit is tainted

                    // if(rand()%P_UNTAINT){ // with p = 1/2
                    //     inp->taints[i] &= ~((uint32_t )(1<<j)); // untaint that bit by masking it out
                    // }

                    if(n_tainted_bits+this->n_untainted_bits == this->taint_idx){
                        this->taint_idx++;
                        if(this->taint_idx == this->ini_candidate_weight-1) this->done = true;
                        inp->taints[i] &= ~((uint32_t )(1<<j)); // try untainting this one
                        this->n_untainted_bits ++;
                        return;
                    }
                    n_tainted_bits ++;
                    // inp->taints[i] = 0;
                }
            }
        }
    }
    // return;
    assert(false); // if we end up here we messed up
}

bool TaintMutator::is_done(){
    return this->done;
}

void TaintMutator::add_io_taint_vec(Queue *q){
    for(auto &out: q->outputs){
        this->acc_output.add_or(out);
    }
    this->io_taint_vecs.push_back(q);
}

void TaintMutator::filter_taint_vecs(){ // filter out all taint input vectors that dont cover any of the currently non-toggled coverage points 
    assert(N_TAINT_OUTPUTS_b32 == N_COV_POINTS_b32);
    size_t ini_size = this->io_taint_vecs.size();
    uint32_t *target_cov_points = this->corpus->get_accumulated_output()->coverage; // the ones that are zero are the ones we want to taint!
    std::vector<Queue *>::iterator q = this->io_taint_vecs.begin();
    while(q != this->io_taint_vecs.end()){
        doutput_t *ioq_acc_output = (*q)->get_accumulated_output();
        ioq_acc_output->check();
        bool keep = false;
        for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
            if(ioq_acc_output->taints[i] & (~target_cov_points[i])){ // we keep the queue if it tainted an untoggled coverage point
                keep = true;
            }
        }
        if(keep) ++q;
        else{
            (*q)->clear_tb_inputs();
            (*q)->clear_tb_outputs();
            q = this->io_taint_vecs.erase(q);  
        }
    }
    std::cout << "Deleted " << ini_size - this->io_taint_vecs.size() << " queues. Now have " << this->io_taint_vecs.size() << "\n";
}

void TaintMutator::find_candidate(){ // find taint input vectors that cover all untoggled coverage points
    assert(N_TAINT_OUTPUTS_b32 == N_COV_POINTS_b32);
    uint32_t *target_cov_points = this->corpus->get_accumulated_output()->coverage; // the ones that are zero are the ones we want to taint!
    // std::cout << "looking to taint: \n";
    // this->corpus->get_accumulated_output()->print();
    std::vector<Queue *>::iterator q = this->io_taint_vecs.begin();
    while(q != this->io_taint_vecs.end()){
        size_t score = 0;
        doutput_t *ioq_acc_output = (*q)->get_accumulated_output();
        ioq_acc_output->check();
        for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
            score += __builtin_popcount(ioq_acc_output->taints[i] & (~target_cov_points[i]));
        }
        if(score > this->candidate_score){
            this->candidate = *q;
            this->candidate_score = score;
        } 
        ++q;
    }
    assert(this->candidate != nullptr);
    for(auto &inp: this->candidate->inputs){
        for(int i=0; i<N_TAINT_INPUTS_b32; i++){
            this->candidate_weight += __builtin_popcount(inp->taints[i]);
        }
    }
   
    this->ini_candidate_weight = this->candidate_weight;
}

bool TaintMutator::check_good(Queue *q){
    size_t count = 0;
    doutput_t *acc_out = q->get_accumulated_output();
    uint32_t *target_cov_points = this->corpus->get_accumulated_output()->coverage; // the ones that are zero are the ones we want to taint!
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        count += __builtin_popcount(acc_out->taints[i] & (~target_cov_points[i]));
    }
    if(count != this->candidate_score) return false; // we cant taint more outputs by reducing the input taints anyway -> need to change this if we start messing with the inputs too
    return true;
}

void TaintMutator::set_new_candidate(Queue *q){
    assert(q != this->candidate);
    this->candidate->clear_tb_inputs();
    this->candidate->clear_tb_outputs();
    this->candidate = q;
    this->candidate_weight = 0;
    for(auto &inp: this->candidate->inputs){
        for(int i=0; i<N_TAINT_INPUTS_b32; i++){
            this->candidate_weight += __builtin_popcount(inp->taints[i]);
        }
    }
}

TaintBruteForceMutator::TaintBruteForceMutator(Queue *candidate){
    this->candidate = candidate;
    this->candidate_weight = 0;
    this->permutation_idx = 0;
    this->done = false;

    for(auto &inp: this->candidate->inputs){
        for(int i=0; i<N_TAINT_INPUTS_b32; i++){
            this->candidate_weight += __builtin_popcount(inp->taints[i]);
        }
    }

    this->n_permutations = 2<<this->candidate_weight;
}

bool TaintBruteForceMutator::is_done(){
    return this->done;
}
Queue *TaintBruteForceMutator::apply_next(Queue *q){
    assert(N_FUZZ_INPUTS_b32 == N_TAINT_INPUTS_b32);
    size_t taint_idx = 0;
    Queue *out_q = q->copy();
    out_q->clear_tb_outputs();
    out_q->clear_accumulated_output();
    for(auto &inp: out_q->inputs){
        for(int i=0; i<N_FUZZ_INPUTS_b32; i++){
            for(int j=0; j<32; j++){
                if(inp->taints[i] & (1<<j)){ // bit is tainted
                    if(this->permutation_idx & (1<<taint_idx)){ // the bit in the permutation index is set, so we flip the bit
                        inp->inputs[i] = (inp->inputs[i] & ~(1<<j)) | (~inp->inputs[i] & (1<<j)); // this is the uint_32 with the bit inverted
                    }
                    taint_idx++; // go to next bit in permutaton idx
                } 
            }
        }
    }
    if(this->permutation_idx == this->n_permutations-1) this->done = true;
    this->permutation_idx++;
    return out_q;
}

#endif // TAINT_EN

void Mutator::init(){
    this->done = false;
    this->idx = -1;
}

void Mutator::print(){
    std::cout << "Running mutator " << this->name << "\n";
}

bool Mutator::is_done(){
    return this->done;
}

Queue *Mutator::apply_next(Queue *in_q){
    this->next();
    return this->apply(in_q);
}

Queue *Mutator::apply(Queue *in_q) { // flip a bit in input but just copy taints for now
    assert(in_q->size());
    size_t input_size = in_q->inputs.size() * N_FUZZ_INPUTS_b32 * sizeof(uint32_t); // total number of bytes 
    uint8_t *inp_buf = (uint8_t *) malloc(input_size);
    for(int i=0; i<in_q->inputs.size(); i++){ // copy all inputs in queue to contigous memory
        memcpy(inp_buf + i * N_FUZZ_INPUTS_b32 * sizeof(uint32_t), in_q->inputs[i]->inputs,  N_FUZZ_INPUTS_b32 * sizeof(uint32_t));
    }
    this->permute(inp_buf);
    Queue *out_q = new Queue();
    for(int i=0; i<in_q->inputs.size(); i++){
        dinput_t *new_input = (dinput_t *) malloc(sizeof(dinput_t));
        memcpy(new_input->inputs, inp_buf + i * N_FUZZ_INPUTS_b32 * sizeof(uint32_t),  N_FUZZ_INPUTS_b32 * sizeof(uint32_t));
        #ifdef TAINT_EN
        memcpy(new_input->taints, in_q->inputs[i]->taints,  N_TAINT_INPUTS_b32 * sizeof(uint32_t));
        #endif // TAINT_EN
        new_input->clean();
        out_q->push_tb_input(new_input);
    }
    free(inp_buf);
    assert(out_q->size());
    return out_q;
}

void DetMutator::next(){
            assert(!this->done);
            size_t i = this->idx;
            this->idx++;
            if(this->idx == this->max) this->done=true;
}

void RandMutator::next(){
            assert(!this->done);
            this->idx = rand()%this->max;
            this->done=true; // change this back
}

void SingleBitFlipMutator::permute(uint8_t *buf){
    FLIP_BIT(buf, this->idx);
}

void DoubleBitFlipMutator::permute(uint8_t *buf){
    FLIP_BIT(buf, this->idx);
    FLIP_BIT(buf, this->idx+1);
}

void NibbleFlipMutator::permute(uint8_t *buf){
    FLIP_BIT(buf, this->idx);
    FLIP_BIT(buf, this->idx+1);
    FLIP_BIT(buf, this->idx+2);
    FLIP_BIT(buf, this->idx+3);
}

void SingleByteFlipMutator::permute(uint8_t *buf){
    buf[this->idx] ^= 0xFF;
}

void DoubleByteFlipMutator::permute(uint8_t *buf){
    buf[this->idx] ^= 0xFF;
    buf[this->idx+1] ^= 0xFF;
}

void QuadByteFlipMutator::permute(uint8_t *buf){
    buf[this->idx] ^= 0xFF;
    buf[this->idx+1] ^= 0xFF;
    buf[this->idx+2] ^= 0xFF;
    buf[this->idx+3] ^= 0xFF;

}

void AddSingleByteMutator::permute(uint8_t *buf){
    size_t rand_v = rand()% 35; // [0,35] as in rfuzz paper
    if(rand()%2){
        buf[this->idx] += rand_v;
    }
    else{
        buf[this->idx] -= rand_v;
    }
}

void AddDoubleByteMutator::permute(uint8_t *buf){
    uint16_t rand_v = rand() % 35; // [0,35] as in rfuzz paper
    switch(rand()%4){
        case 0: 
            buf[idx] += rand_v&0xFF;
            buf[idx+1] += (rand_v&0xFF00)>>8;
            break;
        case 1: 
            buf[idx] -= rand_v&0xFF;
            buf[idx+1] -= (rand_v&0xFF00)>>8;
            break;
        case 2: 
            rand_v = SWAP16(SWAP16(((uint16_t *) buf)[idx]) + rand_v);
            buf[idx] = rand_v&0xFF; 
            buf[idx+1] = (rand_v&0xFF00)>>8; 
            break;
        case 3: 
            rand_v = SWAP16(SWAP16(((uint16_t *) buf)[idx]) - rand_v);
            buf[idx] = rand_v&0xFF; 
            buf[idx+1] = (rand_v&0xFF00)>>8;  // is this right or should idx be switched?
            break;
    }
}


void AddQuadByteMutator::permute(uint8_t *buf){
    uint32_t rand_v = rand() % 35; // [0,35] as in rfuzz paper
    switch(rand()%4){
        case 0: 
            buf[idx] += rand_v&0xFF;
            buf[idx+1] += (rand_v&0xFF00)>>8;
            buf[idx+2] += (rand_v&0xFF0000)>>16;
            buf[idx+3] += (rand_v&0xFF000000)>>24;
            break;
        case 1: 
            buf[idx] -= rand_v&0xFF;
            buf[idx+1] -= (rand_v&0xFF00)>>8;
            buf[idx+2] -= (rand_v&0xFF0000)>>16;
            buf[idx+3] -= (rand_v&0xFF000000)>>24;
            break;
        case 2: 
            rand_v = SWAP16(SWAP16(((uint16_t *) buf)[idx]) + rand_v);
            buf[idx] = rand_v&0xFF;
            buf[idx+1] = (rand_v&0xFF00)>>8;
            buf[idx+2] = (rand_v&0xFF0000)>>16;
            buf[idx+3] = (rand_v&0xFF000000)>>24;
            break;
        case 3: 
            rand_v = SWAP16(SWAP16(((uint16_t *) buf)[idx]) - rand_v);
            buf[idx] = rand_v&0xFF;
            buf[idx+1] = (rand_v&0xFF00)>>8;
            buf[idx+2] = (rand_v&0xFF0000)>>16;
            buf[idx+3] = (rand_v&0xFF000000)>>24;
            break;
    }
}


void OverwriteInterestingSingleByteMutator::permute(uint8_t *buf){
    int8_t interesting[] = {INTERESTING_8};
    buf[this->idx] = interesting[rand() % (INTERESTING_8_LEN-1)];
}

void OverwriteInterestingDoubleByteMutator::permute(uint8_t *buf){
    int16_t interesting[] = {INTERESTING_16};
    int16_t rand_v = interesting[rand() % (INTERESTING_16_LEN-1)];
    buf[this->idx] = rand_v&0xFF;
    buf[this->idx+1] = (rand_v&0xFF00)>>8;
}

void OverwriteInterestingQuadByteMutator::permute(uint8_t *buf){
    int32_t interesting[] = {INTERESTING_32};
    int32_t rand_v = interesting[rand() % (INTERESTING_32_LEN-1)];
    buf[idx] = rand_v&0xFF;
    buf[idx+1] = (rand_v&0xFF00)>>8;
    buf[idx+2] = (rand_v&0xFF0000)>>16;
    buf[idx+3] = (rand_v&0xFF000000)>>24;
}

void OverwriteRandomByteMutator::permute(uint8_t *buf){
    buf[this->idx] = rand()%255;
}

void DeleteRandomBytesMutator::permute(uint8_t *buf){
    size_t n_bytes = rand()%this->max;
    for(int i=0; i<n_bytes; i++){
        buf[(this->idx+i)%(this->max-1)] = 0x00;
    }
}

void CloneRandomBytesMutator::permute(uint8_t *buf){
    size_t n_bytes = rand()%(this->max/2);
    size_t src_idx = rand()%(this->max-n_bytes);
    size_t dst_idx = rand()%(this->max-n_bytes);
    memcpy(&buf[dst_idx], &buf[src_idx], n_bytes);
}

void OverwriteRandomBytesMutator::permute(uint8_t *buf){
    size_t n_bytes = rand()%this->max;
    for(int i=0; i<n_bytes; i++){
        buf[(this->idx+i)%(this->max-1)] = rand()%255;
    }
}


std::deque<Mutator *> *get_det_mutators(size_t max){
    Mutator *det_mutators[] = {
                            new DetSingleBitFlipMutator(max),
                            new DetDoubleBitFlipMutator(max),
                            new DetNibbleFlipMutator(max),
                            new DetSingleByteFlipMutator(max),
                            new DetDoubleByteFlipMutator(max),
                            new DetQuadByteFlipMutator(max),
                            new DetAddSingleByteMutator(max),
                            new DetAddDoubleByteMutator(max),
                            new DetAddQuadByteMutator(max),
                            };

    std::deque<Mutator *> *mutators = new std::deque<Mutator *>();
    for(int i=0; i<N_DET_MUTATORS; i++){
        mutators->push_back(det_mutators[i]);
    }
    return mutators;
}

std::deque<Mutator *> *get_rand_mutators(size_t max){
    Mutator *rand_mutators[] = {
                            new RandSingleBitFlipMutator(max),
                            new RandAddSingleByteMutator(max),
                            new RandAddDoubleByteMutator(max),
                            new RandAddQuadByteMutator(max),
                            new RandOverwriteInterestingSingleByteMutator(max),
                            new RandOverwriteInterestingDoubleByteMutator(max),
                            new RandOverwriteInterestingQuadByteMutator(max),
                            new RandOverwriteRandomByteMutator(max),
                            new RandDeleteRandomBytesMutator(max),
                            new RandCloneRandomBytesMutator(max),
                            new RandOverwriteRandomBytesMutator(max)
                            };

    std::deque<Mutator *> *mutators = new std::deque<Mutator *>();
    for(int i=0; i<N_RAND_MUTATORS; i++){
        mutators->push_back(rand_mutators[i]);
    }
    return mutators;
}

std::deque<Mutator *> *get_all_mutators(size_t max){
   std::deque<Mutator *> *det_mutators = get_det_mutators(max);
   std::deque<Mutator *> *rand_mutators = get_rand_mutators(max);
   std::deque<Mutator *> *mutators = new std::deque<Mutator *>();

   while(det_mutators->size()){
    mutators->push_back(det_mutators->front());
    det_mutators->pop_front();
   }

   while(rand_mutators->size()){
    mutators->push_back(rand_mutators->front());
    rand_mutators->pop_front();
   }

   return mutators;
}










    
