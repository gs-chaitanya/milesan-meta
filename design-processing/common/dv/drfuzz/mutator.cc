#include "mutator.h"
#include "corpus.h"
#include "log.h"

#include <cstring>
#include <deque>

#ifdef TAINT_EN
TaintMutator::TaintMutator(Corpus *corpus){
    this->acc_output.init();
    this->corpus = corpus;
    this->init();
}

void TaintMutator::init(){
    this->done = false;
    this->candidate_score = 0;
    this->candidate_weight = 0;
    this->ini_candidate_weight = 0;
    this->taint_idx = 0;
    this->n_untainted_bits = 0; // keep track of the number of taint bits we flipped to 0
}

void TaintMutator::reduce(Queue *q){
    size_t n_tainted_bits = 0;

    q->clear_accumulated_output();
    q->clear_tb_outputs();
    assert(q->outputs.size() ==0);

    for(auto &inp: q->inputs){
        for(int i=0; i<N_TAINT_INPUTS_b32; i++){
            for(int j=0; j<32; j++){
                if(inp->taints[i] & (1<<j)){ // bit is tainted
                    if(n_tainted_bits+this->n_untainted_bits == this->taint_idx){
                        this->taint_idx++;
                        if(this->taint_idx == this->ini_candidate_weight-1) this->done = true;
                        inp->taints[i] &= ~((uint32_t )(1<<j)); // try untainting this one
                        this->n_untainted_bits ++;
                        return;
                    }
                    n_tainted_bits ++;
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

bool TaintMutator::check_weight(){
    if(this->candidate_weight <= MAX_CANDIDATE_WEIGHT){
       return true;
    }
    return false;
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
    this->remove_candidate(this->candidate); // remove from candidate list
}

void TaintMutator::remove_candidate(Queue *candidate){
    std::vector<Queue *>::iterator q = this->io_taint_vecs.begin();
    while(q != this->io_taint_vecs.end()){
        if((*q)->is_equal(candidate)){
            q = this->io_taint_vecs.erase(q);  
            return;
        }
        ++q;
    }
    assert(false);
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
        inp->check();
        for(int i=0; i<N_TAINT_INPUTS_b32; i++){
            this->candidate_weight += __builtin_popcount(inp->taints[i]);
        }
    }
    assert(this->candidate_weight < MAX_CANDIDATE_WEIGHT);
    this->n_permutations = 1<<this->candidate_weight;
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
    if(this->max == 0) this->done=true;
    else this->done = false;
    this->idx = -1;
    this->prev_taint_buf = nullptr;
}

void Mutator::print(){
    std::cout << "Running mutator " << this->name << ": max:" << this->max << "\n";
}

bool Mutator::is_done(){
    return this->done;
}

void Mutator::set_max(size_t max){
    this->max = max;
}

Queue *Mutator::apply_next(Queue *in_q){
    this->next();
    return this->apply(in_q);
}

#ifndef TAINT_EN
Queue *Mutator::apply(Queue *in_q) { // flip a bit in input but just copy taints for now
    assert(in_q->size());
    size_t input_size = in_q->inputs.size() * N_FUZZ_INPUTS_b32 * sizeof(uint32_t); // total number of bytes 
    uint8_t *inp_buf = (uint8_t *) malloc(input_size);
    for(int i=0; i<in_q->inputs.size(); i++){ // copy all inputs in queue to contigous memory
        memcpy(inp_buf + i * N_FUZZ_INPUTS_b32 * sizeof(uint32_t), in_q->inputs[i]->inputs,  N_FUZZ_INPUTS_b32 * sizeof(uint32_t));
    }
    this->permute(inp_buf);
    Queue *out_q = new_queue(in_q);
    out_q->mutator = std::string(this->name);
    for(int i=0; i<in_q->inputs.size(); i++){
        dinput_t *new_input = (dinput_t *) malloc(sizeof(dinput_t));
        memcpy(new_input->inputs, inp_buf + i * N_FUZZ_INPUTS_b32 * sizeof(uint32_t),  N_FUZZ_INPUTS_b32 * sizeof(uint32_t));
        new_input->clean();
        out_q->push_tb_input(new_input);
    }
    free(inp_buf);
    assert(out_q->size());
    return out_q;
}
#else

Queue *Mutator::apply(Queue *in_q) { // only apply mutator to tainted bits
    assert(in_q->size());
    assert(N_FUZZ_INPUTS_b32 == N_TAINT_INPUTS_b32);

    size_t input_size = in_q->inputs.size() * N_FUZZ_INPUTS_b32 * sizeof(uint32_t); // total number of bytes 
    uint8_t *inp_buf = (uint8_t *) malloc(input_size);
    for(int i=0; i<in_q->inputs.size(); i++){ // copy all inputs in queue to contigous memory
        memcpy(inp_buf + i * N_FUZZ_INPUTS_b32 * sizeof(uint32_t), in_q->inputs[i]->inputs,  N_FUZZ_INPUTS_b32 * sizeof(uint32_t));
    }

    size_t taint_size = in_q->inputs.size() * N_TAINT_INPUTS_b32 * sizeof(uint32_t); // total number of bytes 
    uint8_t *taint_buf = (uint8_t *) malloc(taint_size);
    for(int i=0; i<in_q->inputs.size(); i++){ // copy all taints in queue to contigous memory
        memcpy(taint_buf + i * N_TAINT_INPUTS_b32 * sizeof(uint32_t), in_q->inputs[i]->taints,  N_TAINT_INPUTS_b32 * sizeof(uint32_t));
    }


    assert(taint_size == input_size);
    size_t taint_idx = 0;
    size_t inp_t_size = b8(in_q->compute_input_hw());
    uint8_t *inp_t_buf = (uint8_t *) calloc(inp_t_size, sizeof(uint8_t)); // buffer that only holds tainted input bits 
    for(int i=0; i<taint_size; i++){
        for(int j=0; j<8; j++){
            if(taint_buf[i] & (1<<j)){ // taint_idx>>3 to get byte pos, j selects bit, taint_idx&7 selects lower 3 bit i.e. shift within byte
                inp_t_buf[taint_idx>>3] |= ((inp_buf[i]  & (1<<j))>>j)<<(taint_idx&7);
                taint_idx++;
            }
        }
    }



    this->permute(inp_t_buf);

    taint_idx = 0;
    for(int i=0; i<taint_size; i++){ // is this shift madness going to work? Or is it just phantasy?
        for(int j=0; j<8; j++){
            if(taint_buf[i] & (1<<j)){ // taint_idx>>3 to get byte pos, j selects bit, taint_idx&7 selects lower 3 bit i.e. shift within byte
                inp_buf[i] = (inp_t_buf[taint_idx>>3] & (1<<(taint_idx & 7)))>>(taint_idx & 7)<<j |   (inp_buf[i] & ~(1<< j));
                taint_idx++;
            }
        }
    }

    uint8_t *taint_t_buf = (uint8_t *) calloc(inp_t_size, sizeof(uint8_t)); // buffer that only holds tainted input bits 
    std::fill_n(taint_t_buf,inp_t_size,-1);
    this->permute_taints(taint_t_buf);

    // store taints so we can reverse them

    if(this->prev_taint_buf != nullptr) free(this->prev_taint_buf);
    this->prev_taint_buf = (uint8_t *) malloc(taint_size);
    memcpy(this->prev_taint_buf, taint_buf, taint_size);


    taint_idx = 0;
    for(int i=0; i<taint_size; i++){ // is this shift madness going to work? Or is it just phantasy?
        for(int j=0; j<8; j++){
            if(taint_buf[i] & (1<<j)){ // taint_idx>>3 to get byte pos, j selects bit, taint_idx&7 selects lower 3 bit i.e. shift within byte
                taint_buf[i] = (taint_t_buf[taint_idx>>3] & (1<<(taint_idx & 7)))>>(taint_idx & 7)<<j | (taint_buf[i] & ~(1<< j));
                taint_idx++;
            }
        }
    }

    Queue *out_q = new_queue(in_q);
    out_q->mutator = std::string(this->name);
    
    for(int i=0; i<in_q->inputs.size(); i++){
        dinput_t *new_input = (dinput_t *) malloc(sizeof(dinput_t));
        memcpy(new_input->inputs, inp_buf + i * N_FUZZ_INPUTS_b32 * sizeof(uint32_t),  N_FUZZ_INPUTS_b32 * sizeof(uint32_t));
        memcpy(new_input->taints, taint_buf + i * N_TAINT_INPUTS_b32 * sizeof(uint32_t),  N_TAINT_INPUTS_b32 * sizeof(uint32_t));
        new_input->clean();
        out_q->push_tb_input(new_input);
    }
    assert(inp_buf != nullptr);
    free(inp_buf);
    assert(taint_buf != nullptr);
    free(taint_buf);
    assert(inp_t_buf != nullptr);
    free(inp_t_buf);
    assert(taint_t_buf != nullptr);
    free(taint_t_buf);
    assert(out_q->size());
    out_q->recompute_input_hw();
    return out_q;
}

void Mutator::revert_taints(Queue *in_q){
    assert(this->prev_taint_buf != nullptr);
    for(int i=0; i<in_q->inputs.size(); i++){
        memcpy(in_q->inputs[i]->taints, this->prev_taint_buf + i * N_TAINT_INPUTS_b32 * sizeof(uint32_t),  N_TAINT_INPUTS_b32 * sizeof(uint32_t));
    }
}
#endif // TAINT_EN

void DetMutator::next(){
            assert(!this->done);
            size_t i = this->idx;
            this->idx++;
            if(this->idx == this->max) this->done=true;
}

void RandMutator::next(){
            assert(!this->done);
            assert(this->max);
            this->idx = rand()%(this->max);
            // std::cout << "idx: " << this->idx << std::endl;
            this->done=true;
}

void EndlessMutator::next(){
            return;
}

void SingleBitFlipMutator::permute(uint8_t *buf){
    FLIP_BIT(buf, this->idx);
}

#ifdef TAINT_EN
void SingleBitFlipMutator::permute_taints(uint8_t *buf){
    #ifndef EN_SBITFLIP_TAINT_MUT
    return;
    #endif
    if(this->idx==0) return;
    FLIP_BIT(buf, this->idx-1);
}
#endif

void DoubleBitFlipMutator::permute(uint8_t *buf){
    FLIP_BIT(buf, this->idx);
    FLIP_BIT(buf, this->idx+1);
}


#ifdef TAINT_EN
void DoubleBitFlipMutator::permute_taints(uint8_t *buf){ 
    #ifndef EN_DBITFLIP_TAINT_MUT
    return;
    #endif
    if(this->idx<2) return;
    FLIP_BIT(buf, this->idx-1);
    FLIP_BIT(buf, this->idx-2);

}
#endif


void NibbleFlipMutator::permute(uint8_t *buf){
    FLIP_BIT(buf, this->idx);
    FLIP_BIT(buf, this->idx+1);
    FLIP_BIT(buf, this->idx+2);
    FLIP_BIT(buf, this->idx+3);
}

#ifdef TAINT_EN
void NibbleFlipMutator::permute_taints(uint8_t *buf){ 
    #ifndef EN_QBITFLIP_TAINT_MUT
    return;
    #endif
    if(this->idx<4) return;
    FLIP_BIT(buf, this->idx-1);
    FLIP_BIT(buf, this->idx-2);
    FLIP_BIT(buf, this->idx-3);
    FLIP_BIT(buf, this->idx-4);
}
#endif

void SingleByteFlipMutator::permute(uint8_t *buf){
    buf[this->idx] ^= 0xFF;
}

#ifdef TAINT_EN
void SingleByteFlipMutator::permute_taints(uint8_t *buf){ 
    #ifndef EN_SBYTEFLIP_TAINT_MUT
    return;
    #endif
    if(this->idx<1) return;
    buf[this->idx-1] &= 0x00;
}
#endif


void DoubleByteFlipMutator::permute(uint8_t *buf){
    buf[this->idx] ^= 0xFF;
    buf[this->idx+1] ^= 0xFF;
}

#ifdef TAINT_EN
void DoubleByteFlipMutator::permute_taints(uint8_t *buf){ 
    #ifndef EN_DBYTEFLIP_TAINT_MUT
    return;
    #endif
    if(this->idx<2) return;
    buf[this->idx-1] &= 0x00;
    buf[this->idx-2] &= 0x00;
}
#endif


void QuadByteFlipMutator::permute(uint8_t *buf){
    buf[this->idx] ^= 0xFF;
    buf[this->idx+1] ^= 0xFF;
    buf[this->idx+2] ^= 0xFF;
    buf[this->idx+3] ^= 0xFF;

}

#ifdef TAINT_EN
void QuadByteFlipMutator::permute_taints(uint8_t *buf){ 
    #ifndef EN_QBYTEFLIP_TAINT_MUT
    return;
    #endif
    if(this->idx<4) return;
    buf[this->idx-1] &= 0x00;
    buf[this->idx-2] &= 0x00;
    buf[this->idx-3] &= 0x00;
    buf[this->idx-4] &= 0x00;

}
#endif


void AddSingleByteMutator::permute(uint8_t *buf){
    uint8_t rand_v = rand()% 35; // [0,35] as in rfuzz paper
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
    if(!this->max/2) return; // TODO kinda hacky
    size_t n_bytes = rand()%(this->max/2);
    assert(this->max-n_bytes);
    size_t src_idx = rand()%(this->max-n_bytes);
    size_t dst_idx = rand()%(this->max-n_bytes);
    memcpy(&buf[dst_idx], &buf[src_idx], n_bytes);
}

void OverwriteRandomBytesMutator::permute(uint8_t *buf){
    if(!this->max) return;  // TODO also hacky...
    if(!this->max-1) return;  // TODO also hacky...
    size_t n_bytes = rand()%this->max;
    for(int i=0; i<n_bytes; i++){
        buf[(this->idx+i)%(this->max-1)] = rand()%255;
    }
}
#ifdef TAINT_EN
void RandomMutator::permute(uint8_t *buf){
    for(int i=0; i<this->max; i++){
        buf[i] = rand()%MAX_b8_VAL;
    }
}

void RandomMutator::permute_taints(uint8_t *buf){
    return;
}
#endif

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










    
