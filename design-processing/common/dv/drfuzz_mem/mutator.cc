#include "mutator.h"
#include "corpus.h"
#include "log.h"

#include <cstring>
#include <deque>


void Mutator::init(){
    if(this->max_idx <= 0) this->done=true;
    else this->done = false;
    this->idx = -1;
    // this->prev_taint_buf = nullptr;
}

void Mutator::print(){
    std::cout << "Running mutator " << this->name << ", max_idx: " << this->max_idx << std::endl;
}

bool Mutator::is_done(){
    return this->done;
}

void Mutator::set_max(size_t n_bits){
    this->max_idx = n_bits;
}

size_t Mutator::idx_to_array_pos(size_t idx){
    size_t r;
    if(this->tail_b8) r = idx < this->n_bits_b8-8 ? idx : idx+8-this->tail_b8;
    else r = idx;
    // std::cout << "index " << std::dec << r << "/" << this->max_idx<<  std::endl;
    return r; 
}

Queue *Mutator::apply_next(Queue *in_q){
    this->next();
    return this->apply(in_q);
}


Queue *Mutator::apply(Queue *in_q) { // only apply mutator to tainted bits
    assert(in_q->instructions.size());

    size_t n_instructions = in_q->instructions.size();

    size_t nbytes_instructions = n_instructions * N_BYTES_PER_INST; // total number of bytes 
    uint8_t *inp_buf = (uint8_t *) malloc(nbytes_instructions);
    for(int i=0; i<n_instructions; i++){ // copy all instructions in queue to contigous memory
        *((uint32_t *)(inp_buf + i * N_BYTES_PER_INST)) = in_q->instructions[i]->get_binary();
        // std::cout << std::hex << *((uint32_t *)(inp_buf + i * N_BYTES_PER_INST)) << std::endl;
    }

    size_t taint_size = n_instructions * N_BYTES_PER_INST; // total number of bytes 
    uint8_t *taint_buf = (uint8_t *) malloc(taint_size);
    for(int i=0; i<n_instructions; i++){ // copy all taints in queue to contigous memory
        *((uint32_t *)(taint_buf + i * N_BYTES_PER_INST)) = in_q->instructions[i]->get_binary_t0();
        // std::cout << std::hex << *((uint32_t *)(taint_buf + i * N_BYTES_PER_INST)) << std::endl;
    }
    assert(taint_size == nbytes_instructions);
    size_t taint_idx = 0;
    size_t inst_taint_hw = in_q->compute_inst_taint_hw();
    assert(inst_taint_hw != 0);
    size_t inp_t_size = b8(inst_taint_hw);
    uint8_t *inp_t_buf = (uint8_t *) calloc(inp_t_size, sizeof(uint8_t)); // buffer that only holds tainted instruction bits, TODO rewrite to simpler expression
    for(int i=0; i<taint_size; i++){
        int n_bits = 8;
        for(int j=0; j<n_bits; j++){
            if(taint_buf[i] & (1<<j)){ // taint_idx>>3 to get byte pos, j selects bit, taint_idx&7 selects lower 3 bit i.e. shift within byte
                inp_t_buf[taint_idx>>3] |= ((inp_buf[i]  & (1<<j))>>j)<<(taint_idx&7);
                taint_idx++;
            }
        }
    }

    
    // std::cout << std::endl;
    this->permute(inp_t_buf);
    // for(int i=0; i<inp_t_size; i++){
    //     for(int j=7; j>=0; j--) std::cout << ((inp_t_buf[i]&(1<<j))>>j);
    //     // std::cout << std::hex << inp_t_buf[i];
    // }
    // std::cout << std::endl;

    taint_idx = 0;
    for(int i=0; i<taint_size; i++){ // is this shift madness going to work? Or is it just fantasy?
        for(int j=0; j<8; j++){
            if(taint_buf[i] & (1<<j)){ // taint_idx>>3 to get byte pos, j selects bit, taint_idx&7 selects lower 3 bit i.e. shift within byte
                inp_buf[i] = (inp_t_buf[taint_idx>>3] & (1<<(taint_idx & 7)))>>(taint_idx & 7)<<j |   (inp_buf[i] & ~(1<< j));
                taint_idx++;
            }
        }
    }

    // store taints so we can reverse them

    // if(this->prev_taint_buf != nullptr) free(this->prev_taint_buf);
    // this->prev_taint_buf = (uint8_t *) malloc(taint_size);
    // memcpy(this->prev_taint_buf, taint_buf, taint_size);

    uint8_t *taint_t_buf = (uint8_t *) calloc(inp_t_size, sizeof(uint8_t)); 
    std::fill_n(taint_t_buf,inp_t_size,-1);
    // taint_t_buf[inp_t_size-1] &= ~(0xff<<remainder); // mask out the 8-remainder bits, note the lsb is at position 0 within the byte
    #ifdef TAINT_EN
    this->permute_taints(taint_t_buf);
    #endif

    taint_idx = 0;
    for(int i=0; i<taint_size; i++){ // is this shift madness going to work? Or is it just phantasy?
        for(int j=0; j<8; j++){
            if(taint_buf[i] & (1<<j)){ // taint_idx>>3 to get byte pos, j selects bit, taint_idx&7 selects lower 3 bit i.e. shift within byte
                taint_buf[i] = (taint_t_buf[taint_idx>>3] & (1<<(taint_idx & 7)))>>(taint_idx & 7)<<j | (taint_buf[i] & ~(1<< j));
                taint_idx++;
            }
        }
    }

    Queue *out_q = new_queue(in_q,false);
    out_q->mutator = std::string(this->name);

    for(int i=0; i<n_instructions; i++){
        uint32_t bin = *((uint32_t *)(inp_buf + i * N_BYTES_PER_INST));
        uint32_t bin_t0 =  *((uint32_t *)(taint_buf + i * N_BYTES_PER_INST));
        Instruction *new_inst = in_q->instructions[i]->copy();
        new_inst->set_binary(bin);
        new_inst->set_binary_t0(bin_t0);
        out_q->push_tb_instruction(new_inst);
    }
    assert(inp_buf != nullptr);
    free(inp_buf);
    assert(taint_buf != nullptr);
    free(taint_buf);
    assert(inp_t_buf != nullptr);
    free(inp_t_buf);
    assert(taint_t_buf != nullptr);
    free(taint_t_buf);
    assert(out_q->instructions.size() == in_q->instructions.size());
    out_q->recompute_inst_taint_hw();
    return out_q;
}

void DetMutator::next(){
            assert(!this->done);
            this->idx++;
            // std::cout << "IDX: " << std::dec << this->idx << "/" << this->max_idx << std::endl;
            assert(this->idx <= this->max_idx);
            if(this->idx == this->max_idx) this->done=true;
}

void RandMutator::next(){
            assert(!this->done);
            assert(this->max_idx);
            this->idx = rand()%(this->max_idx);
            // std::cout << "idx: " << this->idx << std::endl;
            this->done=true;
}

void EndlessMutator::next(){
    return;
}

void SingleBitFlipMutator::permute(uint8_t *buf){
    // std::cout << "permuting " << std::dec << this->idx << std::endl;
    FLIP_BIT(buf, this->idx_to_array_pos(this->idx));
}

#ifdef TAINT_EN
void SingleBitFlipMutator::permute_taints(uint8_t *buf){
    #ifndef EN_SBITFLIP_TAINT_MUT
    return;
    #endif
    if(this->idx==0) return;
    // std::cout << "permuting " << std::dec << this->idx-1 << std::endl;
    FLIP_BIT(buf, this->idx_to_array_pos(this->idx-1));
}
#endif

void DoubleBitFlipMutator::permute(uint8_t *buf){
    FLIP_BIT(buf, this->idx_to_array_pos(this->idx));
    FLIP_BIT(buf, this->idx_to_array_pos(this->idx+1));
}


#ifdef TAINT_EN
void DoubleBitFlipMutator::permute_taints(uint8_t *buf){ 
    #ifndef EN_DBITFLIP_TAINT_MUT
    return;
    #endif
    for(int i=0; i<this->idx & i<2; i++){
        FLIP_BIT(buf, this->idx_to_array_pos(this->idx-i-1));
    }
}
#endif


void NibbleFlipMutator::permute(uint8_t *buf){
    for(int i=0; i<4; i++) FLIP_BIT(buf,this->idx_to_array_pos(this->idx+i));
}

#ifdef TAINT_EN
void NibbleFlipMutator::permute_taints(uint8_t *buf){ 
    #ifndef EN_QBITFLIP_TAINT_MUT
    return;
    #endif
    for(int i=0; i<this->idx && i<4; i++) FLIP_BIT(buf,this->idx_to_array_pos(this->idx-i-1));
}
#endif

// void SingleByteFlipMutator::permute(uint8_t *buf){
//     buf[this->idx_to_array_pos(this->idx)] ^= 0xFF;
// }

// #ifdef TAINT_EN
// void SingleByteFlipMutator::permute_taints(uint8_t *buf){ 
//     #ifndef EN_SBYTEFLIP_TAINT_MUT
//     return;
//     #endif
//     if(this->idx<1) return;
//     buf[this->idx_to_array_pos(this->idx-1)] &= 0x00;
// }
// #endif


// void DoubleByteFlipMutator::permute(uint8_t *buf){
//     buf[this->idx] ^= 0xFF;
//     buf[this->idx+1] ^= 0xFF;
// }

// #ifdef TAINT_EN
// void DoubleByteFlipMutator::permute_taints(uint8_t *buf){ 
//     #ifndef EN_DBYTEFLIP_TAINT_MUT
//     return;
//     #endif
//     if(this->idx<2) return;
//     buf[this->idx-1] &= 0x00;
//     buf[this->idx-2] &= 0x00;
// }
// #endif


// void QuadByteFlipMutator::permute(uint8_t *buf){
//     buf[this->idx] ^= 0xFF;
//     buf[this->idx+1] ^= 0xFF;
//     buf[this->idx+2] ^= 0xFF;
//     buf[this->idx+3] ^= 0xFF;

// }

// #ifdef TAINT_EN
// void QuadByteFlipMutator::permute_taints(uint8_t *buf){ 
//     #ifndef EN_QBYTEFLIP_TAINT_MUT
//     return;
//     #endif
//     if(this->idx<4) return;
//     buf[this->idx-1] &= 0x00;
//     buf[this->idx-2] &= 0x00;
//     buf[this->idx-3] &= 0x00;
//     buf[this->idx-4] &= 0x00;

// }
// #endif


// void AddSingleByteMutator::permute(uint8_t *buf){
//     uint8_t rand_v = rand()% 35; // [0,35] as in rfuzz paper
//     if(rand()%2){
//         buf[this->idx] += rand_v;
//     }
//     else{
//         buf[this->idx] -= rand_v;
//     }
// }

// void AddDoubleByteMutator::permute(uint8_t *buf){
//     uint16_t rand_v = rand() % 35; // [0,35] as in rfuzz paper
//     switch(rand()%4){
//         case 0: 
//             buf[idx] += rand_v&0xFF;
//             buf[idx+1] += (rand_v&0xFF00)>>8;
//             break;
//         case 1: 
//             buf[idx] -= rand_v&0xFF;
//             buf[idx+1] -= (rand_v&0xFF00)>>8;
//             break;
//         case 2: 
//             rand_v = SWAP16(SWAP16(((uint16_t *) buf)[idx]) + rand_v);
//             buf[idx] = rand_v&0xFF; 
//             buf[idx+1] = (rand_v&0xFF00)>>8; 
//             break;
//         case 3: 
//             rand_v = SWAP16(SWAP16(((uint16_t *) buf)[idx]) - rand_v);
//             buf[idx] = rand_v&0xFF; 
//             buf[idx+1] = (rand_v&0xFF00)>>8;  // is this right or should idx be switched?
//             break;
//     }
// }


// void AddQuadByteMutator::permute(uint8_t *buf){
//     uint32_t rand_v = rand() % 35; // [0,35] as in rfuzz paper
//     switch(rand()%4){
//         case 0: 
//             buf[idx] += rand_v&0xFF;
//             buf[idx+1] += (rand_v&0xFF00)>>8;
//             buf[idx+2] += (rand_v&0xFF0000)>>16;
//             buf[idx+3] += (rand_v&0xFF000000)>>24;
//             break;
//         case 1: 
//             buf[idx] -= rand_v&0xFF;
//             buf[idx+1] -= (rand_v&0xFF00)>>8;
//             buf[idx+2] -= (rand_v&0xFF0000)>>16;
//             buf[idx+3] -= (rand_v&0xFF000000)>>24;
//             break;
//         case 2: 
//             rand_v = SWAP16(SWAP16(((uint16_t *) buf)[idx]) + rand_v);
//             buf[idx] = rand_v&0xFF;
//             buf[idx+1] = (rand_v&0xFF00)>>8;
//             buf[idx+2] = (rand_v&0xFF0000)>>16;
//             buf[idx+3] = (rand_v&0xFF000000)>>24;
//             break;
//         case 3: 
//             rand_v = SWAP16(SWAP16(((uint16_t *) buf)[idx]) - rand_v);
//             buf[idx] = rand_v&0xFF;
//             buf[idx+1] = (rand_v&0xFF00)>>8;
//             buf[idx+2] = (rand_v&0xFF0000)>>16;
//             buf[idx+3] = (rand_v&0xFF000000)>>24;
//             break;
//     }
// }


// void OverwriteInterestingSingleByteMutator::permute(uint8_t *buf){
//     int8_t interesting[] = {INTERESTING_8};
//     buf[this->idx] = interesting[rand() % (INTERESTING_8_LEN-1)];
// }

// void OverwriteInterestingDoubleByteMutator::permute(uint8_t *buf){
//     int16_t interesting[] = {INTERESTING_16};
//     int16_t rand_v = interesting[rand() % (INTERESTING_16_LEN-1)];
//     buf[this->idx] = rand_v&0xFF;
//     buf[this->idx+1] = (rand_v&0xFF00)>>8;
// }

// void OverwriteInterestingQuadByteMutator::permute(uint8_t *buf){
//     int32_t interesting[] = {INTERESTING_32};
//     int32_t rand_v = interesting[rand() % (INTERESTING_32_LEN-1)];
//     buf[idx] = rand_v&0xFF;
//     buf[idx+1] = (rand_v&0xFF00)>>8;
//     buf[idx+2] = (rand_v&0xFF0000)>>16;
//     buf[idx+3] = (rand_v&0xFF000000)>>24;
// }

// void OverwriteRandomByteMutator::permute(uint8_t *buf){
//     buf[this->idx] = rand()%255;
// }

// void DeleteRandomBytesMutator::permute(uint8_t *buf){
//     size_t n_bytes = rand()%this->max_idx;
//     for(int i=0; i<n_bytes; i++){
//         buf[(this->idx+i)%(this->max_idx-1)] = 0x00;
//     }
// }

// void CloneRandomBytesMutator::permute(uint8_t *buf){
//     if(!this->max_idx/2) return; // TODO kinda hacky
//     size_t n_bytes = rand()%(this->max_idx/2);
//     assert(this->max_idx-n_bytes);
//     size_t src_idx = rand()%(this->max_idx-n_bytes);
//     size_t dst_idx = rand()%(this->max_idx-n_bytes);
//     memcpy(&buf[dst_idx], &buf[src_idx], n_bytes);
// }

// void OverwriteRandomBytesMutator::permute(uint8_t *buf){
//     if(!this->max_idx) return;  // TODO also hacky...
//     if(!this->max_idx-1) return;  // TODO also hacky...
//     size_t n_bytes = rand()%this->max_idx;
//     for(int i=0; i<n_bytes; i++){
//         buf[(this->idx+i)%(this->max_idx-1)] = rand()%255;
//     }
// }
#ifdef TAINT_EN
void RandomMutator::permute(uint8_t *buf){
    for(int i=0; i<this->max_idx; i++){
        buf[i] = rand()%MAX_b8_VAL;
    }
}

void EndlessRandomMutator::permute_taints(uint8_t *buf){
    return;
}

void ReduceRandomTaintsMutator::permute_taints(uint8_t *buf){
    for(int i=0; i<this->max_idx; i++){
        buf[i] &= rand()%MAX_b8_VAL;
    }
}
#endif

void BruteForceMutator::permute(uint8_t *buf){
    *((size_t *) buf) = this->idx;
}

#ifdef TAINT_EN
void DetBruteForceMutator::permute_taints(uint8_t *buf){
    return;
}
#endif

std::deque<Mutator *> *get_det_mutators(size_t n_bits){ // adjust macros in header if number of mutarors changes
    Mutator *det_mutators[] = {
                            new DetSingleBitFlipMutator(n_bits),
                            new DetDoubleBitFlipMutator(n_bits),
                            new DetNibbleFlipMutator(n_bits)
                            // new DetSingleByteFlipMutator(n_bits),
                            // new DetDoubleByteFlipMutator(n_bits),
                            // new DetQuadByteFlipMutator(n_bits)
                            // new DetAddSingleByteMutator(n_bits),
                            // new DetAddDoubleByteMutator(n_bits),
                            // new DetAddQuadByteMutator(n_bits)
                            };

    std::deque<Mutator *> *mutators = new std::deque<Mutator *>();
    for(int i=0; i<N_DET_MUTATORS; i++){
        mutators->push_back(det_mutators[i]);
    }
    return mutators;
}

std::deque<Mutator *> *get_rand_mutators(size_t n_bits){
    Mutator *rand_mutators[] = {
                            // new RandSingleBitFlipMutator(n_bits),
                            // new RandAddSingleByteMutator(n_bits),
                            // new RandAddDoubleByteMutator(n_bits),
                            // new RandAddQuadByteMutator(n_bits),
                            // new RandOverwriteInterestingSingleByteMutator(n_bits),
                            // new RandOverwriteInterestingDoubleByteMutator(n_bits),
                            // new RandOverwriteInterestingQuadByteMutator(n_bits),
                            // new RandOverwriteRandomByteMutator(n_bits),
                            // new RandDeleteRandomBytesMutator(n_bits),
                            // new RandCloneRandomBytesMutator(n_bits)
                            // new RandOverwriteRandomBytesMutator(n_bits),
                            // new ReduceRandomTaintsMutator(n_bits)
                            };

    std::deque<Mutator *> *mutators = new std::deque<Mutator *>();
    for(int i=0; i<N_RAND_MUTATORS; i++){
        mutators->push_back(rand_mutators[i]);
    }
    return mutators;
}

std::deque<Mutator *> *get_all_mutators(size_t n_bits){
   std::deque<Mutator *> *det_mutators = get_det_mutators(n_bits);
   std::deque<Mutator *> *rand_mutators = get_rand_mutators(n_bits);
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










    
