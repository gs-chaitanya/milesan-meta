#ifndef MUTATOR_H
#define MUTATOR_H
#include <vector>

#include "afl.h"
#include "queue.h"
#include "corpus.h"
#include "log.h"

#define N_DET_MUTATORS 9
#define N_RAND_MUTATORS 11

#define EN_SBITFLIP_TAINT_MUT
#define EN_DBITFLIP_TAINT_MUT
#define EN_QBITFLIP_TAINT_MUT
#define EN_SBYTEFLIP_TAINT_MUT
#define EN_DBYTEFLIP_TAINT_MUT
#define EN_QBYTEFLIP_TAINT_MUT

//*** TAINT MUTATOR *** 
#ifdef TAINT_EN
class TaintMutator{
    public: 
        std::vector<Queue *> io_taint_vecs; // store the queues because they contain f(inputs):input taints -> output taints
        Queue *candidate;
        size_t candidate_score;
        size_t candidate_weight;
        size_t ini_candidate_weight;
        doutput_t acc_output;
        bool done;
        Corpus *corpus;
        size_t taint_idx = 0;
        size_t n_untainted_bits;

        
        TaintMutator(Corpus *corpus);        
        void reduce(Queue *q);
        void add_io_taint_vec(Queue *q);
        void filter_taint_vecs();
        void find_candidate();
        void remove_candidate(Queue *candidate);
        bool check_good(Queue *q);
        void set_new_candidate(Queue *q);
        bool is_done();
        bool check_weight();
        void init();

};

class TaintBruteForceMutator{ // this mutator just brute forces all input permutations of the candidate that differ only in the tainted bits
    public:
        bool done;
        Queue *candidate;
        size_t n_permutations;
        size_t candidate_weight;
        size_t permutation_idx;
        TaintBruteForceMutator(Queue *candidate);
        bool is_done();
        Queue *apply_next(Queue *q);

};
#endif

//*** INPUT MUTATORS ***

class Mutator{
    public:
        size_t idx;
        bool done;
        size_t max;
        const char* name;
        uint8_t *prev_taint_buf;

        bool is_done();
        void init();
        virtual void next() {return;};
        Queue *apply(Queue *in_q);
        virtual void permute(uint8_t *buf) {return;};
        #ifdef TAINT_EN
        virtual void permute_taints(uint8_t *buf){return;};
        void revert_taints(Queue *in_q);
        #endif
        Queue *apply_next(Queue *in_q);
        void print();
        void set_max(size_t max);
        ~Mutator(){
            if(prev_taint_buf != nullptr){
                free(prev_taint_buf);
            }
        }
};

class DetMutator: public virtual Mutator{
    public:
        void next() override;
};

class RandMutator: public virtual Mutator{
    public:
        void next() override;
};

class EndlessMutator: public virtual Mutator{
    public:
        void next() override;
};

//*** SINGLE BIT FLIP MUTATOR ***

class SingleBitFlipMutator: public virtual Mutator{
    public:
        SingleBitFlipMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max)*8;
            if(max_b8>1) this->max = max_b8 - 1; // at some points the HW might be smaller than 32 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 - 1;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf);
        #endif
};

class DetSingleBitFlipMutator: public DetMutator, public SingleBitFlipMutator{
    public:
        DetSingleBitFlipMutator(size_t max): SingleBitFlipMutator(max, "det bitflip 1/1"){
        }
};

class RandSingleBitFlipMutator: public RandMutator, public SingleBitFlipMutator{
    public:
        RandSingleBitFlipMutator(size_t max): SingleBitFlipMutator(max, "rand bitflip 1/1"){
        }
};

//*** DoubleByte BIT FLIP MUTATOR ***

class DoubleBitFlipMutator: public virtual Mutator{
    public:
        DoubleBitFlipMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max)*8;
            if(max_b8>2) this->max = max_b8 - 2; // at some points the HW might be smaller than 2 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 - 2;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf);
        #endif
};

class DetDoubleBitFlipMutator: public DetMutator, public DoubleBitFlipMutator{
    public:
        DetDoubleBitFlipMutator(size_t max): DoubleBitFlipMutator(max, "det bitflip 2/1"){
        }
};

class RandDoubleBitFlipMutator: public RandMutator, public DoubleBitFlipMutator{
    public:
        RandDoubleBitFlipMutator(size_t max): DoubleBitFlipMutator(max, "rand bitflip 2/1"){
        }
};

//*** NIBBLE FLIP MUTATOR ***

class NibbleFlipMutator: public virtual Mutator{
    public:
        NibbleFlipMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max)*8;
            if(max_b8>4) this->max = max_b8 - 4; // at some points the HW might be smaller than 4 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 - 4;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf);
        #endif
};

class DetNibbleFlipMutator: public DetMutator, public NibbleFlipMutator{
    public:
        DetNibbleFlipMutator(size_t max): NibbleFlipMutator(max, "det bitflip 4/1"){
        }
};

class RandNibbleFlipMutator: public RandMutator, public NibbleFlipMutator{
    public:
        RandNibbleFlipMutator(size_t max): NibbleFlipMutator(max, "rand bitflip 4/1"){
        }
};

//*** SINGLE BYTE FLIP MUTATOR ***

class SingleByteFlipMutator: public virtual Mutator{
    public:
        SingleByteFlipMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>1) this->max = max_b8 - 1; // at some points the HW might be smaller than 32 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 1;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf);
        #endif
};

class DetSingleByteFlipMutator: public DetMutator, public SingleByteFlipMutator{
    public:
        DetSingleByteFlipMutator(size_t max): SingleByteFlipMutator(max, "det bitflip 8/8"){
        }
};

class RandSingleByteFlipMutator: public RandMutator, public SingleByteFlipMutator{
    public:
        RandSingleByteFlipMutator(size_t max): SingleByteFlipMutator(max, "rand bitflip 8/8"){
        }
};

//***  DOUBLE BYTE FLIP MUTATOR ***

class DoubleByteFlipMutator: public virtual Mutator{
    public:
        DoubleByteFlipMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>2) this->max = max_b8 - 2; // at some points the HW might be smaller than 32 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 2;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf);
        #endif

};

class DetDoubleByteFlipMutator: public DetMutator, public DoubleByteFlipMutator{
    public:
        DetDoubleByteFlipMutator(size_t max): DoubleByteFlipMutator(max, "det bitflip 16/8"){
        }
};

class RandDoubleByteFlipMutator: public RandMutator, public DoubleByteFlipMutator{
    public:
        RandDoubleByteFlipMutator(size_t max): DoubleByteFlipMutator(max, "rand bitflip 16/8"){
        }
};

//***  QUAD BYTE FLIP MUTATOR ***

class QuadByteFlipMutator: public virtual Mutator{
    public:
        QuadByteFlipMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>4) this->max = max_b8 - 4; // at some points the HW might be smaller than 32 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 4;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf);
        #endif
};

class DetQuadByteFlipMutator: public DetMutator, public QuadByteFlipMutator{
    public:
        DetQuadByteFlipMutator(size_t max): QuadByteFlipMutator(max, "det bitflip 32/8"){
        }
};

class RandQuadByteFlipMutator: public RandMutator, public QuadByteFlipMutator{
    public:
        RandQuadByteFlipMutator(size_t max): QuadByteFlipMutator(max, "rand bitflip 32/8"){
        }
};

//***  ADD SINGLE BYTE MUTATOR ***

class AddSingleByteMutator: public virtual Mutator{
    public:
        AddSingleByteMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>1) this->max = max_b8 - 1; // at some points the HW might be smaller than 32 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 1;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class DetAddSingleByteMutator: public DetMutator, public AddSingleByteMutator{
    public:
        DetAddSingleByteMutator(size_t max): AddSingleByteMutator(max, "det arith 8/8"){
        }
};

class RandAddSingleByteMutator: public RandMutator, public AddSingleByteMutator{
    public:
        RandAddSingleByteMutator(size_t max): AddSingleByteMutator(max, "rand arith 8/8"){
        }
};

//***  ADD DOUBLE BYTE MUTATOR ***

class AddDoubleByteMutator: public virtual Mutator{
    public:
        AddDoubleByteMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>2) this->max = max_b8 - 2; // at some points the HW might be smaller than 32 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 2;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class DetAddDoubleByteMutator: public DetMutator, public AddDoubleByteMutator{
    public:
        DetAddDoubleByteMutator(size_t max): AddDoubleByteMutator(max, "det arith 16/8"){
        }
};

class RandAddDoubleByteMutator: public RandMutator, public AddDoubleByteMutator{
    public:
        RandAddDoubleByteMutator(size_t max): AddDoubleByteMutator(max, "rand arith 16/8"){
        }
};


//***  ADD QUAD BYTE MUTATOR ***

class AddQuadByteMutator: public virtual Mutator{
    public:
        AddQuadByteMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>4) this->max = max_b8 - 4;
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 4;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class DetAddQuadByteMutator: public DetMutator, public AddQuadByteMutator{
    public:
        DetAddQuadByteMutator(size_t max): AddQuadByteMutator(max, "det arith 32/8"){
        }
};

class RandAddQuadByteMutator: public RandMutator, public AddQuadByteMutator{
    public:
        RandAddQuadByteMutator(size_t max): AddQuadByteMutator(max, "rand arith 32/8"){
        }
};

//***  OVERWRITE INTERESTING BYTE MUTATOR ***

class OverwriteInterestingSingleByteMutator: public virtual Mutator{
    public:
        OverwriteInterestingSingleByteMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>1) this->max = max_b8 - 1; // at some points the HW might be smaller than 8 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 1;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class DetOverwriteInterestingSingleByteMutator: public DetMutator, public OverwriteInterestingSingleByteMutator{
    public:
        DetOverwriteInterestingSingleByteMutator(size_t max): OverwriteInterestingSingleByteMutator(max, "det interest 8"){
        }
};

class RandOverwriteInterestingSingleByteMutator: public RandMutator, public OverwriteInterestingSingleByteMutator{
    public:
        RandOverwriteInterestingSingleByteMutator(size_t max): OverwriteInterestingSingleByteMutator(max, "rand interest 8"){
        }
};


//***  OVERWRITE INTERESTING DOUBLE BYTE MUTATOR ***

class OverwriteInterestingDoubleByteMutator: public virtual Mutator{
    public:
        OverwriteInterestingDoubleByteMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>2) this->max = max_b8 - 2; // at some points the HW might be smaller than 8 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 2;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class DetOverwriteInterestingDoubleByteMutator: public DetMutator, public OverwriteInterestingDoubleByteMutator{
    public:
        DetOverwriteInterestingDoubleByteMutator(size_t max): OverwriteInterestingDoubleByteMutator(max, "det interest 16"){
        }
};

class RandOverwriteInterestingDoubleByteMutator: public RandMutator, public OverwriteInterestingDoubleByteMutator{
    public:
        RandOverwriteInterestingDoubleByteMutator(size_t max): OverwriteInterestingDoubleByteMutator(max, "rand interest 16"){
        }
};


//***  OVERWRITE INTERESTING QUAD BYTE MUTATOR ***

class OverwriteInterestingQuadByteMutator: public virtual Mutator{
    public:
        OverwriteInterestingQuadByteMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>4) this->max = max_b8 - 4; // at some points the HW might be smaller than 8 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 4;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class DetOverwriteInterestingQuadByteMutator: public DetMutator, public OverwriteInterestingQuadByteMutator{
    public:
        DetOverwriteInterestingQuadByteMutator(size_t max): OverwriteInterestingQuadByteMutator(max, "det interest 32"){
        }
};

class RandOverwriteInterestingQuadByteMutator: public RandMutator, public OverwriteInterestingQuadByteMutator{
    public:
        RandOverwriteInterestingQuadByteMutator(size_t max): OverwriteInterestingQuadByteMutator(max, "rand interest 32"){
        }
};

//***  OVERWRITE WITH RANDOM BYTE MUTATOR ***

class OverwriteRandomByteMutator: public virtual Mutator{
    public:
        OverwriteRandomByteMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>1) this->max = max_b8 - 1; // at some points the HW might be smaller than 8 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 1;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class DetOverwriteRandomByteMutator: public DetMutator, public OverwriteRandomByteMutator{
    public:
        DetOverwriteRandomByteMutator(size_t max): OverwriteRandomByteMutator(max, "det random 8"){
        }
};

class RandOverwriteRandomByteMutator: public RandMutator, public OverwriteRandomByteMutator{
    public:
        RandOverwriteRandomByteMutator(size_t max): OverwriteRandomByteMutator(max, "rand random 8"){
        }
};

//***  DELETE RANDOM BYTES MUTATOR ***

class DeleteRandomBytesMutator: public virtual Mutator{
    public:
        DeleteRandomBytesMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>1) this->max = max_b8 - 1; // at some points the HW might be smaller than 8 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 1;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class RandDeleteRandomBytesMutator: public RandMutator, public DeleteRandomBytesMutator{
    public:
        RandDeleteRandomBytesMutator(size_t max): DeleteRandomBytesMutator(max, "delete"){
        }
};


//***  CLONE RANDOM BYTES MUTATOR ***

class CloneRandomBytesMutator: public virtual Mutator{
    public:
        CloneRandomBytesMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>1) this->max = max_b8 - 1; // at some points the HW might be smaller than 8 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 1;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class RandCloneRandomBytesMutator: public RandMutator, public CloneRandomBytesMutator{
    public:
        RandCloneRandomBytesMutator(size_t max): CloneRandomBytesMutator(max, "clone"){
        }
};


//***  OVERWRITE RANDOM BYTES MUTATOR ***

class OverwriteRandomBytesMutator: public virtual Mutator{
    public:
        OverwriteRandomBytesMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            if(max_b8>1) this->max = max_b8 - 1; // at some points the HW might be smaller than 8 so we cant mutate then
            else this->max = 0;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8 - 1;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class RandOverwriteRandomBytesMutator: public RandMutator, public OverwriteRandomBytesMutator{
    public:
        RandOverwriteRandomBytesMutator(size_t max): OverwriteRandomBytesMutator(max, "overwrite"){
        }
};

class RandomMutator: public virtual Mutator{
    public:
        RandomMutator(size_t max, const char *name){
            #ifdef TAINT_EN // max is taint hamming weight
            int max_b8 = b8(max);
            this->max =  max_b8;
            #else // max is total number of bits
            this->max = max * N_FUZZ_INPUTS_b32 * 32 / 8;
            #endif
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf);
        #endif
};

class EndlessRandomMutator: public EndlessMutator, public RandomMutator{
    public: 
        EndlessRandomMutator(size_t max): RandomMutator(max, "endless random"){};
};



std::deque<Mutator *> *get_det_mutators(size_t max);
std::deque<Mutator *> *get_rand_mutators(size_t max);
std::deque<Mutator *> *get_all_mutators(size_t max);

#endif // MUTATOR_H