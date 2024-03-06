#ifndef MUTATOR_H
#define MUTATOR_H
#include <vector>

#include "afl.h"
#include "queue.h"
#include "corpus.h"
#include "log.h"

#define N_DET_MUTATORS 3 // rest not implemented, probably not very useful for instruction mutations
#define N_RAND_MUTATORS 0

#define EN_SBITFLIP_TAINT_MUT
#define EN_DBITFLIP_TAINT_MUT
#define EN_QBITFLIP_TAINT_MUT
#define EN_SBYTEFLIP_TAINT_MUT
#define EN_DBYTEFLIP_TAINT_MUT
#define EN_QBYTEFLIP_TAINT_MUT

//*** INPUT MUTATORS ***

class Mutator{
    public:
        size_t idx;
        bool done;
        int max_idx;
        size_t n_bits_b8; // n_bits #mutations extended to multiple of 8
        size_t tail_b8; // if #tainted_bits not a multiple of 8 we need extra bits to store the taints in byte-array but skip those during mutation
        size_t step;
        size_t width;
        const char* name;
        // uint8_t *prev_taint_buf;

        bool is_done();
        void init();
        virtual void next() {return;};
        Queue *apply(Queue *in_q);
        virtual void permute(uint8_t *buf) {return;};
        #ifdef TAINT_EN
        virtual void permute_taints(uint8_t *buf){return;};
        // void revert_taints(Queue *new_q,Queue *prev_q);
        #endif
        Queue *apply_next(Queue *in_q);
        void print();
        void set_max(size_t n_bits);
        size_t idx_to_array_pos(size_t idx);
        // ~Mutator(){
        //     if(prev_taint_buf != nullptr){
        //         free(prev_taint_buf);
        //     }
        // }
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
        SingleBitFlipMutator(const char *name, size_t n_bits, size_t step, size_t width){
            this->max_idx = n_bits-width;
            this->n_bits_b8 = b8(n_bits)*8;
            this->tail_b8 = n_bits%8;
            this->step = step;
            this->width = width;
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
        DetSingleBitFlipMutator(size_t n_bits): SingleBitFlipMutator("det bitflip 1/1", n_bits,1,1){
        }
};

class RandSingleBitFlipMutator: public RandMutator, public SingleBitFlipMutator{
    public:
        RandSingleBitFlipMutator(size_t n_bits): SingleBitFlipMutator("rand bitflip 1/1", n_bits,1,1){
        }
};

//*** DoubleByte BIT FLIP MUTATOR ***

class DoubleBitFlipMutator: public virtual Mutator{
    public:
        DoubleBitFlipMutator(const char *name, size_t n_bits, size_t step, size_t width){
            this->n_bits_b8 = b8(n_bits)*8;
            this->max_idx = n_bits-width;
            this->tail_b8 = n_bits%8;
            this->step = step;
            this->width = width;
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
        DetDoubleBitFlipMutator(size_t n_bits): DoubleBitFlipMutator("det bitflip 2/1",n_bits,1,2){
        }
};

class RandDoubleBitFlipMutator: public RandMutator, public DoubleBitFlipMutator{
    public:
        RandDoubleBitFlipMutator(size_t n_bits): DoubleBitFlipMutator("rand bitflip 2/1",n_bits,1,2){
        }
};

//*** NIBBLE FLIP MUTATOR ***

class NibbleFlipMutator: public virtual Mutator{
    public:
        NibbleFlipMutator(const char *name, size_t n_bits, size_t step, size_t width){
            this->n_bits_b8 = b8(n_bits)*8;
            this->max_idx = n_bits-width;
            this->tail_b8 = n_bits%8;
            this->step = step;
            this->width = width;
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
        DetNibbleFlipMutator(size_t n_bits): NibbleFlipMutator("det bitflip 4/1",n_bits,1,4){
        }
};

class RandNibbleFlipMutator: public RandMutator, public NibbleFlipMutator{
    public:
        RandNibbleFlipMutator(size_t n_bits): NibbleFlipMutator("rand bitflip 4/1",n_bits,1,4){
        }
};

//*** SINGLE BYTE FLIP MUTATOR ***

// class SingleByteFlipMutator: public virtual Mutator{
//     public:
//         SingleByteFlipMutator(const char *name, size_t n_bits, size_t step, size_t width){
//             this->n_bits_b8 = b8(n_bits)*8;
//             this->max_idx = n_bits-width;
//             this->tail_b8 = n_bits%8;
//             this->step = step;
//             this->width = width;
//             this->name = name;
//             this->init();
//         }        
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf);
//         #endif
// };

// class DetSingleByteFlipMutator: public DetMutator, public SingleByteFlipMutator{
//     public:
//         DetSingleByteFlipMutator(size_t n_bits): SingleByteFlipMutator("det bitflip 8/8",n_bits,8,8){
//         }
// };

// class RandSingleByteFlipMutator: public RandMutator, public SingleByteFlipMutator{
//     public:
//         RandSingleByteFlipMutator(size_t n_bits): SingleByteFlipMutator("rand bitflip 8/8",n_bits,8,8){
//         }
// };

// //***  DOUBLE BYTE FLIP MUTATOR ***

// class DoubleByteFlipMutator: public virtual Mutator{
//     public:
//         DoubleByteFlipMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>2) this->max_idx = n_bits_b8 - 2; // at some points the HW might be smaller than 32 so we cant mutate then
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf);
//         #endif

// };

// class DetDoubleByteFlipMutator: public DetMutator, public DoubleByteFlipMutator{
//     public:
//         DetDoubleByteFlipMutator(size_t n_bits): DoubleByteFlipMutator(n_bits, "det bitflip 16/8"){
//         }
// };

// class RandDoubleByteFlipMutator: public RandMutator, public DoubleByteFlipMutator{
//     public:
//         RandDoubleByteFlipMutator(size_t n_bits): DoubleByteFlipMutator(n_bits, "rand bitflip 16/8"){
//         }
// };

// //***  QUAD BYTE FLIP MUTATOR ***

// class QuadByteFlipMutator: public virtual Mutator{
//     public:
//         QuadByteFlipMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>4) this->max_idx = n_bits_b8 - 4; // at some points the HW might be smaller than 32 so we cant mutate then
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf);
//         #endif
// };

// class DetQuadByteFlipMutator: public DetMutator, public QuadByteFlipMutator{
//     public:
//         DetQuadByteFlipMutator(size_t n_bits): QuadByteFlipMutator(n_bits, "det bitflip 32/8"){
//         }
// };

// class RandQuadByteFlipMutator: public RandMutator, public QuadByteFlipMutator{
//     public:
//         RandQuadByteFlipMutator(size_t n_bits): QuadByteFlipMutator(n_bits, "rand bitflip 32/8"){
//         }
// };

// //***  ADD SINGLE BYTE MUTATOR ***

// class AddSingleByteMutator: public virtual Mutator{
//     public:
//         AddSingleByteMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>1) this->max_idx = n_bits_b8 - 1; // at some points the HW might be smaller than 32 so we cant mutate then
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf){return;};
//         #endif
// };

// class DetAddSingleByteMutator: public DetMutator, public AddSingleByteMutator{
//     public:
//         DetAddSingleByteMutator(size_t n_bits): AddSingleByteMutator(n_bits, "det arith 8/8"){
//         }
// };

// class RandAddSingleByteMutator: public RandMutator, public AddSingleByteMutator{
//     public:
//         RandAddSingleByteMutator(size_t n_bits): AddSingleByteMutator(n_bits, "rand arith 8/8"){
//         }
// };

// //***  ADD DOUBLE BYTE MUTATOR ***

// class AddDoubleByteMutator: public virtual Mutator{
//     public:
//         AddDoubleByteMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>2) this->max_idx = n_bits_b8 - 2; // at some points the HW might be smaller than 32 so we cant mutate then
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf){return;};
//         #endif
// };

// class DetAddDoubleByteMutator: public DetMutator, public AddDoubleByteMutator{
//     public:
//         DetAddDoubleByteMutator(size_t n_bits): AddDoubleByteMutator(n_bits, "det arith 16/8"){
//         }
// };

// class RandAddDoubleByteMutator: public RandMutator, public AddDoubleByteMutator{
//     public:
//         RandAddDoubleByteMutator(size_t n_bits): AddDoubleByteMutator(n_bits, "rand arith 16/8"){
//         }
// };


// //***  ADD QUAD BYTE MUTATOR ***

// class AddQuadByteMutator: public virtual Mutator{
//     public:
//         AddQuadByteMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>4) this->max_idx = n_bits_b8 - 4;
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf){return;};
//         #endif
// };

// class DetAddQuadByteMutator: public DetMutator, public AddQuadByteMutator{
//     public:
//         DetAddQuadByteMutator(size_t n_bits): AddQuadByteMutator(n_bits, "det arith 32/8"){
//         }
// };

// class RandAddQuadByteMutator: public RandMutator, public AddQuadByteMutator{
//     public:
//         RandAddQuadByteMutator(size_t n_bits): AddQuadByteMutator(n_bits, "rand arith 32/8"){
//         }
// };

// //***  OVERWRITE INTERESTING BYTE MUTATOR ***

// class OverwriteInterestingSingleByteMutator: public virtual Mutator{
//     public:
//         OverwriteInterestingSingleByteMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>1) this->max_idx = n_bits_b8 - 1; // at some points the HW might be smaller than 8 so we cant mutate then
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf){return;};
//         #endif
// };

// class DetOverwriteInterestingSingleByteMutator: public DetMutator, public OverwriteInterestingSingleByteMutator{
//     public:
//         DetOverwriteInterestingSingleByteMutator(size_t n_bits): OverwriteInterestingSingleByteMutator(n_bits, "det interest 8"){
//         }
// };

// class RandOverwriteInterestingSingleByteMutator: public RandMutator, public OverwriteInterestingSingleByteMutator{
//     public:
//         RandOverwriteInterestingSingleByteMutator(size_t n_bits): OverwriteInterestingSingleByteMutator(n_bits, "rand interest 8"){
//         }
// };


// //***  OVERWRITE INTERESTING DOUBLE BYTE MUTATOR ***

// class OverwriteInterestingDoubleByteMutator: public virtual Mutator{
//     public:
//         OverwriteInterestingDoubleByteMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>2) this->max_idx = n_bits_b8 - 2; // at some points the HW might be smaller than 8 so we cant mutate then
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf){return;};
//         #endif
// };

// class DetOverwriteInterestingDoubleByteMutator: public DetMutator, public OverwriteInterestingDoubleByteMutator{
//     public:
//         DetOverwriteInterestingDoubleByteMutator(size_t n_bits): OverwriteInterestingDoubleByteMutator(n_bits, "det interest 16"){
//         }
// };

// class RandOverwriteInterestingDoubleByteMutator: public RandMutator, public OverwriteInterestingDoubleByteMutator{
//     public:
//         RandOverwriteInterestingDoubleByteMutator(size_t n_bits): OverwriteInterestingDoubleByteMutator(n_bits, "rand interest 16"){
//         }
// };


// //***  OVERWRITE INTERESTING QUAD BYTE MUTATOR ***

// class OverwriteInterestingQuadByteMutator: public virtual Mutator{
//     public:
//         OverwriteInterestingQuadByteMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>4) this->max_idx = n_bits_b8 - 4; // at some points the HW might be smaller than 8 so we cant mutate then
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf){return;};
//         #endif
// };

// class DetOverwriteInterestingQuadByteMutator: public DetMutator, public OverwriteInterestingQuadByteMutator{
//     public:
//         DetOverwriteInterestingQuadByteMutator(size_t n_bits): OverwriteInterestingQuadByteMutator(n_bits, "det interest 32"){
//         }
// };

// class RandOverwriteInterestingQuadByteMutator: public RandMutator, public OverwriteInterestingQuadByteMutator{
//     public:
//         RandOverwriteInterestingQuadByteMutator(size_t n_bits): OverwriteInterestingQuadByteMutator(n_bits, "rand interest 32"){
//         }
// };

// //***  OVERWRITE WITH RANDOM BYTE MUTATOR ***

// class OverwriteRandomByteMutator: public virtual Mutator{
//     public:
//         OverwriteRandomByteMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>1) this->max_idx = n_bits_b8 - 1; // at some points the HW might be smaller than 8 so we cant mutate then
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf){return;};
//         #endif
// };

// class DetOverwriteRandomByteMutator: public DetMutator, public OverwriteRandomByteMutator{
//     public:
//         DetOverwriteRandomByteMutator(size_t n_bits): OverwriteRandomByteMutator(n_bits, "det random 8"){
//         }
// };

// class RandOverwriteRandomByteMutator: public RandMutator, public OverwriteRandomByteMutator{
//     public:
//         RandOverwriteRandomByteMutator(size_t n_bits): OverwriteRandomByteMutator(n_bits, "rand random 8"){
//         }
// };

// //***  DELETE RANDOM BYTES MUTATOR ***

// class DeleteRandomBytesMutator: public virtual Mutator{
//     public:
//         DeleteRandomBytesMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>1) this->max_idx = n_bits_b8 - 1; // at some points the HW might be smaller than 8 so we cant mutate then
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf){return;};
//         #endif
// };

// class RandDeleteRandomBytesMutator: public RandMutator, public DeleteRandomBytesMutator{
//     public:
//         RandDeleteRandomBytesMutator(size_t n_bits): DeleteRandomBytesMutator(n_bits, "delete"){
//         }
// };


// //***  CLONE RANDOM BYTES MUTATOR ***

// class CloneRandomBytesMutator: public virtual Mutator{
//     public:
//         CloneRandomBytesMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>1) this->max_idx = n_bits_b8 - 1; // at some points the HW might be smaller than 8 so we cant mutate then
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf){return;};
//         #endif
// };

// class RandCloneRandomBytesMutator: public RandMutator, public CloneRandomBytesMutator{
//     public:
//         RandCloneRandomBytesMutator(size_t n_bits): CloneRandomBytesMutator(n_bits, "clone"){
//         }
// };


// //***  OVERWRITE RANDOM BYTES MUTATOR ***

// class OverwriteRandomBytesMutator: public virtual Mutator{
//     public:
//         OverwriteRandomBytesMutator(size_t n_bits, const char *name){
//             int n_bits_b8 = b8(n_bits);
//             if(n_bits_b8>1) this->max_idx = n_bits_b8 - 1; // at some points the HW might be smaller than 8 so we cant mutate then
//             else this->max_idx = 0;
//             this->name = name;
//             this->init();
//         }
//         void permute(uint8_t *buf);
//         #ifdef TAINT_EN
//         void permute_taints(uint8_t *buf){return;};
//         #endif
// };

// class RandOverwriteRandomBytesMutator: public RandMutator, public OverwriteRandomBytesMutator{
//     public:
//         RandOverwriteRandomBytesMutator(size_t n_bits): OverwriteRandomBytesMutator(n_bits, "overwrite"){
//         }
// };

// //***  RANDOM FUZZING MUTATOR ***

class RandomMutator: public virtual Mutator{
    public:
        RandomMutator(size_t n_bits, const char *name){
            int n_bits_b8 = b8(n_bits);
            this->max_idx =  n_bits_b8;
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class EndlessRandomMutator: public EndlessMutator, public virtual RandomMutator{
    public: 
        EndlessRandomMutator(size_t n_bits): RandomMutator(n_bits, "endless random"){};
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf);
        #endif

};

class ReduceRandomTaintsMutator: public EndlessMutator, public virtual RandomMutator{
    public: 
        ReduceRandomTaintsMutator(size_t n_bits): RandomMutator(n_bits, "reduce taints random"){};
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf);
        #endif

};

//***  BRUTE FORCE FUZZING MUTATOR ***

class BruteForceMutator: public virtual Mutator{
    public:
        BruteForceMutator(size_t n_bits, const char *name){
            this->max_idx = pow(2,n_bits)-1;
            this->name = name;
            this->init();
        }
        void permute(uint8_t *buf);
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf){return;};
        #endif
};

class DetBruteForceMutator: public DetMutator, public BruteForceMutator{
    public:
        DetBruteForceMutator(size_t n_bits): BruteForceMutator(n_bits, "deterministic brute force"){
        }
        #ifdef TAINT_EN
        void permute_taints(uint8_t *buf);
        #endif

};

std::deque<Mutator *> *get_det_mutators(size_t n_bits);
std::deque<Mutator *> *get_rand_mutators(size_t n_bits);
std::deque<Mutator *> *get_all_mutators(size_t n_bits);

#endif // MUTATOR_H