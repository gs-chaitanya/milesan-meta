#include <iostream>
#include <fstream>
#include <cassert>

#include "dtypes.h"
#include "macros.h"
#include "testbench.h"

void dinput_t::print(){
    #ifdef TAINT_EN
    assert(N_FUZZ_INPUTS_b32 == N_TAINT_INPUTS_b32);
    #endif // TAINT_EN
    for(int i=0; i<N_FUZZ_INPUTS_b32; i++){
        int trail = 32;
        if(i == N_FUZZ_INPUTS_b32-1) trail = N_FUZZ_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            #ifdef TAINT_EN
            if(((taints[i] & (1ul<<j))>>j)){
                std::cout << "\033[1;31m" << ((inputs[i] & (1<<j))>>j) << "\033[1;0m";
            }
            else{
                std::cout << ((inputs[i] & (1<<j))>>j);
            }
            #else
            std::cout << ((inputs[i] & (1<<j))>>j);
            #endif // TAINT_EN
        }
    }
    std::cout << std::endl;
}
#ifdef TAINT_EN
void dinput_t::print_taint_map(){
    for(int i=0; i<N_TAINT_INPUTS_b32; i++){
        for(int j=0; j<32; j++){
            std::cout << ((taints[i] & (1<<j))>>j);
        
        }
    }
    std::cout << std::endl;
}
#endif // TAINT_EN

void dinput_t::check(){
    assert((inputs[N_FUZZ_INPUTS_b32-1] & ~FUZZ_INPUT_MASK) == 0);
    #ifdef TAINT_EN
    assert((taints[N_TAINT_INPUTS_b32-1] & ~TAINT_INPUT_MASK) == 0);
    #endif // TAINT_EN
}

void dinput_t::clean(){ // when we mutate inputs we might get into padded area, for now just cut that off...
    inputs[N_FUZZ_INPUTS_b32-1] &= FUZZ_INPUT_MASK;
    #ifdef TAINT_EN
    taints[N_TAINT_INPUTS_b32-1] &= TAINT_INPUT_MASK;
    #endif
}

void dinput_t::print_diff(dinput_t *other){
    for(int i=0; i<N_FUZZ_INPUTS_b32; i++){
        int trail = 32;
        if(i == N_FUZZ_INPUTS_b32-1) trail = N_FUZZ_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            if(((other->inputs[i] & (1ul<<j))>>j) != ((inputs[i] & (1ul<<j))>>j)){
                std::cout << "\033[1;33m" << ((inputs[i] & (1<<j))>>j) << "\033[1;0m";
            }
            else{
                std::cout << ((this->inputs[i] & (1<<j))>>j);
            }
        }
    }
    std::cout << std::endl;
}

#ifdef TAINT_EN
void dinput_t::print_taint_diff(dinput_t *other){
    for(int i=0; i<N_TAINT_INPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_INPUTS_b32-1) trail = N_TAINT_INPUT_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            if(((other->taints[i] & (1ul<<j))>>j) != ((taints[i] & (1ul<<j))>>j)){
                std::cout << "\033[1;33m" << ((taints[i] & (1<<j))>>j) << "\033[1;0m";
            }
            else{
                std::cout << ((this->taints[i] & (1<<j))>>j);
            }
        }
    }
    std::cout << std::endl;
}
#endif // TAINT_EN




#ifdef WRITE_COVERAGE
void doutput_t::dump(Testbench *tb){ // pickle current values into json like format
    
    std::ofstream cov_ofstream;
    std::string path = std::string(COV_DUMP) + std::string("/") + std::to_string(tb->tick_count_) + std::string(".json");
    cov_ofstream.open(path);

    cov_ofstream << "{\"coverage\":[";
    for(int i=0; i<N_COV_POINTS_b32; i++){
        int trail = 32;
        if(i == N_COV_POINTS_b32-1) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->coverage[i] & (1<<j))>>j);
            if((i != N_COV_POINTS_b32-1) || (j!=trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "],";
    cov_ofstream << std::endl;
    cov_ofstream << "\"taints\": [";
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_OUTPUTS_b32-1) trail = N_TAINT_OUTPUT_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->coverage[i] & (1<<j))>>j);
            if((i != N_TAINT_OUTPUTS_b32-1) || (j != trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "],";
    long timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - tb->start_time).count();
    cov_ofstream << "\"timestamp:\"" << timestamp << ",";
    cov_ofstream << "\"ticks:\"" << tb->tick_count_;

    cov_ofstream << "}";
}
#endif

void doutput_t::print(){
    #ifdef TAINT_EN
    assert(N_COV_POINTS_b32 == N_TAINT_OUTPUTS_b32);
    #endif
    for(int i=0; i<N_COV_POINTS_b32; i++){
        int trail = 32;
        if(i == N_COV_POINTS_b32-1) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            #ifdef TAINT_EN
            if(((taints[i] & (1ul<<j))>>j)){
                std::cout << "\033[1;31m" << ((coverage[i] & (1<<j))>>j) << "\033[1;0m";
            }
            else{
                std::cout << ((this->coverage[i] & (1<<j))>>j);
            }
            #else
            std::cout << ((this->coverage[i] & (1<<j))>>j);
            #endif // TAINT_EN
        }
    }
    std::cout << std::endl;
    if(failed()){
        std::cout << "\033[1;31mFAILED\033[1;0m" << "\n";
        for(int i=0; i<N_ASSERTS_b32; i++){
            int trail = 32;
            if(i == N_ASSERTS_b32-1) trail = N_ASSERTS_TRAIL_BITS;
            for(int j=0; j<trail; j++){
                if(((asserts[i] & (1ul<<j))>>j)){
                    std::cout << "\033[1;31m" << ((asserts[i] & (1<<j))>>j) << "\033[1;0m";
                }
                else{
                    std::cout << ((this->asserts[i] & (1<<j))>>j);
                }
            }
    }
    }
}
bool doutput_t::failed(){
    if(N_ASSERTS_b32==0) return false;
    for(int i=0; i<N_ASSERTS_b32; i++) if(asserts[i] != 0) return true;
    return false;
}
void doutput_t::check_failed(){
    if(failed()) printf("FAIL!\n");
}

#ifdef TAINT_EN
void doutput_t::print_taint_map(){
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_OUTPUTS_b32-1) trail = N_TAINT_OUTPUT_TRAIL_BITS;
        for(int j=0; j<32; j++){
            std::cout << ((taints[i] & (1<<j))>>j);
        
        }
    }
    std::cout << std::endl;
}
#endif

void doutput_t::check(){
    assert((coverage[N_COV_POINTS_b32-1] & ~COV_MASK) == 0);
    #ifdef TAINT_EN
    assert((taints[N_TAINT_OUTPUTS_b32-1] & ~TAINT_OUPUT_MASK) == 0);
    #endif // TAINT_EN
    #ifdef CHECK_ASSERTS
    assert((asserts[N_ASSERTS_b32-1] & ~ASSERTS_MASK) == 0);
    #endif // CHECK_ASSERTS
}

void doutput_t::print_diff(doutput_t *other){
    for(int i=0; i<N_COV_POINTS_b32; i++){
        int trail = 32;
        if(i == N_COV_POINTS_b32-1) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            if(((other->coverage[i] & (1ul<<j))>>j) != ((coverage[i] & (1ul<<j))>>j)){
                std::cout << "\033[1;33m" << ((coverage[i] & (1<<j))>>j) << "\033[1;0m";
            }
            else{
                std::cout << ((this->coverage[i] & (1<<j))>>j);
            }
        }
    }
    std::cout << std::endl;
}

#ifdef TAINT_EN
void doutput_t::print_taint_diff(doutput_t *other){
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_OUTPUTS_b32-1) trail = N_TAINT_OUTPUT_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            if(((other->taints[i] & (1ul<<j))>>j) != ((taints[i] & (1ul<<j))>>j)){
                std::cout << "\033[1;33m" << ((taints[i] & (1<<j))>>j) << "\033[1;0m";
            }
            else{
                std::cout << ((this->taints[i] & (1<<j))>>j);
            }
        }
    }
    std::cout << std::endl;
}
#endif

void doutput_t::print_asserts_diff(doutput_t *other){
    for(int i=0; i<N_ASSERTS_b32; i++){
        int trail = 32;
        if(i == N_ASSERTS_b32-1) trail = N_ASSERTS_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            if(((other->asserts[i] & (1ul<<j))>>j) != ((asserts[i] & (1ul<<j))>>j)){
                std::cout << "\033[1;33m" << ((asserts[i] & (1<<j))>>j) << "\033[1;0m";
            }
            else{
                std::cout << ((this->asserts[i] & (1<<j))>>j);
            }
        }
    }
    std::cout << std::endl;
}

void doutput_t::print_increase(doutput_t *other){ // increase of this by adding other
    for(int i=0; i<N_COV_POINTS_b32; i++){
        int trail = 32;
        if(i == N_COV_POINTS_b32-1) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            if(((other->coverage[i] & (1ul<<j))>>j) & !((coverage[i] & (1ul<<j))>>j)){
                std::cout << "\033[1;32m" << ((other->coverage[i] & (1<<j))>>j) << "\033[1;0m";
            }
            else{
                std::cout << ((this->coverage[i] & (1<<j))>>j);
            }
        }
    }
    std::cout << std::endl;
}

void doutput_t::add_or(doutput_t *other){
    for(int i=0; i<N_COV_POINTS_b32; i++){
        this->coverage[i] |= other->coverage[i];
    }

    #ifdef TAINT_EN
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        this->taints[i] |= other->taints[i];
    }
    #endif // TAINT_EN

    for(int i=0; i<N_ASSERTS_b32; i++){
        this->asserts[i] |= other->asserts[i];
    }
}

void doutput_t::init(){
    for(int i=0; i<N_COV_POINTS_b32; i++){
        this->coverage[i] = 0;
    }
    
    #ifdef TAINT_EN
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        this->taints[i] = 0;
    }
    #endif // TAINT_EN

    for(int i=0; i<N_ASSERTS_b32; i++){
        this->asserts[i] = 0;
    }


}
