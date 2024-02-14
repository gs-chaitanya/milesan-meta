#include <iostream>
#include <fstream>
#include <cassert>
#include <map>
#include <sstream>  

#include "dtypes.h"
#include "macros.h"
#include "testbench.h"
#include "log.h"

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
    #if N_FUZZ_INPUT_TRAIL_BITS != 0 
    assert((inputs[N_FUZZ_INPUTS_b32-1] & ~FUZZ_INPUT_MASK) == 0);
    #endif // FUZZ_INPUT_MASK != 0 
    #ifdef TAINT_EN
    #if N_TAINT_INPUT_TRAIL_BITS != 0 
    assert((taints[N_TAINT_INPUTS_b32-1] & ~TAINT_INPUT_MASK) == 0);
    #endif
    #endif // TAINT_EN
}

void dinput_t::clean(){ // when we mutate inputs we might get into padded area, for now just cut that off...
    #if N_FUZZ_INPUT_TRAIL_BITS != 0 
    inputs[N_FUZZ_INPUTS_b32-1] &= FUZZ_INPUT_MASK;
    #endif // FUZZ_INPUT_MASK != 0 
    #ifdef TAINT_EN
    #if N_TAINT_INPUT_TRAIL_BITS != 0 
    taints[N_TAINT_INPUTS_b32-1] &= TAINT_INPUT_MASK;
    #endif //TAINT_INPUT_MASK != 0 
    #endif // TAINT_EN
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
void dinput_t::dump(Testbench *tb){ // pickle current values into json like format
    
    std::ofstream cov_ofstream;
    long timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - tb->start_time).count();
    std::string path = std::string(COV_DIR) + std::to_string(timestamp) + std::string("in.json");
    
    cov_ofstream.open(path);

    cov_ofstream << "{\"input\":[";
    for(int i=0; i<N_FUZZ_INPUTS_b32; i++){
        int trail = 32;
        if(i == N_FUZZ_INPUTS_b32-1 && N_FUZZ_TRAIL_BITS != 0) trail = N_FUZZ_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->inputs[i] & (1<<j))>>j);
            if((i != N_FUZZ_INPUTS_b32-1) || (j!=trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "],";
    cov_ofstream << std::endl;
    #ifdef TAINT_EN
    cov_ofstream << "\"taints\":[";
    for(int i=0; i<N_TAINT_INPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_INPUTS_b32-1 && N_TAINT_INPUT_TRAIL_BITS != 0) trail = N_TAINT_INPUT_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->taints[i] & (1<<j))>>j);
            if((i != N_TAINT_INPUTS_b32-1) || (j != trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "],";
    #endif // TAINT_EN
    cov_ofstream << "\"timestamp\": " << timestamp << ",";
    cov_ofstream << "\"ticks\": " << tb->tick_count_;

    cov_ofstream << "}";

}

void dinput_t::dump(Testbench *tb, long timestamp, long idx){ // pickle current values into json like format
    std::string dir = std::string(Q_DIR) + std::string("/") + std::to_string(timestamp)  + std::string("/");
    mkdir(dir.c_str(),S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    dir += std::string("inputs") + std::string("/");
    mkdir(dir.c_str(),PERMISSIONS);
    std::string path = dir + std::to_string(idx) + std::string(".json");
    std::ofstream cov_ofstream;    
    cov_ofstream.open(path);

    cov_ofstream << "{\"input\":[";
    for(int i=0; i<N_FUZZ_INPUTS_b32; i++){
        int trail = 32;
        if(i == N_FUZZ_INPUTS_b32-1 && N_FUZZ_TRAIL_BITS != 0) trail = N_FUZZ_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->inputs[i] & (1<<j))>>j);
            if((i != N_FUZZ_INPUTS_b32-1) || (j!=trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "],";
    cov_ofstream << std::endl;
    #ifdef TAINT_EN
    cov_ofstream << "\"taints\":[";
    for(int i=0; i<N_TAINT_INPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_INPUTS_b32-1 && N_TAINT_INPUT_TRAIL_BITS != 0) trail = N_TAINT_INPUT_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->taints[i] & (1<<j))>>j);
            if((i != N_TAINT_INPUTS_b32-1) || (j != trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "],";
    #endif // TAINT_EN
    cov_ofstream << "\"timestamp\": " << timestamp << ",";
    cov_ofstream << "\"ticks\": " << tb->tick_count_;

    cov_ofstream << "}";

}

std::map<std::string,std::stringstream> dinput_t::dump_buf(){ // pickle current values into json like format
   std::map<std::string,std::stringstream> kv_pairs;
   kv_pairs["inputs"] << "[";
    for(int i=0; i<N_FUZZ_INPUTS_b32; i++){
        int trail = 32;
        if(i == N_FUZZ_INPUTS_b32-1 && N_FUZZ_TRAIL_BITS != 0) trail = N_FUZZ_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            kv_pairs["inputs"] << ((this->inputs[i] & (1<<j))>>j);
            if((i != N_FUZZ_INPUTS_b32-1) || (j!=trail-1)) kv_pairs["inputs"] << ",";
        }
    }
    kv_pairs["inputs"] << "]";
    #ifdef TAINT_EN
    kv_pairs["taints"]  << "[";
    for(int i=0; i<N_TAINT_INPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_INPUTS_b32-1 && N_TAINT_INPUT_TRAIL_BITS != 0) trail = N_TAINT_INPUT_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            kv_pairs["taints"] << ((this->taints[i] & (1<<j))>>j);
            if((i != N_TAINT_INPUTS_b32-1) || (j != trail-1)) kv_pairs["taints"] << ",";
        }
    }
    kv_pairs["taints"] << "]";
    #endif // TAINT_EN
   return kv_pairs;
}


#endif // WRITE_COVERAGE





#ifdef WRITE_COVERAGE
void doutput_t::dump(Testbench *tb){ // pickle current values into json like format
    std::ofstream cov_ofstream;
    long timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - tb->start_time).count();

    std::string path = std::string(COV_DIR) + std::to_string(timestamp) + std::string(".cov.json");

    cov_ofstream.open(path);


    cov_ofstream << "{\"coverage\":[";
    for(int i=0; i<N_COV_POINTS_b32; i++){
        int trail = 32;
        if(i == N_COV_POINTS_b32-1 && N_COV_TRAIL_BITS != 0) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->coverage[i] & (1<<j))>>j);
            if((i != N_COV_POINTS_b32-1) || (j!=trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "],";
    cov_ofstream << std::endl;
    #ifdef TAINT_EN
    cov_ofstream << "\"taints\":[";
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_OUTPUTS_b32-1 && N_TAINT_OUTPUT_TRAIL_BITS != 0) trail = N_TAINT_OUTPUT_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->taints[i] & (1<<j))>>j);
            if((i != N_TAINT_OUTPUTS_b32-1) || (j != trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "],";
    #endif // TAINT_EN
    cov_ofstream << "\"timestamp\": " << timestamp << ",";
    cov_ofstream << "\"ticks\": " << tb->tick_count_;

    cov_ofstream << "}";

}

void doutput_t::dump(Testbench *tb, long timestamp, long idx){ // pickle current values into json like format
    
    std::string dir = std::string(Q_DIR) + std::string("/") + std::to_string(timestamp) + std::string("/");
    mkdir(dir.c_str(),PERMISSIONS);
    dir += std::string("outputs") + std::string("/");
    mkdir(dir.c_str(), PERMISSIONS);
    std::string path = dir + std::to_string(idx) + std::string(".json");
    std::ofstream cov_ofstream;    
    cov_ofstream.open(path);

    cov_ofstream << "{\"coverage\":[";
    for(int i=0; i<N_COV_POINTS_b32; i++){
        int trail = 32;
        if(i == N_COV_POINTS_b32-1 && N_COV_TRAIL_BITS != 0) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->coverage[i] & (1<<j))>>j);
            if((i != N_COV_POINTS_b32-1) || (j!=trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "],";
    cov_ofstream << std::endl;
    #ifdef TAINT_EN
    cov_ofstream << "\"taints\":[";
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_OUTPUTS_b32-1 && N_TAINT_OUTPUT_TRAIL_BITS != 0) trail = N_TAINT_OUTPUT_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->taints[i] & (1<<j))>>j);
            if((i != N_TAINT_OUTPUTS_b32-1) || (j != trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "],";
    #endif // TAINT_EN
    cov_ofstream << "\"timestamp\": " << timestamp << ",";
    cov_ofstream << "\"ticks\": " << tb->tick_count_;

    cov_ofstream << "}";
}


std::map<std::string,std::stringstream> doutput_t::dump_buf(){ // pickle current values into json like format
   std::map<std::string,std::stringstream> kv_pairs;
   kv_pairs["coverage"] << "[";
    for(int i=0; i<N_COV_POINTS_b32; i++){
        int trail = 32;
        if(i == N_COV_POINTS_b32-1 && N_COV_TRAIL_BITS != 0) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            kv_pairs["coverage"]  << ((this->coverage[i] & (1<<j))>>j);
            if((i != N_COV_POINTS_b32-1) || (j!=trail-1))  kv_pairs["coverage"] << ",";
        }
    }
    kv_pairs["coverage"] << "]";
    #ifdef TAINT_EN
    kv_pairs["taints"]  << "[";
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_OUTPUTS_b32-1 && N_TAINT_OUTPUT_TRAIL_BITS != 0) trail = N_TAINT_OUTPUT_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            kv_pairs["taints"] << ((this->taints[i] & (1<<j))>>j);
            if((i != N_TAINT_OUTPUTS_b32-1) || (j != trail-1)) kv_pairs["taints"] << ",";
        }
    }
    kv_pairs["taints"] << "]";
    #endif // TAINT_EN
    return kv_pairs;
}

#endif // WRITE_COVERAGE

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
    // if(failed()) PRINT("FAIL!\n");
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
    #if N_COV_TRAIL_BITS != 0 
    assert((coverage[N_COV_POINTS_b32-1] & ~COV_MASK) == 0);
    #endif //COV_MASK != 0 
    #ifdef TAINT_EN
    #if N_TAINT_OUTPUT_TRAIL_BITS != 0 
    assert((taints[N_TAINT_OUTPUTS_b32-1] & ~TAINT_OUPUT_MASK) == 0); 
    #endif  // COV_MASK != 0  
    #endif // TAINT_EN
    #ifdef CHECK_ASSERTS
    #if N_COV_TRAIL_BITS != 0
    assert((asserts[N_ASSERTS_b32-1] & ~ASSERTS_MASK) == 0);
    #endif // COV_MASK != 0 
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
