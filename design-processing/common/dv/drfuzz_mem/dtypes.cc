#include <iostream>
#include <fstream>
#include <cassert>
#include <map>
#include <sstream>  
#include <iomanip>

#include "dtypes.h"
#include "macros.h"
#include "testbench.h"
#include "def_tb.h"
#include "log.h"
#include "helperfuncs.h"
std::string abi_names[] = {"zero","ra","sp","gp","tp","t0","t1","t2","s0/fp","s1","a0","a1","a2","a3","a4","a5","a6","a7"};

void tick_req_t::print(){
    if(this->type == REQ_INTREGDUMP){
        std::string abi_name = "";
        if(this->id<18) abi_name = abi_names[this->id];
        else if(this->id<28) abi_name =  "s" + std::to_string(this->id-16);
        else if (this->id<32) abi_name =  "t" + std::to_string(this->id-31);
        printf("Dump of reg %5s: 0x%016lx: 0x%016lx: ", abi_name.c_str(), this->content, this->content_t0);
    }
    else if(this->type == REQ_INTREGDUMP){
        printf("Dump of reg f%5lu: 0x%016lx: 0x%016lx:", this->id, this->content, this->content_t0);
    }
    else{
        printf("Dump at idx 0x%08lx: 0x%016lx: 0x%016lx:", this->id, this->content, this->content_t0);
    }
    #ifdef ARCH_32b
    int n_bits = 32;
    #else
    int n_bits = 64;
    #endif // ARCH_32b
    for(int i=n_bits-1; i>=0; i--){
        #ifdef TAINT_EN
                    if(((content_t0 & (1ul<<i))>>i)){
            std::cout << "\033[1;31m" << ((content & (1ul<<i))>>i) << "\033[1;0m";
        }
        else{
            std::cout << ((content & (1ul<<i))>>i);
        }
        #else
            std::cout << ((content & (1ul<<i))>>i);
        #endif // TAINT_EN
    }
    std::cout << std::endl;
}

std::string tick_req_t::get_json(){
    std::stringstream out;
    if(this->type == REQ_INTREGDUMP){
        out << "{\"id\": \"i" << this->id << "\", \"value\": \"0x" << std::hex << this->content  << "\", \"value_t0\": \"0x" << std::hex << this->content_t0 << "\"}";
    }
    else if(this->type == REQ_FLOATREGDUMP){
        out << "{\"id\": \"f" << this->id << "\", \"value\": \"0x" << std::hex << this->content  << "\", \"value_t0\": \"0x" << std::hex << this->content_t0 << "\"}";
    }
    else if(this->type == REQ_REGSTREAM){
        out << "{\"id\": \"0x" << std::hex << this->id << "\", \"value\": \"0x" << std::hex << this->content  << "\", \"value_t0\": \"0x" << std::hex << this->content_t0 << "\"}";
    }

    return out.str();
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

bool doutput_t::is_tainted(){
    if(N_TAINT_OUTPUTS_b32==0) return false;
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++) if(taints[i] != 0) return true;
    return false;
}
#endif //TAINT_EN

void doutput_t::dump(Testbench *tb){ // write current values into json
    std::ofstream cov_ofstream;
    long timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - tb->start_time).count();

    std::string path = get_cov_dir() + std::to_string(tb->tick_count_) + ".cov.json"; 
    std::cout << "Dumping coverage to " << path << std::endl;
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
    cov_ofstream << "\"ticks\": " << tb->tick_count_ << ",";
    cov_ofstream << "\"id\": " << "\"" << get_id() << "\",";
    cov_ofstream << "\"inst\": " << "\"" << INST << "\",";
    cov_ofstream << "\"dut\": " <<  "\"" << DUT <<"\",";
    cov_ofstream << "\"elf\": " <<  "\"" << get_sramelf() << "\"";

    cov_ofstream << "}";

}

// std::string doutput_t::get_str(){ // write current values into json
//     std::stringstream cov_ofstream;
//     cov_ofstream << "{\"coverage\":[";
//     for(int i=0; i<N_COV_POINTS_b32; i++){
//         int trail = 32;
//         if(i == N_COV_POINTS_b32-1 && N_COV_TRAIL_BITS != 0) trail = N_COV_TRAIL_BITS;
//         for(int j=0; j<trail; j++){
//             cov_ofstream << ((this->coverage[i] & (1<<j))>>j);
//             if((i != N_COV_POINTS_b32-1) || (j!=trail-1)) cov_ofstream << ",";
//         }
//     }
//     cov_ofstream << "],";
//     cov_ofstream << std::endl;
//     #ifdef TAINT_EN
//     cov_ofstream << "\"taints\":[";
//     for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
//         int trail = 32;
//         if(i == N_TAINT_OUTPUTS_b32-1 && N_TAINT_OUTPUT_TRAIL_BITS != 0) trail = N_TAINT_OUTPUT_TRAIL_BITS;
//         for(int j=0; j<trail; j++){
//             cov_ofstream << ((this->taints[i] & (1<<j))>>j);
//             if((i != N_TAINT_OUTPUTS_b32-1) || (j != trail-1)) cov_ofstream << ",";
//         }
//     }
//     cov_ofstream << "],";
//     #endif // TAINT_EN
//     cov_ofstream << "\"ticks\": " << tb->tick_count_;
//     cov_ofstream << "}";
//     return cov_ofstream.str();

// }
std::string doutput_t::get_cov_str(){ // write current values into json
    std::stringstream cov_ofstream;
    cov_ofstream << "[";
    for(int i=0; i<N_COV_POINTS_b32; i++){
        int trail = 32;
        if(i == N_COV_POINTS_b32-1 && N_COV_TRAIL_BITS != 0) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->coverage[i] & (1<<j))>>j);
            if((i != N_COV_POINTS_b32-1) || (j!=trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "]";
    return cov_ofstream.str();

}
#ifdef TAINT_EN
std::string doutput_t::get_cov_t0_str(){ // write current values into json
    std::stringstream cov_ofstream;
    cov_ofstream << "[";
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        int trail = 32;
        if(i == N_TAINT_OUTPUTS_b32-1 && N_TAINT_OUTPUT_TRAIL_BITS != 0) trail = N_TAINT_OUTPUT_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            cov_ofstream << ((this->taints[i] & (1<<j))>>j);
            if((i != N_TAINT_OUTPUTS_b32-1) || (j != trail-1)) cov_ofstream << ",";
        }
    }
    cov_ofstream << "]";
    return cov_ofstream.str();
}
#endif




void doutput_t::dump_q(Testbench *tb){ // pickle current values into json like format
    std::ofstream cov_ofstream;
    long timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - tb->start_time).count();

    std::string path = get_q_dir() + std::to_string(tb->tick_count_) + ".cov.json"; 
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
                if ((coverage[i] & (1<<j))>>j) std::cout << "\033[1;33m" << 1 << "\033[1;0m";
                else  std::cout << "\033[1;31m" << 0 << "\033[1;0m";
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
    if(failed()) PRINT("FAIL!\n");
}

void doutput_t::check(){
    #ifdef MUXCOV_EN
    #if N_COV_TRAIL_BITS != 0 
    assert((coverage[N_COV_POINTS_b32-1] & ~COV_MASK) == 0);
    #endif //COV_MASK != 0 
    #ifdef TAINT_EN
    #if N_TAINT_OUTPUT_TRAIL_BITS != 0 
    assert((taints[N_TAINT_OUTPUTS_b32-1] & ~TAINT_OUPUT_MASK) == 0); 
    #endif  // COV_MASK != 0  
    #endif // TAINT_EN
    #endif // MUXCOV_EN
    #ifdef ASSERTCOV_EN
    #ifdef CHECK_ASSERTS
    #if N_COV_TRAIL_BITS != 0
    assert((asserts[N_ASSERTS_b32-1] & ~ASSERTS_MASK) == 0);
    #endif // COV_MASK != 0 
    #endif // CHECK_ASSERTS
    #endif // ASSERTCOV_EN
}

void doutput_t::print_diff(doutput_t *other){ // print coverage and highlight bits where other has different value
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
#endif //TAINT_EN

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
                // #ifdef TAINT_EN
                // if(other->taints[i] & (1ul<<j)){
                //     std::cout << "\033[1;33m" << ((other->coverage[i] & (1<<j))>>j) << "\033[1;0m";
                // }
                // else{
                // std::cout << "\033[1;32m" << ((other->coverage[i] & (1<<j))>>j) << "\033[1;0m";
                // }
                // #else
                std::cout << "\033[1;32m" << ((other->coverage[i] & (1<<j))>>j) << "\033[1;0m";
                // #endif

            }
            #ifdef TAINT_EN
            else if(this->coverage[i] & other->taints[i] & (1ul<<j)){
                std::cout << "\033[1;33m" << ((this->coverage[i] & (1<<j))>>j) << "\033[1;0m";
            }
            else if(other->taints[i] & (1ul<<j)){
                std::cout << "\033[1;31m" << ((this->coverage[i] & (1<<j))>>j) << "\033[1;0m";
            }
            #endif
            else{
                std::cout << ((this->coverage[i] & (1<<j))>>j);
            }
        }
    }
    std::cout << std::endl;
}

void doutput_t::add_or(doutput_t *other){
    assert(other != nullptr);
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

void doutput_t::print_hex_mask(){
    this->check();
    for(int i=0; i<N_COV_POINTS_b32; i++){
        printf("%08x", this->coverage[i]);
    }
    std::cout << std::endl;
}

size_t doutput_t::get_muxcount(){
    size_t count = 0;
    for(int i=0; i<N_COV_POINTS_b32; i++){
        // for(int j=0; j<32; j++){
        //     if(this->coverage[i]&(1<<j)) count ++;
        // }
        if(i==N_COV_POINTS_b32-1) count += __builtin_popcount(this->coverage[i] & COV_MASK);
        else count += __builtin_popcount(this->coverage[i]);
    }
    return count;
}
#ifdef TAINT_EN
size_t doutput_t::get_taintcount(){
    size_t count = 0;
    for(int i=0; i<N_COV_POINTS_b32; i++){
        // for(int j=0; j<32; j++){
        //     if(this->taints[i]&(1<<j)) count ++;
        // }
        if(i == N_TAINT_OUTPUTS_b32-1) count +=  __builtin_popcount(this->taints[i]&TAINT_OUPUT_MASK);
        else count += __builtin_popcount(this->taints[i]);
    }
    return count;
}
#endif

#ifdef TAINT_EN
size_t doutput_t::get_untoggled_taintcount(){
    size_t count = 0;
    assert(N_COV_POINTS_b32 == N_TAINT_OUTPUTS_b32);
    for(int i=0; i<N_COV_POINTS_b32; i++){
        if(i == N_COV_POINTS_b32-1) count +=  __builtin_popcount(this->taints[i] & ~this->coverage[i] &COV_MASK);
        else count += __builtin_popcount(this->taints[i] & ~this->coverage[i]);
    }
    return count;
}

size_t doutput_t::get_n_untoggled_by_this_and_tainted_by_other(doutput_t *other){
    size_t count = 0;
    assert(N_COV_POINTS_b32 == N_TAINT_OUTPUTS_b32);
    for(int i=0; i<N_COV_POINTS_b32; i++){
        if(i == N_COV_POINTS_b32-1) count +=  __builtin_popcount(other->taints[i] & ~this->coverage[i] &COV_MASK);
        else count += __builtin_popcount(other->taints[i] & ~this->coverage[i]);
    }
    return count;
}

bool doutput_t::compare_taints(doutput_t *other){
    uint32_t mask;
    for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        mask = (i == N_TAINT_OUTPUTS_b32-1) ? TAINT_OUPUT_MASK : FULLMASK_b32;
        if(__builtin_popcount((this->taints[i]^other->taints[i])&mask)) return false;
    }
    return true;
}
#endif //TAINT_EN
