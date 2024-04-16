#ifndef HELPERFUNCS_H
#define HELPFERFUNCS_H
#include "queue.h"

#include <cstdint>
#include <string>

class Queue; // forward declaration

uint64_t expand_mask(uint8_t mask_8bits);
std::string get_cov_dir();
std::string get_reg_dir();
std::string get_taint_path();
std::string get_q_dir();
std::string get_id();
std::string get_sramelf();
int get_seed();
char char_to_hex(char c); // duplicate from taintloader.cc
void dump_regs(std::string path, std::map<std::string, uint64_t> regs, Queue *q);
int check_regs(std::map<std::string, uint64_t> regs);
std::string get_new_timeout_path();
std::string get_new_reg_mismatch_path();
std::string get_mut_inst_path();
std::string get_regdump_path();
std::string get_regstream_path();
void recompute_elf();
#endif //HELPFERFUNCS_H