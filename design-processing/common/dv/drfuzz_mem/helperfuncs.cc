#include "helperfuncs.h"
#include "macros.h"

#include <cstdlib>
#include <cstdint>
#include <string>
#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>


uint64_t expand_mask(uint8_t mask_8bits) {
  uint64_t mask_64bits = 0;
  for (int i = 0; i < 8; i++) {
    if ((mask_8bits & (1 << i)) != 0) {
      mask_64bits |= 0xFFULL << (i * 8);
    }
  }
  return mask_64bits;
}

std::string get_cov_dir(){
  const static char* cov_dir = std::getenv("COV_DIR");
  static bool printed = false;
  if(cov_dir) return std::string(cov_dir);
  else if(!printed) std::cout << "COV_DIR not set, defaulting to " << COV_DIR << std::endl; 
  printed = true;
  return std::string(COV_DIR);
}

std::string get_reg_mismatch_dir(){
  const static char* reg_dir = std::getenv("REG_MISMATCH_DIR");
  static bool printed = false;
  if(reg_dir) return std::string(reg_dir);
  else if(!printed) std::cout << "REG_MISMATCH_DIR not set, defaulting to " << REG_MISMATCH_DIR << std::endl;
  printed = true;
  return std::string(REG_MISMATCH_DIR);
}

std::string get_new_reg_mismatch_path(){
  static const std::string dir = get_reg_mismatch_dir();
  static size_t idx = 0;
  return dir + std::string("/") + std::to_string(idx++) + std::string(".reg_mismatch.json");
}

std::string get_timeout_dir(){
  const static char* timeout_dir = std::getenv("TMETOUT_DIR");
  static bool printed = false;
  if(timeout_dir) return std::string(timeout_dir);
  else if(!printed) std::cout << "TIMEOUT_DIR not set, defaulting to " << TIMEOUT_DIR << std::endl;
  printed = true;
  return std::string(TIMEOUT_DIR);
}

std::string get_mut_inst_path(){
  if(const char* inst_path = std::getenv("MUT_INST_PATH")) return std::string(inst_path);
  else return std::string(MUT_INST_PATH);

}

int get_seed(){
  const static char* seed = std::getenv("SEED");
  if(seed) return std::stoi(seed);
  else return SEED;
}

std::string get_new_timeout_path(){
  static const std::string dir = get_timeout_dir();
  static size_t idx = 0;
  return dir + std::string("/") + std::to_string(idx++) + std::string(".timeout.json");
}

std::string get_q_dir(){
  const static char* q_dir = std::getenv("Q_DIR");
  static bool printed = false;
  if(q_dir) return std::string(q_dir);
  else if(!printed) std::cout << "Q_DIR not set, defaulting to" << Q_DIR << std::endl; 
  printed = true;
  return Q_DIR;
}

std::string get_regdump_path(){
  const static char* p = std::getenv("REGDUMP_PATH");
  static bool printed = false;
  if(p) return std::string(p);
  else if(!printed) std::cout << "REDDUMP_PATH not set, defaulting to" << REGDUMP_PATH << std::endl; 
  printed = true;
  return REGDUMP_PATH;
}

std::string get_regstream_path(){
  const static char* p = std::getenv("REGSTREAM_PATH");
  static bool printed = false;
  if(p) return std::string(p);
  else if(!printed) std::cout << "REGSTREAM_PATH not set, defaulting to" << REGSTREAM_PATH << std::endl; 
  printed = true;
  return REGSTREAM_PATH;
}

std::string get_id(){
  const static char* id = std::getenv("ID");
  static bool printed = false;
  if(id) return std::string(id);
  else if(!printed) std::cout << "ID not set, defaulting to " << DEFAULT_ID << std::endl; 
  printed = true;
  return std::to_string(DEFAULT_ID);
}

// std::string get_taint_path(){
//   static char *taintpath = getenv("SIMSRAMTAINT");
//   if(taintpath == nullptr){
//     std::cerr << "SIMSRAMTAINT variable not set.\n"; 
//   }
//   // std::cout << "SIMSRAMTAINT set to" << std::string(taintpath) << std::endl;
//   return std::string(taintpath);
// }

std::string get_expected_regs_path(){
  const static char* expected_regs_path = std::getenv("EXPECTED_REGVALS");
  if(expected_regs_path) return std::string(expected_regs_path);
  else std::cerr << "EXPECTED_REGVALS not set.\n"; 
  return std::string(expected_regs_path);
}

std::string get_sramelf()
{
  static char *sramelf = getenv("SIMSRAMELF");
  static bool printed = false;
  if(sramelf == nullptr){
    std::cerr << "SIMSRAMELF not set.\n"; 
  }
  if(!printed) std::cout << "SIMSRAMELF set to" << std::string(sramelf) << std::endl;
  printed = true;
  return std::string(sramelf);
}

char char_to_hex(char c) {
  if (c >= '0' && c <= '9')
    return c-'0';
  else if (c >= 'a' && c <= 'f')
    return c-'a'+10;
  else if (c >= 'A' && c <= 'F')
    return c-'A'+10;

  std::cerr << "Error in taint assignment string. Unexpected character: `" << c << "`" << std::endl;
  exit(0);
}

void dump_regs(std::string path, std::map<std::string, uint64_t> regs, Queue *q){
  static const std::string expected_regs_path = get_expected_regs_path();
  std::ifstream expected_regs_file(expected_regs_path, std::ifstream::binary);
  Json::Value expected_regs;
  expected_regs_file >> expected_regs;

  std::ofstream out;
  out.open(path);
  out << "{\"registers\":\n[";
  for(std::map<std::string, uint64_t>::iterator it = regs.begin(); it != regs.end(); ){
    std::string expected_regval_str = expected_regs[it->first].asString();
    if(!expected_regval_str.size()) {
      it++;
      continue; // reg not in expected regvals so we dont care
    }
    uint64_t expected_regval = std::stoul(expected_regval_str,nullptr,16);

    out << "\"" << it->first << "\": {\"expected\" : \"0x" << std::hex << expected_regval << "\", \"actual\" : \"0x" << std::hex << it->second << "\"}";
    it++;
    if(it == regs.end()){
      break;
    }
    out << ",\n";
  }
  out << "],\n";
  out << "\"instructions\":\n[";
  for(std::deque<Instruction *>::iterator it = q->instructions.begin(); it != q->instructions.end(); ) {
    // (*it)->dump_json(out);
    it++;
    if(it == q->instructions.end()){
      break;
    }
    out << ",\n";
  }
  out << "]}";
}


int check_regs(std::map<std::string, uint64_t> regs){
  static const std::string expected_regs_path = get_expected_regs_path();
  std::ifstream expected_regs_file(expected_regs_path, std::ifstream::binary);
  Json::Value expected_regs;
  expected_regs_file >> expected_regs;
  int reg_mismatch = 0;
  for(auto &reg: regs){
      std::string expected_regval_str = expected_regs[reg.first].asString();
      if(!expected_regval_str.size()) continue; // reg not in expected regvals so we dont care
      uint64_t expected_regval = std::stoul(expected_regval_str,nullptr,16);
    if(expected_regval != reg.second){
      reg_mismatch = 1;
      std::cout << reg.first <<" : " << "\033[1;31m" << "expected: 0x" << std::hex << expected_regval << ", actual: 0x" << std::hex << reg.second << "\033[1;0m" << std::endl;
      }
    else{
      // std::cout << reg.first <<" : " << "0x" << std::hex << reg.second << std::endl;
      continue;
    }
  }
  // for(auto &r: regs){
  //   std::cout << r.first <<" : 0x" << std::hex << r.second << std::endl;
  // }
  return 1-reg_mismatch;
}

void recompute_elf(){
  if(std::system("python /mnt/milesan-meta/fuzzer/do_recompute_elf.py") != 0){
    exit(-1);
  }
}