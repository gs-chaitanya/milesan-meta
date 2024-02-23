#include "isa_masks.h"
#include "def_inst.h"
#include "macros.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#pragma once
class Instruction{
    public:
        Instruction(uint32_t addr, uint32_t inject_inst, uint32_t inject_taint, std::string i_str, std::string type){
            this->set_address(addr);
            this->inject_inst = inject_inst;
            this->inject_taint = inject_taint;
            this->retired = false;
            assert(std::string(INST_TS).find(type) != std::string::npos);
            this->type = type;
            this->i_str = i_str;
        };
        uint32_t addr;
        uint32_t alignment;
        uint32_t opcode;
        uint32_t opcode_t0;
        uint32_t inject_inst;
        uint32_t inject_taint;
        uint32_t bytecode;
        uint32_t bytecode_t0;
        uint32_t retired;
        std::string type;
        std::string i_str;
        
        void print(){ // prints starting with highest bit [msb...lsb]
            if(this->retired) std::cout << "(retired) (" << this->type << ") 0x" << std::hex << this->get_address() << ": ";
            else std::cout << "(" << this->type << ") 0x" << std::hex << this->get_address() << ": ";
            this->decode();
            std::stringstream bits;
            bits << ": ";
            for(int i=N_BYTES_PER_INST*8-1; i>=0; i--){
                if(bytecode_t0&(1ul<<i)) bits << "\033[1;31m" << ((bytecode & (1ul<<i))>>i) << "\033[1;0m";
                else  bits << ((bytecode & (1ul<<i))>>i);
            }
            std::cout << bits.str();

            if(!this->inject_inst) std::cout << " (inject_inst off)";
            if(!this->inject_taint) std::cout << " (inject_taint off)";
            
            std::cout << std::endl;
        };

        std::string get_json_str(){
            std::stringstream s;
            s << "{";
            s << "\"addr\":\"0x" << std::hex << this->get_address() << "\",";
            s << "\"bytecode\":\"0x" << std::hex << this->bytecode << "\",";
            s << "\"bytecode_t0\":\"0x" << std::hex << this->bytecode_t0 << "\",";
            s << "\"i_str\":\"0x" << std::hex << this->i_str << "\",";
            s << "\"type\":\"" << this->type << "\"}"; 
            return s.str();
        }

        virtual uint32_t get_binary(){std::cout << "wrong get_binary\n";return  0;};
        virtual void set_binary(uint32_t bytecode){std::cout << "wrong set_binary\n"; assert(0); return;};

        virtual uint32_t get_binary_t0(){std::cout << "wrong get_binary_t0\n";return  0;};
        virtual void set_binary_t0(uint32_t bytecode_t0){std::cout << "wrong set_binary_t0\n"; assert(0); return;};

        void print_binary(){std::cout << std::hex << "0x" << bytecode << std::endl;};
        void print_binary_t0(){std::cout << std::hex << "0x" << bytecode_t0 << std::endl;};

        virtual void decode(){};

        void set_address(uint32_t addr){
            this->addr = ((addr| RELOCATE_UP)>>DATA_WIDTH_BYTES_LOG2);
            this->alignment = addr%DATA_WIDTH_BYTES;
        }

        uint32_t get_address(){
            return (this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment;
        }

        bool equals(Instruction *other){ // does not check address
            if(this->bytecode != other->bytecode) return false;
            if(this->bytecode_t0 != other->bytecode_t0) return false;
            if(this->type != other->type) return false;
            return true;
        }

        void print_intercept(uint32_t bytecode, uint32_t bytecode_t0){
            // std::cout << "Intercepting: (" << this->type << ") 0x" << std::hex << this->get_address() << ": ";
            // std::cout << std::hex << this->bytecode << "(" << bytecode << "), t0: " << this->bytecode_t0 << "(" << bytecode_t0 << ")";
            // if(!this->inject_inst) std::cout << " (inject_inst off) ";
            // if(!this->inject_taint) std::cout << " (inject_taint off) ";
            // std::cout << std::endl;
            std::cout << "Intercepting: ";
            this->print();

        }

        void dump_json(){};
        void taint_all(){};
        void rand_taint(){};
        void untaint(){};
        virtual Instruction *copy(){};
};

class RegImmInstruction: public virtual Instruction{
    public:
        RegImmInstruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"RegImm"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        RegImmInstruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"RegImm"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t rd;
        uint32_t rs1;
        uint32_t imm;
        uint32_t funct3;

        uint32_t rd_t0;
        uint32_t rs1_t0;
        uint32_t imm_t0;
        uint32_t funct3_t0;


        uint32_t get_binary(){
            assert(bytecode==(imm&IMMI_MASK)<<IMMI_BIT | (rs1&RS1_MASK)<<RS1_BIT | (funct3&FUNCT3_MASK)<<FUNCT3_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            imm = (bytecode>>IMMI_BIT)&IMMI_MASK;
            rs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            funct3 = (bytecode>>FUNCT3_BIT)&FUNCT3_MASK;
            rd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(imm&IMMI_MASK)<<IMMI_BIT | (rs1&RS1_MASK)<<RS1_BIT | (funct3&FUNCT3_MASK)<<FUNCT3_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0 ==(imm_t0&IMMI_MASK)<<IMMI_BIT | (rs1_t0&RS1_MASK)<<RS1_BIT | (funct3_t0&FUNCT3_MASK)<<FUNCT3_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }

        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            imm_t0 = (bytecode_t0>>IMMI_BIT)&IMMI_MASK;
            rs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            funct3_t0 = (bytecode_t0>>FUNCT3_BIT)&FUNCT3_MASK;
            rd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0 ==(imm_t0&IMMI_MASK)<<IMMI_BIT | (rs1_t0&RS1_MASK)<<RS1_BIT | (funct3_t0&FUNCT3_MASK)<<FUNCT3_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0 || this->funct3_t0) std::cout << std::left << std::setw(10) << "\033[1;31m" << this->i_str << "\033[1;0m";
            else std::cout << std::left << std::setw(10) << this->i_str;
            std::cout << " ";
            if(this->rd_t0)  std::cout << "\033[1;31m" << " r" << std::setw(2) << this->rd << "\033[1;0m";
            else std::cout  << "r" << this->rd;
            std::cout << " ";
            if(this->rs1_t0)  std::cout << "\033[1;31m" << " r" << std::setw(2) << this->rs1 << "\033[1;0m";
            else std::cout << "r" << this->rs1;
            std::cout << " ";
            if(this->imm_t0) std::cout << "\033[1;31m" << std::right << std::setw(5) << this->imm << "\033[1;0m";
            else std::cout << std::right << std::setw(5) << this->imm;

        }

        RegImmInstruction *copy(){
            if(inject_taint) return new RegImmInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0,this->i_str);
            return new RegImmInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};


class R12DInstruction: public virtual Instruction{
    public:
        R12DInstruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"R12D"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        R12DInstruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"R12D"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t rd;
        uint32_t rs1;
        uint32_t rs2;
        uint32_t funct7;
        uint32_t funct3;

        uint32_t rd_t0;
        uint32_t rs1_t0;
        uint32_t rs2_t0;
        uint32_t funct7_t0;
        uint32_t funct3_t0;

        uint32_t get_binary(){
            assert(bytecode==(funct7&FUNCT7_MASK)<<FUNCT7_BIT | (rs2&RS2_MASK)<<RS2_BIT | (rs1&RS1_MASK)<<RS1_BIT | (funct3&FUNCT3_MASK)<<FUNCT3_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            rs2 = (bytecode>>RS2_BIT)&RS2_MASK;
            rs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            funct7 = (bytecode>>FUNCT7_BIT)&FUNCT7_MASK;
            funct3 = (bytecode>>FUNCT3_BIT)&FUNCT3_MASK;
            rd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(funct7&FUNCT7_MASK)<<FUNCT7_BIT | (rs2&RS2_MASK)<<RS2_BIT | (rs1&RS1_MASK)<<RS1_BIT | (funct3&FUNCT3_MASK)<<FUNCT3_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0==(funct7_t0&FUNCT7_MASK)<<FUNCT7_BIT | (rs2_t0&RS2_MASK)<<RS2_BIT | (rs1_t0&RS1_MASK)<<RS1_BIT | (funct3_t0&FUNCT3_MASK)<<FUNCT3_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }
        
        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            rs2_t0 = (bytecode_t0>>RS2_BIT)&RS2_MASK;
            rs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            funct7_t0 = (bytecode_t0>>FUNCT7_BIT)&FUNCT7_MASK;
            funct3_t0 = (bytecode_t0>>FUNCT3_BIT)&FUNCT3_MASK;
            rd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0==(funct7_t0&FUNCT7_MASK)<<FUNCT7_BIT | (rs2_t0&RS2_MASK)<<RS2_BIT | (rs1_t0&RS1_MASK)<<RS1_BIT | (funct3_t0&FUNCT3_MASK)<<FUNCT3_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0 || this->funct3_t0) std::cout << std::left << std::setw(10) << "\033[1;31m" << this->i_str << "\033[1;0m";
            else std::cout << std::left << std::setw(10) << this->i_str;
            std::cout << " ";
            if(this->rd_t0) std::cout << "\033[1;31m" << " r" <<  std::setw(2) << this->rd << "\033[1;0m";
            else std::cout  << "r" << this->rd;
            std::cout << " ";
            if(this->rs1_t0) std::cout << "\033[1;31m" << " r" <<  std::setw(2) << this->rs1 << "\033[1;0m";
            else std::cout  << "r" <<this->rs1;
            std::cout << " ";
            if(this->rs2_t0) std::cout << "\033[1;31m" << std::right << std::setw(5) << this->rs2 << "\033[1;0m";
            else std::cout << std::right << std::setw(5) << this->rs2;
        }

        R12DInstruction *copy(){
            if(inject_taint) return new R12DInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new R12DInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};
