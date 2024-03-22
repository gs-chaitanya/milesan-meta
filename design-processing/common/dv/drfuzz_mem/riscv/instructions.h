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
            s << "\"i_str\":\"" << std::hex << this->i_str << "\",";
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
        RegImmInstruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"REGIMM"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        RegImmInstruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"REGIMM"){
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
            if(this->opcode_t0 || this->funct3_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->rd_t0) printf("\033[1;31mr%02i\033[1;0m",this->rd);
            else printf("r%02i",this->rd);
            std::cout << " ";
            if(this->rs1_t0) printf("\033[1;31mr%02i\033[1;0m",this->rs1);
            else printf("r%02i",this->rs1);
            std::cout << " ";
            if(this->imm_t0) printf("\033[1;31m%05i\033[1;0m",this->imm);
            else printf("%05i",this->imm);
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
            if(this->opcode_t0 || this->funct3_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->rd_t0) printf("\033[1;31mr%02i\033[1;0m",this->rd);
            else printf("r%02i",this->rd);
            std::cout << " ";
            if(this->rs1_t0) printf("\033[1;31mr%02i\033[1;0m",this->rs1);
            else printf("r%02i",this->rs1);
            std::cout << " ";
            if(this->rs2_t0) printf("\033[1;31mr%02i\033[1;0m",this->rs2);
            else printf("r%02i",this->rs2);

            if(this->rd_t0){
                std::cout << " (possile rds with taint 0x" << std::hex << this->rd_t0 << ": ";
                for(int reg=0; reg<32; reg++){
                    // std::cout << ((reg^this->rd)&~this->rd_t0) << ", ";
                    if(((reg^this->rd)&~this->rd_t0) == 0) printf("r%02i,",reg); // untainted bits match
                }
                std::cout << ")\t";
            }
            if(this->rs1_t0){
                std::cout << " (possile rs1 with taint 0x" << std::hex << this->rs1_t0 << ": ";
                for(int reg=0; reg<32; reg++){
                    // std::cout << ((reg^this->rd)&~this->rd_t0) << ", ";
                    if(((reg^this->rs1)&~this->rs1_t0) == 0) printf("r%02i,",reg); // untainted bits match
                }
                std::cout << ")\t";
            }
            if(this->rs2_t0){
                std::cout << " (possile rs2 with taint 0x" << std::hex << this->rs2_t0 << ": ";
                for(int reg=0; reg<32; reg++){
                    // std::cout << ((reg^this->rd)&~this->rd_t0) << ", ";
                    if(((reg^this->rs2)&~this->rs2_t0) == 0) printf("r%02i,",reg); // untainted bits match
                }
                std::cout << ")\t";
            }

        }

        R12DInstruction *copy(){
            if(inject_taint) return new R12DInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new R12DInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};

class ImmRdInstruction: public virtual Instruction{
    public:
        ImmRdInstruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"IMMRD"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        ImmRdInstruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"IMMRD"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t rd;
        uint32_t imm;

        uint32_t rd_t0;
        uint32_t imm_t0;

        uint32_t get_binary(){
            assert(bytecode==(imm&IMMU_MASK)<<IMMU_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            imm = (bytecode>>IMMU_BIT)&IMMU_MASK;
            rd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(imm&IMMU_MASK)<<IMMU_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0 ==(imm_t0&IMMU_MASK)<<IMMU_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }

        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            imm_t0 = (bytecode_t0>>IMMU_BIT)&IMMU_MASK;
            rd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0 ==(imm_t0&IMMU_MASK)<<IMMU_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->rd_t0) printf("\033[1;31mr%02i\033[1;0m",this->rd);
            else printf("r%02i",this->rd);
            std::cout << " ";
            if(this->imm_t0) printf("\033[1;31mr%05i\033[1;0m",this->imm);
            else printf("r%05i",this->imm);
        }

        ImmRdInstruction *copy(){
            if(inject_taint) return new ImmRdInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0,this->i_str);
            return new ImmRdInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};


class FloatToIntInstruction: public virtual Instruction{
    public:
        FloatToIntInstruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"F2I"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        FloatToIntInstruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"F2I"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t rd;
        uint32_t rm; // rounding mode
        uint32_t fmt;
        uint32_t frs1;
        uint32_t funct5;

        uint32_t rd_t0;
        uint32_t rm_t0;
        uint32_t fmt_t0;
        uint32_t frs1_t0;
        uint32_t funct5_t0;

        uint32_t get_binary(){
            assert(bytecode==(funct5&FUNCT5_MASK)<<FUNCT5_BIT | (fmt&FMT_MASK)<<FMT_BIT | (frs1&RS1_MASK)<<RS1_BIT | (rm&RM_MASK)<<RM_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            frs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            fmt = (bytecode>>FMT_BIT)&FMT_MASK;
            rm = (bytecode>>RM_BIT)&RM_MASK;
            funct5 = (bytecode>>FUNCT5_BIT)&FUNCT5_MASK;
            rd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(funct5&FUNCT5_MASK)<<FUNCT5_BIT | (fmt&FMT_MASK)<<FMT_BIT | (frs1&RS1_MASK)<<RS1_BIT | (rm&RM_MASK)<<RM_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0==(funct5_t0&FUNCT5_MASK)<<FUNCT5_BIT | (fmt_t0&FMT_MASK)<<FMT_BIT | (frs1_t0&RS1_MASK)<<RS1_BIT | (rm_t0&RM_MASK)<<RM_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }
        
        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            frs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            funct5_t0 = (bytecode_t0>>FUNCT5_BIT)&FUNCT5_MASK;
            fmt_t0 =  (bytecode_t0>>FMT_BIT)&FMT_MASK;
            rm_t0 =  (bytecode_t0>>RM_BIT)&RM_MASK;
            rd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0==(funct5_t0&FUNCT5_MASK)<<FUNCT5_BIT | (fmt_t0&FMT_MASK)<<FMT_BIT | (frs1_t0&RS1_MASK)<<RS1_BIT | (rm_t0&RM_MASK)<<RM_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0 || this->funct5_t0 || this->rm_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->rd_t0) printf("\033[1;31mr%02i\033[1;0m",this->rd);
            else printf("r%02i",this->rd);
            std::cout << " ";
            if(this->frs1_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs1);
            else printf("fr%02i",this->frs1);
        }

        FloatToIntInstruction *copy(){
            if(inject_taint) return new FloatToIntInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new FloatToIntInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};


class IntToFloatInstruction: public virtual Instruction{
    public:
        IntToFloatInstruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"I2F"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        IntToFloatInstruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"I2F"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t frd;
        uint32_t rm; // rounding mode
        uint32_t fmt;
        uint32_t rs1;
        uint32_t funct5;

        uint32_t frd_t0;
        uint32_t rm_t0;
        uint32_t fmt_t0;
        uint32_t rs1_t0;
        uint32_t funct5_t0;

        uint32_t get_binary(){
            assert(bytecode==(funct5&FUNCT5_MASK)<<FUNCT5_BIT | (fmt&FMT_MASK)<<FMT_BIT | (rs1&RS1_MASK)<<RS1_BIT | (rm&RM_MASK)<<RM_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            rs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            fmt = (bytecode>>FMT_BIT)&FMT_MASK;
            rm = (bytecode>>RM_BIT)&RM_MASK;
            funct5 = (bytecode>>FUNCT5_BIT)&FUNCT5_MASK;
            frd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(funct5&FUNCT5_MASK)<<FUNCT5_BIT | (fmt&FMT_MASK)<<FMT_BIT | (rs1&RS1_MASK)<<RS1_BIT | (rm&RM_MASK)<<RM_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0==(funct5_t0&FUNCT5_MASK)<<FUNCT5_BIT | (fmt_t0&FMT_MASK)<<FMT_BIT | (rs1_t0&RS1_MASK)<<RS1_BIT | (rm_t0&RM_MASK)<<RM_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }
        
        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            rs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            funct5_t0 = (bytecode_t0>>FUNCT5_BIT)&FUNCT5_MASK;
            fmt_t0 =  (bytecode_t0>>FMT_BIT)&FMT_MASK;
            rm_t0 =  (bytecode_t0>>RM_BIT)&RM_MASK;
            frd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0==(funct5_t0&FUNCT5_MASK)<<FUNCT5_BIT | (fmt_t0&FMT_MASK)<<FMT_BIT | (rs1_t0&RS1_MASK)<<RS1_BIT | (rm_t0&RM_MASK)<<RM_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0 || this->funct5_t0 || this->rm_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->frd_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frd);
            else printf("fr%02i",this->frd);
            std::cout << " ";
            if(this->rs1_t0) printf("\033[1;31mr%02i\033[1;0m",this->rs1);
            else printf("r%02i",this->rs1);
        }

        IntToFloatInstruction *copy(){
            if(inject_taint) return new IntToFloatInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new IntToFloatInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};





class Float4Instruction: public virtual Instruction{
    public:
        Float4Instruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"F4"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        Float4Instruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"F4"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t frd;
        uint32_t rm; // rounding mode
        uint32_t frs1;
        uint32_t frs2;
        uint32_t frs3;

        uint32_t frd_t0;
        uint32_t rm_t0;
        uint32_t frs1_t0;
        uint32_t frs2_t0;
        uint32_t frs3_t0;

        uint32_t get_binary(){
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (frs2&RS2_MASK)<<RS2_BIT | (frs3&RS3_MASK)<<RS3_BIT | (rm&RM_MASK)<<RM_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            frs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            frs2 = (bytecode>>RS2_BIT)&RS2_MASK;
            frs3 = (bytecode>>RS3_BIT)&RS3_MASK;
            rm = (bytecode>>RM_BIT)&RM_MASK;
            frd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (frs2&RS2_MASK)<<RS2_BIT | (frs3&RS3_MASK)<<RS3_BIT | (rm&RM_MASK)<<RM_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (frs2_t0&RS2_MASK)<<RS2_BIT | (frs3_t0&RS3_MASK)<<RS3_BIT | (rm_t0&RM_MASK)<<RM_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }
        
        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            frs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            frs2_t0 = (bytecode_t0>>RS2_BIT)&RS2_MASK;
            frs3_t0 = (bytecode_t0>>RS3_BIT)&RS3_MASK;
            rm_t0 =  (bytecode_t0>>RM_BIT)&RM_MASK;
            frd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (frs2_t0&RS2_MASK)<<RS2_BIT | (frs3_t0&RS3_MASK)<<RS3_BIT | (rm_t0&RM_MASK)<<RM_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0 || this->rm_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->frd_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frd);
            else printf("fr%02i",this->frd);
            std::cout << " ";
            if(this->frs1_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs1);
            else printf("fr%02i",this->frs1);
            std::cout << " ";
            if(this->frs2_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs2);
            else printf("fr%02i",this->frs2);
            std::cout << " ";
            if(this->frs3_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs3);
            else printf("fr%02i",this->frs3);
        }

        Float4Instruction *copy(){
            if(inject_taint) return new Float4Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new Float4Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};




class Float3Instruction: public virtual Instruction{
    public:
        Float3Instruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"F3"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        Float3Instruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"F3"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t frd;
        uint32_t rm; // rounding mode
        uint32_t frs1;
        uint32_t frs2;

        uint32_t frd_t0;
        uint32_t rm_t0;
        uint32_t frs1_t0;
        uint32_t frs2_t0;

        uint32_t get_binary(){
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (frs2&RS2_MASK)<<RS2_BIT | (rm&RM_MASK)<<RM_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            frs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            frs2 = (bytecode>>RS2_BIT)&RS2_MASK;
            rm = (bytecode>>RM_BIT)&RM_MASK;
            frd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (frs2&RS2_MASK)<<RS2_BIT| (rm&RM_MASK)<<RM_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (frs2_t0&RS2_MASK)<<RS2_BIT | (rm_t0&RM_MASK)<<RM_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }
        
        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            frs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            frs2_t0 = (bytecode_t0>>RS2_BIT)&RS2_MASK;
            rm_t0 =  (bytecode_t0>>RM_BIT)&RM_MASK;
            frd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (frs2_t0&RS2_MASK)<<RS2_BIT | (rm_t0&RM_MASK)<<RM_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0 || this->rm_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->frd_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frd);
            else printf("fr%02i",this->frd);
            std::cout << " ";
            if(this->frs1_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs1);
            else printf("fr%02i",this->frs1);
            std::cout << " ";
            if(this->frs2_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs2);
            else printf("fr%02i",this->frs2);
        }

        Float3Instruction *copy(){
            if(inject_taint) return new Float3Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new Float3Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};



class Float3NoRmInstruction: public virtual Instruction{
    public:
        Float3NoRmInstruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"F3NORM"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        Float3NoRmInstruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"F3NORM"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t frd;
        uint32_t frs1;
        uint32_t frs2;

        uint32_t frd_t0;
        uint32_t frs1_t0;
        uint32_t frs2_t0;

        uint32_t get_binary(){
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (frs2&RS2_MASK)<<RS2_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            frs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            frs2 = (bytecode>>RS2_BIT)&RS2_MASK;
            frd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (frs2&RS2_MASK)<<RS2_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (frs2_t0&RS2_MASK)<<RS2_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }
        
        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            frs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            frs2_t0 = (bytecode_t0>>RS2_BIT)&RS2_MASK;
            frd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (frs2_t0&RS2_MASK)<<RS2_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->frd_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frd);
            else printf("fr%02i",this->frd);
            std::cout << " ";
            if(this->frs1_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs1);
            else printf("fr%02i",this->frs1);
            std::cout << " ";
            if(this->frs2_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs2);
            else printf("fr%02i",this->frs2);
        }

        Float3NoRmInstruction *copy(){
            if(inject_taint) return new Float3NoRmInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new Float3NoRmInstruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};



class Float2Instruction: public virtual Instruction{
    public:
        Float2Instruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"F2"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        Float2Instruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"F2"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t frd;
        uint32_t frs1;

        uint32_t frd_t0;
        uint32_t frs1_t0;

        uint32_t get_binary(){
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            frs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            frd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }
        
        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            frs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            frd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->frd_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frd);
            else printf("fr%02i",this->frd);
            std::cout << " ";
            if(this->frs1_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs1);
            else printf("fr%02i",this->frs1);
        }

        Float2Instruction *copy(){
            if(inject_taint) return new Float2Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new Float2Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};


class FloatIntRd2Instruction: public virtual Instruction{
    public:
        FloatIntRd2Instruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"FIRD2"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        FloatIntRd2Instruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"FIRD2"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t rd;
        uint32_t frs1;
        uint32_t frs2;

        uint32_t rd_t0;
        uint32_t frs1_t0;
        uint32_t frs2_t0;

        uint32_t get_binary(){
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (frs2&RS2_MASK)<<RS2_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            frs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            frs2 = (bytecode>>RS2_BIT)&RS2_MASK;
            rd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (frs2&RS2_MASK)<<RS2_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (frs2_t0&RS2_MASK)<<RS2_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }
        
        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            frs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            frs2_t0 = (bytecode_t0>>RS2_BIT)&RS2_MASK;
            rd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (frs2_t0&RS2_MASK)<<RS2_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->rd_t0) printf("\033[1;31mr%02i\033[1;0m",this->rd);
            else printf("r%02i",this->rd);
            std::cout << " ";
            if(this->frs1_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs1);
            else printf("fr%02i",this->frs1);
            std::cout << " ";
            if(this->frs2_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs2);
            else printf("fr%02i",this->frs2);
        }

        FloatIntRd2Instruction *copy(){
            if(inject_taint) return new FloatIntRd2Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new FloatIntRd2Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};




class FloatIntRd1Instruction: public virtual Instruction{
    public:
        FloatIntRd1Instruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"FIRD1"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        FloatIntRd1Instruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"FIRD1"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t rd;
        uint32_t frs1;

        uint32_t rd_t0;
        uint32_t frs1_t0;

        uint32_t get_binary(){
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            frs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            rd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(frs1&RS1_MASK)<<RS1_BIT | (rd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }
        
        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            frs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            rd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0==(frs1_t0&RS1_MASK)<<RS1_BIT | (rd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->rd_t0) printf("\033[1;31mr%02i\033[1;0m",this->rd);
            else printf("r%02i",this->rd);
            std::cout << " ";
            if(this->frs1_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frs1);
            else printf("fr%02i",this->frs1);
        }

        FloatIntRd1Instruction *copy(){
            if(inject_taint) return new FloatIntRd1Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new FloatIntRd1Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};


class FloatIntRs1Instruction: public virtual Instruction{
    public:
        FloatIntRs1Instruction(uint32_t addr, uint32_t bytecode, std::string i_str): Instruction(addr,true,false,i_str,"FIRD1"){
            this->set_binary(bytecode);
            this->set_binary_t0(0x0);
        };

        FloatIntRs1Instruction(uint32_t addr, uint32_t bytecode, uint32_t bytecode_t0, std::string i_str): Instruction(addr,true,true,i_str,"FIRD1"){
            this->set_binary(bytecode);
            this->set_binary_t0(bytecode_t0);
        };

        uint32_t frd;
        uint32_t rs1;

        uint32_t frd_t0;
        uint32_t rs1_t0;

        uint32_t get_binary(){
            assert(bytecode==(rs1&RS1_MASK)<<RS1_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode;
        }

        void set_binary(uint32_t bytecode){
            this->bytecode = bytecode;
            rs1 = (bytecode>>RS1_BIT)&RS1_MASK;
            frd = (bytecode>>RD_BIT)&RD_MASK;
            opcode = (bytecode>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode==(rs1&RS1_MASK)<<RS1_BIT | (frd&RD_MASK)<<RD_BIT | (opcode&OPCODE_MASK)<<OPCODE_BIT);
        }

        uint32_t get_binary_t0(){
            assert(bytecode_t0==(rs1_t0&RS1_MASK)<<RS1_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
            return bytecode_t0;
        }
        
        void set_binary_t0(uint32_t bytecode_t0){
            this->bytecode_t0 = bytecode_t0;
            rs1_t0 = (bytecode_t0>>RS1_BIT)&RS1_MASK;
            frd_t0 = (bytecode_t0>>RD_BIT)&RD_MASK;
            opcode_t0 = (bytecode_t0>>OPCODE_BIT)&OPCODE_MASK;
            assert(bytecode_t0==(rs1_t0&RS1_MASK)<<RS1_BIT | (frd_t0&RD_MASK)<<RD_BIT | (opcode_t0&OPCODE_MASK)<<OPCODE_BIT);
        }

        void decode(){
            if(this->opcode_t0) printf("\033[1;31m%10s\033[1;0m",this->i_str.c_str());
            else printf("%10s",this->i_str.c_str());
            std::cout << " ";
            if(this->frd_t0) printf("\033[1;31mfr%02i\033[1;0m",this->frd);
            else printf("fr%02i",this->frd);
            std::cout << " ";
            if(this->rs1_t0) printf("\033[1;31mr%02i\033[1;0m",this->rs1);
            else printf("r%02i",this->rs1);
        }

        FloatIntRs1Instruction *copy(){
            if(inject_taint) return new FloatIntRs1Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->bytecode_t0, this->i_str);
            return new FloatIntRs1Instruction((this->addr<<DATA_WIDTH_BYTES_LOG2)+this->alignment, this->bytecode, this->i_str);
        }
};







