#include <stdio.h>
#include <stdint.h>
#define N_RUNS 10
int main(void){
    uint64_t time1=0;
    uint64_t time2=0;
    uint64_t diff1=0;
    uint64_t diff2=0; 
    uint8_t *data = 0x80005000;
    volatile uint8_t dummy;
    uint64_t result=0;
    uint64_t *regdump_addr = 0x60000010;
    uint64_t *stopsig_addr = 0x60000000;

    for(int i=0; i<N_RUNS; i++){
            asm volatile ( "CSRR %[out], mcycle"
            : [out] "=r" (time1)
            :
            :);
            asm volatile("fence");
            dummy = data[63];
            asm volatile("fence");

            asm volatile ( "CSRR %[out], mcycle"
            : [out] "=r" (time2)
            :
            :);
            diff1 = time2 - time1;

            *regdump_addr = diff1;
    }

    *stopsig_addr = 0x0;
    asm volatile("fence");
    while(1);
}

void transient(uint64_t idx){
    asm volatile("sfence.vma zero, zero");
    


}