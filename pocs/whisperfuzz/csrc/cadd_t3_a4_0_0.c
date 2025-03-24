#include <stdio.h>
#include <stdint.h>

int main(void){
    uint64_t time1=0;
    uint64_t time2=0;
    uint64_t diff=0;
    uint64_t result=0;
    uint64_t *regdump_addr = 0x10;
    uint64_t *stopsig_addr = 0x00;


    asm volatile ("li a4, 0");
    asm volatile ("li a7, 0");

    asm volatile ( "CSRR %[out], mcycle"
    : [out] "=r" (time1)
    :
    :);

    asm volatile ( "c.add  t3, a4" );

    asm volatile ( "CSRR %[out], mcycle"
    : [out] "=r" (time2)
    :
    :);
    diff = time2 - time1;

    asm volatile ( "add %[out], zero, a3"
    : [out] "=r" (result)
    :
    :);

    // printf("Time diff:%ld:%ld:c.add  t3, a4:0:0\n", diff, result);
    *regdump_addr = diff;
    *stopsig_addr = 0x0;
    while(1);
}
