/* entry.S */

#include "encoding.h"
#include "template.h"

#if __riscv_xlen == 64
# define STORE    sd
# define LOAD     ld
# define REGBYTES 8
#else
# define STORE    sw
# define LOAD     lw
# define REGBYTES 4
#endif

#if TARGET == Boom || ISA == 1
#define PASS 1
#define FAIL 3
#else // Nutshell
#define PASS 0
#define FAIL 1
#endif

#define STACK_TOP (_end + 4096)

#if ATTACK == U2M && COMMIT == VICTIM
# error
#endif


#if ATTACK == U2S && COMMIT == VICTIM
#define v(sym) sym + USR_OFFSET
#else
#define v(sym) sym
#endif

#define vfn0 v(fn0)
#define vfn1 v(fn1)
#define vfn2 v(fn2)
#define vfn3 v(fn3)
#define vfn4 v(fn4)

#define vdata0 v(data0)
#define vdata1 v(data1)
#define vdata2 v(data2)
#define vdata3 v(data3)
#define vdata4 v(data4)
#define vdata5 v(data5)
#define vdata6 v(data5)
#define vdata7 v(data5)

    .section ".text","ax",@progbits
    .global _start
    .align 2
_start:
    j handle_reset

    /* NMI vector */
    .align 2
nmi_vector:
    j nmi_vector

    .global mtvec_handler
    .align 2
mtvec_handler:
    li a0, 1
    slli a0, a0, 63
    addi a0, a0, IRQ_M_EXT
    csrr t0, mcause
    bne a0, t0, 1f
    j xcpt
1:
#if ATTACK == S2M || ATTACK == U2M
#if COMMIT == VICTIM
    li gp, PASS
#else // ATTACKER
    li gp, FAIL
#endif // COMMIT
#else // U2S
    li gp, FAIL
#endif // ATTACK
    sim_exit

    .global stvec_handler
    .align 2
stvec_handler:
#if ATTACK == S2M
#if COMMIT == ATTACKER
    spdoc_check_c
#endif
    li gp, PASS
#elif ATTACK == U2M // && COMMIT == ATTACKER
    li a0, CAUSE_USER_ECALL
    csrr t0, scause
    li gp, PASS
    beq a0, t0, 1f
    li gp, FAIL
1:
#else // U2S
#if COMMIT == VICTIM
    li gp, PASS
#else
    li a0, CAUSE_USER_ECALL
    csrr t0, scause
    li gp, PASS
    beq a0, t0, 1f
    li gp, FAIL
1:
#endif // COMMIT
#endif // ATTACK
    sim_exit

handle_reset:
#if TARGET == Boom
    csrwi pmpcfg0, 0
#endif
    csrwi mstatus, 0

    /* Init xregs */
    li x1,  0
    li x2,  0
    li x3,  0
    li x4,  0
    li x5,  0
    li x6,  0
    li x7,  0
    li x8,  0
    li x9,  0
    li x10, 0
    li x11, 0
    li x12, 0
    li x13, 0
    li x14, 0
    li x15, 0
    li x16, 0
    li x17, 0
    li x18, 0
    li x19, 0
    li x20, 0
    li x21, 0
    li x22, 0
    li x23, 0
    li x24, 0
    li x25, 0
    li x26, 0
    li x27, 0
    li x28, 0
    li x29, 0
    li x30, 0
    li x31, 0

#if TARGET == Boom
    /* Init fregs */
    li a0, (MSTATUS_FS & (MSTATUS_FS >> 0))
    csrs mstatus, a0
    csrwi fcsr, 0
    fcvt.d.l f0,  zero
    fcvt.d.l f1,  zero
    fcvt.d.l f2,  zero
    fcvt.d.l f3,  zero
    fcvt.d.l f4,  zero
    fcvt.d.l f5,  zero
    fcvt.d.l f6,  zero
    fcvt.d.l f7,  zero
    fcvt.d.l f8,  zero
    fcvt.d.l f9,  zero
    fcvt.d.l f10, zero
    fcvt.d.l f11, zero
    fcvt.d.l f12, zero
    fcvt.d.l f13, zero
    fcvt.d.l f14, zero
    fcvt.d.l f15, zero
    fcvt.d.l f16, zero
    fcvt.d.l f17, zero
    fcvt.d.l f18, zero
    fcvt.d.l f19, zero
    fcvt.d.l f20, zero
    fcvt.d.l f21, zero
    fcvt.d.l f22, zero
    fcvt.d.l f23, zero
    fcvt.d.l f24, zero
    fcvt.d.l f25, zero
    fcvt.d.l f26, zero
    fcvt.d.l f27, zero
    fcvt.d.l f28, zero
    fcvt.d.l f29, zero
    fcvt.d.l f30, zero
    fcvt.d.l f31, zero
#endif

    la t0, mtvec_handler
    csrw mtvec, t0
    la t0, stvec_handler
    csrw stvec, t0

    la sp, STACK_TOP

    /* Memory layout configuration */
#if TARGET == Boom
    call pmp_boot
#endif
    call vm_boot

    /* Enable S-mode cycle reading */
    li a0, 1
#if TARGET == Boom
    csrs mcounteren, a0
#endif

    /* Set up external interrupt */
    li a0, MSTATUS_MPIE
    csrs mstatus, a0
    li a0, MIP_MEIP
    csrs mie, a0
#if ISA == 1
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
#else
    plic_on
#endif

prefix:
pfx:
pfx.entry:
pfx.bb0:
pfx.bb0.l0:         andi x19, x19, 0x3f8                      
                    la x21, data3                             
                    add x19, x19, x21                         
                    fld f0, 24(x19)                           
pfx.bb0.l1:         andi x20, x20, 0x3f8                      
                    la x19, data6                             
                    add x20, x20, x19                         
                    fld f1, 24(x20)                           
pfx.bb0.l2:         andi x21, x21, 0x3f8                      
                    la x19, data6                             
                    add x21, x21, x19                         
                    fld f2, 8(x21)                            
pfx.bb0.l3:         andi x21, x21, 0x3f8                      
                    la x18, data5                             
                    add x21, x21, x18                         
                    fld f3, 16(x21)                           
pfx.bb0.l4:         andi x22, x22, 0x3f8                      
                    la x21, data3                             
                    add x22, x22, x21                         
                    fld f4, 24(x22)                           
pfx.bb0.l5:         andi x21, x21, 0x3f8                      
                    la x19, data2                             
                    add x21, x21, x19                         
                    fld f5, 0(x21)                            
pfx.bb0.l6:         andi x19, x19, 0x3f8                      
                    la x22, data4                             
                    add x19, x19, x22                         
                    fld f6, 24(x19)                           
pfx.bb0.l7:         andi x21, x21, 0x3f8                      
                    la x19, data2                             
                    add x21, x21, x19                         
                    fld f7, 16(x21)                           
pfx.bb0.l8:         andi x19, x19, 0x3f8                      
                    la x20, data6                             
                    add x19, x19, x20                         
                    fld f8, 8(x19)                            
pfx.bb0.l9:         andi x22, x22, 0x3f8                      
                    la x19, data2                             
                    add x22, x22, x19                         
                    fld f9, 24(x22)                           
pfx.bb0.l10:        addi x18, zero, 1755                      
pfx.bb0.l11:        addi x19, zero, 1460                      
pfx.bb0.l12:        addi x20, zero, 307                       
pfx.bb0.l13:        addi x21, zero, 530                       
pfx.bb0.l14:        addi x22, zero, 187                       
pfx.bb0.l15:        addi x23, zero, 428                       
pfx.bb0.l16:        addi x24, zero, 164                       
pfx.bb0.l17:        addi x25, zero, 1410                      
pfx.bb0.l18:        addi x26, zero, 1103                      
pfx.bb0.l19:        addi x27, zero, 1650                      
pfx.exit:


    /* TODO: Random setting for csrs */

    /* Used for mutation */
    li t5, 1

    /* Return to attacker */
    li a0, MSTATUS_MPP
    csrc mstatus, a0

#if COMMIT == VICTIM
  #if ATTACK == S2M || ATTACK == U2M
    li a0, MSTATUS_MPP
  #else // U2S
    li a0, (MSTATUS_MPP & (MSTATUS_MPP >> 1))
  #endif
    csrs mstatus, a0
#else // ATTACKER
  #if ATTACK == S2M
    li a0, (MSTATUS_MPP & (MSTATUS_MPP >> 1))
    csrs mstatus, a0
  #endif
#endif
    la t0, pre_attack0
    csrw mepc, t0
    mret

recv_end_m:
    cycle_end

    li gp, PASS
    li a1, CAUSE_SUPERVISOR_ECALL
    csrr t0, mcause
    beq a1, t0, 0f
    li gp, FAIL
0:  sim_exit

recv_end_s:
    cycle_end

    li gp, PASS
#if ATTACK == U2M || ATTACK == U2S
    li a1, CAUSE_USER_ECALL
    csrr t0, scause
    beq a1, t0, 0f
    li gp, FAIL
#endif
0:  sim_exit

xcpt:
    /* Disable external interrupt */
    li a0, MSTATUS_MPIE
    csrc mstatus, a0
    li a0, MIP_MEIP
    csrc mie, a0

    la a0, recv_end_m
    csrw mtvec, a0
    la a0, recv_end_s
    csrw stvec, a0

#if ISA == 1
    nop
    nop
    nop
#else
    plic_off
#endif

    cycle_start

    li a0, MSTATUS_MPP
    csrc mstatus, a0
#if ATTACK == S2M
    li a0, (MSTATUS_MPP & (MSTATUS_MPP >> 1))
    csrs mstatus, a0
#endif
    la t0, receive
    csrw mepc, t0
    mret

    .section ".tohost","aw",@progbits
    .align 6
    .global tohost
tohost:     .dword 0
    .align 6
    .global fromhost
fromhost:   .dword 0
    .align 6
    .global timing
timing:     .dword 0


    .section ".text.preattack0"
    .global pre_attack0
    .align 2
pre_attack0:
prp0:
prp0.entry:
prp0.entry.l0:      slliw x20, x22, 1                         
prp0.entry.l1:      fsub.s f0, f1, f2, rne                    
prp0.entry.l2:      fle.d x22, f2, f3                         
prp0.entry.l3:      fsgnjx.d f1, f3, f4                       
prp0.entry.l4:      fcvt.wu.s x21, f4                         
prp0.entry.l5:      sltiu x19, x22, 1780                      
prp0.entry.l6:      add x20, x18, x22                         
prp0.entry.l7:      call fn0                                  
prp0.entry.l8:      fmsub.d f4, f2, f0, f1, dyn               
prp0.entry.l9:      fmadd.d f0, f2, f4, f1, rdn               
prp0.entry.l10:     bltu x19, x18, prp0.bb0                   
prp0.bb0:
prp0.bb0.l0:        fcvt.d.s f2, f2                           
prp0.bb0.l1:        fcvt.d.l f2, x21                          
prp0.bb0.l2:        fmv.w.x f0, x22                           
prp0.bb0.l3:        call fn3                                  
prp0.bb0.l4:        fnmadd.s f0, f2, f1, f4, rne              
prp0.bb0.l5:        sub x18, x19, x21                         
prp0.bb0.l6:        blt x20, x21, prp0.bb1                    
prp0.bb1:
prp0.bb1.l0:        call fn0                                  
prp0.bb1.l1:        fcvt.w.d x22, f3                          
prp0.bb1.l2:        auipc x19, 3921                           
prp0.bb1.l3:        addi x18, x20, 1371                       
prp0.bb1.l4:        fsgnj.d f2, f3, f0                        
prp0.bb1.l5:        call fn0                                  
prp0.bb1.l6:        jal x21, prp0.bb4                         
prp0.bb2:
prp0.bb2.l0:        fnmadd.d f0, f4, f1, f2, rdn              
prp0.bb2.l1:        fdiv.s f4, f1, f0, rdn                    
prp0.bb2.l2:        srliw x19, x20, 30                        
prp0.bb2.l3:        bgeu x20, x19, prp0.bb3                   
prp0.bb2.l4:        fnmsub.d f4, f0, f3, f2, rtz              
prp0.bb2.l5:        fcvt.d.w f3, x22                          
prp0.bb2.l6:        la x18, prp0.bb3                          
                    jalr x19, 0(x18)                          
prp0.bb3:
prp0.bb3.l0:        fcvt.lu.d x20, f3                         
prp0.bb3.l1:        slliw x18, x19, 26                        
prp0.bb3.l2:        fclass.s x20, f4                          
prp0.bb3.l3:        fsqrt.d f2, f1, rmm                       
prp0.bb3.l4:        or x21, x20, x22                          
prp0.bb3.l5:        addi x19, x22, 46                         
prp0.bb3.l6:        fclass.d x19, f3                          
prp0.bb3.l7:        fsqrt.s f0, f3, rup                       
prp0.bb3.l8:        sraiw x20, x19, 19                        
prp0.bb3.l9:        beq x19, x22, prp0.exit                   
prp0.bb4:
prp0.bb4.l0:        call fn0                                  
prp0.bb4.l1:        sub x22, x19, x20                         
prp0.bb4.l2:        fsgnj.d f2, f4, f0                        
prp0.bb4.l3:        xor x18, x20, x19                         
prp0.bb4.l4:        mulhu x22, x21, x18                       
prp0.bb4.l5:        bgeu x18, x21, prp0.exit                  
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      bge x22, x19, prp1.exit                   
prp1.entry.l1:      fsgnjx.s f0, f3, f2                       
prp1.entry.l2:      slli x18, x21, 2                          
prp1.entry.l3:      fcvt.d.lu f4, x20                         
prp1.entry.l4:      fcvt.d.lu f4, x18                         
prp1.entry.l5:      fsgnjn.d f1, f0, f2                       
prp1.entry.l6:      jal x22, prp1.exit                        
prp1.bb0:
prp1.bb0.l0:        fnmsub.d f1, f2, f3, f4, rup              
prp1.bb0.l1:        sltu x18, x19, x21                        
prp1.bb0.l2:        call fn0                                  
prp1.bb0.l3:        fnmadd.d f2, f0, f3, f1, rne              
prp1.bb0.l4:        slli x22, x19, 45                         
prp1.bb0.l5:        fclass.s x20, f3                          
prp1.bb0.l6:        fcvt.w.d x22, f2                          
prp1.bb0.l7:        call fn2                                  
prp1.bb0.l8:        fmax.s f4, f3, f1                         
prp1.bb0.l9:        la x22, prp1.exit                         
                    jalr x20, 0(x22)                          
prp1.bb1:
prp1.bb1.l0:        call fn1                                  
prp1.bb1.l1:        fcvt.s.w f4, x18                          
prp1.bb1.l2:        sltu x19, x21, x22                        
prp1.bb1.l3:        call fn3                                  
prp1.bb1.l4:        fmadd.s f3, f1, f2, f4, rtz               
prp1.bb1.l5:        fadd.s f1, f0, f4, rtz                    
prp1.bb1.l6:        fmadd.s f3, f4, f1, f0, rtz               
prp1.bb1.l7:        bne x22, x19, prp1.exit                   
prp1.bb2:
prp1.bb2.l0:        fmax.d f1, f3, f0                         
prp1.bb2.l1:        fnmadd.d f1, f4, f0, f3, rne              
prp1.bb2.l2:        call fn0                                  
prp1.bb2.l3:        fsub.d f4, f0, f1, rup                    
prp1.bb2.l4:        bne x18, x22, prp1.bb3                    
prp1.bb2.l5:        bge x19, x22, prp1.bb3                    
prp1.bb3:
prp1.bb3.l0:        call fn3                                  
prp1.bb3.l1:        fsgnjn.d f4, f0, f3                       
prp1.bb3.l2:        slli x18, x21, 8                          
prp1.bb3.l3:        fsgnj.s f4, f2, f0                        
prp1.bb3.l4:        call fn1                                  
prp1.bb3.l5:        sraiw x19, x21, 31                        
prp1.bb3.l6:        la x22, prp1.exit                         
                    jalr x18, 0(x22)                          
prp1.bb4:
prp1.bb4.l0:        fmv.x.d x20, f1                           
prp1.bb4.l1:        fmul.d f2, f4, f0, rtz                    
prp1.bb4.l2:        fmax.s f3, f0, f2                         
prp1.bb4.l3:        mulhu x19, x20, x22                       
prp1.bb4.l4:        fcvt.d.l f1, x21                          
prp1.bb4.l5:        fcvt.s.w f3, x20                          
prp1.bb4.l6:        call fn1                                  
prp1.bb4.l7:        fsgnjx.s f2, f3, f0                       
prp1.bb4.l8:        fmul.d f4, f2, f0, dyn                    
prp1.bb4.l9:        auipc x18, 2115                           
prp1.bb4.l10:       la x20, prp1.exit                         
                    jalr x18, 0(x20)                          
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        fclass.d x21, f2                          
tc.entry.l1:        andi x22, x22, 0x3f8                      
                    la x21, data4                             
                    add x22, x22, x21                         
                    amomaxu.w x18, x19, (x22)                 
tc.entry.l2:        andi x22, x22, 0x3f8                      
                    la x19, data4                             
                    add x22, x22, x19                         
                    sd x18, 0(x22)                            
tc.entry.l3:        fcvt.lu.s x18, f0                         
tc.entry.l4:        andi x20, x20, 0x3f8                      
                    la x21, data4                             
                    add x20, x20, x21                         
                    amominu.w x18, x22, (x20)                 
tc.entry.l5:        andi x19, x19, 0x3f8                      
                    la x22, data5                             
                    add x19, x19, x22                         
                    sd x18, 24(x19)                           
tc.entry.l6:        fcvt.wu.d x19, f0                         
tc.entry.l7:        or x20, x21, x19                          
tc.entry.l8:        sra x20, x19, x21                         
tc.entry.l9:        bge x19, x20, tc.bb0                      
tc.bb0:
tc.bb0.l0:          fcvt.d.s f1, f1                           
tc.bb0.l1:          fnmadd.s f0, f1, f3, f4, dyn              
tc.bb0.l2:          fdiv.s f4, f2, f1, rtz                    
tc.bb0.l3:          fmsub.s f4, f3, f1, f0, rne               
tc.bb0.l4:          andi x22, x22, 0x3f8                      
                    la x18, data3                             
                    add x22, x22, x18                         
                    amoadd.w x21, x19, (x22)                  
tc.bb0.l5:          fnmsub.d f4, f1, f3, f2, dyn              
tc.bb0.l6:          call fn1                                  
tc.bb0.l7:          andi x22, x22, 0x3f8                      
                    la x18, data0                             
                    add x22, x22, x18                         
                    amomin.w x20, x19, (x22)                  
tc.bb0.l8:          blt x19, x18, tc.exit                     
tc.bb1:
tc.bb1.l0:          slli x18, x21, 8                          
tc.bb1.l1:          fcvt.s.w f2, x19                          
tc.bb1.l2:          andi x21, x19, 1939                       
tc.bb1.l3:          fmax.d f1, f4, f3                         
tc.bb1.l4:          fclass.d x18, f3                          
tc.bb1.l5:          call fn1                                  
tc.bb1.l6:          remw x22, x20, x21                        
tc.bb1.l7:          srl x18, x22, x20                         
tc.bb1.l8:          bgeu x22, x20, tc.bb2                     
tc.bb2:
tc.bb2.l0:          divw x22, x19, x20                        
tc.bb2.l1:          fcvt.s.l f2, x19                          
tc.bb2.l2:          auipc x21, 497                            
tc.bb2.l3:          fcvt.s.l f4, x20                          
tc.bb2.l4:          fmul.s f2, f4, f1, rdn                    
tc.bb2.l5:          andi x19, x19, 0x3f8                      
                    la x18, data1                             
                    add x19, x19, x18                         
                    amoand.d x21, x20, (x19)                  
tc.bb2.l6:          fence                                     
tc.bb2.l7:          blt x22, x19, tc.bb3                      
tc.bb3:
tc.bb3.l0:          call fn3                                  
tc.bb3.l1:          call fn4                                  
tc.bb3.l2:          fcvt.lu.s x22, f1                         
tc.bb3.l3:          fmadd.s f2, f3, f1, f4, rup               
tc.bb3.l4:          beq x18, x21, tc.bb4                      
tc.bb3.l5:          fcvt.l.s x19, f3                          
tc.bb3.l6:          andi x18, x18, 0x3f8                      
                    la x19, data1                             
                    add x18, x18, x19                         
                    lwu x21, 28(x18)                          
tc.bb3.l7:          andi x18, x18, 0x3f8                      
                    la x21, data1                             
                    add x18, x18, x21                         
                    amomin.w x20, x19, (x18)                  
tc.bb3.l8:          fadd.s f0, f4, f1, rne                    
tc.bb3.l9:          call fn1                                  
tc.bb3.l10:         bge x20, x21, tc.bb4                      
tc.bb4:
tc.bb4.l0:          flt.s x20, f2, f4                         
tc.bb4.l1:          andi x19, x19, 0x3f8                      
                    la x18, data5                             
                    add x19, x19, x18                         
                    sb x21, 3(x19)                            
tc.bb4.l2:          call fn3                                  
tc.bb4.l3:          add x21, x19, x22                         
tc.bb4.l4:          or x22, x19, x18                          
tc.bb4.l5:          fadd.s f3, f0, f1, rup                    
tc.bb4.l6:          sltiu x18, x22, 1511                      
tc.bb4.l7:          andi x21, x21, 0x3f8                      
                    la x20, data2                             
                    add x21, x21, x20                         
                    lhu x22, 18(x21)                          
tc.bb4.l8:          la x18, tc.exit                           
                    jalr x20, 0(x18)                          
tc.exit:
attack_end:
#if ATTACK == S2M
  #if COMMIT == VICTIM
    la t0, mtvec_handler
  #else // ATTACK
    la t0, stvec_handler
  #endif // COMMIT
    jr t0
#elif ATTACK == U2M
  #if COMMIT == VICTIM
    la t0, mtvec_handler
    jr t0
  #else // ATTACK
    ecall
  #endif // COMMIT
#else // U2S
  #if COMMIT == VICTIM
    la t0, stvec_handler
    jr t0
  #else // ATTACK
    ecall
  #endif // COMMIT
#endif // ATTACK

    .align 6
    .global spdoc
spdoc:      .dword 0


    .global shared
    .align 12
shared:
fn0:
fn0.entry:
fn0.entry.l0:       fsgnjn.s f7, f9, f6                       
fn0.entry.l1:       fadd.s f5, f8, f6, rup                    
fn0.entry.l2:       andi x25, x26, 618                        
fn0.entry.l3:       fle.d x25, f7, f5                         
fn0.entry.l4:       fsub.s f8, f5, f7, rup                    
fn0.entry.l5:       fcvt.s.lu f8, x26                         
fn0.entry.l6:       feq.d x26, f5, f6                         
fn0.entry.l7:       fcvt.l.d x25, f9                          
fn0.entry.l8:       slti x25, x24, 1871                       
fn0.entry.l9:       fclass.s x24, f6                          
fn0.entry.l10:      ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       fmadd.s f6, f9, f5, f8, rtz               
fn1.entry.l1:       fmax.d f7, f8, f6                         
fn1.entry.l2:       mul x24, x25, x27                         
fn1.entry.l3:       fcvt.d.wu f5, x27                         
fn1.entry.l4:       mulhsu x27, x25, x24                      
fn1.entry.l5:       ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       fmax.d f6, f7, f5                         
fn2.entry.l1:       mulw x24, x25, x26                        
fn2.entry.l2:       sraiw x27, x25, 22                        
fn2.entry.l3:       fsqrt.s f6, f9, rne                       
fn2.entry.l4:       sra x25, x27, x24                         
fn2.entry.l5:       fsgnj.d f6, f7, f9                        
fn2.entry.l6:       srl x27, x24, x25                         
fn2.entry.l7:       divuw x26, x25, x27                       
fn2.entry.l8:       fsub.s f6, f5, f8, rmm                    
fn2.entry.l9:       and x24, x25, x23                         
fn2.entry.l10:      ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       andi x27, x24, 664                        
fn3.entry.l1:       fmv.x.d x26, f8                           
fn3.entry.l2:       fsub.s f5, f9, f6, dyn                    
fn3.entry.l3:       mul x27, x25, x24                         
fn3.entry.l4:       fcvt.d.s f6, f6                           
fn3.entry.l5:       ret                                       
fn3.exit:
fn4:
.align 8
fn4.entry:
fn4.entry.l0:       fmax.s f6, f9, f7                         
fn4.entry.l1:       fcvt.d.lu f9, x23                         
fn4.entry.l2:       fsgnjx.d f5, f7, f9                       
fn4.entry.l3:       addiw x26, x27, 360                       
fn4.entry.l4:       fcvt.s.l f8, x26                          
fn4.entry.l5:       lui x23, 303                              
fn4.entry.l6:       slti x27, x25, 1253                       
fn4.entry.l7:       fadd.s f8, f7, f9, rne                    
fn4.entry.l8:       slli x24, x23, 48                         
fn4.entry.l9:       remw x23, x27, x25                        
fn4.entry.l10:      ret                                       
fn4.exit:
shared_end:


    .section ".text.receive","ax",@progbits
    .global receive
    .align 2
receive:
receive_end:
    ecall


    .section ".data","aw",@progbits
    .global data
data:
    .align 12
data0:
    .dword 0xec3c15b0a9ee5daf, 0x98b004fe949767da
    .dword 0x226c6cd31256bb20, 0xbff0b65863c4f83
    .dword 0x47f789bfe9d311ea, 0xa7a521bb4afb1bd2
    .dword 0x7a3617e119503b89, 0xabd59cff53b40e2d
    .dword 0xdf319707b846e3b6, 0x3e99a369d8232daf
    .dword 0x85391c73accc622a, 0x23845d9fe5c33a45
    .dword 0x4e4132894697dd36, 0x4eaff6a97ca8936c
    .dword 0x1a9b82b08c235fcc, 0x8e1cb056ec5bac1f
    .dword 0xc48a7e518bdc11ed, 0x4dc869ee2b059b7f
    .dword 0x9ddec5b43e4184e, 0x65ec6597f25293d2
    .dword 0x82753ded4bfaaa64, 0x2accf7b884c34cff
    .dword 0x5e078a905c4dd42c, 0x1e04890c90840893
    .dword 0xbb61f9426e592f06, 0x3f980fe45f895644
    .dword 0x2f0e8d6707fad8cb, 0xbaa670be735db3ee
    .dword 0x5db4ce99ed9afae1, 0xd71986785fd06719
    .dword 0xcd59e698855ef6fd, 0x14c6bae330ca40cf
    .dword 0x59c4d61f006dea0e, 0x9bd3e8d6b370dfa6
    .dword 0x847b66d79d558379, 0xb242876c413c8832
    .dword 0x473289b53f56ca93, 0x40cb2acbebee7f4
    .dword 0x1f6584f5030fe8d1, 0x541839d026a9b9c0
    .dword 0x44e55fa7c01903d9, 0xb6b2d6b249609acd
    .dword 0xced43ef6c308ac2c, 0xc8c17c90274a7968
    .dword 0x1812062cf9949a64, 0x1ea6390deb51a042
    .dword 0x79153c79d463977f, 0x9be63fe92aee9011
    .dword 0x895e5034f73d352e, 0xe6a1baa936b2982b
    .dword 0x938bc83c2f41d6df, 0x9d1b0285183bc1d5
    .dword 0x7f5caf7f56ac4483, 0x9ac043e72b35dc51
    .dword 0x3b20544780c3d982, 0x6dd525c5ba611c0d
    .dword 0xa5a8ea1530c3ffec, 0xfc29d9c6168e1fa
    .dword 0x803ed00ac4e04239, 0xddfa856e5fa5f04b
    .dword 0xe8b9b7d67cca0c45, 0xf5e0b49496ecc8b6
    .dword 0x4146f11ce230adb9, 0x940953796680696
    .dword 0xdf9cb879b8146791, 0x6341b5683f24f8a8
    .dword 0xe70bc71407991308, 0x679c77d6f11ec001
    .dword 0xf46e2d4f683cfcae, 0x6ad979272df9899d
    .dword 0x384ac048957c691d, 0xed68aa3208a25201
    .dword 0x2cbb1afc3bf94beb, 0xec107e75ccafef29
    .dword 0xca9073ae2a96220d, 0xfaca0ee3a41a1286
    .dword 0x9c6d0ca93a1d6b9b, 0xa2dfa433468a8374
    .dword 0x958435b0dccfcc56, 0xc0153f84f313ccf5
    .dword 0x420f661b6479bd38, 0x2158c1bf4dd06035
    .dword 0xc82a17faf188a9b, 0xfbeca81bac59ce3f
    .dword 0xad07cbb6d5940b70, 0x1734c4c541615991
    .dword 0xf253680179710e6a, 0x4cd02cbfb79e7b8f
    .dword 0x4dc9b58b9faa0ad1, 0xc11dd12085b9a868
    .dword 0xc51206d1a6c1021d, 0xd93baac6347f85e3
    .dword 0x898c33aaa1563ddb, 0x11c8249908c2c7e
    .dword 0x8342cafa92dbc315, 0x2dcee06b24935b6
    .dword 0xd7839cc73fc32379, 0x13e82c0d88e3540e
    .dword 0xe038839dc649e9a8, 0xf77a7e1817997fe4
    .dword 0x583d5eea32da93ad, 0xa68f75702843320f
    .dword 0x8b58df8a868a881c, 0xb6494dde3949389c
    .dword 0xfafc267c79548a87, 0x418d042683d3ad46
    .dword 0x3793e3596f8e2f94, 0x84d7f33542d2e092
    .dword 0x139642d78aa33ba8, 0xde1559010a6c5fff
    .dword 0x7f7c1e2d40eafc46, 0xf550fec40d5c2fa3
    .dword 0x80d7ac27df6862de, 0xf5aad0975509afa0
    .dword 0xb8aba5cb6b94237f, 0xc6003e45d3a8c9bb
    .dword 0xc4938a5cd58ba118, 0xb23e5cddc0e4f0c4
    .dword 0x4dc41ff556d89de2, 0x4d7c2aaa0bda8a78
    .dword 0x5d86d05b01ad30db, 0xf40a80768a72e673
    .dword 0x50300e132d15626d, 0x2e2231304a90ef6d
    .dword 0x94946690367fbdfe, 0xd3ea9dbf33aa5ead
    .dword 0xffc5c25bdaafed73, 0xa30b5bcc0b53d757

    .align 12
data1:
    .dword 0x273530602a4f2441, 0xb844b34ef54024b2
    .dword 0x1d0872830b60a28a, 0xebe8004eb1e2d4ac
    .dword 0x2d6a385cbc17331a, 0x3cba342a0c71ab99
    .dword 0xe0fdaf53cf1b0284, 0x354ca507695c4cd4
    .dword 0x6c55ae2d92f88c47, 0x82358d19c4d578d1
    .dword 0xb35583dc88c72311, 0x3f2449085b94d8a5
    .dword 0x32d6470bdb76082b, 0x9fef2d5e17d8ee99
    .dword 0xc8de945f3555040e, 0xa982de77da851c4b
    .dword 0xcf1fae3509d65590, 0xb836fa70c269e6e5
    .dword 0x343f1a922f47ba24, 0x55678bd9f84946c4
    .dword 0xc748127c3b03e8fc, 0xe29c2898969d5c61
    .dword 0x5f5986d11a9c837a, 0x2d5a214dac4bb364
    .dword 0xd9c4c0c24711d217, 0x15b90ddcc412b2ec
    .dword 0x78980f5021a37db4, 0xebd502649526e3ba
    .dword 0xbf3cb4d39bd9cbb8, 0x1ede6baf661aec0a
    .dword 0xf2a101ea430a9407, 0x4ce4aa530dd87a80
    .dword 0x2994b7039a767356, 0x8238692ece49bdee
    .dword 0xb04fd3adf824de08, 0xf54ecc34a3d25d3b
    .dword 0x71fa0cdfc28319dd, 0x14cd56ae90966676
    .dword 0x4cc32edf652fb8d5, 0x73dce785dbda778b
    .dword 0x59c62f78f56891c1, 0x910e111bf20fcc0d
    .dword 0x5ae6b16ca674108a, 0x9bd1f18f29580a15
    .dword 0xbe655078041bb4e9, 0x102cec43a26c8e94
    .dword 0x5d89989cac793881, 0xc44f5bbcd36b2b16
    .dword 0x79001522b0b80c99, 0x6344ae2364785ce7
    .dword 0x7c0f61f582e7ae6b, 0xa98879f691275a5
    .dword 0xbcfa30e90dbd0638, 0x2d83cc759e4ae0f5
    .dword 0xa937e41bac630038, 0xe67e12936667c54e
    .dword 0x9f9002969e20af8f, 0x3db85ec8057f5a79
    .dword 0xf9a6ac33a7d3b6dd, 0x1de7b64cab71381c
    .dword 0xb935c3f3ee1eb45, 0x7421847324aa5da0
    .dword 0xfbdd3e3d047d4c88, 0x43c47c02d2d28779
    .dword 0x366c5ac3201ef402, 0xde826d809671be21
    .dword 0x1f5397fe1c3fee47, 0xc30820c9d7963ec1
    .dword 0x4c5be4a0ab9b41d3, 0xd698cd44d7511e1a
    .dword 0x80a4866863df7f63, 0x269079426844f5e3
    .dword 0x7abd74683931c744, 0x2b16991ac0bf60bb
    .dword 0xad3e2c89313b20f1, 0x2496e4f1bede3eb3
    .dword 0x38937a3128f8e057, 0xbb86358a5069f720
    .dword 0xaaebda1608b33413, 0x5544a39059f2777f
    .dword 0x1bbb2b9f9db95130, 0xc69a601ad9432651
    .dword 0x419fea0b4425f088, 0x668b454b6d632c3d
    .dword 0x11a64df666ed077b, 0xa18ef5f8553b25ce
    .dword 0x49380400d3f04c67, 0x80f5e31e955eebf0
    .dword 0xfbafcb54ea6bdde8, 0x9ebdb766345481fe
    .dword 0x8b0a351b1dd3052c, 0x926e1a41474224c4
    .dword 0xda6c8880d03bdc0f, 0x5d684b1ca72b1673
    .dword 0xa42bb91efafe51cd, 0xb2af2e8be5e216af
    .dword 0x5edaceda9e23581f, 0x876ab6d4f194fe0d
    .dword 0xa714a9ccb04adda, 0x7b2952385fb887de
    .dword 0xa2f3cee2f46c89b1, 0x9e70f112a9151695
    .dword 0x84d0070b4fb1c6e7, 0x5f16006c82c284d
    .dword 0x9c16b0eeaa56cd18, 0x67025038683dbea7
    .dword 0x2e6c1aab5a03e773, 0xdede441c5207ba80
    .dword 0x876690afa8a926f8, 0xe483a755b6066998
    .dword 0x68956805f3df36ce, 0x600a5cf78465dee3
    .dword 0xe2aa7c0b8aa61d22, 0x97b7d5a68c5a5d90
    .dword 0x6eda1ca92e314cb9, 0x327098c4644edcd3
    .dword 0x7c1405d8ead71477, 0xbe0d82b1f9335384
    .dword 0x36e2c3060bc983e6, 0x1bf3c5e825bb24cc
    .dword 0x1d15ad45cc28e00c, 0x88a057bdcaffc959
    .dword 0xb3d7695cbcfea760, 0xefd42189da5bf8bd
    .dword 0x4240651da8dfe79, 0xc22d0000bc12a1f
    .dword 0xbbf9609f3076418f, 0xd07c3c51b7abd511

    .align 12
data2:
    .dword 0xe2456414f4191aa1, 0x7a9f90dcf6866ace
    .dword 0xf8440c9b5f43add4, 0xf40717a059ef786d
    .dword 0x92230a0ba9d42d96, 0x884f372184265cc
    .dword 0x3329d499ae3a4108, 0x33115aea95c7ac19
    .dword 0xf0f53a3ef1d2f643, 0xd1a8f5dea21754f3
    .dword 0x1d432f76feecaa07, 0x8bbf0c5cdc15e71d
    .dword 0xea52de103be39753, 0x738de4ef80dfa590
    .dword 0x838c70c537f04905, 0x34ea42a6851409c3
    .dword 0x17a99b7388497c02, 0xc3261b41c0cb7b9
    .dword 0x6199cd3ba31e351e, 0x6ba611bcaad34227
    .dword 0x5337fcc8f1908efd, 0x72a3715e837122c6
    .dword 0x6bb59a9368d4f851, 0x4b60b9b5b410090e
    .dword 0x28661c91341ca67, 0x3e25ba03d454164d
    .dword 0xdd07a1676d5f69e7, 0xc8943233db315d74
    .dword 0x9410fdde4cef2e04, 0xea8f9540806eb5ea
    .dword 0x2b3532bc39851661, 0x5bfbfa2cd73a2b2
    .dword 0xe263c7608102f1c4, 0x99c7d2c3a1f6df2b
    .dword 0xf14ad727a8bab4b6, 0xfef83a9c2209a45e
    .dword 0x31c5f8f058317e94, 0xbbffa10296703e94
    .dword 0x91708e872ee7b743, 0x12b09a246e81802
    .dword 0x6d3aed4d8fc58200, 0x6778e9971eb18918
    .dword 0xf809efbcfaf5f2d7, 0x8a0c074808a79d45
    .dword 0xe27cc13c13d8e480, 0x76207bdd8217de12
    .dword 0x142deb95d95db5fe, 0x34810e8edbd028ca
    .dword 0xee434336332eb90d, 0xffb6a37a76613523
    .dword 0x74b7729fb2746b6a, 0x2c3d3638e5df63ae
    .dword 0xf1e79aff4dfbaed0, 0x292d37b81969a6ac
    .dword 0x8a100ff2d5f23a12, 0x7cef3c85515d4d08
    .dword 0x1fd95abd3632f62c, 0xfb6d17efa1429a4f
    .dword 0x4005db0f2b487b48, 0xab672a8982fb4137
    .dword 0xeba54d4bf63e62ee, 0x917c93810c2fb22b
    .dword 0xc9063ad64441dc23, 0x5e3f76850b0dadda
    .dword 0x29ab8f53066d468f, 0x87b898b6ad992170
    .dword 0x45e571259e3782c1, 0x24c5ef6006791edc
    .dword 0x7263fe2e21a3daa9, 0xb8d0e97908ea7a08
    .dword 0x1bfd5e6f5d4a9dd0, 0x5f7be407723bc6e2
    .dword 0xde3927637d638665, 0x9ba9e06dad7341b
    .dword 0xee5b119f2a402038, 0x5c2f4e15b001e377
    .dword 0xb966a3162c51acf0, 0xf5d87f678cb1bd3c
    .dword 0xd28f2dd7cdea5184, 0xa9a8af2bc185fc91
    .dword 0x7dc6a3d386f75ed1, 0x1c228d168fdeb7d8
    .dword 0x9ed2549ce390f1a, 0xd24c5ff51ba4245a
    .dword 0x490f4b8d1a8f29ba, 0x726dd7b0ce34d75a
    .dword 0x32bf8e13c6b723ab, 0x9f41870c29ef57e2
    .dword 0xe177d4e295d6e899, 0x6ef341c980c8466
    .dword 0x8498dbdfdbcb6a47, 0xb50bc7a234b343cd
    .dword 0x62ac8dfbca9fa23d, 0xfeee4a87373440b8
    .dword 0xea07ca2457736b44, 0xf45553a49854bf12
    .dword 0x3ec7cbcf95492551, 0x8f922864cc541208
    .dword 0xb39fafd04e37494c, 0xb12bc51e0d544632
    .dword 0xfb986a286914926a, 0xc34a65ce417f5cc5
    .dword 0x7212617b5eef446c, 0xf465115811fa60f2
    .dword 0xd37cef8e4a97d7a6, 0x8efed02d249eb9a7
    .dword 0x5ab20e1979f6ac0c, 0x9ca825df7c984b5b
    .dword 0x408dcbffe917b619, 0xc5dcf0d131300938
    .dword 0xccd25363cda55bc7, 0x402ebe45f2caa298
    .dword 0xa74e7ff5a00b9c24, 0x4ef9dd10629de689
    .dword 0x7f33bc781853739d, 0x32350df75c94a09a
    .dword 0xb284fcb0967ad6e7, 0x8d2a797e446b51a8
    .dword 0x6d7310d10da5dbad, 0x7b6e048e43b82fa8
    .dword 0x9986f08dcefda84, 0x30734bb1e13beddf
    .dword 0x40857265e29df6d6, 0x71d6f423c2f5039b
    .dword 0xdc0577dc228cb417, 0x89b7b6e0a48cc874
    .dword 0x2e42d5c1c463e4de, 0xd0c36404b27fbbea

    .align 12
data3:
    .dword 0xb8e71c0bd72d6743, 0xa27e5a73ce8d28f9
    .dword 0x8b5562429198a5b4, 0xed0b091a30073e5c
    .dword 0xf1c4b738e0943d2f, 0xb3a5ba7f41742f87
    .dword 0xfd306b6bc5abd9ab, 0xf3a676aa86626eef
    .dword 0x247e3676fe72166e, 0xe4e0ea7652e534c4
    .dword 0x6ab663436e93a331, 0x6d4c5280092b9e7d
    .dword 0xe2a29e4ed2ba8ab9, 0xaa6ff73e922b256c
    .dword 0x5f0906934b87d407, 0x4579c33b3f9a571f
    .dword 0x6874a8866ab1f038, 0x33ead09d8c782212
    .dword 0xf4eb8f295a7a2b19, 0x100357cb19ef0ef5
    .dword 0x2cb6a5f079820535, 0x45d1f259994b3a1f
    .dword 0x929986a3f5c97a40, 0xd807c44bed170aa8
    .dword 0x46bf54680b3ec944, 0x51dc6f9a4921c6ec
    .dword 0xe9e8aeb9eabaf6c2, 0x5cb03e046f028afe
    .dword 0x428c78112a033d4a, 0x45da12e671c5c871
    .dword 0x8875fcfa4a48ae87, 0x164442f03ce0aa48
    .dword 0xcef85667097252c, 0x9222a6ceaba01bdd
    .dword 0xe8875367d1b1e8cb, 0xa776acf9579a752
    .dword 0x31c2a1c254dce23a, 0x640f4caa0fa13db1
    .dword 0xf48b9c5911c71729, 0xbf5ddd57129ef536
    .dword 0x104786a239cc2a48, 0xa68da54c7bf13422
    .dword 0xd3bb48d58e9bac1c, 0x1946685b8fa931d6
    .dword 0xee7b553d7596eada, 0xcdcccf4e74f713f4
    .dword 0x997bed23d2179e2a, 0xdb6df5086660cff5
    .dword 0x9676df00b5deaa40, 0x24fe3459fe3c497c
    .dword 0xb91ce42e713fc3ba, 0x571f0ddb6d547a4a
    .dword 0x1364f8a65a38004e, 0xe005469199d083af
    .dword 0xcd6c973e2ea8d90e, 0x9b66983836c3648d
    .dword 0xd8cd241aaedba0f8, 0x99d975d41d609f23
    .dword 0xc684654d214631b7, 0xca7bac923fdb6260
    .dword 0x9f887201ba4bc668, 0xe2177bc7411e686
    .dword 0xde9520121844dd37, 0x51528f9caf242068
    .dword 0xbec162f016f70cb6, 0x49feb9e1acdcdae
    .dword 0x9cd4aac0fdbf110c, 0x4b3c4288752b97cc
    .dword 0xa8c8b522890840b2, 0x707f195b852aed60
    .dword 0xbf61f231a1c96ed9, 0x6b7d20a41a5fd5db
    .dword 0xe803212f8afac101, 0xc519563779a94ed7
    .dword 0x5b1f90e96bba051, 0x76fd7b25cc2b3177
    .dword 0x3ee470663ef23010, 0x689dfe45bc8edc9c
    .dword 0xa0d0cff129990b1c, 0x2c76917d5d7611bb
    .dword 0x972fbc9576e399b9, 0x23902e744e8b48
    .dword 0xe665d7cdbe48386b, 0xcc7f6c27b85a798b
    .dword 0x6fe4bd41275c4432, 0x84e0f7ee59a7c9e2
    .dword 0x655f5c3c0092995d, 0x447017d88064c7ba
    .dword 0x6f6cef6267c69ed5, 0xcc979676c00223c6
    .dword 0xa8b7d6a22a3b1560, 0x39b4ff2273bcea61
    .dword 0x3d3506d8b072df24, 0x70d18b514bc14e22
    .dword 0xfbe29901357a941d, 0x97d953261ee9966
    .dword 0x88e84617f1efa338, 0x64d0b8ab171ea8f
    .dword 0x3c0263374fee3364, 0x6ab8e3dda14ec394
    .dword 0x65538ef2fc49d85c, 0x94174c776eb0710d
    .dword 0xe102f51033b5b038, 0xefe12eb8f17f8bbd
    .dword 0xf22fe63f78f4c1a2, 0xe4b5d628729e65b3
    .dword 0x8acf156a7a9a4ab0, 0x96d2b31718e26ad9
    .dword 0xe76b5a04107c083c, 0xcd9a4ff758e026d6
    .dword 0xaca2c0687aaa36f9, 0x629d451f6d510ce7
    .dword 0x32640eba7e484a8f, 0xd9f8b48f45a75009
    .dword 0x93521a0f4e0faebf, 0xd4e66df8ade11b0b
    .dword 0x32b39a847be24b80, 0x51ca14ea156bf500
    .dword 0x82b1e9b54949cc64, 0xf57a82161560e5da
    .dword 0xf3eabf6559658e1e, 0x52e3e6974e2f899
    .dword 0xb239d6535a3a2b33, 0x7297e2d4ef7b1dea
    .dword 0x95f04211c9b9b58a, 0xd466573f5dba7d34
    .dword 0x89bf3821d1bcbf40, 0xa75e7485f0807d0a

    .align 12
data4:
    .dword 0xbe23854584f2db33, 0xe5548e3998ece0d5
    .dword 0x61a5ec82cb33ab76, 0x99096af01abdf0f9
    .dword 0xc404addb806af89c, 0x2331803c04f4742c
    .dword 0xa3b96fc0b637b7d0, 0xfd3e589d4aeee925
    .dword 0xe0bd08cfdf9e299c, 0xb58c237a2bcd1942
    .dword 0x5d4a1eed7f376e66, 0x645e61b110b03cec
    .dword 0x61f19b22fd6304bb, 0x22c2badf2ced27e1
    .dword 0xb48da32d2979f93, 0xa07e8f935ebac8c1
    .dword 0xaf79d283c3485c47, 0x54004cfe8922b538
    .dword 0x49e1d5e1d3c67528, 0x9ee3d13d5d7a6eed
    .dword 0xcec2c645c19a4067, 0x6a7e859e8b84b095
    .dword 0x451b23b7d26b714d, 0x196dc1421cd8d2b2
    .dword 0xfbf952f8c0fef6fe, 0x1b4b0e9f72ed81b2
    .dword 0x61e0922b2fd703ca, 0x23433382b013ff7e
    .dword 0xdd50376666cee534, 0x62c8ecf441b8ceb8
    .dword 0xeb656b04cc4b8c, 0xd76ae8db8766594f
    .dword 0x658ea0dd797994ae, 0x1fe4a45f050e690d
    .dword 0x28a9877dd32b9092, 0xc003aa5e786d22b
    .dword 0xa9b7f9c1e3e5dbf6, 0x3130702f9621ff8f
    .dword 0xe8da50d8ff7ade09, 0xaf871cf5737e8f35
    .dword 0x1b7825f74e1d7212, 0x573cbeebb7a77845
    .dword 0x3e9448c5bfa696a8, 0x5f9f3d5ca84c64bd
    .dword 0xc0fe706531d592eb, 0xd165b9f67e53f5dc
    .dword 0xe9ab9bf27aa82dec, 0xa293248efd383580
    .dword 0xa9ac89db8b072f28, 0x796b2ad712e3dc06
    .dword 0x925cd347176c543b, 0x113e88525ecd06d3
    .dword 0x70c2888c13656a63, 0x6b16a9a596f7955d
    .dword 0x2bb11162e3c4db93, 0x873ddcefb5313235
    .dword 0x1095dbf8db1354ab, 0x1e18aa6190be7656
    .dword 0x6eb07a988a93f0f5, 0xb4aa2da6e14d8a9c
    .dword 0x37941f75ac0705b7, 0x145d99648eee8dae
    .dword 0x130b4af5b869edfc, 0x4bc07998840c9be0
    .dword 0x75060ee7fbe13ca1, 0x15f13207c45438a5
    .dword 0xf44d9380599510ef, 0x65634e62b850a18e
    .dword 0x8160b618e30cfa24, 0xb1e13f025a0ee38c
    .dword 0xe167737c9b01956c, 0xd366d2eb49825bd9
    .dword 0x4cd29261a7b71109, 0xb3427029d1def273
    .dword 0x258ef504e1cd9ff8, 0xe226b878c34631fe
    .dword 0xd64b548f37a4a094, 0xec21764a160273ce
    .dword 0xe0acc64d7273a6d, 0x3c86024e1a49b6e0
    .dword 0xc8e9a7b79ba50c2b, 0xeea7444bb5a5e7f
    .dword 0x110758de782c2d51, 0xfadb037d0566f3d2
    .dword 0x51f904e2c1d022e6, 0x25a3a91380f3d4eb
    .dword 0x92b1b4ce1dad4178, 0x7de80c7d888179e2
    .dword 0xb312a251f217150, 0x51ef86adc5a1a75e
    .dword 0xf15fa94c200012c5, 0x72cd48b3726a5f13
    .dword 0x2a0b8ad2892809fc, 0x84774e96098a296d
    .dword 0xbd8994d495fc6a6, 0xc0d0dc260b3a7dab
    .dword 0x78a9eae809ef156a, 0xbc3f4c41f2dfd5f2
    .dword 0xba3cb100960ffcf0, 0x5e1ef00beb3686f7
    .dword 0xd02ac686200313fc, 0x983dc4ed3430a79a
    .dword 0xf41324cd8678b2f4, 0x342868f530c93b3c
    .dword 0x66e65f4b401a1d03, 0xa3649c01e7171c77
    .dword 0xe2dd32d4a9de8b63, 0x693ff61e3b7b16d7
    .dword 0xc7b6902a65c03183, 0x3fa4e57de94cd5b1
    .dword 0x2986ee4907812942, 0x7db06eae2c5983d4
    .dword 0xd32353cd2888b05b, 0x30dd01ef18aba9dd
    .dword 0x81131db09fe373b9, 0x2ce10e166e6c33fc
    .dword 0x9b69cac61d9276b, 0xe61b861b30b9e0b0
    .dword 0xf30e1cc688f60b9b, 0x87159b089c38ed6c
    .dword 0x8ba31c05e13bf8c2, 0xfac938b8253176ff
    .dword 0x32562ca07ce96f97, 0xbd428ac7b68a6ed1
    .dword 0xbaa0837ae36b425d, 0x6fb1cc6a464520b7
    .dword 0xe76dfb5a64114f17, 0x83349d7518c63bda

    .align 12
data5:
    .dword 0x96b06e0b88c2461d, 0xbd3c581274a26c9c
    .dword 0xd52f840f935197c6, 0x95efadf7abef58d6
    .dword 0xeb22d37b490bc4d6, 0xf1e828442752cffd
    .dword 0x18ea52c7d80a5497, 0x145e8aab4553435f
    .dword 0x3215a82d8f7f30c1, 0x93f418b61935e3de
    .dword 0xaf2d28d599224c1a, 0x2e1f4304c3b9ba47
    .dword 0x7afc06ee58a117c6, 0xd3b22f0273552c66
    .dword 0xbace6c0766a090ab, 0x8e1b49149fe43930
    .dword 0x5e4c58bad3fb1e93, 0x920bec8602768f09
    .dword 0x404391317f5e5c40, 0x16d16efeea789e7c
    .dword 0xeae3baf52d3eda7c, 0x434be61b777bc78b
    .dword 0xd151548f1de7dfba, 0xeb15bc2cd0adf869
    .dword 0x3095f2e69356f057, 0x5f5abb63ff8adbec
    .dword 0x4281800816eb373f, 0x3298c76f7522de0e
    .dword 0xdfaddf0a764b057d, 0x34fe5209334c5c06
    .dword 0xcac859e5fa06721a, 0x34e69ab6e708168e
    .dword 0xd1b1fb4806d70e0d, 0x16a993f2a85b0002
    .dword 0x9cc5b75f4b450a19, 0xe5cf91d8a8118bb6
    .dword 0x79f64c9ff59bef32, 0xf6eeca37ddd93379
    .dword 0x8f92efcad50f99a9, 0x5f6325a77c619b28
    .dword 0x31010ee1d8211ad, 0x18885ec27a1f4cbb
    .dword 0x4568fa58a7cc76e7, 0xa579e82c98b69e22
    .dword 0x42da19f43d183fe8, 0xf7d4004e07077368
    .dword 0x7224d3354bb6cc80, 0xd6a153020ee51752
    .dword 0xb1242ea00d156c4, 0x2432b6734f469039
    .dword 0x5315361d5b21bd29, 0x8967bdd4a12a75db
    .dword 0xb78bd725467bb683, 0x8f4aaf991f736f32
    .dword 0x6064682b25b2b235, 0x220119c4aaafba4
    .dword 0xd5662e6939c26b3a, 0xd38c09486df1a3e9
    .dword 0x6e07c7e2b04ccabc, 0xdd00327370ea3e6b
    .dword 0xb3d64c3a9d138f41, 0xa1d1886f30345007
    .dword 0x40eb7dd038773d99, 0x447a26adcba2fc23
    .dword 0xb64efdf1852e3c7d, 0x284089ef0cbc9ed0
    .dword 0x548667ac9902cf9a, 0xd39b7fe69d869e21
    .dword 0x56aa6aa2713eeb6, 0x32d453cf5a03d7e7
    .dword 0x936f155426348df5, 0xd2bc78428b4e543c
    .dword 0x659456396278cb02, 0x92c57ef23e5ca170
    .dword 0x57132fb9f54d03e1, 0xcce15d11049f3cfa
    .dword 0x4c65ff955879fe6b, 0x197c936edb7b19ef
    .dword 0xf467235ea6fee89c, 0x2489812da0160388
    .dword 0xc90a0a5f52cb9708, 0xcf76d4525ef7d6dd
    .dword 0xd5a4453f8efd7168, 0xd36057bf95a191be
    .dword 0x21916d49e9957670, 0xebfc443177afdf66
    .dword 0x2a2fe9e0ddb7aed2, 0x7665ebe92013ab43
    .dword 0xb3376c49f5f2abb6, 0xe65a4f92db177c8b
    .dword 0x584eae43178c7248, 0x2635c8a0443c9546
    .dword 0x13d3e0f5232d97b5, 0x4811054fe008551d
    .dword 0x2f264930ce55e3eb, 0x46895c1fa657fd80
    .dword 0x9038e8a787170b36, 0xb1e56b29d40f4689
    .dword 0x834a4d7ee2b53582, 0xe4bf58ecb79f8507
    .dword 0xdc89c388cc37e401, 0x570a78ee9d40a838
    .dword 0x612e0237501dc23d, 0x849479a84ab75469
    .dword 0xc1b7704de1d09cdf, 0x8d553f318bf18849
    .dword 0x8adcc10f31c1319c, 0x354801a5e8cbd9da
    .dword 0xea5f8f77c98b2354, 0x291e7fa8213e6203
    .dword 0x94b61d6fc72e19fd, 0x4beb38b8762b6acc
    .dword 0xf8f33b9efb72242, 0xa7a4dade5bbb5f88
    .dword 0x549e2101d7142cba, 0xe6dd1d9ae6f7daa5
    .dword 0xede23e7459d2b3a6, 0x9c23982944861500
    .dword 0x3d15ab65a371356d, 0xf44641ac26a97464
    .dword 0xc2270abce117d742, 0x9270afacc954302f
    .dword 0x99badb2c164cc3a8, 0x9392568d34c86fba
    .dword 0x673750b508e791e1, 0xa311954bb48e6415
    .dword 0x7070fa76ec9edeb6, 0xab3d02343b503138

    .align 12
data6:
    .dword 0xe538c5acab050623, 0x393023158d5245fb
    .dword 0x2b44dab7c9e55eca, 0xd3d323041e2ea287
    .dword 0x1b1ff742f904f62, 0x9341655c6ff06689
    .dword 0xf2aaefc2860ff67e, 0x39bc4a50b45279a
    .dword 0x8d374295d4e8394, 0x195e26521b2cdf2b
    .dword 0x8cdaa4533320610, 0x25b7ec16428ac90b
    .dword 0x64f9514254f462d7, 0xec2d166d027329f4
    .dword 0x1849e7991e9dd19f, 0x68e98a47912d21d2
    .dword 0x847cebd23d08d9b8, 0x8b737dd435cb075d
    .dword 0x4e68db51db412be9, 0x7ef0c1d9849b0843
    .dword 0xe3d779c02bef522d, 0xa0eec691764aa2ac
    .dword 0x23c35594192b6a13, 0xb33b70cb954e8728
    .dword 0xf28c53c055f91e59, 0x7977afad4e196558
    .dword 0x291813b65f50fd4b, 0x8504ffbc2606b736
    .dword 0xad3c90b404cb8747, 0x6b3b00d93913be06
    .dword 0x73313d7c182d8987, 0x26664327b8b090cd
    .dword 0x22cafd458dd3272c, 0x2b078f5a28e346de
    .dword 0xd16d82a4aba0dff0, 0x2490276d3f1b3e61
    .dword 0xd14b74cd199c9bad, 0x3a9de2b776d71dfc
    .dword 0x6f1b276e058fbdb9, 0x9b3e1fb5e390642e
    .dword 0xc9023c1ec8deadbe, 0x95f66e9143fd027b
    .dword 0x49693c18aaa42286, 0xcac4a3ce22c081e7
    .dword 0xbb20bd93c10445df, 0x9937b2cb0920e049
    .dword 0x542a90be614bdf4c, 0x5af1a63e693dfa6
    .dword 0x10cb83c484968170, 0x7fb4feb6162199ea
    .dword 0xbaaa4b5e1c08aad1, 0x57ba418c2523d350
    .dword 0xc1f0293cc063283c, 0x31a9be5ce5577326
    .dword 0x6664d291816795a, 0x81608ca76d59492c
    .dword 0x980636d9690d4d7c, 0xe1f66ecbd974336f
    .dword 0xf7759b1402368aac, 0x5d630e860e2fbe7c
    .dword 0xd9fb7544e0b4cb7b, 0x2016b94297cc86a1
    .dword 0xfa9295ae20238d03, 0x71b298a0bc4564fd
    .dword 0x9ae72f8626655b03, 0x246ebe4c71e6b87c
    .dword 0x7753fe562fa58263, 0x13a27f9b366c71e1
    .dword 0x8e5b451a984b9bcd, 0x6c7de253b0abf52e
    .dword 0x5fee8b7d142461b6, 0x7868c1bd1cfadc71
    .dword 0x5c8426da82a99de6, 0x62d8724f1f741743
    .dword 0x566bc431ce3a6cfc, 0x4b6ec0e966d119ec
    .dword 0x9e7cbc2ea7041fd7, 0xb0ab85fc84658233
    .dword 0xd12ec38bda732e0c, 0x693b900975115e00
    .dword 0x490d582654982154, 0xdf4c98846704986e
    .dword 0xaf9a397e12a93d2e, 0x7946807495a057e8
    .dword 0xc1e55b482bc4770a, 0xd3a2128efbeaa8b5
    .dword 0x6d24ea15e7801606, 0x4aa9cad0b1fedd54
    .dword 0x511f79875a772a2c, 0x60e0c1559da34c8b
    .dword 0x1d7c5556f7f949ad, 0xb5d6d4dfb5f709be
    .dword 0xd9c48abb7059d507, 0x1b6adf3cb585560
    .dword 0xd34126dfd2e4611f, 0x77c95a1b255d6e8c
    .dword 0x78d3c64438755eb4, 0xe240a27d92ab02dd
    .dword 0xe96acd6b2ea33fa3, 0x29084e5c69c46f15
    .dword 0x778d90473e32e9c8, 0x8303bd0aa91c0556
    .dword 0xd7228f6947784f9b, 0x28a3dd61d735112
    .dword 0x5a8aeb3b45f45eca, 0x3a14c7a729a24dd8
    .dword 0x9a45e26798b72774, 0xe0eff50ae30f1fb
    .dword 0xc19e8ee386ee9cf0, 0x6f1b332c76882855
    .dword 0xd82b356f1192bad2, 0xc10bd2a7b2d2eba7
    .dword 0x463e7f079f2e825b, 0x2cdae341f1fee4a8
    .dword 0x2169c9bb10fa1a9, 0x96b13944ef2f31b2
    .dword 0x61e61404d3cd323c, 0x1b8a7ca41e3b7ca9
    .dword 0x6d2a096f5e6c04b2, 0xeb7f4aaed184b03e
    .dword 0x1d6ce5ca5e4154ba, 0xe3df961347326211
    .dword 0xf70d143cca0f2c5b, 0x8820fee6b3c7802e
    .dword 0xb8f803793f6cdd1, 0xed57eafa6dec8d67
    .dword 0xb819e32a6ece000e, 0xcc735fe9a0a9d34

    .align 12
data7:
    .dword 0x2ce99a2b78f32c41, 0x8308e058650ba386
    .dword 0xf07bc63bb6d65512, 0xbb9b26be396f66c4
    .dword 0x67c01f214e2d62b7, 0x4d9e054b9b404d2e
    .dword 0x19ee28e2ec9475f0, 0x8aea633bb654982b
    .dword 0x51260da1cf290424, 0xabf0da6f5fac160a
    .dword 0xba533429b537ae09, 0x5d9b078ed9b7ced1
    .dword 0xa4748b87cb41713f, 0xe6dd3e4d6e6b8a6
    .dword 0x11293915b2da4f64, 0x12d96d66c1c22a4f
    .dword 0xa7a48bcb4a5b28e9, 0x65c6ea54df2d0c23
    .dword 0x5e433f11f5d37de9, 0xbe34822c02098b38
    .dword 0x9387a362a1b09885, 0x252e5cd98a3330f6
    .dword 0xa006e1a3fdfe0290, 0x5a325e21da31c4a5
    .dword 0xc032ff15eedbf71, 0xf965f9153118fcfc
    .dword 0x153baf6d19d6262, 0x7ae4f17e2b32b886
    .dword 0xa1ebc549ca55d834, 0x16f194ba9b9d8043
    .dword 0xdba3e3b7f8c293e4, 0x7a16a2cc1bf6c655
    .dword 0x79580c8f049f399e, 0x4c5c040b24f1f8d7
    .dword 0xde3d2cd2376da4c6, 0x2dfa2c87020c0a8
    .dword 0x7d46077f8c274d4d, 0xe62c3061ae6a95b3
    .dword 0xa8330c2b333c1696, 0xc07ae5996d6e2012
    .dword 0x3c1e37f8885a7723, 0x60a8cb551478cd37
    .dword 0x3b454c7e582c2ffa, 0x9a68a0920c9dfce3
    .dword 0xbce3b450fb518b35, 0xb51b2a487079d59e
    .dword 0xe66ce1bf4fa6b467, 0xdc73dda13e34c1b4
    .dword 0xa9ffb3a1e49249dd, 0xc9c92383b0c58746
    .dword 0xe15bafa3885db604, 0xcff61288bde5c4aa
    .dword 0x10372c508765562a, 0x9ad0675a4d8a96ad
    .dword 0x1cbecf0c34f90eb, 0x235f9811255e462f
    .dword 0x9b4732442dbfd48, 0x734d636ad3aba85c
    .dword 0x5eacbf99035d34e, 0xa9d492a478f02ae8
    .dword 0x9e1289b7aa7ad5db, 0x44a5ec2b8b3cf9ca
    .dword 0x9500e34d5b648960, 0xfc1f92be48bde999
    .dword 0x21fe78c5e4345408, 0x7b36a03fc4bfd7b
    .dword 0xcaf8a3f724f36d10, 0x2cf2b53052489cf9
    .dword 0xd86725088f846139, 0x9023236d5f6174bb
    .dword 0xfe31f8f224f79021, 0xe51d8fe53e00aaba
    .dword 0xec15b047f832bda, 0xc862b3cbd863f447
    .dword 0x3031f3c239cf1103, 0xbb6e45841209930c
    .dword 0x79712e6055609a3c, 0x926b28ced707d7e6
    .dword 0xb78951d871980186, 0x4214d99d2b4e9b2e
    .dword 0x7bde2ca99549c55a, 0x5516f44ce6a02753
    .dword 0xef7e35dc0865f708, 0x4e1564fa182e463a
    .dword 0xee70f1e417af7504, 0xc68b4e43d82edea2
    .dword 0xc82b706152c35df1, 0x210ca5f43beb5d8d
    .dword 0x60025db6d01098db, 0x7abeb7fd034b7826
    .dword 0x1d0d188ce17851da, 0xff944f118d36c232
    .dword 0xe27bc64d46b9f175, 0x9dfb17fdc872c023
    .dword 0x5bea2c37ae0bd12, 0x9f618577c30790d4
    .dword 0xc2ec34bfcfc6f02b, 0x847e6a123819507d
    .dword 0x365b6a23f7f1b737, 0xe2a382f796230727
    .dword 0xdf015cc5c028ef2b, 0xb82e3cf702f5b5be
    .dword 0xcfa82257a9bdbc1, 0x785e0689e5983ecb
    .dword 0x47f6710c58f0bc85, 0xcda9bd0cc85e1aab
    .dword 0xceb183c2ccf62506, 0x7d75f8dcc42ca99b
    .dword 0xcc09f0542b8f85b9, 0x4b87c53ff81e9fe8
    .dword 0xa318a5e16fc0e3f6, 0x256da0cc907fd9c7
    .dword 0x528239b686e2ceef, 0x57d748724e4a8a6e
    .dword 0x8dffb7d406a2f104, 0x5da2899931d84df0
    .dword 0xbe965a8b7485fa80, 0xe55ab74d08f4df7d
    .dword 0x208a83624a86a119, 0x4ddd2e31fd7c20e6
    .dword 0x52487b44f13ae6e4, 0xc4daae1de408d2e3
    .dword 0x69dd8b3513a48d5b, 0xf630262cdd0719f7
    .dword 0x25d1c838499304c0, 0x4ee0bfb2d009b87f
    .dword 0x50ec3d2ad6c37c57, 0xbd1f7b39f43d7db1


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
