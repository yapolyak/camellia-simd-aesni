.text

/*
    Inputs:
     v0: data
     v1: lo_table
     v2: hi_table
     v3: mask (0x0f0f...)

    ToDo: use proper registers
*/
.globl  filter_8bit_neon
.type   filter_8bit_neon,%function
.align  5
filter_8bit_neon:
    and     v4.16b,v0.16b,v3.16b
    ushr    v0.16b,v0.16b,#4
    tbl     v4.16b,{v1.16b},v4.16b
    tbl     v0.16b,{v2.16b},v0.16b
    eor     v0.16b,v0.16b,v4.16b
    ret
.size   filter_8bit_neon,.-filter_8bit_neon

/*
    Inputs:
     x0: pointer to v0
     x1: pointer to v1
     x2: pointer to v2
     x3: pointer to v3

    ToDo: use proper registers, remove load/store ins-s
*/
.globl  rol32_1_16_neon
.type   rol32_1_16_neon,%function
.align  5
rol32_1_16_neon:
    .cfi_startproc
    // Load all data from memory into registers first (todo: remove)
    ld1 {v0.16b}, [x0]
    ld1 {v1.16b}, [x1]
    ld1 {v2.16b}, [x2]
    ld1 {v3.16b}, [x3]
    ushr    v4.16b,v0.16b,#7
    add     v0.16b,v0.16b,v0.16b
    ushr    v5.16b,v1.16b,#7
    add     v1.16b,v1.16b,v1.16b
    ushr    v6.16b,v2.16b,#7
    add     v2.16b,v2.16b,v2.16b
    orr     v1.16b,v4.16b,v1.16b
    ushr    v4.16b,v3.16b,#7        // dependency chain - use extra tmp vector?
    add     v3.16b,v3.16b,v3.16b
    orr     v2.16b,v5.16b,v2.16b
    orr     v3.16b,v6.16b,v3.16b
    orr     v0.16b,v4.16b,v0.16b
    // Store the results back to memory (todo: remove)
    st1 {v0.16b}, [x0]
    st1 {v1.16b}, [x1]
    st1 {v2.16b}, [x2]
    st1 {v3.16b}, [x3]
    ret
    .cfi_endproc
.size   rol32_1_16_neon,.-rol32_1_16_neon
