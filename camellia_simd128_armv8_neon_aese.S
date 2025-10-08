.text

.globl  camellia_neon_test
.type   camellia_neon_test,%function
.align  5
camellia_neon_test:
    .cfi_startproc

    EOR v0.16B, v0.16B, v0.16B
    ret
    
    .cfi_endproc
.size   camellia_neon_test,.-camellia_neon_test


/*
    Inputs:
     v0: data
     v1: lo_table
     v2: hi_table
     v3: mask (0x0f0f...)
    
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
