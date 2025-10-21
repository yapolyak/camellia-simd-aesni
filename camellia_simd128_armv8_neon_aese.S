#define filter_8bit_neon(x,lo_t,hi_t,mask,tmp) \
    and     tmp.16b,x.16b,mask.16b; \
    ushr    x.16b,x.16b,#4; \
    tbl     tmp.16b,{lo_t.16b},tmp.16b; \
    tbl     x.16b,{hi_t.16b},x.16b; \
    eor     x.16b,x.16b,tmp.16b

/*
 * IN:
 *  v0..v7: byte-sliced AB state
 *  mem_cd: register pointer storing CD state
 *  key: index for key material
 * OUT:
 *  v0..v7: new byte-sliced CD state
 * Clobbers:
 *  x5 - key value
 *  v8..v15: broadcasted key values
 *  v16: mask_0f
 *  v17: inv_shift_row
 *  v18..v27: pre- and post-filters
 */
#define roundsm16(v0, v1, v2, v3, v4, v5, v6, v7, mem_cd, key) \
    /* Load 64-bit round key */ \
    ldr     x5,[key]; \
\
    /* S-FUNCTION (PRE-AES) */ \
\
    /* Inverse Shift Rows (pre-compensation) */ \
    tbl     v0.16b,{v0.16b},v17.16b; \
    tbl     v7.16b,{v7.16b},v17.16b; \
    tbl     v1.16b,{v1.16b},v17.16b; \
    tbl     v4.16b,{v4.16b},v17.16b; \
    tbl     v2.16b,{v2.16b},v17.16b; \
    tbl     v5.16b,{v5.16b},v17.16b; \
    tbl     v3.16b,{v3.16b},v17.16b; \
    tbl     v6.16b,{v6.16b},v17.16b; \
\
    /* Pre-Filter */ \
    filter_8bit_neon(v0,v18,v19,v16,v28); \
    filter_8bit_neon(v7,v18,v19,v16,v28); \
    filter_8bit_neon(v1,v18,v19,v16,v28); \
    filter_8bit_neon(v4,v18,v19,v16,v28); \
    filter_8bit_neon(v2,v18,v19,v16,v28); \
    filter_8bit_neon(v5,v18,v19,v16,v28); \
    eor  v31.16b, v31.16b, v31.16b; \
    filter_8bit_neon(v3,v20,v21,v16,v28); \
    filter_8bit_neon(v6,v20,v21,v16,v28); \
\
    /* AES CORE */ \
    aese v0.16b, v31.16b; \
    aese v7.16b, v31.16b; \
    aese v1.16b, v31.16b; \
    aese v4.16b, v31.16b; \
    aese v2.16b, v31.16b; \
    aese v5.16b, v31.16b; \
    aese v3.16b, v31.16b; \
    aese v6.16b, v31.16b; \
\
    /* Post-Filter */ \
    filter_8bit_neon(v0,v22,v23,v16,v28); \
    filter_8bit_neon(v7,v22,v23,v16,v28); \
    filter_8bit_neon(v3,v22,v23,v16,v28); \
    filter_8bit_neon(v6,v22,v23,v16,v28); \
\
    filter_8bit_neon(v2,v26,v27,v16,v28); \
    filter_8bit_neon(v5,v26,v27,v16,v28); \
\
    filter_8bit_neon(v1,v24,v25,v16,v28); \
    filter_8bit_neon(v4,v24,v25,v16,v28); \
\
    /* Interleaved P-function and key broadcasting */ \
    fmov    d31,x5; \
\
    eor     v0.16b,v0.16b,v5.16b; \
    movi    v29.16b,#3;\
    eor     v1.16b,v1.16b,v6.16b; \
    movi    v30.16b,#2; \
    eor     v2.16b,v2.16b,v7.16b; \
    eor     v3.16b,v3.16b,v4.16b; \
\
    tbl     v11.16b,{v31.16b},v29.16b;   /* threes */ \
    tbl     v10.16b,{v31.16b},v30.16b;   /* twos */ \
\
    eor     v4.16b,v4.16b,v2.16b; \
    movi    v29.16b,#1; \
    eor     v5.16b,v5.16b,v3.16b; \
    movi    v30.16b,#7; \
    eor     v6.16b,v6.16b,v0.16b; \
    eor     v7.16b,v7.16b,v1.16b; \
\
    tbl     v9.16b,{v31.16b},v29.16b;   /* ones */ \
    tbl     v15.16b,{v31.16b},v30.16b;   /* sevens */ \
\
    eor     v0.16b,v0.16b,v7.16b; \
    movi    v29.16b,#6; \
    eor     v1.16b,v1.16b,v4.16b; \
    movi    v30.16b,#5; \
    eor     v2.16b,v2.16b,v5.16b; \
    eor     v3.16b,v3.16b,v6.16b; \
\
    tbl     v14.16b,{v31.16b},v29.16b;   /* sixs */ \
    tbl     v13.16b,{v31.16b},v30.16b;   /* fives */ \
\
    eor     v4.16b,v4.16b,v3.16b; \
    movi    v29.16b,#4; \
    eor     v5.16b,v5.16b,v0.16b; \
    eor     v30.16b,v30.16b,v30.16b; \
    eor     v6.16b,v6.16b,v1.16b; \
    eor     v7.16b,v7.16b,v2.16b;   /* Now the high snd low parts are swapped */ \
\
    ldr     q28,[mem_cd]; \
\
    tbl     v12.16b,{v31.16b},v29.16b;   /* fours */ \
    tbl     v8.16b,{v31.16b},v30.16b;    /* zeros */ \
\
    /* Final XOR's (w. broadcasted KEY & CD state) */ \
    ldr     q29,[mem_cd,#16]; \
    ldr     q30,[mem_cd,#32]; \
    ldr     q31,[mem_cd,#48]; \
\
    eor     v4.16b,v4.16b,v11.16b; \
    eor     v4.16b,v4.16b,v28.16b; \
\
    eor     v5.16b,v5.16b,v10.16b; \
    eor     v5.16b,v5.16b,v29.16b; \
\
    ldr     q28,[mem_cd,#64]; \
\
    eor     v6.16b,v6.16b,v9.16b; \
    eor     v6.16b,v6.16b,v30.16b; \
\
    ldr     q29,[mem_cd,#80]; \
\
    eor     v7.16b,v7.16b,v8.16b; \
    eor     v7.16b,v7.16b,v31.16b; \
\
    ldr     q30,[mem_cd,#96]; \
\
    eor     v0.16b,v0.16b,v15.16b; \
    eor     v0.16b,v0.16b,v28.16b; \
\
    ldr     q31,[mem_cd,#112]; \
\
    eor     v1.16b,v1.16b,v14.16b; \
    eor     v1.16b,v1.16b,v29.16b; \
\
    eor     v2.16b,v2.16b,v13.16b; \
    eor     v2.16b,v2.16b,v30.16b; \
\
    eor     v3.16b,v3.16b,v12.16b; \
    eor     v3.16b,v3.16b,v31.16b;

/*
 * IN/OUT:
 *  v0..v7: byte-sliced AB state preloaded
 *  mem_ab: byte-sliced AB state in memory
 *  mem_cd: byte-sliced CD state in memory
 *  first_key_ptr: ptr to access first key
 *  store_ab: function to store state
 * Clobbers:
 *  x5 - second key pointer value
 */
#define two_roundsm16(v0, v1, v2, v3, v4, v5, v6, v7, mem_ab, mem_cd, first_key_ptr, store_ab) \
    roundsm16(v0, v1, v2, v3, v4, v5, v6, v7, mem_cd, first_key_ptr); \
\
    stp     q4,q5,[mem_cd]; \
    stp     q6,q7,[mem_cd,#32]; \
    stp     q0,q1,[mem_cd,#64]; \
    stp     q2,q3,[mem_cd,#96]; \
\
    add     x4,first_key_ptr,#8; \
    roundsm16(v4, v5, v6, v7, v0, v1, v2, v3, mem_ab, x4); \
\
    store_ab(v0, v1, v2, v3, v4, v5, v6, v7, mem_ab);

#define dummy_store(v0, v1, v2, v3, v4, v5, v6, v7, mem_ab) /* do nothing */

#define store_ab_state(v0, v1, v2, v3, v4, v5, v6, v7, mem_ab) \
	/* Store new AB state */ \
    stp     q0,q1,[mem_ab]; \
    stp     q2,q3,[mem_ab,#32]; \
    stp     q4,q5,[mem_ab,#64]; \
    stp     q6,q7,[mem_ab,#96];

/*
 * IN:
 *  v0..3: byte-sliced 32-bit integers
 * OUT:
 *  v0..3: (IN <<< 1)
 */
#define rol32_1_16(v0, v1, v2, v3, t0, t1, t2) \
    ushr    t0.16b,v0.16b,#7; \
    add     v0.16b,v0.16b,v0.16b; \
    ushr    t1.16b,v1.16b,#7; \
    add     v1.16b,v1.16b,v1.16b; \
    ushr    t2.16b,v2.16b,#7; \
    add     v2.16b,v2.16b,v2.16b; \
    orr     v1.16b,t0.16b,v1.16b; \
    ushr    t0.16b,v3.16b,#7; \
    add     v3.16b,v3.16b,v3.16b; \
    orr     v2.16b,t1.16b,v2.16b; \
    orr     v3.16b,t2.16b,v3.16b; \
    orr     v0.16b,t0.16b,v0.16b;

/*
 * IN:
 *   v0..v7: byte-sliced AB state in registers
 *   r: byte-sliced AB state in memory
 *   l: byte-sliced CD state in memory
 *   keys_ptr: pointer to keys
 * OUT:
 *   v0..v7: new byte-sliced CD state
 * Cobblers:
 *  x5-x7: storage for keys
 *  v8-v15,v16-19,v28-v31: temporary vectors
 */
#define fls16(v0, v1, v2, v3, v4, v5, v6, v7, mem_l, mem_r, keys_ptr) \
    ldp     x5, x6, [keys_ptr]; /* x5={klr,kll}, x6={krr,krl} */ \
	/* \
	 * t0 = kll; \
	 * t0 &= ll; \
	 * lr ^= rol32(t0, 1); \
	 */ \
    eor     v19.16b,v19.16b,v19.16b; \
    movi    v18.16b,#1; \
    fmov    s31, w5;       /* v31 lower = kll */ \
    movi    v17.16b,#2; \
    movi    v16.16b,#3; \
    tbl     v19.16b,{v31.16b},v19.16b; \
    tbl     v18.16b,{v31.16b},v18.16b; \
    tbl     v17.16b,{v31.16b},v17.16b; \
    tbl     v16.16b,{v31.16b},v16.16b; \
\
    ldp     q12,q13,[mem_r,#64]; /* pre-load right-hand state parts */ \
    and     v16.16b,v0.16b,v16.16b; \
    and     v17.16b,v1.16b,v17.16b; \
    ldp     q14,q15,[mem_r,#96]; /* pre-load right-hand state parts */ \
    and     v18.16b,v2.16b,v18.16b; \
    and     v19.16b,v3.16b,v19.16b; \
\
    rol32_1_16(v19,v18,v17,v16,v28,v29,v30); \
\
    eor     v4.16b,v16.16b,v4.16b; \
    eor     v5.16b,v17.16b,v5.16b; \
    eor     v6.16b,v18.16b,v6.16b; \
    eor     v7.16b,v19.16b,v7.16b; \
    stp     q4,q5,[mem_l,#64]; \
    stp     q6,q7,[mem_l,#96]; \
\
	/* \
	 * t2 = krr; \
	 * t2 |= rr; \
	 * rl ^= t2; \
	 */ \
\
    lsr     x7,x6,#32; \
    eor     v19.16b,v19.16b,v19.16b; \
    ldp     q8,q9,[mem_r]; /* pre-load right-hand state parts */ \
    movi    v18.16b,#1; \
    fmov    s31,w7; \
    movi    v17.16b,#2; \
    movi    v16.16b,#3; \
    ldp     q10,q11,[mem_r,#32]; /* pre-load right-hand state parts */ \
    tbl     v19.16b,{v31.16b},v19.16b; \
    tbl     v18.16b,{v31.16b},v18.16b; \
    tbl     v17.16b,{v31.16b},v17.16b; \
    tbl     v16.16b,{v31.16b},v16.16b; \
\
    orr     v16.16b,v12.16b,v16.16b; \
    orr     v17.16b,v13.16b,v17.16b; \
    orr     v18.16b,v14.16b,v18.16b; \
    orr     v19.16b,v15.16b,v19.16b; \
\
    eor     v8.16b,v8.16b,v16.16b; \
    eor     v9.16b,v9.16b,v17.16b; \
    eor     v10.16b,v10.16b,v18.16b; \
    eor     v11.16b,v11.16b,v19.16b; \
\
    stp     q8,q9,[mem_r]; /*Note, updated values stay in v8-v11*/ \
    stp     q10,q11,[mem_r,#32];\
\
	/* \
	 * t2 = krl; \
	 * t2 &= rl; \
	 * rr ^= rol32(t2, 1); \
	 */ \
\
    eor     v19.16b,v19.16b,v19.16b; \
    movi    v18.16b,#1; \
    fmov    s31,w6; \
    movi    v17.16b,#2; \
    movi    v16.16b,#3; \
    tbl     v19.16b,{v31.16b},v19.16b; \
    tbl     v18.16b,{v31.16b},v18.16b; \
    tbl     v17.16b,{v31.16b},v17.16b; \
    tbl     v16.16b,{v31.16b},v16.16b; \
\
    and     v16.16b,v8.16b,v16.16b; /*Re-use updated right state values*/ \
    and     v17.16b,v9.16b,v17.16b; \
    and     v18.16b,v10.16b,v18.16b; \
    and     v19.16b,v11.16b,v19.16b; \
\
    rol32_1_16(v19,v18,v17,v16,v28,v29,v30); \
\
    eor     v12.16b,v16.16b,v12.16b; \
    eor     v13.16b,v17.16b,v13.16b; \
    eor     v14.16b,v18.16b,v14.16b; \
    eor     v15.16b,v19.16b,v15.16b; \
    stp     q12,q13,[mem_r,#64]; \
    stp     q14,q15,[mem_r,#96]; \
\
	/* \
	 * t0 = klr; \
	 * t0 |= lr; \
	 * ll ^= t0; \
	 */ \
\
    lsr     x7,x5,#32; \
    eor     v19.16b,v19.16b,v19.16b; \
    movi    v18.16b,#1; \
    fmov    s31,w7; \
    movi    v17.16b,#2; \
    movi    v16.16b,#3; \
    tbl     v19.16b,{v31.16b},v19.16b; \
    tbl     v18.16b,{v31.16b},v18.16b; \
    tbl     v17.16b,{v31.16b},v17.16b; \
    tbl     v16.16b,{v31.16b},v16.16b; \
\
    orr     v16.16b,v4.16b,v16.16b; \
    orr     v17.16b,v5.16b,v17.16b; \
    orr     v18.16b,v6.16b,v18.16b; \
    orr     v19.16b,v7.16b,v19.16b; \
\
    eor     v0.16b,v0.16b,v16.16b; \
    eor     v1.16b,v1.16b,v17.16b; \
    eor     v2.16b,v2.16b,v18.16b; \
    eor     v3.16b,v3.16b,v19.16b; \
\
    stp     q0,q1,[mem_l]; \
    stp     q2,q3,[mem_l,#32];\


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
    filter_8bit_neon(v0,v1,v2,v3,v4)
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
    rol32_1_16(v0, v1, v2, v3, v4, v5, v6)
    // Store the results back to memory (todo: remove)
    st1 {v0.16b}, [x0]
    st1 {v1.16b}, [x1]
    st1 {v2.16b}, [x2]
    st1 {v3.16b}, [x3]
    ret
    .cfi_endproc
.size   rol32_1_16_neon,.-rol32_1_16_neon

.section .rodata
.type   camellia_neon_consts,%object
.align  7
camellia_neon_consts:
.Lpre_tf_lo_s1:
    .byte 0x45, 0xe8, 0x40, 0xed, 0x2e, 0x83, 0x2b, 0x86
    .byte 0x4b, 0xe6, 0x4e, 0xe3, 0x20, 0x8d, 0x25, 0x88
.Lpre_tf_hi_s1:
    .byte 0x00, 0x51, 0xf1, 0xa0, 0x8a, 0xdb, 0x7b, 0x2a
    .byte 0x09, 0x58, 0xf8, 0xa9, 0x83, 0xd2, 0x72, 0x23
.Lpre_tf_lo_s4:
    .byte 0x45, 0x40, 0x2e, 0x2b, 0x4b, 0x4e, 0x20, 0x25
    .byte 0x14, 0x11, 0x7f, 0x7a, 0x1a, 0x1f, 0x71, 0x74
.Lpre_tf_hi_s4:
    .byte 0x00, 0xf1, 0x8a, 0x7b, 0x09, 0xf8, 0x83, 0x72
    .byte 0xad, 0x5c, 0x27, 0xd6, 0xa4, 0x55, 0x2e, 0xdf
.Lpost_tf_lo_s1:
    .byte 0x3c, 0xcc, 0xcf, 0x3f, 0x32, 0xc2, 0xc1, 0x31
    .byte 0xdc, 0x2c, 0x2f, 0xdf, 0xd2, 0x22, 0x21, 0xd1
.Lpost_tf_hi_s1:
    .byte 0x00, 0xf9, 0x86, 0x7f, 0xd7, 0x2e, 0x51, 0xa8
    .byte 0xa4, 0x5d, 0x22, 0xdb, 0x73, 0x8a, 0xf5, 0x0c
.Lpost_tf_lo_s2:
    .byte 0x78, 0x99, 0x9f, 0x7e, 0x64, 0x85, 0x83, 0x62
    .byte 0xb9, 0x58, 0x5e, 0xbf, 0xa5, 0x44, 0x42, 0xa3
.Lpost_tf_hi_s2:
    .byte 0x00, 0xf3, 0x0d, 0xfe, 0xaf, 0x5c, 0xa2, 0x51
    .byte 0x49, 0xba, 0x44, 0xb7, 0xe6, 0x15, 0xeb, 0x18
.Lpost_tf_lo_s3:
    .byte 0x1e, 0x66, 0xe7, 0x9f, 0x19, 0x61, 0xe0, 0x98
    .byte 0x6e, 0x16, 0x97, 0xef, 0x69, 0x11, 0x90, 0xe8
.Lpost_tf_hi_s3:
    .byte 0x00, 0xfc, 0x43, 0xbf, 0xeb, 0x17, 0xa8, 0x54
    .byte 0x52, 0xae, 0x11, 0xed, 0xb9, 0x45, 0xfa, 0x06
.Linv_shift_row:
    .byte 0x00, 0x0d, 0x0a, 0x07, 0x04, 0x01, 0x0e, 0x0b
    .byte 0x08, 0x05, 0x02, 0x0f, 0x0c, 0x09, 0x06, 0x03
.Lmask_0f:
    .quad 0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
.size   camellia_neon_consts,.-camellia_neon_consts
.previous

/*
    Inputs:
     x0: ptr to AB state
     x1: ptr to CD state
     x2: key table base pointer
     x3: key index
*/
.globl  enc_rounds16_neon
.type   enc_rounds16_neon,%function
.align  5
enc_rounds16_neon:
    stp     x29,x30,[sp,#-144]!
    mov     x29,sp
    
    stp     q8,q9,[sp,#16]
    stp     q10,q11,[sp,#48]
    stp     q12,q13,[sp,#80]
    stp     q14,q15,[sp,#112]

    // Load ab state vectors
    ldp     q0,q1,[x0]
    ldp     q2,q3,[x0,#32]
    ldp     q4,q5,[x0,#64]
    ldp     q6,q7,[x0,#96]

    // Load constant tables
    adrp    x5,camellia_neon_consts             // Get page address of tables
    add     x5,x5,:lo12:camellia_neon_consts    // Get full address

    ldp     q18,q19,[x5],#32    // Load pre_tf_lo/hi_s1 into v18, v19
    ldp     q20,q21,[x5],#32    // Load pre_tf_lo/hi_s4 into v20, v21
    ldp     q22,q23,[x5],#32    // Load post_tf_lo/hi_s1 into v22, v23
    ldp     q24,q25,[x5],#32    // Load post_tf_lo/hi_s2 into v24, v25
    ldp     q26,q27,[x5],#32    // Load post_tf_lo/hi_s3 into v26, v27
    ldr     q17,[x5],#16        // Load inv_shift_row into v17
    ldr     q16,[x5],#16        // Load mask_0f into v16

    // First key base pointer calculation
    lsl     x6,x3,#3                // i * 8 (using the 64-bit view of w3)
    add     x6,x2,x6    // &key_table[0] + (i * 8) = &key_table[i]

    // First round
    add     x4,x6,#16               // &key_table[i+2]
    two_roundsm16(v0,v1,v2,v3,v4,v5,v6,v7,x0,x1,x4,store_ab_state)
    // Second round
    add     x4,x6,#32               // &key_table[i+4]
    two_roundsm16(v0,v1,v2,v3,v4,v5,v6,v7,x0,x1,x4,store_ab_state)
    // Third round
    add     x4,x6,#48               // &key_table[i+6]
    two_roundsm16(v0,v1,v2,v3,v4,v5,v6,v7,x0,x1,x4,store_ab_state)

    // Restore callee-saved registers
    ldp     q8,q9,[sp,#16]
    ldp     q10,q11,[sp,#48]
    ldp     q12,q13,[sp,#80]
    ldp     q14,q15,[sp,#112]

    ldp     x29,x30,[sp],#144

    ret
.size   enc_rounds16_neon,.-enc_rounds16_neon

.globl  fls16_neon
.type   fls16_neon,%function
.align  5
fls16_neon:
    stp     x29,x30,[sp,#-144]!
    mov     x29,sp
    
    stp     q8,q9,[sp,#16]
    stp     q10,q11,[sp,#48]
    stp     q12,q13,[sp,#80]
    stp     q14,q15,[sp,#112]

    // Load ab state vectors
    ldp     q0,q1,[x0]
    ldp     q2,q3,[x0,#32]
    ldp     q4,q5,[x0,#64]
    ldp     q6,q7,[x0,#96]

    fls16(v0, v1, v2, v3, v4, v5, v6, v7, x0, x1, x2)

    // Restore callee-saved registers
    ldp     q8,q9,[sp,#16]
    ldp     q10,q11,[sp,#48]
    ldp     q12,q13,[sp,#80]
    ldp     q14,q15,[sp,#112]

    ldp     x29,x30,[sp],#144

    ret
.size   fls16_neon,.-fls16_neon