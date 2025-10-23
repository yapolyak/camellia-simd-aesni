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
 * Clobbers:
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

#define transpose_4x4(v0, v1, v2, v3, t1, t2) \
    zip2    t2.4s,v0.4s,v1.4s; \
    zip1    v0.4s,v0.4s,v1.4s; \
\
    zip1    t1.4s,v2.4s,v3.4s; \
    zip2    v2.4s,v2.4s,v3.4s; \
\
    zip2    v1.2d,v0.2d,t1.2d; \
    zip1    v0.2d,v0.2d,t1.2d; \
\
    zip2    v3.2d,t2.2d,v2.2d; \
    zip1    v2.2d,t2.2d,v2.2d;

/* 
 * IN: 
 *  a0-a3, b0-b3, c0-c3, d0-d3 (vector registers)
 * OUT:
 *  a0-a3, b0-b3, c0-c3, d0-d3 (transposed, in registers)
 * Clobbers:
 *  t0 (v16), t1 (v17) (vector registers), tmp (GPR for constant address)
*/
#define byteslice_16x16b_fast(a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, \
                                   a3, b3, c3, d3, t0, t1, tmp) \
    transpose_4x4(a0, a1, a2, a3, t0, t1); \
    transpose_4x4(b0, b1, b2, b3, t0, t1); \
\
    transpose_4x4(c0, c1, c2, c3, t0, t1); \
    transpose_4x4(d0, d1, d2, d3, t0, t1); \
\
    adrp    tmp,.Lshufb_16x16b; \
    add     tmp,tmp,:lo12:.Lshufb_16x16b; \
    ldr     q16,[tmp]; \
\
    tbl     a0.16b,{a0.16b},t0.16b; \
    tbl     a1.16b,{a1.16b},t0.16b; \
    tbl     a2.16b,{a2.16b},t0.16b; \
    tbl     a3.16b,{a3.16b},t0.16b; \
    tbl     b0.16b,{b0.16b},t0.16b; \
    tbl     b1.16b,{b1.16b},t0.16b; \
    tbl     b2.16b,{b2.16b},t0.16b; \
    tbl     b3.16b,{b3.16b},t0.16b; \
    tbl     c0.16b,{c0.16b},t0.16b; \
    tbl     c1.16b,{c1.16b},t0.16b; \
    tbl     c2.16b,{c2.16b},t0.16b; \
    tbl     c3.16b,{c3.16b},t0.16b; \
    tbl     d0.16b,{d0.16b},t0.16b; \
    tbl     d1.16b,{d1.16b},t0.16b; \
    tbl     d2.16b,{d2.16b},t0.16b; \
    tbl     d3.16b,{d3.16b},t0.16b; \
\
    transpose_4x4(a0, b0, c0, d0, t0, t1); \
    transpose_4x4(a1, b1, c1, d1, t0, t1); \
\
    transpose_4x4(a2, b2, c2, d2, t0, t1); \
    transpose_4x4(a3, b3, c3, d3, t0, t1);

/*
 * IN:
 *  key_ptr (GPR), rio_ptr (GPR)
 * OUT:
 *  v0-v15 (whitened plaintext)
 * Clobbers:
 *  tmp_key (v16, vector), tmp_gpr (GPR for addr), v17, v18
 */
#define inpack16_pre(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
                     rio_ptr, key_ptr, tmp_key, tmp_gpr) \
    /* Load and prepare key */ \
    ldr     tmp_gpr,[key_ptr]; \
    fmov    d16,tmp_gpr; \
    adrp    tmp_gpr,.Lpack_bswap; \
    add     tmp_gpr,tmp_gpr,:lo12:.Lpack_bswap; \
    ldr     q17,[tmp_gpr]; /* Load constant into a temporary */ \
    tbl     tmp_key.16b,{tmp_key.16b},v17.16b; \
    \
    /* Load plaintext blocks and XOR with key; TODO: interleave a bit with above? */ \
    ldr     q18,[rio_ptr,#(0*16)]; \
    eor     v15.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(1*16)]; \
    eor     v14.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(2*16)]; \
    eor     v13.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(3*16)]; \
    eor     v12.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(4*16)]; \
    eor     v11.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(5*16)]; \
    eor     v10.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(6*16)]; \
    eor     v9.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(7*16)]; \
    eor     v8.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(8*16)]; \
    eor     v7.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(9*16)]; \
    eor     v6.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(10*16)]; \
    eor     v5.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(11*16)]; \
    eor     v4.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(12*16)]; \
    eor     v3.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(13*16)]; \
    eor     v2.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(14*16)]; \
    eor     v1.16b,v18.16b,tmp_key.16b; \
    ldr     q18,[rio_ptr,#(15*16)]; \
    eor     v0.16b,v18.16b,tmp_key.16b;

/*
 * IN:
 *  v0-v15 (whitened plaintext)
 *  mem_ab, mem_cd (GPRs)
 * OUT:
 *  Writes byte-sliced state to memory buffers.
 * Clobbers:
 *  v0-v15 (become byte-sliced), st0, st1 (vector temps - v16,v17), tmp (GPR temp)
 */
#define inpack16_post(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
                            mem_ab, mem_cd, st0, st1, tmp) \
    /* Perform the byte-slice transpose in-place on v0-v15 */ \
    byteslice_16x16b_fast(v0, v1, v2, v3, v4, v5, v6, v7, \
                          v8, v9, v10, v11, v12, v13, v14, v15, \
                          st0, st1, tmp); \
    \
    /* Store the results */ \
    stp     q0,q1,[mem_ab]; \
    stp     q2,q3,[mem_ab,#32]; \
    stp     q4,q5,[mem_ab,#64]; \
    stp     q6,q7,[mem_ab,#96]; \
    stp     q8,q9,[mem_cd]; \
    stp     q10,q11,[mem_cd,#32]; \
    stp     q12,q13,[mem_cd,#64]; \
    stp     q14,q15,[mem_cd,#96];

/* 
 * IN:
 *  v0-v15 (byte-sliced ciphertext), key_ptr (GPR)
 * OUT:
 *  v0-v15 (block-oriented, whitened ciphertext)
 * Clobbers:
 *  tmp_v0, tmp_v1, tmp_key (vector temps - v16:v18),
 *  tmp_gpr (GPR temp)
 */
#define outunpack16(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
                          key_ptr, tmp_v0, tmp_v1, tmp_key, tmp_gpr) \
    /* Perform inverse byte-slice (transpose) in-place */ \
    byteslice_16x16b_fast(v8, v12, v0, v4, v9, v13, v1, v5, v10, v14, v2, v6, \
                               v11, v15, v3, v7, \
                               tmp_v0, tmp_v1, tmp_gpr); \
    \
    /* Load and prepare final key */ \
    ldr     tmp_gpr,[key_ptr]; \
    fmov    d18,tmp_gpr; \
    adrp    tmp_gpr,.Lpack_bswap; \
    add     tmp_gpr,tmp_gpr,:lo12:.Lpack_bswap; \
    ldr     q16,[tmp_gpr]; /* Load constant into a temporary */ \
    tbl     tmp_key.16b,{tmp_key.16b},tmp_v0.16b; \
    \
    /* XOR with final key */ \
    eor     v0.16b,v0.16b,tmp_key.16b; \
    eor     v1.16b,v1.16b,tmp_key.16b; \
    eor     v2.16b,v2.16b,tmp_key.16b; \
    eor     v3.16b,v3.16b,tmp_key.16b; \
    eor     v4.16b,v4.16b,tmp_key.16b; \
    eor     v5.16b,v5.16b,tmp_key.16b; \
    eor     v6.16b,v6.16b,tmp_key.16b; \
    eor     v7.16b,v7.16b,tmp_key.16b; \
    eor     v8.16b,v8.16b,tmp_key.16b; \
    eor     v9.16b,v9.16b,tmp_key.16b; \
    eor     v10.16b,v10.16b,tmp_key.16b; \
    eor     v11.16b,v11.16b,tmp_key.16b; \
    eor     v12.16b,v12.16b,tmp_key.16b; \
    eor     v13.16b,v13.16b,tmp_key.16b; \
    eor     v14.16b,v14.16b,tmp_key.16b; \
    eor     v15.16b,v15.16b,tmp_key.16b;

/*
 * Inputs:
 *  v0-v15 (final block-oriented ciphertext), rio_ptr (GPR)
 */
#define write_output(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, rio_ptr) \
    /* TODO: check the order! */ \
    stp     q7,q6,[rio_ptr]; \
    stp     q5,q4,[rio_ptr,#32]; \
    stp     q3,q2,[rio_ptr,#64]; \
    stp     q1,q0,[rio_ptr,#96]; \
    stp     q15,q14,[rio_ptr,#128]; \
    stp     q13,q12,[rio_ptr,#160]; \
    stp     q11,q10,[rio_ptr,#192]; \
    stp     q9,q8,[rio_ptr,#224];

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
.Lpack_bswap:
    .byte   3, 2, 1, 0, 7, 6, 5, 4, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
.Lshufb_16x16b:
    .byte   0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15
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

.globl  inpack_pre_post_neon
.type   inpack_pre_post_neon,%function
.align  5
inpack_pre_post_neon:
    stp     x29, x30, [sp, #-144]!      // 16 bytes for FP/LR + 128 bytes for 8 vectors
    mov     x29, sp

    stp     q8,  q9,  [sp, #16]
    stp     q10, q11, [sp, #48]
    stp     q12, q13, [sp, #80]
    stp     q14, q15, [sp, #112]

    inpack16_pre(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
                 x0, x1, v16, x4)
    inpack16_post(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
                  x2, x3, v16, v17, x4)

    ldp     q8,  q9,  [sp, #16]
    ldp     q10, q11, [sp, #48]
    ldp     q12, q13, [sp, #80]
    ldp     q14, q15, [sp, #112]

    ldp     x29, x30, [sp], #144
    ret
.size   inpack_pre_post_neon,.-inpack_pre_post_neon

.globl  outpack_write_neon
.type   outpack_write_neon,%function
.align  5
outpack_write_neon:
    stp     x29, x30, [sp, #-144]!      // 16 bytes for FP/LR + 128 bytes for 8 vectors
    mov     x29, sp

    stp     q8,  q9,  [sp, #16]
    stp     q10, q11, [sp, #48]
    stp     q12, q13, [sp, #80]
    stp     q14, q15, [sp, #112]

    // Load final AB state into v0-v7
    ldp     q0, q1, [x0]
    ldp     q2, q3, [x0, #32]
    ldp     q4, q5, [x0, #64]
    ldp     q6, q7, [x0, #96]
    // Load final CD state into v8-v15
    ldp     q8, q9, [x1]
    ldp     q10, q11, [x1, #32]
    ldp     q12, q13, [x1, #64]
    ldp     q14, q15, [x1, #96]

    outunpack16(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
                x2, v16, v17, v18, x4)

    write_output(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, x3)

    ldp     q8,q9,[sp,#16]
    ldp     q10,q11,[sp,#48]
    ldp     q12,q13,[sp,#80]
    ldp     q14,q15,[sp,#112]

    ldp     x29,x30,[sp],#144

    ret
.size   outpack_write_neon,.-outpack_write_neon

// Define aliases for C function arguments and key temporary GPRs
//#define ctx_ptr         x0
//#define vout_ptr        x1
//#define vin_ptr         x2
//#define key_table_base  x3  // Will hold ctx->key_table address
//#define temp_gpr        x4  // General scratch GPR
//#define tmp_key_ptr     x4  // Alias for key ptr calculations
//#define round_key_val   x5  // Used inside roundsm16
//#define fls_key_gpr_A   x5  // Used inside fls16
//#define fls_key_gpr_B   x6  // Used inside fls16
//#define lastk_reg       x8  // Holds lastk value
//#define k_reg           x12 // Loop counter 'k'
//#define key_base_idx    x13 // Holds &key_table[k]
//#define loop_end_check  x14 // Holds lastk - 8
// Define aliases for temporary buffer pointers
//#define mem_ab_ptr      x10 // Using vout buffer for AB state
//#define mem_cd_ptr      x11 // Using vout buffer (+128) for CD state
// Note: fls16 uses v8-v15, v20-v31 for its temps

.globl  camellia_encrypt_16blks_neon
.type   camellia_encrypt_16blks_neon,%function
.align  5
camellia_encrypt_16blks_neon:
    // === PROLOGUE ===
    stp     x29,x30,[sp,#-144]!
    mov     x29,sp
    
    stp     q8,q9,[sp,#16]
    stp     q10,q11,[sp,#48]
    stp     q12,q13,[sp,#80]
    stp     q14,q15,[sp,#112]

    // === SETUP ===
    // Determine lastk
    ldr     w9,[x0,#272]
    mov     w8,#32
    mov     w10,#24
    cmp     w9,#16
    csel    w8,w10,w8,le         // x8 -> lastk: if key_length <= 16 then 24, else - 32 

    // === INPUT PROCESSING ===
    // Call inpack16_pre: reads vin(x2), key[0](=ctx_ptr: x0), writes v0-v15
    // clobbers: v16-v18 and x4
    inpack16_pre(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
                 x2, x0, v16, x4)

    // Set up temp buffer pointers using vout_ptr (x1)
    mov     x10,x1          // x10 -> vout
    add     x11,x1,#128     // x11 -> vout + 128

    // Call inpack16_post: byte-slices v0-v15, stores to mem_ab(x10), mem_cd(x11)
    // Clobbers: 
    inpack16_post(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
                  x10, x11, v16, v17, x4)

    // === MAIN ROUND LOOP ===
    mov     x12,#0      // x12 -> k = 0
    sub     x14,x8,#8   // x14 -> lastk - 8
.Lenc_loop:
    // Load Constants into v16-v27
    adrp    x15,camellia_neon_consts
    add     x15,x15,:lo12:camellia_neon_consts
    ldp     q18,q19,[x15],#32    // pre_tf_lo/hi_s1
    ldp     q20,q21,[x15],#32    // pre_tf_lo/hi_s4
    ldp     q22,q23,[x15],#32    // post_tf_lo/hi_s1
    ldp     q24,q25,[x15],#32    // post_tf_lo/hi_s2
    ldp     q26,q27,[x15],#32    // post_tf_lo/hi_s3
    ldr     q17,[x15],#16        // inv_shift_row
    ldr     q16,[x15],#16        // mask_0f

    // Calculate base key pointer for this block: &key_table[k]
    lsl     x13,x12,#3  // x13 -> key_base_idx = k * 8
    add     x13,x0,x13  // x13 = &key_table[k] - assuming here key_table_base = ctx[0] -> x0

    // Round 1 (keys k+2, k+3)
    add     x4,x13,#16  // &key_table[k+2]
    two_roundsm16(v0,v1,v2,v3,v4,v5,v6,v7,x10,x11,x4,store_ab_state)

    // Round 2 (keys k+4, k+5)
    add     x4,x13,#32  // &key_table[k+4]
    two_roundsm16(v0,v1,v2,v3,v4,v5,v6,v7,x10,x11,x4,store_ab_state)

    // Round 3 (keys k+6, k+7)
    add     x4,x13,#48  // &key_table[k+6]
    two_roundsm16(v0,v1,v2,v3,v4,v5,v6,v7,x10,x11,x4,dummy_store)

    // Check loop condition
    cmp     x12,x14
    b.eq    .Lenc_done

    // x4 -> key pointer: &key_table[k+8]
    add     x4,x13,#64
    fls16(v0, v1, v2, v3, v4, v5, v6, v7, x10, x11, x4) // uses x5-x7 and v16-v19 as clobbers

    // Increment k
    add     x12,x12,#8
    b       .Lenc_loop

.Lenc_done:
    // Load final CD state from mem_cd(x11) into v8-v15
    ldp     q8,q9,[x11]
    ldp     q10,q11,[x11,#32]
    ldp     q12,q13,[x11,#64]
    ldp     q14,q15,[x11,#96]

    // Calculate final key pointer: &key_table[lastk] (lastk is in x8)
    lsl     x4,x8,#3    // lastk * 8
    add     x4,x0,x4    // &key_table[lastk]

    // Call outunpack16: Operates in-place on v0-v15
    outunpack16(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, \
                x4, v16, v17, v18, x5)

    write_output(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, x1)

    // === EPILOGUE ===
    ldp     q8,q9,[sp,#16]
    ldp     q10,q11,[sp,#48]
    ldp     q12,q13,[sp,#80]
    ldp     q14,q15,[sp,#112]

    ldp     x29,x30,[sp],#144
    ret
.size   camellia_encrypt_16blks_neon,.-camellia_encrypt_16blks_neon