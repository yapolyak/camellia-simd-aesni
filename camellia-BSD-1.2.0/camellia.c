/* camellia.c ver 1.2.0
 *
 * Copyright (c) 2006,2007
 * NTT (Nippon Telegraph and Telephone Corporation) . All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer as
 *   the first lines of this file unmodified.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NTT ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NTT BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Algorithm Specification 
 *  http://info.isl.ntt.co.jp/crypt/eng/camellia/specifications.html
 */


#include <string.h>
#include <stdlib.h>

#include "camellia.h"

/* u32 must be 32bit word */
typedef unsigned int u32;
typedef unsigned char u8;

/* key constants */

#define CAMELLIA_SIGMA1L (0xA09E667FL)
#define CAMELLIA_SIGMA1R (0x3BCC908BL)
#define CAMELLIA_SIGMA2L (0xB67AE858L)
#define CAMELLIA_SIGMA2R (0x4CAA73B2L)
#define CAMELLIA_SIGMA3L (0xC6EF372FL)
#define CAMELLIA_SIGMA3R (0xE94F82BEL)
#define CAMELLIA_SIGMA4L (0x54FF53A5L)
#define CAMELLIA_SIGMA4R (0xF1D36F1CL)
#define CAMELLIA_SIGMA5L (0x10E527FAL)
#define CAMELLIA_SIGMA5R (0xDE682D1DL)
#define CAMELLIA_SIGMA6L (0xB05688C2L)
#define CAMELLIA_SIGMA6R (0xB3E6C1FDL)

/*
 *  macros
 */


#ifdef __GNUC__

typedef u32 u32_unaligned __attribute__((aligned(1), may_alias));

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define SWAP(x) __builtin_bswap32(x)
#else
#  define SWAP(x) (x)
# endif

# define GETU32(p) SWAP(*((u32_unaligned *)(p)))
# define PUTU32(ct, st) ({*((u32_unaligned *)(ct)) = SWAP((st));})

#elif defined(_MSC_VER)

# define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
# define GETU32(p) SWAP(*((u32 *)(p)))
# define PUTU32(ct, st) {*((u32 *)(ct)) = SWAP((st));}

#else /* not MS-VC */

# define GETU32(pt)				\
    (((u32)(pt)[0] << 24)			\
     ^ ((u32)(pt)[1] << 16)			\
     ^ ((u32)(pt)[2] <<  8)			\
     ^ ((u32)(pt)[3]))

# define PUTU32(ct, st)  {			\
	(ct)[0] = (u8)((st) >> 24);		\
	(ct)[1] = (u8)((st) >> 16);		\
	(ct)[2] = (u8)((st) >>  8);		\
	(ct)[3] = (u8)(st); }

#endif

#define CamelliaSubkeyL(INDEX) (subkey[(INDEX)*2])
#define CamelliaSubkeyR(INDEX) (subkey[(INDEX)*2 + 1])

/* rotation right shift 1byte */
#define CAMELLIA_RR8(x) (((x) >> 8) + ((x) << 24))
/* rotation left shift 1bit */
#define CAMELLIA_RL1(x) (((x) << 1) + ((x) >> 31))
/* rotation left shift 1byte */
#define CAMELLIA_RL8(x) (((x) << 8) + ((x) >> 24))

#define CAMELLIA_ROLDQ(ll, lr, rl, rr, w0, w1, bits)	\
    do {						\
	w0 = ll;					\
	ll = (ll << bits) + (lr >> (32 - bits));	\
	lr = (lr << bits) + (rl >> (32 - bits));	\
	rl = (rl << bits) + (rr >> (32 - bits));	\
	rr = (rr << bits) + (w0 >> (32 - bits));	\
    } while(0)

#define CAMELLIA_ROLDQo32(ll, lr, rl, rr, w0, w1, bits)	\
    do {						\
	w0 = ll;					\
	w1 = lr;					\
	ll = (lr << (bits - 32)) + (rl >> (64 - bits));	\
	lr = (rl << (bits - 32)) + (rr >> (64 - bits));	\
	rl = (rr << (bits - 32)) + (w0 >> (64 - bits));	\
	rr = (w0 << (bits - 32)) + (w1 >> (64 - bits));	\
    } while(0)

#define CAMELLIA_SP1110(INDEX) (camellia_sp1110[(INDEX)])
#define CAMELLIA_SP0222(INDEX) (camellia_sp0222[(INDEX)])
#define CAMELLIA_SP3033(INDEX) (camellia_sp3033[(INDEX)])
#define CAMELLIA_SP4404(INDEX) (camellia_sp4404[(INDEX)])

#define CAMELLIA_F(xl, xr, kl, kr, yl, yr, il, ir, t0, t1)	\
    do {							\
	il = xl ^ kl;						\
	ir = xr ^ kr;						\
	t0 = il >> 16;						\
	t1 = ir >> 16;						\
	yl = CAMELLIA_SP1110(ir & 0xff)				\
	    ^ CAMELLIA_SP0222((t1 >> 8) & 0xff)			\
	    ^ CAMELLIA_SP3033(t1 & 0xff)			\
	    ^ CAMELLIA_SP4404((ir >> 8) & 0xff);		\
	yr = CAMELLIA_SP1110((t0 >> 8) & 0xff)			\
	    ^ CAMELLIA_SP0222(t0 & 0xff)			\
	    ^ CAMELLIA_SP3033((il >> 8) & 0xff)			\
	    ^ CAMELLIA_SP4404(il & 0xff);			\
	yl ^= yr;						\
	yr = CAMELLIA_RR8(yr);					\
	yr ^= yl;						\
    } while(0)


/*
 * for speed up
 *
 */
#define CAMELLIA_FLS(ll, lr, rl, rr, kll, klr, krl, krr, t0, t1, t2, t3) \
    do {								\
	t0 = kll;							\
	t0 &= ll;							\
	lr ^= CAMELLIA_RL1(t0);						\
	t1 = klr;							\
	t1 |= lr;							\
	ll ^= t1;							\
									\
	t2 = krr;							\
	t2 |= rr;							\
	rl ^= t2;							\
	t3 = krl;							\
	t3 &= rl;							\
	rr ^= CAMELLIA_RL1(t3);						\
    } while(0)

#define CAMELLIA_ROUNDSM(xl, xr, kl, kr, yl, yr, il, ir, t0, t1)	\
    do {								\
	ir = CAMELLIA_SP1110(xr & 0xff)					\
	    ^ CAMELLIA_SP0222((xr >> 24) & 0xff)			\
	    ^ CAMELLIA_SP3033((xr >> 16) & 0xff)			\
	    ^ CAMELLIA_SP4404((xr >> 8) & 0xff);			\
	il = CAMELLIA_SP1110((xl >> 24) & 0xff)				\
	    ^ CAMELLIA_SP0222((xl >> 16) & 0xff)			\
	    ^ CAMELLIA_SP3033((xl >> 8) & 0xff)				\
	    ^ CAMELLIA_SP4404(xl & 0xff);				\
	il ^= kl;							\
	ir ^= kr;							\
	ir ^= il;							\
	il = CAMELLIA_RR8(il);						\
	il ^= ir;							\
	yl ^= ir;							\
	yr ^= il;							\
    } while(0)


static const u32 camellia_sp1110[256] = {
    0x70707000,0x82828200,0x2c2c2c00,0xececec00,
    0xb3b3b300,0x27272700,0xc0c0c000,0xe5e5e500,
    0xe4e4e400,0x85858500,0x57575700,0x35353500,
    0xeaeaea00,0x0c0c0c00,0xaeaeae00,0x41414100,
    0x23232300,0xefefef00,0x6b6b6b00,0x93939300,
    0x45454500,0x19191900,0xa5a5a500,0x21212100,
    0xededed00,0x0e0e0e00,0x4f4f4f00,0x4e4e4e00,
    0x1d1d1d00,0x65656500,0x92929200,0xbdbdbd00,
    0x86868600,0xb8b8b800,0xafafaf00,0x8f8f8f00,
    0x7c7c7c00,0xebebeb00,0x1f1f1f00,0xcecece00,
    0x3e3e3e00,0x30303000,0xdcdcdc00,0x5f5f5f00,
    0x5e5e5e00,0xc5c5c500,0x0b0b0b00,0x1a1a1a00,
    0xa6a6a600,0xe1e1e100,0x39393900,0xcacaca00,
    0xd5d5d500,0x47474700,0x5d5d5d00,0x3d3d3d00,
    0xd9d9d900,0x01010100,0x5a5a5a00,0xd6d6d600,
    0x51515100,0x56565600,0x6c6c6c00,0x4d4d4d00,
    0x8b8b8b00,0x0d0d0d00,0x9a9a9a00,0x66666600,
    0xfbfbfb00,0xcccccc00,0xb0b0b000,0x2d2d2d00,
    0x74747400,0x12121200,0x2b2b2b00,0x20202000,
    0xf0f0f000,0xb1b1b100,0x84848400,0x99999900,
    0xdfdfdf00,0x4c4c4c00,0xcbcbcb00,0xc2c2c200,
    0x34343400,0x7e7e7e00,0x76767600,0x05050500,
    0x6d6d6d00,0xb7b7b700,0xa9a9a900,0x31313100,
    0xd1d1d100,0x17171700,0x04040400,0xd7d7d700,
    0x14141400,0x58585800,0x3a3a3a00,0x61616100,
    0xdedede00,0x1b1b1b00,0x11111100,0x1c1c1c00,
    0x32323200,0x0f0f0f00,0x9c9c9c00,0x16161600,
    0x53535300,0x18181800,0xf2f2f200,0x22222200,
    0xfefefe00,0x44444400,0xcfcfcf00,0xb2b2b200,
    0xc3c3c300,0xb5b5b500,0x7a7a7a00,0x91919100,
    0x24242400,0x08080800,0xe8e8e800,0xa8a8a800,
    0x60606000,0xfcfcfc00,0x69696900,0x50505000,
    0xaaaaaa00,0xd0d0d000,0xa0a0a000,0x7d7d7d00,
    0xa1a1a100,0x89898900,0x62626200,0x97979700,
    0x54545400,0x5b5b5b00,0x1e1e1e00,0x95959500,
    0xe0e0e000,0xffffff00,0x64646400,0xd2d2d200,
    0x10101000,0xc4c4c400,0x00000000,0x48484800,
    0xa3a3a300,0xf7f7f700,0x75757500,0xdbdbdb00,
    0x8a8a8a00,0x03030300,0xe6e6e600,0xdadada00,
    0x09090900,0x3f3f3f00,0xdddddd00,0x94949400,
    0x87878700,0x5c5c5c00,0x83838300,0x02020200,
    0xcdcdcd00,0x4a4a4a00,0x90909000,0x33333300,
    0x73737300,0x67676700,0xf6f6f600,0xf3f3f300,
    0x9d9d9d00,0x7f7f7f00,0xbfbfbf00,0xe2e2e200,
    0x52525200,0x9b9b9b00,0xd8d8d800,0x26262600,
    0xc8c8c800,0x37373700,0xc6c6c600,0x3b3b3b00,
    0x81818100,0x96969600,0x6f6f6f00,0x4b4b4b00,
    0x13131300,0xbebebe00,0x63636300,0x2e2e2e00,
    0xe9e9e900,0x79797900,0xa7a7a700,0x8c8c8c00,
    0x9f9f9f00,0x6e6e6e00,0xbcbcbc00,0x8e8e8e00,
    0x29292900,0xf5f5f500,0xf9f9f900,0xb6b6b600,
    0x2f2f2f00,0xfdfdfd00,0xb4b4b400,0x59595900,
    0x78787800,0x98989800,0x06060600,0x6a6a6a00,
    0xe7e7e700,0x46464600,0x71717100,0xbababa00,
    0xd4d4d400,0x25252500,0xababab00,0x42424200,
    0x88888800,0xa2a2a200,0x8d8d8d00,0xfafafa00,
    0x72727200,0x07070700,0xb9b9b900,0x55555500,
    0xf8f8f800,0xeeeeee00,0xacacac00,0x0a0a0a00,
    0x36363600,0x49494900,0x2a2a2a00,0x68686800,
    0x3c3c3c00,0x38383800,0xf1f1f100,0xa4a4a400,
    0x40404000,0x28282800,0xd3d3d300,0x7b7b7b00,
    0xbbbbbb00,0xc9c9c900,0x43434300,0xc1c1c100,
    0x15151500,0xe3e3e300,0xadadad00,0xf4f4f400,
    0x77777700,0xc7c7c700,0x80808000,0x9e9e9e00,
};

static const u32 camellia_sp0222[256] = {
    0x00e0e0e0,0x00050505,0x00585858,0x00d9d9d9,
    0x00676767,0x004e4e4e,0x00818181,0x00cbcbcb,
    0x00c9c9c9,0x000b0b0b,0x00aeaeae,0x006a6a6a,
    0x00d5d5d5,0x00181818,0x005d5d5d,0x00828282,
    0x00464646,0x00dfdfdf,0x00d6d6d6,0x00272727,
    0x008a8a8a,0x00323232,0x004b4b4b,0x00424242,
    0x00dbdbdb,0x001c1c1c,0x009e9e9e,0x009c9c9c,
    0x003a3a3a,0x00cacaca,0x00252525,0x007b7b7b,
    0x000d0d0d,0x00717171,0x005f5f5f,0x001f1f1f,
    0x00f8f8f8,0x00d7d7d7,0x003e3e3e,0x009d9d9d,
    0x007c7c7c,0x00606060,0x00b9b9b9,0x00bebebe,
    0x00bcbcbc,0x008b8b8b,0x00161616,0x00343434,
    0x004d4d4d,0x00c3c3c3,0x00727272,0x00959595,
    0x00ababab,0x008e8e8e,0x00bababa,0x007a7a7a,
    0x00b3b3b3,0x00020202,0x00b4b4b4,0x00adadad,
    0x00a2a2a2,0x00acacac,0x00d8d8d8,0x009a9a9a,
    0x00171717,0x001a1a1a,0x00353535,0x00cccccc,
    0x00f7f7f7,0x00999999,0x00616161,0x005a5a5a,
    0x00e8e8e8,0x00242424,0x00565656,0x00404040,
    0x00e1e1e1,0x00636363,0x00090909,0x00333333,
    0x00bfbfbf,0x00989898,0x00979797,0x00858585,
    0x00686868,0x00fcfcfc,0x00ececec,0x000a0a0a,
    0x00dadada,0x006f6f6f,0x00535353,0x00626262,
    0x00a3a3a3,0x002e2e2e,0x00080808,0x00afafaf,
    0x00282828,0x00b0b0b0,0x00747474,0x00c2c2c2,
    0x00bdbdbd,0x00363636,0x00222222,0x00383838,
    0x00646464,0x001e1e1e,0x00393939,0x002c2c2c,
    0x00a6a6a6,0x00303030,0x00e5e5e5,0x00444444,
    0x00fdfdfd,0x00888888,0x009f9f9f,0x00656565,
    0x00878787,0x006b6b6b,0x00f4f4f4,0x00232323,
    0x00484848,0x00101010,0x00d1d1d1,0x00515151,
    0x00c0c0c0,0x00f9f9f9,0x00d2d2d2,0x00a0a0a0,
    0x00555555,0x00a1a1a1,0x00414141,0x00fafafa,
    0x00434343,0x00131313,0x00c4c4c4,0x002f2f2f,
    0x00a8a8a8,0x00b6b6b6,0x003c3c3c,0x002b2b2b,
    0x00c1c1c1,0x00ffffff,0x00c8c8c8,0x00a5a5a5,
    0x00202020,0x00898989,0x00000000,0x00909090,
    0x00474747,0x00efefef,0x00eaeaea,0x00b7b7b7,
    0x00151515,0x00060606,0x00cdcdcd,0x00b5b5b5,
    0x00121212,0x007e7e7e,0x00bbbbbb,0x00292929,
    0x000f0f0f,0x00b8b8b8,0x00070707,0x00040404,
    0x009b9b9b,0x00949494,0x00212121,0x00666666,
    0x00e6e6e6,0x00cecece,0x00ededed,0x00e7e7e7,
    0x003b3b3b,0x00fefefe,0x007f7f7f,0x00c5c5c5,
    0x00a4a4a4,0x00373737,0x00b1b1b1,0x004c4c4c,
    0x00919191,0x006e6e6e,0x008d8d8d,0x00767676,
    0x00030303,0x002d2d2d,0x00dedede,0x00969696,
    0x00262626,0x007d7d7d,0x00c6c6c6,0x005c5c5c,
    0x00d3d3d3,0x00f2f2f2,0x004f4f4f,0x00191919,
    0x003f3f3f,0x00dcdcdc,0x00797979,0x001d1d1d,
    0x00525252,0x00ebebeb,0x00f3f3f3,0x006d6d6d,
    0x005e5e5e,0x00fbfbfb,0x00696969,0x00b2b2b2,
    0x00f0f0f0,0x00313131,0x000c0c0c,0x00d4d4d4,
    0x00cfcfcf,0x008c8c8c,0x00e2e2e2,0x00757575,
    0x00a9a9a9,0x004a4a4a,0x00575757,0x00848484,
    0x00111111,0x00454545,0x001b1b1b,0x00f5f5f5,
    0x00e4e4e4,0x000e0e0e,0x00737373,0x00aaaaaa,
    0x00f1f1f1,0x00dddddd,0x00595959,0x00141414,
    0x006c6c6c,0x00929292,0x00545454,0x00d0d0d0,
    0x00787878,0x00707070,0x00e3e3e3,0x00494949,
    0x00808080,0x00505050,0x00a7a7a7,0x00f6f6f6,
    0x00777777,0x00939393,0x00868686,0x00838383,
    0x002a2a2a,0x00c7c7c7,0x005b5b5b,0x00e9e9e9,
    0x00eeeeee,0x008f8f8f,0x00010101,0x003d3d3d,
};

static const u32 camellia_sp3033[256] = {
    0x38003838,0x41004141,0x16001616,0x76007676,
    0xd900d9d9,0x93009393,0x60006060,0xf200f2f2,
    0x72007272,0xc200c2c2,0xab00abab,0x9a009a9a,
    0x75007575,0x06000606,0x57005757,0xa000a0a0,
    0x91009191,0xf700f7f7,0xb500b5b5,0xc900c9c9,
    0xa200a2a2,0x8c008c8c,0xd200d2d2,0x90009090,
    0xf600f6f6,0x07000707,0xa700a7a7,0x27002727,
    0x8e008e8e,0xb200b2b2,0x49004949,0xde00dede,
    0x43004343,0x5c005c5c,0xd700d7d7,0xc700c7c7,
    0x3e003e3e,0xf500f5f5,0x8f008f8f,0x67006767,
    0x1f001f1f,0x18001818,0x6e006e6e,0xaf00afaf,
    0x2f002f2f,0xe200e2e2,0x85008585,0x0d000d0d,
    0x53005353,0xf000f0f0,0x9c009c9c,0x65006565,
    0xea00eaea,0xa300a3a3,0xae00aeae,0x9e009e9e,
    0xec00ecec,0x80008080,0x2d002d2d,0x6b006b6b,
    0xa800a8a8,0x2b002b2b,0x36003636,0xa600a6a6,
    0xc500c5c5,0x86008686,0x4d004d4d,0x33003333,
    0xfd00fdfd,0x66006666,0x58005858,0x96009696,
    0x3a003a3a,0x09000909,0x95009595,0x10001010,
    0x78007878,0xd800d8d8,0x42004242,0xcc00cccc,
    0xef00efef,0x26002626,0xe500e5e5,0x61006161,
    0x1a001a1a,0x3f003f3f,0x3b003b3b,0x82008282,
    0xb600b6b6,0xdb00dbdb,0xd400d4d4,0x98009898,
    0xe800e8e8,0x8b008b8b,0x02000202,0xeb00ebeb,
    0x0a000a0a,0x2c002c2c,0x1d001d1d,0xb000b0b0,
    0x6f006f6f,0x8d008d8d,0x88008888,0x0e000e0e,
    0x19001919,0x87008787,0x4e004e4e,0x0b000b0b,
    0xa900a9a9,0x0c000c0c,0x79007979,0x11001111,
    0x7f007f7f,0x22002222,0xe700e7e7,0x59005959,
    0xe100e1e1,0xda00dada,0x3d003d3d,0xc800c8c8,
    0x12001212,0x04000404,0x74007474,0x54005454,
    0x30003030,0x7e007e7e,0xb400b4b4,0x28002828,
    0x55005555,0x68006868,0x50005050,0xbe00bebe,
    0xd000d0d0,0xc400c4c4,0x31003131,0xcb00cbcb,
    0x2a002a2a,0xad00adad,0x0f000f0f,0xca00caca,
    0x70007070,0xff00ffff,0x32003232,0x69006969,
    0x08000808,0x62006262,0x00000000,0x24002424,
    0xd100d1d1,0xfb00fbfb,0xba00baba,0xed00eded,
    0x45004545,0x81008181,0x73007373,0x6d006d6d,
    0x84008484,0x9f009f9f,0xee00eeee,0x4a004a4a,
    0xc300c3c3,0x2e002e2e,0xc100c1c1,0x01000101,
    0xe600e6e6,0x25002525,0x48004848,0x99009999,
    0xb900b9b9,0xb300b3b3,0x7b007b7b,0xf900f9f9,
    0xce00cece,0xbf00bfbf,0xdf00dfdf,0x71007171,
    0x29002929,0xcd00cdcd,0x6c006c6c,0x13001313,
    0x64006464,0x9b009b9b,0x63006363,0x9d009d9d,
    0xc000c0c0,0x4b004b4b,0xb700b7b7,0xa500a5a5,
    0x89008989,0x5f005f5f,0xb100b1b1,0x17001717,
    0xf400f4f4,0xbc00bcbc,0xd300d3d3,0x46004646,
    0xcf00cfcf,0x37003737,0x5e005e5e,0x47004747,
    0x94009494,0xfa00fafa,0xfc00fcfc,0x5b005b5b,
    0x97009797,0xfe00fefe,0x5a005a5a,0xac00acac,
    0x3c003c3c,0x4c004c4c,0x03000303,0x35003535,
    0xf300f3f3,0x23002323,0xb800b8b8,0x5d005d5d,
    0x6a006a6a,0x92009292,0xd500d5d5,0x21002121,
    0x44004444,0x51005151,0xc600c6c6,0x7d007d7d,
    0x39003939,0x83008383,0xdc00dcdc,0xaa00aaaa,
    0x7c007c7c,0x77007777,0x56005656,0x05000505,
    0x1b001b1b,0xa400a4a4,0x15001515,0x34003434,
    0x1e001e1e,0x1c001c1c,0xf800f8f8,0x52005252,
    0x20002020,0x14001414,0xe900e9e9,0xbd00bdbd,
    0xdd00dddd,0xe400e4e4,0xa100a1a1,0xe000e0e0,
    0x8a008a8a,0xf100f1f1,0xd600d6d6,0x7a007a7a,
    0xbb00bbbb,0xe300e3e3,0x40004040,0x4f004f4f,
};

static const u32 camellia_sp4404[256] = {
    0x70700070,0x2c2c002c,0xb3b300b3,0xc0c000c0,
    0xe4e400e4,0x57570057,0xeaea00ea,0xaeae00ae,
    0x23230023,0x6b6b006b,0x45450045,0xa5a500a5,
    0xeded00ed,0x4f4f004f,0x1d1d001d,0x92920092,
    0x86860086,0xafaf00af,0x7c7c007c,0x1f1f001f,
    0x3e3e003e,0xdcdc00dc,0x5e5e005e,0x0b0b000b,
    0xa6a600a6,0x39390039,0xd5d500d5,0x5d5d005d,
    0xd9d900d9,0x5a5a005a,0x51510051,0x6c6c006c,
    0x8b8b008b,0x9a9a009a,0xfbfb00fb,0xb0b000b0,
    0x74740074,0x2b2b002b,0xf0f000f0,0x84840084,
    0xdfdf00df,0xcbcb00cb,0x34340034,0x76760076,
    0x6d6d006d,0xa9a900a9,0xd1d100d1,0x04040004,
    0x14140014,0x3a3a003a,0xdede00de,0x11110011,
    0x32320032,0x9c9c009c,0x53530053,0xf2f200f2,
    0xfefe00fe,0xcfcf00cf,0xc3c300c3,0x7a7a007a,
    0x24240024,0xe8e800e8,0x60600060,0x69690069,
    0xaaaa00aa,0xa0a000a0,0xa1a100a1,0x62620062,
    0x54540054,0x1e1e001e,0xe0e000e0,0x64640064,
    0x10100010,0x00000000,0xa3a300a3,0x75750075,
    0x8a8a008a,0xe6e600e6,0x09090009,0xdddd00dd,
    0x87870087,0x83830083,0xcdcd00cd,0x90900090,
    0x73730073,0xf6f600f6,0x9d9d009d,0xbfbf00bf,
    0x52520052,0xd8d800d8,0xc8c800c8,0xc6c600c6,
    0x81810081,0x6f6f006f,0x13130013,0x63630063,
    0xe9e900e9,0xa7a700a7,0x9f9f009f,0xbcbc00bc,
    0x29290029,0xf9f900f9,0x2f2f002f,0xb4b400b4,
    0x78780078,0x06060006,0xe7e700e7,0x71710071,
    0xd4d400d4,0xabab00ab,0x88880088,0x8d8d008d,
    0x72720072,0xb9b900b9,0xf8f800f8,0xacac00ac,
    0x36360036,0x2a2a002a,0x3c3c003c,0xf1f100f1,
    0x40400040,0xd3d300d3,0xbbbb00bb,0x43430043,
    0x15150015,0xadad00ad,0x77770077,0x80800080,
    0x82820082,0xecec00ec,0x27270027,0xe5e500e5,
    0x85850085,0x35350035,0x0c0c000c,0x41410041,
    0xefef00ef,0x93930093,0x19190019,0x21210021,
    0x0e0e000e,0x4e4e004e,0x65650065,0xbdbd00bd,
    0xb8b800b8,0x8f8f008f,0xebeb00eb,0xcece00ce,
    0x30300030,0x5f5f005f,0xc5c500c5,0x1a1a001a,
    0xe1e100e1,0xcaca00ca,0x47470047,0x3d3d003d,
    0x01010001,0xd6d600d6,0x56560056,0x4d4d004d,
    0x0d0d000d,0x66660066,0xcccc00cc,0x2d2d002d,
    0x12120012,0x20200020,0xb1b100b1,0x99990099,
    0x4c4c004c,0xc2c200c2,0x7e7e007e,0x05050005,
    0xb7b700b7,0x31310031,0x17170017,0xd7d700d7,
    0x58580058,0x61610061,0x1b1b001b,0x1c1c001c,
    0x0f0f000f,0x16160016,0x18180018,0x22220022,
    0x44440044,0xb2b200b2,0xb5b500b5,0x91910091,
    0x08080008,0xa8a800a8,0xfcfc00fc,0x50500050,
    0xd0d000d0,0x7d7d007d,0x89890089,0x97970097,
    0x5b5b005b,0x95950095,0xffff00ff,0xd2d200d2,
    0xc4c400c4,0x48480048,0xf7f700f7,0xdbdb00db,
    0x03030003,0xdada00da,0x3f3f003f,0x94940094,
    0x5c5c005c,0x02020002,0x4a4a004a,0x33330033,
    0x67670067,0xf3f300f3,0x7f7f007f,0xe2e200e2,
    0x9b9b009b,0x26260026,0x37370037,0x3b3b003b,
    0x96960096,0x4b4b004b,0xbebe00be,0x2e2e002e,
    0x79790079,0x8c8c008c,0x6e6e006e,0x8e8e008e,
    0xf5f500f5,0xb6b600b6,0xfdfd00fd,0x59590059,
    0x98980098,0x6a6a006a,0x46460046,0xbaba00ba,
    0x25250025,0x42420042,0xa2a200a2,0xfafa00fa,
    0x07070007,0x55550055,0xeeee00ee,0x0a0a000a,
    0x49490049,0x68680068,0x38380038,0xa4a400a4,
    0x28280028,0x7b7b007b,0xc9c900c9,0xc1c100c1,
    0xe3e300e3,0xf4f400f4,0xc7c700c7,0x9e9e009e,
};


/**
 * Stuff related to the Camellia key schedule
 */
#define subl(x) subL[(x)]
#define subr(x) subR[(x)]

static void camellia_setup128(const unsigned char *key, u32 *subkey)
{
    u32 kll, klr, krl, krr;
    u32 il, ir, t0, t1, w0, w1;
    u32 kw4l, kw4r, dw, tl, tr;
    u32 subL[26];
    u32 subR[26];

    /**
     *  k == kll || klr || krl || krr (|| is concatination)
     */
    kll = GETU32(key     );
    klr = GETU32(key +  4);
    krl = GETU32(key +  8);
    krr = GETU32(key + 12);
    /**
     * generate KL dependent subkeys
     */
    subl(0) = kll; subr(0) = klr;
    subl(1) = krl; subr(1) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(4) = kll; subr(4) = klr;
    subl(5) = krl; subr(5) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 30);
    subl(10) = kll; subr(10) = klr;
    subl(11) = krl; subr(11) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(13) = krl; subr(13) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(16) = kll; subr(16) = klr;
    subl(17) = krl; subr(17) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(18) = kll; subr(18) = klr;
    subl(19) = krl; subr(19) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(22) = kll; subr(22) = klr;
    subl(23) = krl; subr(23) = krr;

    /* generate KA */
    kll = subl(0); klr = subr(0);
    krl = subl(1); krr = subr(1);
    CAMELLIA_F(kll, klr,
	       CAMELLIA_SIGMA1L, CAMELLIA_SIGMA1R,
	       w0, w1, il, ir, t0, t1);
    krl ^= w0; krr ^= w1;
    CAMELLIA_F(krl, krr,
	       CAMELLIA_SIGMA2L, CAMELLIA_SIGMA2R,
	       kll, klr, il, ir, t0, t1);
    CAMELLIA_F(kll, klr,
	       CAMELLIA_SIGMA3L, CAMELLIA_SIGMA3R,
	       krl, krr, il, ir, t0, t1);
    krl ^= w0; krr ^= w1;
    CAMELLIA_F(krl, krr,
	       CAMELLIA_SIGMA4L, CAMELLIA_SIGMA4R,
	       w0, w1, il, ir, t0, t1);
    kll ^= w0; klr ^= w1;

    /* generate KA dependent subkeys */
    subl(2) = kll; subr(2) = klr;
    subl(3) = krl; subr(3) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(6) = kll; subr(6) = klr;
    subl(7) = krl; subr(7) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(8) = kll; subr(8) = klr;
    subl(9) = krl; subr(9) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(12) = kll; subr(12) = klr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(14) = kll; subr(14) = klr;
    subl(15) = krl; subr(15) = krr;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 34);
    subl(20) = kll; subr(20) = klr;
    subl(21) = krl; subr(21) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(24) = kll; subr(24) = klr;
    subl(25) = krl; subr(25) = krr;


    /* absorb kw2 to other subkeys */
    subl(3) ^= subl(1); subr(3) ^= subr(1);
    subl(5) ^= subl(1); subr(5) ^= subr(1);
    subl(7) ^= subl(1); subr(7) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(9);
    dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw);
    subl(11) ^= subl(1); subr(11) ^= subr(1);
    subl(13) ^= subl(1); subr(13) ^= subr(1);
    subl(15) ^= subl(1); subr(15) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(17);
    dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw);
    subl(19) ^= subl(1); subr(19) ^= subr(1);
    subl(21) ^= subl(1); subr(21) ^= subr(1);
    subl(23) ^= subl(1); subr(23) ^= subr(1);
    subl(24) ^= subl(1); subr(24) ^= subr(1);

    /* absorb kw4 to other subkeys */
    kw4l = subl(25); kw4r = subr(25);
    subl(22) ^= kw4l; subr(22) ^= kw4r;
    subl(20) ^= kw4l; subr(20) ^= kw4r;
    subl(18) ^= kw4l; subr(18) ^= kw4r;
    kw4l ^= kw4r & ~subr(16);
    dw = kw4l & subl(16), kw4r ^= CAMELLIA_RL1(dw);
    subl(14) ^= kw4l; subr(14) ^= kw4r;
    subl(12) ^= kw4l; subr(12) ^= kw4r;
    subl(10) ^= kw4l; subr(10) ^= kw4r;
    kw4l ^= kw4r & ~subr(8);
    dw = kw4l & subl(8), kw4r ^= CAMELLIA_RL1(dw);
    subl(6) ^= kw4l; subr(6) ^= kw4r;
    subl(4) ^= kw4l; subr(4) ^= kw4r;
    subl(2) ^= kw4l; subr(2) ^= kw4r;
    subl(0) ^= kw4l; subr(0) ^= kw4r;

    /* key XOR is end of F-function */
    CamelliaSubkeyL(0) = subl(0) ^ subl(2);
    CamelliaSubkeyR(0) = subr(0) ^ subr(2);
    CamelliaSubkeyL(2) = subl(3);
    CamelliaSubkeyR(2) = subr(3);
    CamelliaSubkeyL(3) = subl(2) ^ subl(4);
    CamelliaSubkeyR(3) = subr(2) ^ subr(4);
    CamelliaSubkeyL(4) = subl(3) ^ subl(5);
    CamelliaSubkeyR(4) = subr(3) ^ subr(5);
    CamelliaSubkeyL(5) = subl(4) ^ subl(6);
    CamelliaSubkeyR(5) = subr(4) ^ subr(6);
    CamelliaSubkeyL(6) = subl(5) ^ subl(7);
    CamelliaSubkeyR(6) = subr(5) ^ subr(7);
    tl = subl(10) ^ (subr(10) & ~subr(8));
    dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(7) = subl(6) ^ tl;
    CamelliaSubkeyR(7) = subr(6) ^ tr;
    CamelliaSubkeyL(8) = subl(8);
    CamelliaSubkeyR(8) = subr(8);
    CamelliaSubkeyL(9) = subl(9);
    CamelliaSubkeyR(9) = subr(9);
    tl = subl(7) ^ (subr(7) & ~subr(9));
    dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(10) = tl ^ subl(11);
    CamelliaSubkeyR(10) = tr ^ subr(11);
    CamelliaSubkeyL(11) = subl(10) ^ subl(12);
    CamelliaSubkeyR(11) = subr(10) ^ subr(12);
    CamelliaSubkeyL(12) = subl(11) ^ subl(13);
    CamelliaSubkeyR(12) = subr(11) ^ subr(13);
    CamelliaSubkeyL(13) = subl(12) ^ subl(14);
    CamelliaSubkeyR(13) = subr(12) ^ subr(14);
    CamelliaSubkeyL(14) = subl(13) ^ subl(15);
    CamelliaSubkeyR(14) = subr(13) ^ subr(15);
    tl = subl(18) ^ (subr(18) & ~subr(16));
    dw = tl & subl(16),	tr = subr(18) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(15) = subl(14) ^ tl;
    CamelliaSubkeyR(15) = subr(14) ^ tr;
    CamelliaSubkeyL(16) = subl(16);
    CamelliaSubkeyR(16) = subr(16);
    CamelliaSubkeyL(17) = subl(17);
    CamelliaSubkeyR(17) = subr(17);
    tl = subl(15) ^ (subr(15) & ~subr(17));
    dw = tl & subl(17),	tr = subr(15) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(18) = tl ^ subl(19);
    CamelliaSubkeyR(18) = tr ^ subr(19);
    CamelliaSubkeyL(19) = subl(18) ^ subl(20);
    CamelliaSubkeyR(19) = subr(18) ^ subr(20);
    CamelliaSubkeyL(20) = subl(19) ^ subl(21);
    CamelliaSubkeyR(20) = subr(19) ^ subr(21);
    CamelliaSubkeyL(21) = subl(20) ^ subl(22);
    CamelliaSubkeyR(21) = subr(20) ^ subr(22);
    CamelliaSubkeyL(22) = subl(21) ^ subl(23);
    CamelliaSubkeyR(22) = subr(21) ^ subr(23);
    CamelliaSubkeyL(23) = subl(22);
    CamelliaSubkeyR(23) = subr(22);
    CamelliaSubkeyL(24) = subl(24) ^ subl(23);
    CamelliaSubkeyR(24) = subr(24) ^ subr(23);

    /* apply the inverse of the last half of P-function */
    dw = CamelliaSubkeyL(2) ^ CamelliaSubkeyR(2), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(2) = CamelliaSubkeyL(2) ^ dw, CamelliaSubkeyL(2) = dw;
    dw = CamelliaSubkeyL(3) ^ CamelliaSubkeyR(3), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(3) = CamelliaSubkeyL(3) ^ dw, CamelliaSubkeyL(3) = dw;
    dw = CamelliaSubkeyL(4) ^ CamelliaSubkeyR(4), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(4) = CamelliaSubkeyL(4) ^ dw, CamelliaSubkeyL(4) = dw;
    dw = CamelliaSubkeyL(5) ^ CamelliaSubkeyR(5), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(5) = CamelliaSubkeyL(5) ^ dw, CamelliaSubkeyL(5) = dw;
    dw = CamelliaSubkeyL(6) ^ CamelliaSubkeyR(6), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(6) = CamelliaSubkeyL(6) ^ dw, CamelliaSubkeyL(6) = dw;
    dw = CamelliaSubkeyL(7) ^ CamelliaSubkeyR(7), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(7) = CamelliaSubkeyL(7) ^ dw, CamelliaSubkeyL(7) = dw;
    dw = CamelliaSubkeyL(10) ^ CamelliaSubkeyR(10), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(10) = CamelliaSubkeyL(10) ^ dw, CamelliaSubkeyL(10) = dw;
    dw = CamelliaSubkeyL(11) ^ CamelliaSubkeyR(11), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(11) = CamelliaSubkeyL(11) ^ dw, CamelliaSubkeyL(11) = dw;
    dw = CamelliaSubkeyL(12) ^ CamelliaSubkeyR(12), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(12) = CamelliaSubkeyL(12) ^ dw, CamelliaSubkeyL(12) = dw;
    dw = CamelliaSubkeyL(13) ^ CamelliaSubkeyR(13), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(13) = CamelliaSubkeyL(13) ^ dw, CamelliaSubkeyL(13) = dw;
    dw = CamelliaSubkeyL(14) ^ CamelliaSubkeyR(14), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(14) = CamelliaSubkeyL(14) ^ dw, CamelliaSubkeyL(14) = dw;
    dw = CamelliaSubkeyL(15) ^ CamelliaSubkeyR(15), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(15) = CamelliaSubkeyL(15) ^ dw, CamelliaSubkeyL(15) = dw;
    dw = CamelliaSubkeyL(18) ^ CamelliaSubkeyR(18), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(18) = CamelliaSubkeyL(18) ^ dw, CamelliaSubkeyL(18) = dw;
    dw = CamelliaSubkeyL(19) ^ CamelliaSubkeyR(19), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(19) = CamelliaSubkeyL(19) ^ dw, CamelliaSubkeyL(19) = dw;
    dw = CamelliaSubkeyL(20) ^ CamelliaSubkeyR(20), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(20) = CamelliaSubkeyL(20) ^ dw, CamelliaSubkeyL(20) = dw;
    dw = CamelliaSubkeyL(21) ^ CamelliaSubkeyR(21), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(21) = CamelliaSubkeyL(21) ^ dw, CamelliaSubkeyL(21) = dw;
    dw = CamelliaSubkeyL(22) ^ CamelliaSubkeyR(22), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(22) = CamelliaSubkeyL(22) ^ dw, CamelliaSubkeyL(22) = dw;
    dw = CamelliaSubkeyL(23) ^ CamelliaSubkeyR(23), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(23) = CamelliaSubkeyL(23) ^ dw, CamelliaSubkeyL(23) = dw;

    return;
}

static void camellia_setup256(const unsigned char *key, u32 *subkey)
{
    u32 kll,klr,krl,krr;           /* left half of key */
    u32 krll,krlr,krrl,krrr;       /* right half of key */
    u32 il, ir, t0, t1, w0, w1;    /* temporary variables */
    u32 kw4l, kw4r, dw, tl, tr;
    u32 subL[34];
    u32 subR[34];

    /**
     *  key = (kll || klr || krl || krr || krll || krlr || krrl || krrr)
     *  (|| is concatination)
     */

    kll  = GETU32(key     );
    klr  = GETU32(key +  4);
    krl  = GETU32(key +  8);
    krr  = GETU32(key + 12);
    krll = GETU32(key + 16);
    krlr = GETU32(key + 20);
    krrl = GETU32(key + 24);
    krrr = GETU32(key + 28);

    /* generate KL dependent subkeys */
    subl(0) = kll; subr(0) = klr;
    subl(1) = krl; subr(1) = krr;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 45);
    subl(12) = kll; subr(12) = klr;
    subl(13) = krl; subr(13) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(16) = kll; subr(16) = klr;
    subl(17) = krl; subr(17) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(22) = kll; subr(22) = klr;
    subl(23) = krl; subr(23) = krr;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 34);
    subl(30) = kll; subr(30) = klr;
    subl(31) = krl; subr(31) = krr;

    /* generate KR dependent subkeys */
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 15);
    subl(4) = krll; subr(4) = krlr;
    subl(5) = krrl; subr(5) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 15);
    subl(8) = krll; subr(8) = krlr;
    subl(9) = krrl; subr(9) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(18) = krll; subr(18) = krlr;
    subl(19) = krrl; subr(19) = krrr;
    CAMELLIA_ROLDQo32(krll, krlr, krrl, krrr, w0, w1, 34);
    subl(26) = krll; subr(26) = krlr;
    subl(27) = krrl; subr(27) = krrr;
    CAMELLIA_ROLDQo32(krll, krlr, krrl, krrr, w0, w1, 34);

    /* generate KA */
    kll = subl(0) ^ krll; klr = subr(0) ^ krlr;
    krl = subl(1) ^ krrl; krr = subr(1) ^ krrr;
    CAMELLIA_F(kll, klr,
	       CAMELLIA_SIGMA1L, CAMELLIA_SIGMA1R,
	       w0, w1, il, ir, t0, t1);
    krl ^= w0; krr ^= w1;
    CAMELLIA_F(krl, krr,
	       CAMELLIA_SIGMA2L, CAMELLIA_SIGMA2R,
	       kll, klr, il, ir, t0, t1);
    kll ^= krll; klr ^= krlr;
    CAMELLIA_F(kll, klr,
	       CAMELLIA_SIGMA3L, CAMELLIA_SIGMA3R,
	       krl, krr, il, ir, t0, t1);
    krl ^= w0 ^ krrl; krr ^= w1 ^ krrr;
    CAMELLIA_F(krl, krr,
	       CAMELLIA_SIGMA4L, CAMELLIA_SIGMA4R,
	       w0, w1, il, ir, t0, t1);
    kll ^= w0; klr ^= w1;

    /* generate KB */
    krll ^= kll; krlr ^= klr;
    krrl ^= krl; krrr ^= krr;
    CAMELLIA_F(krll, krlr,
	       CAMELLIA_SIGMA5L, CAMELLIA_SIGMA5R,
	       w0, w1, il, ir, t0, t1);
    krrl ^= w0; krrr ^= w1;
    CAMELLIA_F(krrl, krrr,
	       CAMELLIA_SIGMA6L, CAMELLIA_SIGMA6R,
	       w0, w1, il, ir, t0, t1);
    krll ^= w0; krlr ^= w1;

    /* generate KA dependent subkeys */
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(6) = kll; subr(6) = klr;
    subl(7) = krl; subr(7) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 30);
    subl(14) = kll; subr(14) = klr;
    subl(15) = krl; subr(15) = krr;
    subl(24) = klr; subr(24) = krl;
    subl(25) = krr; subr(25) = kll;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 49);
    subl(28) = kll; subr(28) = klr;
    subl(29) = krl; subr(29) = krr;

    /* generate KB dependent subkeys */
    subl(2) = krll; subr(2) = krlr;
    subl(3) = krrl; subr(3) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(10) = krll; subr(10) = krlr;
    subl(11) = krrl; subr(11) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(20) = krll; subr(20) = krlr;
    subl(21) = krrl; subr(21) = krrr;
    CAMELLIA_ROLDQo32(krll, krlr, krrl, krrr, w0, w1, 51);
    subl(32) = krll; subr(32) = krlr;
    subl(33) = krrl; subr(33) = krrr;

    /* absorb kw2 to other subkeys */
    subl(3) ^= subl(1); subr(3) ^= subr(1);
    subl(5) ^= subl(1); subr(5) ^= subr(1);
    subl(7) ^= subl(1); subr(7) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(9);
    dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw);
    subl(11) ^= subl(1); subr(11) ^= subr(1);
    subl(13) ^= subl(1); subr(13) ^= subr(1);
    subl(15) ^= subl(1); subr(15) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(17);
    dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw);
    subl(19) ^= subl(1); subr(19) ^= subr(1);
    subl(21) ^= subl(1); subr(21) ^= subr(1);
    subl(23) ^= subl(1); subr(23) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(25);
    dw = subl(1) & subl(25), subr(1) ^= CAMELLIA_RL1(dw);
    subl(27) ^= subl(1); subr(27) ^= subr(1);
    subl(29) ^= subl(1); subr(29) ^= subr(1);
    subl(31) ^= subl(1); subr(31) ^= subr(1);
    subl(32) ^= subl(1); subr(32) ^= subr(1);

    /* absorb kw4 to other subkeys */
    kw4l = subl(33); kw4r = subr(33);
    subl(30) ^= kw4l; subr(30) ^= kw4r;
    subl(28) ^= kw4l; subr(28) ^= kw4r;
    subl(26) ^= kw4l; subr(26) ^= kw4r;
    kw4l ^= kw4r & ~subr(24);
    dw = kw4l & subl(24), kw4r ^= CAMELLIA_RL1(dw);
    subl(22) ^= kw4l; subr(22) ^= kw4r;
    subl(20) ^= kw4l; subr(20) ^= kw4r;
    subl(18) ^= kw4l; subr(18) ^= kw4r;
    kw4l ^= kw4r & ~subr(16);
    dw = kw4l & subl(16), kw4r ^= CAMELLIA_RL1(dw);
    subl(14) ^= kw4l; subr(14) ^= kw4r;
    subl(12) ^= kw4l; subr(12) ^= kw4r;
    subl(10) ^= kw4l; subr(10) ^= kw4r;
    kw4l ^= kw4r & ~subr(8);
    dw = kw4l & subl(8), kw4r ^= CAMELLIA_RL1(dw);
    subl(6) ^= kw4l; subr(6) ^= kw4r;
    subl(4) ^= kw4l; subr(4) ^= kw4r;
    subl(2) ^= kw4l; subr(2) ^= kw4r;
    subl(0) ^= kw4l; subr(0) ^= kw4r;

    /* key XOR is end of F-function */
    CamelliaSubkeyL(0) = subl(0) ^ subl(2);
    CamelliaSubkeyR(0) = subr(0) ^ subr(2);
    CamelliaSubkeyL(2) = subl(3);
    CamelliaSubkeyR(2) = subr(3);
    CamelliaSubkeyL(3) = subl(2) ^ subl(4);
    CamelliaSubkeyR(3) = subr(2) ^ subr(4);
    CamelliaSubkeyL(4) = subl(3) ^ subl(5);
    CamelliaSubkeyR(4) = subr(3) ^ subr(5);
    CamelliaSubkeyL(5) = subl(4) ^ subl(6);
    CamelliaSubkeyR(5) = subr(4) ^ subr(6);
    CamelliaSubkeyL(6) = subl(5) ^ subl(7);
    CamelliaSubkeyR(6) = subr(5) ^ subr(7);
    tl = subl(10) ^ (subr(10) & ~subr(8));
    dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(7) = subl(6) ^ tl;
    CamelliaSubkeyR(7) = subr(6) ^ tr;
    CamelliaSubkeyL(8) = subl(8);
    CamelliaSubkeyR(8) = subr(8);
    CamelliaSubkeyL(9) = subl(9);
    CamelliaSubkeyR(9) = subr(9);
    tl = subl(7) ^ (subr(7) & ~subr(9));
    dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(10) = tl ^ subl(11);
    CamelliaSubkeyR(10) = tr ^ subr(11);
    CamelliaSubkeyL(11) = subl(10) ^ subl(12);
    CamelliaSubkeyR(11) = subr(10) ^ subr(12);
    CamelliaSubkeyL(12) = subl(11) ^ subl(13);
    CamelliaSubkeyR(12) = subr(11) ^ subr(13);
    CamelliaSubkeyL(13) = subl(12) ^ subl(14);
    CamelliaSubkeyR(13) = subr(12) ^ subr(14);
    CamelliaSubkeyL(14) = subl(13) ^ subl(15);
    CamelliaSubkeyR(14) = subr(13) ^ subr(15);
    tl = subl(18) ^ (subr(18) & ~subr(16));
    dw = tl & subl(16), tr = subr(18) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(15) = subl(14) ^ tl;
    CamelliaSubkeyR(15) = subr(14) ^ tr;
    CamelliaSubkeyL(16) = subl(16);
    CamelliaSubkeyR(16) = subr(16);
    CamelliaSubkeyL(17) = subl(17);
    CamelliaSubkeyR(17) = subr(17);
    tl = subl(15) ^ (subr(15) & ~subr(17));
    dw = tl & subl(17), tr = subr(15) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(18) = tl ^ subl(19);
    CamelliaSubkeyR(18) = tr ^ subr(19);
    CamelliaSubkeyL(19) = subl(18) ^ subl(20);
    CamelliaSubkeyR(19) = subr(18) ^ subr(20);
    CamelliaSubkeyL(20) = subl(19) ^ subl(21);
    CamelliaSubkeyR(20) = subr(19) ^ subr(21);
    CamelliaSubkeyL(21) = subl(20) ^ subl(22);
    CamelliaSubkeyR(21) = subr(20) ^ subr(22);
    CamelliaSubkeyL(22) = subl(21) ^ subl(23);
    CamelliaSubkeyR(22) = subr(21) ^ subr(23);
    tl = subl(26) ^ (subr(26) & ~subr(24));
    dw = tl & subl(24), tr = subr(26) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(23) = subl(22) ^ tl;
    CamelliaSubkeyR(23) = subr(22) ^ tr;
    CamelliaSubkeyL(24) = subl(24);
    CamelliaSubkeyR(24) = subr(24);
    CamelliaSubkeyL(25) = subl(25);
    CamelliaSubkeyR(25) = subr(25);
    tl = subl(23) ^ (subr(23) &  ~subr(25));
    dw = tl & subl(25), tr = subr(23) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(26) = tl ^ subl(27);
    CamelliaSubkeyR(26) = tr ^ subr(27);
    CamelliaSubkeyL(27) = subl(26) ^ subl(28);
    CamelliaSubkeyR(27) = subr(26) ^ subr(28);
    CamelliaSubkeyL(28) = subl(27) ^ subl(29);
    CamelliaSubkeyR(28) = subr(27) ^ subr(29);
    CamelliaSubkeyL(29) = subl(28) ^ subl(30);
    CamelliaSubkeyR(29) = subr(28) ^ subr(30);
    CamelliaSubkeyL(30) = subl(29) ^ subl(31);
    CamelliaSubkeyR(30) = subr(29) ^ subr(31);
    CamelliaSubkeyL(31) = subl(30);
    CamelliaSubkeyR(31) = subr(30);
    CamelliaSubkeyL(32) = subl(32) ^ subl(31);
    CamelliaSubkeyR(32) = subr(32) ^ subr(31);

    /* apply the inverse of the last half of P-function */
    dw = CamelliaSubkeyL(2) ^ CamelliaSubkeyR(2), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(2) = CamelliaSubkeyL(2) ^ dw, CamelliaSubkeyL(2) = dw;
    dw = CamelliaSubkeyL(3) ^ CamelliaSubkeyR(3), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(3) = CamelliaSubkeyL(3) ^ dw, CamelliaSubkeyL(3) = dw;
    dw = CamelliaSubkeyL(4) ^ CamelliaSubkeyR(4), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(4) = CamelliaSubkeyL(4) ^ dw, CamelliaSubkeyL(4) = dw;
    dw = CamelliaSubkeyL(5) ^ CamelliaSubkeyR(5), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(5) = CamelliaSubkeyL(5) ^ dw, CamelliaSubkeyL(5) = dw;
    dw = CamelliaSubkeyL(6) ^ CamelliaSubkeyR(6), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(6) = CamelliaSubkeyL(6) ^ dw, CamelliaSubkeyL(6) = dw;
    dw = CamelliaSubkeyL(7) ^ CamelliaSubkeyR(7), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(7) = CamelliaSubkeyL(7) ^ dw, CamelliaSubkeyL(7) = dw;
    dw = CamelliaSubkeyL(10) ^ CamelliaSubkeyR(10), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(10) = CamelliaSubkeyL(10) ^ dw, CamelliaSubkeyL(10) = dw;
    dw = CamelliaSubkeyL(11) ^ CamelliaSubkeyR(11), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(11) = CamelliaSubkeyL(11) ^ dw, CamelliaSubkeyL(11) = dw;
    dw = CamelliaSubkeyL(12) ^ CamelliaSubkeyR(12), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(12) = CamelliaSubkeyL(12) ^ dw, CamelliaSubkeyL(12) = dw;
    dw = CamelliaSubkeyL(13) ^ CamelliaSubkeyR(13), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(13) = CamelliaSubkeyL(13) ^ dw, CamelliaSubkeyL(13) = dw;
    dw = CamelliaSubkeyL(14) ^ CamelliaSubkeyR(14), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(14) = CamelliaSubkeyL(14) ^ dw, CamelliaSubkeyL(14) = dw;
    dw = CamelliaSubkeyL(15) ^ CamelliaSubkeyR(15), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(15) = CamelliaSubkeyL(15) ^ dw, CamelliaSubkeyL(15) = dw;
    dw = CamelliaSubkeyL(18) ^ CamelliaSubkeyR(18), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(18) = CamelliaSubkeyL(18) ^ dw, CamelliaSubkeyL(18) = dw;
    dw = CamelliaSubkeyL(19) ^ CamelliaSubkeyR(19), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(19) = CamelliaSubkeyL(19) ^ dw, CamelliaSubkeyL(19) = dw;
    dw = CamelliaSubkeyL(20) ^ CamelliaSubkeyR(20), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(20) = CamelliaSubkeyL(20) ^ dw, CamelliaSubkeyL(20) = dw;
    dw = CamelliaSubkeyL(21) ^ CamelliaSubkeyR(21), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(21) = CamelliaSubkeyL(21) ^ dw, CamelliaSubkeyL(21) = dw;
    dw = CamelliaSubkeyL(22) ^ CamelliaSubkeyR(22), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(22) = CamelliaSubkeyL(22) ^ dw, CamelliaSubkeyL(22) = dw;
    dw = CamelliaSubkeyL(23) ^ CamelliaSubkeyR(23), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(23) = CamelliaSubkeyL(23) ^ dw, CamelliaSubkeyL(23) = dw;
    dw = CamelliaSubkeyL(26) ^ CamelliaSubkeyR(26), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(26) = CamelliaSubkeyL(26) ^ dw, CamelliaSubkeyL(26) = dw;
    dw = CamelliaSubkeyL(27) ^ CamelliaSubkeyR(27), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(27) = CamelliaSubkeyL(27) ^ dw, CamelliaSubkeyL(27) = dw;
    dw = CamelliaSubkeyL(28) ^ CamelliaSubkeyR(28), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(28) = CamelliaSubkeyL(28) ^ dw, CamelliaSubkeyL(28) = dw;
    dw = CamelliaSubkeyL(29) ^ CamelliaSubkeyR(29), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(29) = CamelliaSubkeyL(29) ^ dw, CamelliaSubkeyL(29) = dw;
    dw = CamelliaSubkeyL(30) ^ CamelliaSubkeyR(30), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(30) = CamelliaSubkeyL(30) ^ dw, CamelliaSubkeyL(30) = dw;
    dw = CamelliaSubkeyL(31) ^ CamelliaSubkeyR(31), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(31) = CamelliaSubkeyL(31) ^ dw,CamelliaSubkeyL(31) = dw;
    
    return;
}

static void camellia_setup192(const unsigned char *key, u32 *subkey)
{
    unsigned char kk[32];
    u32 krll, krlr, krrl,krrr;

    memcpy(kk, key, 24);
    memcpy((unsigned char *)&krll, key+16,4);
    memcpy((unsigned char *)&krlr, key+20,4);
    krrl = ~krll;
    krrr = ~krlr;
    memcpy(kk+24, (unsigned char *)&krrl, 4);
    memcpy(kk+28, (unsigned char *)&krrr, 4);
    camellia_setup256(kk, subkey);
    return;
}


/**
 * Stuff related to camellia encryption/decryption
 *
 * "io" must be 4byte aligned and big-endian data.
 */
static void camellia_encrypt128(const u32 *subkey, u32 *io)
{
    u32 il, ir, t0, t1;

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(0);
    io[1] ^= CamelliaSubkeyR(0);
    /* main iteration */

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(24);
    io[3] ^= CamelliaSubkeyR(24);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;
	
    return;
}

static void camellia_decrypt128(const u32 *subkey, u32 *io)
{
    u32 il,ir,t0,t1;               /* temporary valiables */
    
    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(24);
    io[1] ^= CamelliaSubkeyR(24);

    /* main iteration */
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(0);
    io[3] ^= CamelliaSubkeyR(0);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

/**
 * stuff for 192 and 256bit encryption/decryption
 */
static void camellia_encrypt256(const u32 *subkey, u32 *io)
{
    u32 il,ir,t0,t1;           /* temporary valiables */

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(0);
    io[1] ^= CamelliaSubkeyR(0);

    /* main iteration */
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(24),CamelliaSubkeyR(24),
		 CamelliaSubkeyL(25),CamelliaSubkeyR(25),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(26),CamelliaSubkeyR(26),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(27),CamelliaSubkeyR(27),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(28),CamelliaSubkeyR(28),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(29),CamelliaSubkeyR(29),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(30),CamelliaSubkeyR(30),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(31),CamelliaSubkeyR(31),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(32);
    io[3] ^= CamelliaSubkeyR(32);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

static void camellia_decrypt256(const u32 *subkey, u32 *io)
{
    u32 il,ir,t0,t1;           /* temporary valiables */

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(32);
    io[1] ^= CamelliaSubkeyR(32);
	
    /* main iteration */
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(31),CamelliaSubkeyR(31),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(30),CamelliaSubkeyR(30),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(29),CamelliaSubkeyR(29),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(28),CamelliaSubkeyR(28),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(27),CamelliaSubkeyR(27),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(26),CamelliaSubkeyR(26),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(25),CamelliaSubkeyR(25),
		 CamelliaSubkeyL(24),CamelliaSubkeyR(24),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(23),CamelliaSubkeyR(23),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(22),CamelliaSubkeyR(22),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(21),CamelliaSubkeyR(21),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(20),CamelliaSubkeyR(20),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(19),CamelliaSubkeyR(19),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(18),CamelliaSubkeyR(18),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(17),CamelliaSubkeyR(17),
		 CamelliaSubkeyL(16),CamelliaSubkeyR(16),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(15),CamelliaSubkeyR(15),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(14),CamelliaSubkeyR(14),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(13),CamelliaSubkeyR(13),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(12),CamelliaSubkeyR(12),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(11),CamelliaSubkeyR(11),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(10),CamelliaSubkeyR(10),
		     io[0],io[1],il,ir,t0,t1);

    CAMELLIA_FLS(io[0],io[1],io[2],io[3],
		 CamelliaSubkeyL(9),CamelliaSubkeyR(9),
		 CamelliaSubkeyL(8),CamelliaSubkeyR(8),
		 t0,t1,il,ir);

    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(7),CamelliaSubkeyR(7),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(6),CamelliaSubkeyR(6),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(5),CamelliaSubkeyR(5),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(4),CamelliaSubkeyR(4),
		     io[0],io[1],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[0],io[1],
		     CamelliaSubkeyL(3),CamelliaSubkeyR(3),
		     io[2],io[3],il,ir,t0,t1);
    CAMELLIA_ROUNDSM(io[2],io[3],
		     CamelliaSubkeyL(2),CamelliaSubkeyR(2),
		     io[0],io[1],il,ir,t0,t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(0);
    io[3] ^= CamelliaSubkeyR(0);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

/***
 *
 * API for compatibility
 */

void Camellia_Ekeygen(const int keyBitLength, 
		      const unsigned char *rawKey, 
		      KEY_TABLE_TYPE keyTable)
{
    switch(keyBitLength) {
    case 128:
	camellia_setup128(rawKey, keyTable);
	break;
    case 192:
	camellia_setup192(rawKey, keyTable);
	break;
    case 256:
	camellia_setup256(rawKey, keyTable);
	break;
    default:
	break;
    }
}


void Camellia_EncryptBlock(const int keyBitLength, 
			   const unsigned char *plaintext, 
			   const KEY_TABLE_TYPE keyTable, 
			   unsigned char *ciphertext)
{
    u32 tmp[4];

    tmp[0] = GETU32(plaintext);
    tmp[1] = GETU32(plaintext + 4);
    tmp[2] = GETU32(plaintext + 8);
    tmp[3] = GETU32(plaintext + 12);

    switch (keyBitLength) {
    case 128:
	camellia_encrypt128(keyTable, tmp);
	break;
    case 192:
	/* fall through */
    case 256:
	camellia_encrypt256(keyTable, tmp);
	break;
    default:
	break;
    }

    PUTU32(ciphertext, tmp[0]);
    PUTU32(ciphertext + 4, tmp[1]);
    PUTU32(ciphertext + 8, tmp[2]);
    PUTU32(ciphertext + 12, tmp[3]);
}

void Camellia_DecryptBlock(const int keyBitLength, 
			   const unsigned char *ciphertext, 
			   const KEY_TABLE_TYPE keyTable, 
			   unsigned char *plaintext)
{
    u32 tmp[4];

    tmp[0] = GETU32(ciphertext);
    tmp[1] = GETU32(ciphertext + 4);
    tmp[2] = GETU32(ciphertext + 8);
    tmp[3] = GETU32(ciphertext + 12);

    switch (keyBitLength) {
    case 128:
	camellia_decrypt128(keyTable, tmp);
	break;
    case 192:
	/* fall through */
    case 256:
	camellia_decrypt256(keyTable, tmp);
	break;
    default:
	break;
    }
    PUTU32(plaintext, tmp[0]);
    PUTU32(plaintext + 4, tmp[1]);
    PUTU32(plaintext + 8, tmp[2]);
    PUTU32(plaintext + 12, tmp[3]);
}

typedef unsigned long long int u64;

const u64 camellia_sp10011110[256] = {
    0x7000007070707000ULL, 0x8200008282828200ULL, 0x2c00002c2c2c2c00ULL,
    0xec0000ecececec00ULL, 0xb30000b3b3b3b300ULL, 0x2700002727272700ULL,
    0xc00000c0c0c0c000ULL, 0xe50000e5e5e5e500ULL, 0xe40000e4e4e4e400ULL,
    0x8500008585858500ULL, 0x5700005757575700ULL, 0x3500003535353500ULL,
    0xea0000eaeaeaea00ULL, 0x0c00000c0c0c0c00ULL, 0xae0000aeaeaeae00ULL,
    0x4100004141414100ULL, 0x2300002323232300ULL, 0xef0000efefefef00ULL,
    0x6b00006b6b6b6b00ULL, 0x9300009393939300ULL, 0x4500004545454500ULL,
    0x1900001919191900ULL, 0xa50000a5a5a5a500ULL, 0x2100002121212100ULL,
    0xed0000edededed00ULL, 0x0e00000e0e0e0e00ULL, 0x4f00004f4f4f4f00ULL,
    0x4e00004e4e4e4e00ULL, 0x1d00001d1d1d1d00ULL, 0x6500006565656500ULL,
    0x9200009292929200ULL, 0xbd0000bdbdbdbd00ULL, 0x8600008686868600ULL,
    0xb80000b8b8b8b800ULL, 0xaf0000afafafaf00ULL, 0x8f00008f8f8f8f00ULL,
    0x7c00007c7c7c7c00ULL, 0xeb0000ebebebeb00ULL, 0x1f00001f1f1f1f00ULL,
    0xce0000cececece00ULL, 0x3e00003e3e3e3e00ULL, 0x3000003030303000ULL,
    0xdc0000dcdcdcdc00ULL, 0x5f00005f5f5f5f00ULL, 0x5e00005e5e5e5e00ULL,
    0xc50000c5c5c5c500ULL, 0x0b00000b0b0b0b00ULL, 0x1a00001a1a1a1a00ULL,
    0xa60000a6a6a6a600ULL, 0xe10000e1e1e1e100ULL, 0x3900003939393900ULL,
    0xca0000cacacaca00ULL, 0xd50000d5d5d5d500ULL, 0x4700004747474700ULL,
    0x5d00005d5d5d5d00ULL, 0x3d00003d3d3d3d00ULL, 0xd90000d9d9d9d900ULL,
    0x0100000101010100ULL, 0x5a00005a5a5a5a00ULL, 0xd60000d6d6d6d600ULL,
    0x5100005151515100ULL, 0x5600005656565600ULL, 0x6c00006c6c6c6c00ULL,
    0x4d00004d4d4d4d00ULL, 0x8b00008b8b8b8b00ULL, 0x0d00000d0d0d0d00ULL,
    0x9a00009a9a9a9a00ULL, 0x6600006666666600ULL, 0xfb0000fbfbfbfb00ULL,
    0xcc0000cccccccc00ULL, 0xb00000b0b0b0b000ULL, 0x2d00002d2d2d2d00ULL,
    0x7400007474747400ULL, 0x1200001212121200ULL, 0x2b00002b2b2b2b00ULL,
    0x2000002020202000ULL, 0xf00000f0f0f0f000ULL, 0xb10000b1b1b1b100ULL,
    0x8400008484848400ULL, 0x9900009999999900ULL, 0xdf0000dfdfdfdf00ULL,
    0x4c00004c4c4c4c00ULL, 0xcb0000cbcbcbcb00ULL, 0xc20000c2c2c2c200ULL,
    0x3400003434343400ULL, 0x7e00007e7e7e7e00ULL, 0x7600007676767600ULL,
    0x0500000505050500ULL, 0x6d00006d6d6d6d00ULL, 0xb70000b7b7b7b700ULL,
    0xa90000a9a9a9a900ULL, 0x3100003131313100ULL, 0xd10000d1d1d1d100ULL,
    0x1700001717171700ULL, 0x0400000404040400ULL, 0xd70000d7d7d7d700ULL,
    0x1400001414141400ULL, 0x5800005858585800ULL, 0x3a00003a3a3a3a00ULL,
    0x6100006161616100ULL, 0xde0000dededede00ULL, 0x1b00001b1b1b1b00ULL,
    0x1100001111111100ULL, 0x1c00001c1c1c1c00ULL, 0x3200003232323200ULL,
    0x0f00000f0f0f0f00ULL, 0x9c00009c9c9c9c00ULL, 0x1600001616161600ULL,
    0x5300005353535300ULL, 0x1800001818181800ULL, 0xf20000f2f2f2f200ULL,
    0x2200002222222200ULL, 0xfe0000fefefefe00ULL, 0x4400004444444400ULL,
    0xcf0000cfcfcfcf00ULL, 0xb20000b2b2b2b200ULL, 0xc30000c3c3c3c300ULL,
    0xb50000b5b5b5b500ULL, 0x7a00007a7a7a7a00ULL, 0x9100009191919100ULL,
    0x2400002424242400ULL, 0x0800000808080800ULL, 0xe80000e8e8e8e800ULL,
    0xa80000a8a8a8a800ULL, 0x6000006060606000ULL, 0xfc0000fcfcfcfc00ULL,
    0x6900006969696900ULL, 0x5000005050505000ULL, 0xaa0000aaaaaaaa00ULL,
    0xd00000d0d0d0d000ULL, 0xa00000a0a0a0a000ULL, 0x7d00007d7d7d7d00ULL,
    0xa10000a1a1a1a100ULL, 0x8900008989898900ULL, 0x6200006262626200ULL,
    0x9700009797979700ULL, 0x5400005454545400ULL, 0x5b00005b5b5b5b00ULL,
    0x1e00001e1e1e1e00ULL, 0x9500009595959500ULL, 0xe00000e0e0e0e000ULL,
    0xff0000ffffffff00ULL, 0x6400006464646400ULL, 0xd20000d2d2d2d200ULL,
    0x1000001010101000ULL, 0xc40000c4c4c4c400ULL, 0x0000000000000000ULL,
    0x4800004848484800ULL, 0xa30000a3a3a3a300ULL, 0xf70000f7f7f7f700ULL,
    0x7500007575757500ULL, 0xdb0000dbdbdbdb00ULL, 0x8a00008a8a8a8a00ULL,
    0x0300000303030300ULL, 0xe60000e6e6e6e600ULL, 0xda0000dadadada00ULL,
    0x0900000909090900ULL, 0x3f00003f3f3f3f00ULL, 0xdd0000dddddddd00ULL,
    0x9400009494949400ULL, 0x8700008787878700ULL, 0x5c00005c5c5c5c00ULL,
    0x8300008383838300ULL, 0x0200000202020200ULL, 0xcd0000cdcdcdcd00ULL,
    0x4a00004a4a4a4a00ULL, 0x9000009090909000ULL, 0x3300003333333300ULL,
    0x7300007373737300ULL, 0x6700006767676700ULL, 0xf60000f6f6f6f600ULL,
    0xf30000f3f3f3f300ULL, 0x9d00009d9d9d9d00ULL, 0x7f00007f7f7f7f00ULL,
    0xbf0000bfbfbfbf00ULL, 0xe20000e2e2e2e200ULL, 0x5200005252525200ULL,
    0x9b00009b9b9b9b00ULL, 0xd80000d8d8d8d800ULL, 0x2600002626262600ULL,
    0xc80000c8c8c8c800ULL, 0x3700003737373700ULL, 0xc60000c6c6c6c600ULL,
    0x3b00003b3b3b3b00ULL, 0x8100008181818100ULL, 0x9600009696969600ULL,
    0x6f00006f6f6f6f00ULL, 0x4b00004b4b4b4b00ULL, 0x1300001313131300ULL,
    0xbe0000bebebebe00ULL, 0x6300006363636300ULL, 0x2e00002e2e2e2e00ULL,
    0xe90000e9e9e9e900ULL, 0x7900007979797900ULL, 0xa70000a7a7a7a700ULL,
    0x8c00008c8c8c8c00ULL, 0x9f00009f9f9f9f00ULL, 0x6e00006e6e6e6e00ULL,
    0xbc0000bcbcbcbc00ULL, 0x8e00008e8e8e8e00ULL, 0x2900002929292900ULL,
    0xf50000f5f5f5f500ULL, 0xf90000f9f9f9f900ULL, 0xb60000b6b6b6b600ULL,
    0x2f00002f2f2f2f00ULL, 0xfd0000fdfdfdfd00ULL, 0xb40000b4b4b4b400ULL,
    0x5900005959595900ULL, 0x7800007878787800ULL, 0x9800009898989800ULL,
    0x0600000606060600ULL, 0x6a00006a6a6a6a00ULL, 0xe70000e7e7e7e700ULL,
    0x4600004646464600ULL, 0x7100007171717100ULL, 0xba0000babababa00ULL,
    0xd40000d4d4d4d400ULL, 0x2500002525252500ULL, 0xab0000abababab00ULL,
    0x4200004242424200ULL, 0x8800008888888800ULL, 0xa20000a2a2a2a200ULL,
    0x8d00008d8d8d8d00ULL, 0xfa0000fafafafa00ULL, 0x7200007272727200ULL,
    0x0700000707070700ULL, 0xb90000b9b9b9b900ULL, 0x5500005555555500ULL,
    0xf80000f8f8f8f800ULL, 0xee0000eeeeeeee00ULL, 0xac0000acacacac00ULL,
    0x0a00000a0a0a0a00ULL, 0x3600003636363600ULL, 0x4900004949494900ULL,
    0x2a00002a2a2a2a00ULL, 0x6800006868686800ULL, 0x3c00003c3c3c3c00ULL,
    0x3800003838383800ULL, 0xf10000f1f1f1f100ULL, 0xa40000a4a4a4a400ULL,
    0x4000004040404000ULL, 0x2800002828282800ULL, 0xd30000d3d3d3d300ULL,
    0x7b00007b7b7b7b00ULL, 0xbb0000bbbbbbbb00ULL, 0xc90000c9c9c9c900ULL,
    0x4300004343434300ULL, 0xc10000c1c1c1c100ULL, 0x1500001515151500ULL,
    0xe30000e3e3e3e300ULL, 0xad0000adadadad00ULL, 0xf40000f4f4f4f400ULL,
    0x7700007777777700ULL, 0xc70000c7c7c7c700ULL, 0x8000008080808000ULL,
    0x9e00009e9e9e9e00ULL,
};

const u64 camellia_sp22000222[256] = {
    0xe0e0000000e0e0e0ULL, 0x0505000000050505ULL, 0x5858000000585858ULL,
    0xd9d9000000d9d9d9ULL, 0x6767000000676767ULL, 0x4e4e0000004e4e4eULL,
    0x8181000000818181ULL, 0xcbcb000000cbcbcbULL, 0xc9c9000000c9c9c9ULL,
    0x0b0b0000000b0b0bULL, 0xaeae000000aeaeaeULL, 0x6a6a0000006a6a6aULL,
    0xd5d5000000d5d5d5ULL, 0x1818000000181818ULL, 0x5d5d0000005d5d5dULL,
    0x8282000000828282ULL, 0x4646000000464646ULL, 0xdfdf000000dfdfdfULL,
    0xd6d6000000d6d6d6ULL, 0x2727000000272727ULL, 0x8a8a0000008a8a8aULL,
    0x3232000000323232ULL, 0x4b4b0000004b4b4bULL, 0x4242000000424242ULL,
    0xdbdb000000dbdbdbULL, 0x1c1c0000001c1c1cULL, 0x9e9e0000009e9e9eULL,
    0x9c9c0000009c9c9cULL, 0x3a3a0000003a3a3aULL, 0xcaca000000cacacaULL,
    0x2525000000252525ULL, 0x7b7b0000007b7b7bULL, 0x0d0d0000000d0d0dULL,
    0x7171000000717171ULL, 0x5f5f0000005f5f5fULL, 0x1f1f0000001f1f1fULL,
    0xf8f8000000f8f8f8ULL, 0xd7d7000000d7d7d7ULL, 0x3e3e0000003e3e3eULL,
    0x9d9d0000009d9d9dULL, 0x7c7c0000007c7c7cULL, 0x6060000000606060ULL,
    0xb9b9000000b9b9b9ULL, 0xbebe000000bebebeULL, 0xbcbc000000bcbcbcULL,
    0x8b8b0000008b8b8bULL, 0x1616000000161616ULL, 0x3434000000343434ULL,
    0x4d4d0000004d4d4dULL, 0xc3c3000000c3c3c3ULL, 0x7272000000727272ULL,
    0x9595000000959595ULL, 0xabab000000abababULL, 0x8e8e0000008e8e8eULL,
    0xbaba000000bababaULL, 0x7a7a0000007a7a7aULL, 0xb3b3000000b3b3b3ULL,
    0x0202000000020202ULL, 0xb4b4000000b4b4b4ULL, 0xadad000000adadadULL,
    0xa2a2000000a2a2a2ULL, 0xacac000000acacacULL, 0xd8d8000000d8d8d8ULL,
    0x9a9a0000009a9a9aULL, 0x1717000000171717ULL, 0x1a1a0000001a1a1aULL,
    0x3535000000353535ULL, 0xcccc000000ccccccULL, 0xf7f7000000f7f7f7ULL,
    0x9999000000999999ULL, 0x6161000000616161ULL, 0x5a5a0000005a5a5aULL,
    0xe8e8000000e8e8e8ULL, 0x2424000000242424ULL, 0x5656000000565656ULL,
    0x4040000000404040ULL, 0xe1e1000000e1e1e1ULL, 0x6363000000636363ULL,
    0x0909000000090909ULL, 0x3333000000333333ULL, 0xbfbf000000bfbfbfULL,
    0x9898000000989898ULL, 0x9797000000979797ULL, 0x8585000000858585ULL,
    0x6868000000686868ULL, 0xfcfc000000fcfcfcULL, 0xecec000000ecececULL,
    0x0a0a0000000a0a0aULL, 0xdada000000dadadaULL, 0x6f6f0000006f6f6fULL,
    0x5353000000535353ULL, 0x6262000000626262ULL, 0xa3a3000000a3a3a3ULL,
    0x2e2e0000002e2e2eULL, 0x0808000000080808ULL, 0xafaf000000afafafULL,
    0x2828000000282828ULL, 0xb0b0000000b0b0b0ULL, 0x7474000000747474ULL,
    0xc2c2000000c2c2c2ULL, 0xbdbd000000bdbdbdULL, 0x3636000000363636ULL,
    0x2222000000222222ULL, 0x3838000000383838ULL, 0x6464000000646464ULL,
    0x1e1e0000001e1e1eULL, 0x3939000000393939ULL, 0x2c2c0000002c2c2cULL,
    0xa6a6000000a6a6a6ULL, 0x3030000000303030ULL, 0xe5e5000000e5e5e5ULL,
    0x4444000000444444ULL, 0xfdfd000000fdfdfdULL, 0x8888000000888888ULL,
    0x9f9f0000009f9f9fULL, 0x6565000000656565ULL, 0x8787000000878787ULL,
    0x6b6b0000006b6b6bULL, 0xf4f4000000f4f4f4ULL, 0x2323000000232323ULL,
    0x4848000000484848ULL, 0x1010000000101010ULL, 0xd1d1000000d1d1d1ULL,
    0x5151000000515151ULL, 0xc0c0000000c0c0c0ULL, 0xf9f9000000f9f9f9ULL,
    0xd2d2000000d2d2d2ULL, 0xa0a0000000a0a0a0ULL, 0x5555000000555555ULL,
    0xa1a1000000a1a1a1ULL, 0x4141000000414141ULL, 0xfafa000000fafafaULL,
    0x4343000000434343ULL, 0x1313000000131313ULL, 0xc4c4000000c4c4c4ULL,
    0x2f2f0000002f2f2fULL, 0xa8a8000000a8a8a8ULL, 0xb6b6000000b6b6b6ULL,
    0x3c3c0000003c3c3cULL, 0x2b2b0000002b2b2bULL, 0xc1c1000000c1c1c1ULL,
    0xffff000000ffffffULL, 0xc8c8000000c8c8c8ULL, 0xa5a5000000a5a5a5ULL,
    0x2020000000202020ULL, 0x8989000000898989ULL, 0x0000000000000000ULL,
    0x9090000000909090ULL, 0x4747000000474747ULL, 0xefef000000efefefULL,
    0xeaea000000eaeaeaULL, 0xb7b7000000b7b7b7ULL, 0x1515000000151515ULL,
    0x0606000000060606ULL, 0xcdcd000000cdcdcdULL, 0xb5b5000000b5b5b5ULL,
    0x1212000000121212ULL, 0x7e7e0000007e7e7eULL, 0xbbbb000000bbbbbbULL,
    0x2929000000292929ULL, 0x0f0f0000000f0f0fULL, 0xb8b8000000b8b8b8ULL,
    0x0707000000070707ULL, 0x0404000000040404ULL, 0x9b9b0000009b9b9bULL,
    0x9494000000949494ULL, 0x2121000000212121ULL, 0x6666000000666666ULL,
    0xe6e6000000e6e6e6ULL, 0xcece000000cececeULL, 0xeded000000edededULL,
    0xe7e7000000e7e7e7ULL, 0x3b3b0000003b3b3bULL, 0xfefe000000fefefeULL,
    0x7f7f0000007f7f7fULL, 0xc5c5000000c5c5c5ULL, 0xa4a4000000a4a4a4ULL,
    0x3737000000373737ULL, 0xb1b1000000b1b1b1ULL, 0x4c4c0000004c4c4cULL,
    0x9191000000919191ULL, 0x6e6e0000006e6e6eULL, 0x8d8d0000008d8d8dULL,
    0x7676000000767676ULL, 0x0303000000030303ULL, 0x2d2d0000002d2d2dULL,
    0xdede000000dededeULL, 0x9696000000969696ULL, 0x2626000000262626ULL,
    0x7d7d0000007d7d7dULL, 0xc6c6000000c6c6c6ULL, 0x5c5c0000005c5c5cULL,
    0xd3d3000000d3d3d3ULL, 0xf2f2000000f2f2f2ULL, 0x4f4f0000004f4f4fULL,
    0x1919000000191919ULL, 0x3f3f0000003f3f3fULL, 0xdcdc000000dcdcdcULL,
    0x7979000000797979ULL, 0x1d1d0000001d1d1dULL, 0x5252000000525252ULL,
    0xebeb000000ebebebULL, 0xf3f3000000f3f3f3ULL, 0x6d6d0000006d6d6dULL,
    0x5e5e0000005e5e5eULL, 0xfbfb000000fbfbfbULL, 0x6969000000696969ULL,
    0xb2b2000000b2b2b2ULL, 0xf0f0000000f0f0f0ULL, 0x3131000000313131ULL,
    0x0c0c0000000c0c0cULL, 0xd4d4000000d4d4d4ULL, 0xcfcf000000cfcfcfULL,
    0x8c8c0000008c8c8cULL, 0xe2e2000000e2e2e2ULL, 0x7575000000757575ULL,
    0xa9a9000000a9a9a9ULL, 0x4a4a0000004a4a4aULL, 0x5757000000575757ULL,
    0x8484000000848484ULL, 0x1111000000111111ULL, 0x4545000000454545ULL,
    0x1b1b0000001b1b1bULL, 0xf5f5000000f5f5f5ULL, 0xe4e4000000e4e4e4ULL,
    0x0e0e0000000e0e0eULL, 0x7373000000737373ULL, 0xaaaa000000aaaaaaULL,
    0xf1f1000000f1f1f1ULL, 0xdddd000000ddddddULL, 0x5959000000595959ULL,
    0x1414000000141414ULL, 0x6c6c0000006c6c6cULL, 0x9292000000929292ULL,
    0x5454000000545454ULL, 0xd0d0000000d0d0d0ULL, 0x7878000000787878ULL,
    0x7070000000707070ULL, 0xe3e3000000e3e3e3ULL, 0x4949000000494949ULL,
    0x8080000000808080ULL, 0x5050000000505050ULL, 0xa7a7000000a7a7a7ULL,
    0xf6f6000000f6f6f6ULL, 0x7777000000777777ULL, 0x9393000000939393ULL,
    0x8686000000868686ULL, 0x8383000000838383ULL, 0x2a2a0000002a2a2aULL,
    0xc7c7000000c7c7c7ULL, 0x5b5b0000005b5b5bULL, 0xe9e9000000e9e9e9ULL,
    0xeeee000000eeeeeeULL, 0x8f8f0000008f8f8fULL, 0x0101000000010101ULL,
    0x3d3d0000003d3d3dULL,
};

const u64 camellia_sp03303033[256] = {
    0x0038380038003838ULL, 0x0041410041004141ULL, 0x0016160016001616ULL,
    0x0076760076007676ULL, 0x00d9d900d900d9d9ULL, 0x0093930093009393ULL,
    0x0060600060006060ULL, 0x00f2f200f200f2f2ULL, 0x0072720072007272ULL,
    0x00c2c200c200c2c2ULL, 0x00abab00ab00ababULL, 0x009a9a009a009a9aULL,
    0x0075750075007575ULL, 0x0006060006000606ULL, 0x0057570057005757ULL,
    0x00a0a000a000a0a0ULL, 0x0091910091009191ULL, 0x00f7f700f700f7f7ULL,
    0x00b5b500b500b5b5ULL, 0x00c9c900c900c9c9ULL, 0x00a2a200a200a2a2ULL,
    0x008c8c008c008c8cULL, 0x00d2d200d200d2d2ULL, 0x0090900090009090ULL,
    0x00f6f600f600f6f6ULL, 0x0007070007000707ULL, 0x00a7a700a700a7a7ULL,
    0x0027270027002727ULL, 0x008e8e008e008e8eULL, 0x00b2b200b200b2b2ULL,
    0x0049490049004949ULL, 0x00dede00de00dedeULL, 0x0043430043004343ULL,
    0x005c5c005c005c5cULL, 0x00d7d700d700d7d7ULL, 0x00c7c700c700c7c7ULL,
    0x003e3e003e003e3eULL, 0x00f5f500f500f5f5ULL, 0x008f8f008f008f8fULL,
    0x0067670067006767ULL, 0x001f1f001f001f1fULL, 0x0018180018001818ULL,
    0x006e6e006e006e6eULL, 0x00afaf00af00afafULL, 0x002f2f002f002f2fULL,
    0x00e2e200e200e2e2ULL, 0x0085850085008585ULL, 0x000d0d000d000d0dULL,
    0x0053530053005353ULL, 0x00f0f000f000f0f0ULL, 0x009c9c009c009c9cULL,
    0x0065650065006565ULL, 0x00eaea00ea00eaeaULL, 0x00a3a300a300a3a3ULL,
    0x00aeae00ae00aeaeULL, 0x009e9e009e009e9eULL, 0x00ecec00ec00ececULL,
    0x0080800080008080ULL, 0x002d2d002d002d2dULL, 0x006b6b006b006b6bULL,
    0x00a8a800a800a8a8ULL, 0x002b2b002b002b2bULL, 0x0036360036003636ULL,
    0x00a6a600a600a6a6ULL, 0x00c5c500c500c5c5ULL, 0x0086860086008686ULL,
    0x004d4d004d004d4dULL, 0x0033330033003333ULL, 0x00fdfd00fd00fdfdULL,
    0x0066660066006666ULL, 0x0058580058005858ULL, 0x0096960096009696ULL,
    0x003a3a003a003a3aULL, 0x0009090009000909ULL, 0x0095950095009595ULL,
    0x0010100010001010ULL, 0x0078780078007878ULL, 0x00d8d800d800d8d8ULL,
    0x0042420042004242ULL, 0x00cccc00cc00ccccULL, 0x00efef00ef00efefULL,
    0x0026260026002626ULL, 0x00e5e500e500e5e5ULL, 0x0061610061006161ULL,
    0x001a1a001a001a1aULL, 0x003f3f003f003f3fULL, 0x003b3b003b003b3bULL,
    0x0082820082008282ULL, 0x00b6b600b600b6b6ULL, 0x00dbdb00db00dbdbULL,
    0x00d4d400d400d4d4ULL, 0x0098980098009898ULL, 0x00e8e800e800e8e8ULL,
    0x008b8b008b008b8bULL, 0x0002020002000202ULL, 0x00ebeb00eb00ebebULL,
    0x000a0a000a000a0aULL, 0x002c2c002c002c2cULL, 0x001d1d001d001d1dULL,
    0x00b0b000b000b0b0ULL, 0x006f6f006f006f6fULL, 0x008d8d008d008d8dULL,
    0x0088880088008888ULL, 0x000e0e000e000e0eULL, 0x0019190019001919ULL,
    0x0087870087008787ULL, 0x004e4e004e004e4eULL, 0x000b0b000b000b0bULL,
    0x00a9a900a900a9a9ULL, 0x000c0c000c000c0cULL, 0x0079790079007979ULL,
    0x0011110011001111ULL, 0x007f7f007f007f7fULL, 0x0022220022002222ULL,
    0x00e7e700e700e7e7ULL, 0x0059590059005959ULL, 0x00e1e100e100e1e1ULL,
    0x00dada00da00dadaULL, 0x003d3d003d003d3dULL, 0x00c8c800c800c8c8ULL,
    0x0012120012001212ULL, 0x0004040004000404ULL, 0x0074740074007474ULL,
    0x0054540054005454ULL, 0x0030300030003030ULL, 0x007e7e007e007e7eULL,
    0x00b4b400b400b4b4ULL, 0x0028280028002828ULL, 0x0055550055005555ULL,
    0x0068680068006868ULL, 0x0050500050005050ULL, 0x00bebe00be00bebeULL,
    0x00d0d000d000d0d0ULL, 0x00c4c400c400c4c4ULL, 0x0031310031003131ULL,
    0x00cbcb00cb00cbcbULL, 0x002a2a002a002a2aULL, 0x00adad00ad00adadULL,
    0x000f0f000f000f0fULL, 0x00caca00ca00cacaULL, 0x0070700070007070ULL,
    0x00ffff00ff00ffffULL, 0x0032320032003232ULL, 0x0069690069006969ULL,
    0x0008080008000808ULL, 0x0062620062006262ULL, 0x0000000000000000ULL,
    0x0024240024002424ULL, 0x00d1d100d100d1d1ULL, 0x00fbfb00fb00fbfbULL,
    0x00baba00ba00babaULL, 0x00eded00ed00ededULL, 0x0045450045004545ULL,
    0x0081810081008181ULL, 0x0073730073007373ULL, 0x006d6d006d006d6dULL,
    0x0084840084008484ULL, 0x009f9f009f009f9fULL, 0x00eeee00ee00eeeeULL,
    0x004a4a004a004a4aULL, 0x00c3c300c300c3c3ULL, 0x002e2e002e002e2eULL,
    0x00c1c100c100c1c1ULL, 0x0001010001000101ULL, 0x00e6e600e600e6e6ULL,
    0x0025250025002525ULL, 0x0048480048004848ULL, 0x0099990099009999ULL,
    0x00b9b900b900b9b9ULL, 0x00b3b300b300b3b3ULL, 0x007b7b007b007b7bULL,
    0x00f9f900f900f9f9ULL, 0x00cece00ce00ceceULL, 0x00bfbf00bf00bfbfULL,
    0x00dfdf00df00dfdfULL, 0x0071710071007171ULL, 0x0029290029002929ULL,
    0x00cdcd00cd00cdcdULL, 0x006c6c006c006c6cULL, 0x0013130013001313ULL,
    0x0064640064006464ULL, 0x009b9b009b009b9bULL, 0x0063630063006363ULL,
    0x009d9d009d009d9dULL, 0x00c0c000c000c0c0ULL, 0x004b4b004b004b4bULL,
    0x00b7b700b700b7b7ULL, 0x00a5a500a500a5a5ULL, 0x0089890089008989ULL,
    0x005f5f005f005f5fULL, 0x00b1b100b100b1b1ULL, 0x0017170017001717ULL,
    0x00f4f400f400f4f4ULL, 0x00bcbc00bc00bcbcULL, 0x00d3d300d300d3d3ULL,
    0x0046460046004646ULL, 0x00cfcf00cf00cfcfULL, 0x0037370037003737ULL,
    0x005e5e005e005e5eULL, 0x0047470047004747ULL, 0x0094940094009494ULL,
    0x00fafa00fa00fafaULL, 0x00fcfc00fc00fcfcULL, 0x005b5b005b005b5bULL,
    0x0097970097009797ULL, 0x00fefe00fe00fefeULL, 0x005a5a005a005a5aULL,
    0x00acac00ac00acacULL, 0x003c3c003c003c3cULL, 0x004c4c004c004c4cULL,
    0x0003030003000303ULL, 0x0035350035003535ULL, 0x00f3f300f300f3f3ULL,
    0x0023230023002323ULL, 0x00b8b800b800b8b8ULL, 0x005d5d005d005d5dULL,
    0x006a6a006a006a6aULL, 0x0092920092009292ULL, 0x00d5d500d500d5d5ULL,
    0x0021210021002121ULL, 0x0044440044004444ULL, 0x0051510051005151ULL,
    0x00c6c600c600c6c6ULL, 0x007d7d007d007d7dULL, 0x0039390039003939ULL,
    0x0083830083008383ULL, 0x00dcdc00dc00dcdcULL, 0x00aaaa00aa00aaaaULL,
    0x007c7c007c007c7cULL, 0x0077770077007777ULL, 0x0056560056005656ULL,
    0x0005050005000505ULL, 0x001b1b001b001b1bULL, 0x00a4a400a400a4a4ULL,
    0x0015150015001515ULL, 0x0034340034003434ULL, 0x001e1e001e001e1eULL,
    0x001c1c001c001c1cULL, 0x00f8f800f800f8f8ULL, 0x0052520052005252ULL,
    0x0020200020002020ULL, 0x0014140014001414ULL, 0x00e9e900e900e9e9ULL,
    0x00bdbd00bd00bdbdULL, 0x00dddd00dd00ddddULL, 0x00e4e400e400e4e4ULL,
    0x00a1a100a100a1a1ULL, 0x00e0e000e000e0e0ULL, 0x008a8a008a008a8aULL,
    0x00f1f100f100f1f1ULL, 0x00d6d600d600d6d6ULL, 0x007a7a007a007a7aULL,
    0x00bbbb00bb00bbbbULL, 0x00e3e300e300e3e3ULL, 0x0040400040004040ULL,
    0x004f4f004f004f4fULL,
};

const u64 camellia_sp00444404[256] = {
    0x0000707070700070ULL, 0x00002c2c2c2c002cULL, 0x0000b3b3b3b300b3ULL,
    0x0000c0c0c0c000c0ULL, 0x0000e4e4e4e400e4ULL, 0x0000575757570057ULL,
    0x0000eaeaeaea00eaULL, 0x0000aeaeaeae00aeULL, 0x0000232323230023ULL,
    0x00006b6b6b6b006bULL, 0x0000454545450045ULL, 0x0000a5a5a5a500a5ULL,
    0x0000edededed00edULL, 0x00004f4f4f4f004fULL, 0x00001d1d1d1d001dULL,
    0x0000929292920092ULL, 0x0000868686860086ULL, 0x0000afafafaf00afULL,
    0x00007c7c7c7c007cULL, 0x00001f1f1f1f001fULL, 0x00003e3e3e3e003eULL,
    0x0000dcdcdcdc00dcULL, 0x00005e5e5e5e005eULL, 0x00000b0b0b0b000bULL,
    0x0000a6a6a6a600a6ULL, 0x0000393939390039ULL, 0x0000d5d5d5d500d5ULL,
    0x00005d5d5d5d005dULL, 0x0000d9d9d9d900d9ULL, 0x00005a5a5a5a005aULL,
    0x0000515151510051ULL, 0x00006c6c6c6c006cULL, 0x00008b8b8b8b008bULL,
    0x00009a9a9a9a009aULL, 0x0000fbfbfbfb00fbULL, 0x0000b0b0b0b000b0ULL,
    0x0000747474740074ULL, 0x00002b2b2b2b002bULL, 0x0000f0f0f0f000f0ULL,
    0x0000848484840084ULL, 0x0000dfdfdfdf00dfULL, 0x0000cbcbcbcb00cbULL,
    0x0000343434340034ULL, 0x0000767676760076ULL, 0x00006d6d6d6d006dULL,
    0x0000a9a9a9a900a9ULL, 0x0000d1d1d1d100d1ULL, 0x0000040404040004ULL,
    0x0000141414140014ULL, 0x00003a3a3a3a003aULL, 0x0000dededede00deULL,
    0x0000111111110011ULL, 0x0000323232320032ULL, 0x00009c9c9c9c009cULL,
    0x0000535353530053ULL, 0x0000f2f2f2f200f2ULL, 0x0000fefefefe00feULL,
    0x0000cfcfcfcf00cfULL, 0x0000c3c3c3c300c3ULL, 0x00007a7a7a7a007aULL,
    0x0000242424240024ULL, 0x0000e8e8e8e800e8ULL, 0x0000606060600060ULL,
    0x0000696969690069ULL, 0x0000aaaaaaaa00aaULL, 0x0000a0a0a0a000a0ULL,
    0x0000a1a1a1a100a1ULL, 0x0000626262620062ULL, 0x0000545454540054ULL,
    0x00001e1e1e1e001eULL, 0x0000e0e0e0e000e0ULL, 0x0000646464640064ULL,
    0x0000101010100010ULL, 0x0000000000000000ULL, 0x0000a3a3a3a300a3ULL,
    0x0000757575750075ULL, 0x00008a8a8a8a008aULL, 0x0000e6e6e6e600e6ULL,
    0x0000090909090009ULL, 0x0000dddddddd00ddULL, 0x0000878787870087ULL,
    0x0000838383830083ULL, 0x0000cdcdcdcd00cdULL, 0x0000909090900090ULL,
    0x0000737373730073ULL, 0x0000f6f6f6f600f6ULL, 0x00009d9d9d9d009dULL,
    0x0000bfbfbfbf00bfULL, 0x0000525252520052ULL, 0x0000d8d8d8d800d8ULL,
    0x0000c8c8c8c800c8ULL, 0x0000c6c6c6c600c6ULL, 0x0000818181810081ULL,
    0x00006f6f6f6f006fULL, 0x0000131313130013ULL, 0x0000636363630063ULL,
    0x0000e9e9e9e900e9ULL, 0x0000a7a7a7a700a7ULL, 0x00009f9f9f9f009fULL,
    0x0000bcbcbcbc00bcULL, 0x0000292929290029ULL, 0x0000f9f9f9f900f9ULL,
    0x00002f2f2f2f002fULL, 0x0000b4b4b4b400b4ULL, 0x0000787878780078ULL,
    0x0000060606060006ULL, 0x0000e7e7e7e700e7ULL, 0x0000717171710071ULL,
    0x0000d4d4d4d400d4ULL, 0x0000abababab00abULL, 0x0000888888880088ULL,
    0x00008d8d8d8d008dULL, 0x0000727272720072ULL, 0x0000b9b9b9b900b9ULL,
    0x0000f8f8f8f800f8ULL, 0x0000acacacac00acULL, 0x0000363636360036ULL,
    0x00002a2a2a2a002aULL, 0x00003c3c3c3c003cULL, 0x0000f1f1f1f100f1ULL,
    0x0000404040400040ULL, 0x0000d3d3d3d300d3ULL, 0x0000bbbbbbbb00bbULL,
    0x0000434343430043ULL, 0x0000151515150015ULL, 0x0000adadadad00adULL,
    0x0000777777770077ULL, 0x0000808080800080ULL, 0x0000828282820082ULL,
    0x0000ecececec00ecULL, 0x0000272727270027ULL, 0x0000e5e5e5e500e5ULL,
    0x0000858585850085ULL, 0x0000353535350035ULL, 0x00000c0c0c0c000cULL,
    0x0000414141410041ULL, 0x0000efefefef00efULL, 0x0000939393930093ULL,
    0x0000191919190019ULL, 0x0000212121210021ULL, 0x00000e0e0e0e000eULL,
    0x00004e4e4e4e004eULL, 0x0000656565650065ULL, 0x0000bdbdbdbd00bdULL,
    0x0000b8b8b8b800b8ULL, 0x00008f8f8f8f008fULL, 0x0000ebebebeb00ebULL,
    0x0000cececece00ceULL, 0x0000303030300030ULL, 0x00005f5f5f5f005fULL,
    0x0000c5c5c5c500c5ULL, 0x00001a1a1a1a001aULL, 0x0000e1e1e1e100e1ULL,
    0x0000cacacaca00caULL, 0x0000474747470047ULL, 0x00003d3d3d3d003dULL,
    0x0000010101010001ULL, 0x0000d6d6d6d600d6ULL, 0x0000565656560056ULL,
    0x00004d4d4d4d004dULL, 0x00000d0d0d0d000dULL, 0x0000666666660066ULL,
    0x0000cccccccc00ccULL, 0x00002d2d2d2d002dULL, 0x0000121212120012ULL,
    0x0000202020200020ULL, 0x0000b1b1b1b100b1ULL, 0x0000999999990099ULL,
    0x00004c4c4c4c004cULL, 0x0000c2c2c2c200c2ULL, 0x00007e7e7e7e007eULL,
    0x0000050505050005ULL, 0x0000b7b7b7b700b7ULL, 0x0000313131310031ULL,
    0x0000171717170017ULL, 0x0000d7d7d7d700d7ULL, 0x0000585858580058ULL,
    0x0000616161610061ULL, 0x00001b1b1b1b001bULL, 0x00001c1c1c1c001cULL,
    0x00000f0f0f0f000fULL, 0x0000161616160016ULL, 0x0000181818180018ULL,
    0x0000222222220022ULL, 0x0000444444440044ULL, 0x0000b2b2b2b200b2ULL,
    0x0000b5b5b5b500b5ULL, 0x0000919191910091ULL, 0x0000080808080008ULL,
    0x0000a8a8a8a800a8ULL, 0x0000fcfcfcfc00fcULL, 0x0000505050500050ULL,
    0x0000d0d0d0d000d0ULL, 0x00007d7d7d7d007dULL, 0x0000898989890089ULL,
    0x0000979797970097ULL, 0x00005b5b5b5b005bULL, 0x0000959595950095ULL,
    0x0000ffffffff00ffULL, 0x0000d2d2d2d200d2ULL, 0x0000c4c4c4c400c4ULL,
    0x0000484848480048ULL, 0x0000f7f7f7f700f7ULL, 0x0000dbdbdbdb00dbULL,
    0x0000030303030003ULL, 0x0000dadadada00daULL, 0x00003f3f3f3f003fULL,
    0x0000949494940094ULL, 0x00005c5c5c5c005cULL, 0x0000020202020002ULL,
    0x00004a4a4a4a004aULL, 0x0000333333330033ULL, 0x0000676767670067ULL,
    0x0000f3f3f3f300f3ULL, 0x00007f7f7f7f007fULL, 0x0000e2e2e2e200e2ULL,
    0x00009b9b9b9b009bULL, 0x0000262626260026ULL, 0x0000373737370037ULL,
    0x00003b3b3b3b003bULL, 0x0000969696960096ULL, 0x00004b4b4b4b004bULL,
    0x0000bebebebe00beULL, 0x00002e2e2e2e002eULL, 0x0000797979790079ULL,
    0x00008c8c8c8c008cULL, 0x00006e6e6e6e006eULL, 0x00008e8e8e8e008eULL,
    0x0000f5f5f5f500f5ULL, 0x0000b6b6b6b600b6ULL, 0x0000fdfdfdfd00fdULL,
    0x0000595959590059ULL, 0x0000989898980098ULL, 0x00006a6a6a6a006aULL,
    0x0000464646460046ULL, 0x0000babababa00baULL, 0x0000252525250025ULL,
    0x0000424242420042ULL, 0x0000a2a2a2a200a2ULL, 0x0000fafafafa00faULL,
    0x0000070707070007ULL, 0x0000555555550055ULL, 0x0000eeeeeeee00eeULL,
    0x00000a0a0a0a000aULL, 0x0000494949490049ULL, 0x0000686868680068ULL,
    0x0000383838380038ULL, 0x0000a4a4a4a400a4ULL, 0x0000282828280028ULL,
    0x00007b7b7b7b007bULL, 0x0000c9c9c9c900c9ULL, 0x0000c1c1c1c100c1ULL,
    0x0000e3e3e3e300e3ULL, 0x0000f4f4f4f400f4ULL, 0x0000c7c7c7c700c7ULL,
    0x00009e9e9e9e009eULL,
};

const u64 camellia_sp02220222[256] = {
    0x00e0e0e000e0e0e0ULL, 0x0005050500050505ULL, 0x0058585800585858ULL,
    0x00d9d9d900d9d9d9ULL, 0x0067676700676767ULL, 0x004e4e4e004e4e4eULL,
    0x0081818100818181ULL, 0x00cbcbcb00cbcbcbULL, 0x00c9c9c900c9c9c9ULL,
    0x000b0b0b000b0b0bULL, 0x00aeaeae00aeaeaeULL, 0x006a6a6a006a6a6aULL,
    0x00d5d5d500d5d5d5ULL, 0x0018181800181818ULL, 0x005d5d5d005d5d5dULL,
    0x0082828200828282ULL, 0x0046464600464646ULL, 0x00dfdfdf00dfdfdfULL,
    0x00d6d6d600d6d6d6ULL, 0x0027272700272727ULL, 0x008a8a8a008a8a8aULL,
    0x0032323200323232ULL, 0x004b4b4b004b4b4bULL, 0x0042424200424242ULL,
    0x00dbdbdb00dbdbdbULL, 0x001c1c1c001c1c1cULL, 0x009e9e9e009e9e9eULL,
    0x009c9c9c009c9c9cULL, 0x003a3a3a003a3a3aULL, 0x00cacaca00cacacaULL,
    0x0025252500252525ULL, 0x007b7b7b007b7b7bULL, 0x000d0d0d000d0d0dULL,
    0x0071717100717171ULL, 0x005f5f5f005f5f5fULL, 0x001f1f1f001f1f1fULL,
    0x00f8f8f800f8f8f8ULL, 0x00d7d7d700d7d7d7ULL, 0x003e3e3e003e3e3eULL,
    0x009d9d9d009d9d9dULL, 0x007c7c7c007c7c7cULL, 0x0060606000606060ULL,
    0x00b9b9b900b9b9b9ULL, 0x00bebebe00bebebeULL, 0x00bcbcbc00bcbcbcULL,
    0x008b8b8b008b8b8bULL, 0x0016161600161616ULL, 0x0034343400343434ULL,
    0x004d4d4d004d4d4dULL, 0x00c3c3c300c3c3c3ULL, 0x0072727200727272ULL,
    0x0095959500959595ULL, 0x00ababab00abababULL, 0x008e8e8e008e8e8eULL,
    0x00bababa00bababaULL, 0x007a7a7a007a7a7aULL, 0x00b3b3b300b3b3b3ULL,
    0x0002020200020202ULL, 0x00b4b4b400b4b4b4ULL, 0x00adadad00adadadULL,
    0x00a2a2a200a2a2a2ULL, 0x00acacac00acacacULL, 0x00d8d8d800d8d8d8ULL,
    0x009a9a9a009a9a9aULL, 0x0017171700171717ULL, 0x001a1a1a001a1a1aULL,
    0x0035353500353535ULL, 0x00cccccc00ccccccULL, 0x00f7f7f700f7f7f7ULL,
    0x0099999900999999ULL, 0x0061616100616161ULL, 0x005a5a5a005a5a5aULL,
    0x00e8e8e800e8e8e8ULL, 0x0024242400242424ULL, 0x0056565600565656ULL,
    0x0040404000404040ULL, 0x00e1e1e100e1e1e1ULL, 0x0063636300636363ULL,
    0x0009090900090909ULL, 0x0033333300333333ULL, 0x00bfbfbf00bfbfbfULL,
    0x0098989800989898ULL, 0x0097979700979797ULL, 0x0085858500858585ULL,
    0x0068686800686868ULL, 0x00fcfcfc00fcfcfcULL, 0x00ececec00ecececULL,
    0x000a0a0a000a0a0aULL, 0x00dadada00dadadaULL, 0x006f6f6f006f6f6fULL,
    0x0053535300535353ULL, 0x0062626200626262ULL, 0x00a3a3a300a3a3a3ULL,
    0x002e2e2e002e2e2eULL, 0x0008080800080808ULL, 0x00afafaf00afafafULL,
    0x0028282800282828ULL, 0x00b0b0b000b0b0b0ULL, 0x0074747400747474ULL,
    0x00c2c2c200c2c2c2ULL, 0x00bdbdbd00bdbdbdULL, 0x0036363600363636ULL,
    0x0022222200222222ULL, 0x0038383800383838ULL, 0x0064646400646464ULL,
    0x001e1e1e001e1e1eULL, 0x0039393900393939ULL, 0x002c2c2c002c2c2cULL,
    0x00a6a6a600a6a6a6ULL, 0x0030303000303030ULL, 0x00e5e5e500e5e5e5ULL,
    0x0044444400444444ULL, 0x00fdfdfd00fdfdfdULL, 0x0088888800888888ULL,
    0x009f9f9f009f9f9fULL, 0x0065656500656565ULL, 0x0087878700878787ULL,
    0x006b6b6b006b6b6bULL, 0x00f4f4f400f4f4f4ULL, 0x0023232300232323ULL,
    0x0048484800484848ULL, 0x0010101000101010ULL, 0x00d1d1d100d1d1d1ULL,
    0x0051515100515151ULL, 0x00c0c0c000c0c0c0ULL, 0x00f9f9f900f9f9f9ULL,
    0x00d2d2d200d2d2d2ULL, 0x00a0a0a000a0a0a0ULL, 0x0055555500555555ULL,
    0x00a1a1a100a1a1a1ULL, 0x0041414100414141ULL, 0x00fafafa00fafafaULL,
    0x0043434300434343ULL, 0x0013131300131313ULL, 0x00c4c4c400c4c4c4ULL,
    0x002f2f2f002f2f2fULL, 0x00a8a8a800a8a8a8ULL, 0x00b6b6b600b6b6b6ULL,
    0x003c3c3c003c3c3cULL, 0x002b2b2b002b2b2bULL, 0x00c1c1c100c1c1c1ULL,
    0x00ffffff00ffffffULL, 0x00c8c8c800c8c8c8ULL, 0x00a5a5a500a5a5a5ULL,
    0x0020202000202020ULL, 0x0089898900898989ULL, 0x0000000000000000ULL,
    0x0090909000909090ULL, 0x0047474700474747ULL, 0x00efefef00efefefULL,
    0x00eaeaea00eaeaeaULL, 0x00b7b7b700b7b7b7ULL, 0x0015151500151515ULL,
    0x0006060600060606ULL, 0x00cdcdcd00cdcdcdULL, 0x00b5b5b500b5b5b5ULL,
    0x0012121200121212ULL, 0x007e7e7e007e7e7eULL, 0x00bbbbbb00bbbbbbULL,
    0x0029292900292929ULL, 0x000f0f0f000f0f0fULL, 0x00b8b8b800b8b8b8ULL,
    0x0007070700070707ULL, 0x0004040400040404ULL, 0x009b9b9b009b9b9bULL,
    0x0094949400949494ULL, 0x0021212100212121ULL, 0x0066666600666666ULL,
    0x00e6e6e600e6e6e6ULL, 0x00cecece00cececeULL, 0x00ededed00edededULL,
    0x00e7e7e700e7e7e7ULL, 0x003b3b3b003b3b3bULL, 0x00fefefe00fefefeULL,
    0x007f7f7f007f7f7fULL, 0x00c5c5c500c5c5c5ULL, 0x00a4a4a400a4a4a4ULL,
    0x0037373700373737ULL, 0x00b1b1b100b1b1b1ULL, 0x004c4c4c004c4c4cULL,
    0x0091919100919191ULL, 0x006e6e6e006e6e6eULL, 0x008d8d8d008d8d8dULL,
    0x0076767600767676ULL, 0x0003030300030303ULL, 0x002d2d2d002d2d2dULL,
    0x00dedede00dededeULL, 0x0096969600969696ULL, 0x0026262600262626ULL,
    0x007d7d7d007d7d7dULL, 0x00c6c6c600c6c6c6ULL, 0x005c5c5c005c5c5cULL,
    0x00d3d3d300d3d3d3ULL, 0x00f2f2f200f2f2f2ULL, 0x004f4f4f004f4f4fULL,
    0x0019191900191919ULL, 0x003f3f3f003f3f3fULL, 0x00dcdcdc00dcdcdcULL,
    0x0079797900797979ULL, 0x001d1d1d001d1d1dULL, 0x0052525200525252ULL,
    0x00ebebeb00ebebebULL, 0x00f3f3f300f3f3f3ULL, 0x006d6d6d006d6d6dULL,
    0x005e5e5e005e5e5eULL, 0x00fbfbfb00fbfbfbULL, 0x0069696900696969ULL,
    0x00b2b2b200b2b2b2ULL, 0x00f0f0f000f0f0f0ULL, 0x0031313100313131ULL,
    0x000c0c0c000c0c0cULL, 0x00d4d4d400d4d4d4ULL, 0x00cfcfcf00cfcfcfULL,
    0x008c8c8c008c8c8cULL, 0x00e2e2e200e2e2e2ULL, 0x0075757500757575ULL,
    0x00a9a9a900a9a9a9ULL, 0x004a4a4a004a4a4aULL, 0x0057575700575757ULL,
    0x0084848400848484ULL, 0x0011111100111111ULL, 0x0045454500454545ULL,
    0x001b1b1b001b1b1bULL, 0x00f5f5f500f5f5f5ULL, 0x00e4e4e400e4e4e4ULL,
    0x000e0e0e000e0e0eULL, 0x0073737300737373ULL, 0x00aaaaaa00aaaaaaULL,
    0x00f1f1f100f1f1f1ULL, 0x00dddddd00ddddddULL, 0x0059595900595959ULL,
    0x0014141400141414ULL, 0x006c6c6c006c6c6cULL, 0x0092929200929292ULL,
    0x0054545400545454ULL, 0x00d0d0d000d0d0d0ULL, 0x0078787800787878ULL,
    0x0070707000707070ULL, 0x00e3e3e300e3e3e3ULL, 0x0049494900494949ULL,
    0x0080808000808080ULL, 0x0050505000505050ULL, 0x00a7a7a700a7a7a7ULL,
    0x00f6f6f600f6f6f6ULL, 0x0077777700777777ULL, 0x0093939300939393ULL,
    0x0086868600868686ULL, 0x0083838300838383ULL, 0x002a2a2a002a2a2aULL,
    0x00c7c7c700c7c7c7ULL, 0x005b5b5b005b5b5bULL, 0x00e9e9e900e9e9e9ULL,
    0x00eeeeee00eeeeeeULL, 0x008f8f8f008f8f8fULL, 0x0001010100010101ULL,
    0x003d3d3d003d3d3dULL,
};

const u64 camellia_sp30333033[256] = {
    0x3800383838003838ULL, 0x4100414141004141ULL, 0x1600161616001616ULL,
    0x7600767676007676ULL, 0xd900d9d9d900d9d9ULL, 0x9300939393009393ULL,
    0x6000606060006060ULL, 0xf200f2f2f200f2f2ULL, 0x7200727272007272ULL,
    0xc200c2c2c200c2c2ULL, 0xab00ababab00ababULL, 0x9a009a9a9a009a9aULL,
    0x7500757575007575ULL, 0x0600060606000606ULL, 0x5700575757005757ULL,
    0xa000a0a0a000a0a0ULL, 0x9100919191009191ULL, 0xf700f7f7f700f7f7ULL,
    0xb500b5b5b500b5b5ULL, 0xc900c9c9c900c9c9ULL, 0xa200a2a2a200a2a2ULL,
    0x8c008c8c8c008c8cULL, 0xd200d2d2d200d2d2ULL, 0x9000909090009090ULL,
    0xf600f6f6f600f6f6ULL, 0x0700070707000707ULL, 0xa700a7a7a700a7a7ULL,
    0x2700272727002727ULL, 0x8e008e8e8e008e8eULL, 0xb200b2b2b200b2b2ULL,
    0x4900494949004949ULL, 0xde00dedede00dedeULL, 0x4300434343004343ULL,
    0x5c005c5c5c005c5cULL, 0xd700d7d7d700d7d7ULL, 0xc700c7c7c700c7c7ULL,
    0x3e003e3e3e003e3eULL, 0xf500f5f5f500f5f5ULL, 0x8f008f8f8f008f8fULL,
    0x6700676767006767ULL, 0x1f001f1f1f001f1fULL, 0x1800181818001818ULL,
    0x6e006e6e6e006e6eULL, 0xaf00afafaf00afafULL, 0x2f002f2f2f002f2fULL,
    0xe200e2e2e200e2e2ULL, 0x8500858585008585ULL, 0x0d000d0d0d000d0dULL,
    0x5300535353005353ULL, 0xf000f0f0f000f0f0ULL, 0x9c009c9c9c009c9cULL,
    0x6500656565006565ULL, 0xea00eaeaea00eaeaULL, 0xa300a3a3a300a3a3ULL,
    0xae00aeaeae00aeaeULL, 0x9e009e9e9e009e9eULL, 0xec00ececec00ececULL,
    0x8000808080008080ULL, 0x2d002d2d2d002d2dULL, 0x6b006b6b6b006b6bULL,
    0xa800a8a8a800a8a8ULL, 0x2b002b2b2b002b2bULL, 0x3600363636003636ULL,
    0xa600a6a6a600a6a6ULL, 0xc500c5c5c500c5c5ULL, 0x8600868686008686ULL,
    0x4d004d4d4d004d4dULL, 0x3300333333003333ULL, 0xfd00fdfdfd00fdfdULL,
    0x6600666666006666ULL, 0x5800585858005858ULL, 0x9600969696009696ULL,
    0x3a003a3a3a003a3aULL, 0x0900090909000909ULL, 0x9500959595009595ULL,
    0x1000101010001010ULL, 0x7800787878007878ULL, 0xd800d8d8d800d8d8ULL,
    0x4200424242004242ULL, 0xcc00cccccc00ccccULL, 0xef00efefef00efefULL,
    0x2600262626002626ULL, 0xe500e5e5e500e5e5ULL, 0x6100616161006161ULL,
    0x1a001a1a1a001a1aULL, 0x3f003f3f3f003f3fULL, 0x3b003b3b3b003b3bULL,
    0x8200828282008282ULL, 0xb600b6b6b600b6b6ULL, 0xdb00dbdbdb00dbdbULL,
    0xd400d4d4d400d4d4ULL, 0x9800989898009898ULL, 0xe800e8e8e800e8e8ULL,
    0x8b008b8b8b008b8bULL, 0x0200020202000202ULL, 0xeb00ebebeb00ebebULL,
    0x0a000a0a0a000a0aULL, 0x2c002c2c2c002c2cULL, 0x1d001d1d1d001d1dULL,
    0xb000b0b0b000b0b0ULL, 0x6f006f6f6f006f6fULL, 0x8d008d8d8d008d8dULL,
    0x8800888888008888ULL, 0x0e000e0e0e000e0eULL, 0x1900191919001919ULL,
    0x8700878787008787ULL, 0x4e004e4e4e004e4eULL, 0x0b000b0b0b000b0bULL,
    0xa900a9a9a900a9a9ULL, 0x0c000c0c0c000c0cULL, 0x7900797979007979ULL,
    0x1100111111001111ULL, 0x7f007f7f7f007f7fULL, 0x2200222222002222ULL,
    0xe700e7e7e700e7e7ULL, 0x5900595959005959ULL, 0xe100e1e1e100e1e1ULL,
    0xda00dadada00dadaULL, 0x3d003d3d3d003d3dULL, 0xc800c8c8c800c8c8ULL,
    0x1200121212001212ULL, 0x0400040404000404ULL, 0x7400747474007474ULL,
    0x5400545454005454ULL, 0x3000303030003030ULL, 0x7e007e7e7e007e7eULL,
    0xb400b4b4b400b4b4ULL, 0x2800282828002828ULL, 0x5500555555005555ULL,
    0x6800686868006868ULL, 0x5000505050005050ULL, 0xbe00bebebe00bebeULL,
    0xd000d0d0d000d0d0ULL, 0xc400c4c4c400c4c4ULL, 0x3100313131003131ULL,
    0xcb00cbcbcb00cbcbULL, 0x2a002a2a2a002a2aULL, 0xad00adadad00adadULL,
    0x0f000f0f0f000f0fULL, 0xca00cacaca00cacaULL, 0x7000707070007070ULL,
    0xff00ffffff00ffffULL, 0x3200323232003232ULL, 0x6900696969006969ULL,
    0x0800080808000808ULL, 0x6200626262006262ULL, 0x0000000000000000ULL,
    0x2400242424002424ULL, 0xd100d1d1d100d1d1ULL, 0xfb00fbfbfb00fbfbULL,
    0xba00bababa00babaULL, 0xed00ededed00ededULL, 0x4500454545004545ULL,
    0x8100818181008181ULL, 0x7300737373007373ULL, 0x6d006d6d6d006d6dULL,
    0x8400848484008484ULL, 0x9f009f9f9f009f9fULL, 0xee00eeeeee00eeeeULL,
    0x4a004a4a4a004a4aULL, 0xc300c3c3c300c3c3ULL, 0x2e002e2e2e002e2eULL,
    0xc100c1c1c100c1c1ULL, 0x0100010101000101ULL, 0xe600e6e6e600e6e6ULL,
    0x2500252525002525ULL, 0x4800484848004848ULL, 0x9900999999009999ULL,
    0xb900b9b9b900b9b9ULL, 0xb300b3b3b300b3b3ULL, 0x7b007b7b7b007b7bULL,
    0xf900f9f9f900f9f9ULL, 0xce00cecece00ceceULL, 0xbf00bfbfbf00bfbfULL,
    0xdf00dfdfdf00dfdfULL, 0x7100717171007171ULL, 0x2900292929002929ULL,
    0xcd00cdcdcd00cdcdULL, 0x6c006c6c6c006c6cULL, 0x1300131313001313ULL,
    0x6400646464006464ULL, 0x9b009b9b9b009b9bULL, 0x6300636363006363ULL,
    0x9d009d9d9d009d9dULL, 0xc000c0c0c000c0c0ULL, 0x4b004b4b4b004b4bULL,
    0xb700b7b7b700b7b7ULL, 0xa500a5a5a500a5a5ULL, 0x8900898989008989ULL,
    0x5f005f5f5f005f5fULL, 0xb100b1b1b100b1b1ULL, 0x1700171717001717ULL,
    0xf400f4f4f400f4f4ULL, 0xbc00bcbcbc00bcbcULL, 0xd300d3d3d300d3d3ULL,
    0x4600464646004646ULL, 0xcf00cfcfcf00cfcfULL, 0x3700373737003737ULL,
    0x5e005e5e5e005e5eULL, 0x4700474747004747ULL, 0x9400949494009494ULL,
    0xfa00fafafa00fafaULL, 0xfc00fcfcfc00fcfcULL, 0x5b005b5b5b005b5bULL,
    0x9700979797009797ULL, 0xfe00fefefe00fefeULL, 0x5a005a5a5a005a5aULL,
    0xac00acacac00acacULL, 0x3c003c3c3c003c3cULL, 0x4c004c4c4c004c4cULL,
    0x0300030303000303ULL, 0x3500353535003535ULL, 0xf300f3f3f300f3f3ULL,
    0x2300232323002323ULL, 0xb800b8b8b800b8b8ULL, 0x5d005d5d5d005d5dULL,
    0x6a006a6a6a006a6aULL, 0x9200929292009292ULL, 0xd500d5d5d500d5d5ULL,
    0x2100212121002121ULL, 0x4400444444004444ULL, 0x5100515151005151ULL,
    0xc600c6c6c600c6c6ULL, 0x7d007d7d7d007d7dULL, 0x3900393939003939ULL,
    0x8300838383008383ULL, 0xdc00dcdcdc00dcdcULL, 0xaa00aaaaaa00aaaaULL,
    0x7c007c7c7c007c7cULL, 0x7700777777007777ULL, 0x5600565656005656ULL,
    0x0500050505000505ULL, 0x1b001b1b1b001b1bULL, 0xa400a4a4a400a4a4ULL,
    0x1500151515001515ULL, 0x3400343434003434ULL, 0x1e001e1e1e001e1eULL,
    0x1c001c1c1c001c1cULL, 0xf800f8f8f800f8f8ULL, 0x5200525252005252ULL,
    0x2000202020002020ULL, 0x1400141414001414ULL, 0xe900e9e9e900e9e9ULL,
    0xbd00bdbdbd00bdbdULL, 0xdd00dddddd00ddddULL, 0xe400e4e4e400e4e4ULL,
    0xa100a1a1a100a1a1ULL, 0xe000e0e0e000e0e0ULL, 0x8a008a8a8a008a8aULL,
    0xf100f1f1f100f1f1ULL, 0xd600d6d6d600d6d6ULL, 0x7a007a7a7a007a7aULL,
    0xbb00bbbbbb00bbbbULL, 0xe300e3e3e300e3e3ULL, 0x4000404040004040ULL,
    0x4f004f4f4f004f4fULL,
};

const u64 camellia_sp44044404[256] = {
    0x7070007070700070ULL, 0x2c2c002c2c2c002cULL, 0xb3b300b3b3b300b3ULL,
    0xc0c000c0c0c000c0ULL, 0xe4e400e4e4e400e4ULL, 0x5757005757570057ULL,
    0xeaea00eaeaea00eaULL, 0xaeae00aeaeae00aeULL, 0x2323002323230023ULL,
    0x6b6b006b6b6b006bULL, 0x4545004545450045ULL, 0xa5a500a5a5a500a5ULL,
    0xeded00ededed00edULL, 0x4f4f004f4f4f004fULL, 0x1d1d001d1d1d001dULL,
    0x9292009292920092ULL, 0x8686008686860086ULL, 0xafaf00afafaf00afULL,
    0x7c7c007c7c7c007cULL, 0x1f1f001f1f1f001fULL, 0x3e3e003e3e3e003eULL,
    0xdcdc00dcdcdc00dcULL, 0x5e5e005e5e5e005eULL, 0x0b0b000b0b0b000bULL,
    0xa6a600a6a6a600a6ULL, 0x3939003939390039ULL, 0xd5d500d5d5d500d5ULL,
    0x5d5d005d5d5d005dULL, 0xd9d900d9d9d900d9ULL, 0x5a5a005a5a5a005aULL,
    0x5151005151510051ULL, 0x6c6c006c6c6c006cULL, 0x8b8b008b8b8b008bULL,
    0x9a9a009a9a9a009aULL, 0xfbfb00fbfbfb00fbULL, 0xb0b000b0b0b000b0ULL,
    0x7474007474740074ULL, 0x2b2b002b2b2b002bULL, 0xf0f000f0f0f000f0ULL,
    0x8484008484840084ULL, 0xdfdf00dfdfdf00dfULL, 0xcbcb00cbcbcb00cbULL,
    0x3434003434340034ULL, 0x7676007676760076ULL, 0x6d6d006d6d6d006dULL,
    0xa9a900a9a9a900a9ULL, 0xd1d100d1d1d100d1ULL, 0x0404000404040004ULL,
    0x1414001414140014ULL, 0x3a3a003a3a3a003aULL, 0xdede00dedede00deULL,
    0x1111001111110011ULL, 0x3232003232320032ULL, 0x9c9c009c9c9c009cULL,
    0x5353005353530053ULL, 0xf2f200f2f2f200f2ULL, 0xfefe00fefefe00feULL,
    0xcfcf00cfcfcf00cfULL, 0xc3c300c3c3c300c3ULL, 0x7a7a007a7a7a007aULL,
    0x2424002424240024ULL, 0xe8e800e8e8e800e8ULL, 0x6060006060600060ULL,
    0x6969006969690069ULL, 0xaaaa00aaaaaa00aaULL, 0xa0a000a0a0a000a0ULL,
    0xa1a100a1a1a100a1ULL, 0x6262006262620062ULL, 0x5454005454540054ULL,
    0x1e1e001e1e1e001eULL, 0xe0e000e0e0e000e0ULL, 0x6464006464640064ULL,
    0x1010001010100010ULL, 0x0000000000000000ULL, 0xa3a300a3a3a300a3ULL,
    0x7575007575750075ULL, 0x8a8a008a8a8a008aULL, 0xe6e600e6e6e600e6ULL,
    0x0909000909090009ULL, 0xdddd00dddddd00ddULL, 0x8787008787870087ULL,
    0x8383008383830083ULL, 0xcdcd00cdcdcd00cdULL, 0x9090009090900090ULL,
    0x7373007373730073ULL, 0xf6f600f6f6f600f6ULL, 0x9d9d009d9d9d009dULL,
    0xbfbf00bfbfbf00bfULL, 0x5252005252520052ULL, 0xd8d800d8d8d800d8ULL,
    0xc8c800c8c8c800c8ULL, 0xc6c600c6c6c600c6ULL, 0x8181008181810081ULL,
    0x6f6f006f6f6f006fULL, 0x1313001313130013ULL, 0x6363006363630063ULL,
    0xe9e900e9e9e900e9ULL, 0xa7a700a7a7a700a7ULL, 0x9f9f009f9f9f009fULL,
    0xbcbc00bcbcbc00bcULL, 0x2929002929290029ULL, 0xf9f900f9f9f900f9ULL,
    0x2f2f002f2f2f002fULL, 0xb4b400b4b4b400b4ULL, 0x7878007878780078ULL,
    0x0606000606060006ULL, 0xe7e700e7e7e700e7ULL, 0x7171007171710071ULL,
    0xd4d400d4d4d400d4ULL, 0xabab00ababab00abULL, 0x8888008888880088ULL,
    0x8d8d008d8d8d008dULL, 0x7272007272720072ULL, 0xb9b900b9b9b900b9ULL,
    0xf8f800f8f8f800f8ULL, 0xacac00acacac00acULL, 0x3636003636360036ULL,
    0x2a2a002a2a2a002aULL, 0x3c3c003c3c3c003cULL, 0xf1f100f1f1f100f1ULL,
    0x4040004040400040ULL, 0xd3d300d3d3d300d3ULL, 0xbbbb00bbbbbb00bbULL,
    0x4343004343430043ULL, 0x1515001515150015ULL, 0xadad00adadad00adULL,
    0x7777007777770077ULL, 0x8080008080800080ULL, 0x8282008282820082ULL,
    0xecec00ececec00ecULL, 0x2727002727270027ULL, 0xe5e500e5e5e500e5ULL,
    0x8585008585850085ULL, 0x3535003535350035ULL, 0x0c0c000c0c0c000cULL,
    0x4141004141410041ULL, 0xefef00efefef00efULL, 0x9393009393930093ULL,
    0x1919001919190019ULL, 0x2121002121210021ULL, 0x0e0e000e0e0e000eULL,
    0x4e4e004e4e4e004eULL, 0x6565006565650065ULL, 0xbdbd00bdbdbd00bdULL,
    0xb8b800b8b8b800b8ULL, 0x8f8f008f8f8f008fULL, 0xebeb00ebebeb00ebULL,
    0xcece00cecece00ceULL, 0x3030003030300030ULL, 0x5f5f005f5f5f005fULL,
    0xc5c500c5c5c500c5ULL, 0x1a1a001a1a1a001aULL, 0xe1e100e1e1e100e1ULL,
    0xcaca00cacaca00caULL, 0x4747004747470047ULL, 0x3d3d003d3d3d003dULL,
    0x0101000101010001ULL, 0xd6d600d6d6d600d6ULL, 0x5656005656560056ULL,
    0x4d4d004d4d4d004dULL, 0x0d0d000d0d0d000dULL, 0x6666006666660066ULL,
    0xcccc00cccccc00ccULL, 0x2d2d002d2d2d002dULL, 0x1212001212120012ULL,
    0x2020002020200020ULL, 0xb1b100b1b1b100b1ULL, 0x9999009999990099ULL,
    0x4c4c004c4c4c004cULL, 0xc2c200c2c2c200c2ULL, 0x7e7e007e7e7e007eULL,
    0x0505000505050005ULL, 0xb7b700b7b7b700b7ULL, 0x3131003131310031ULL,
    0x1717001717170017ULL, 0xd7d700d7d7d700d7ULL, 0x5858005858580058ULL,
    0x6161006161610061ULL, 0x1b1b001b1b1b001bULL, 0x1c1c001c1c1c001cULL,
    0x0f0f000f0f0f000fULL, 0x1616001616160016ULL, 0x1818001818180018ULL,
    0x2222002222220022ULL, 0x4444004444440044ULL, 0xb2b200b2b2b200b2ULL,
    0xb5b500b5b5b500b5ULL, 0x9191009191910091ULL, 0x0808000808080008ULL,
    0xa8a800a8a8a800a8ULL, 0xfcfc00fcfcfc00fcULL, 0x5050005050500050ULL,
    0xd0d000d0d0d000d0ULL, 0x7d7d007d7d7d007dULL, 0x8989008989890089ULL,
    0x9797009797970097ULL, 0x5b5b005b5b5b005bULL, 0x9595009595950095ULL,
    0xffff00ffffff00ffULL, 0xd2d200d2d2d200d2ULL, 0xc4c400c4c4c400c4ULL,
    0x4848004848480048ULL, 0xf7f700f7f7f700f7ULL, 0xdbdb00dbdbdb00dbULL,
    0x0303000303030003ULL, 0xdada00dadada00daULL, 0x3f3f003f3f3f003fULL,
    0x9494009494940094ULL, 0x5c5c005c5c5c005cULL, 0x0202000202020002ULL,
    0x4a4a004a4a4a004aULL, 0x3333003333330033ULL, 0x6767006767670067ULL,
    0xf3f300f3f3f300f3ULL, 0x7f7f007f7f7f007fULL, 0xe2e200e2e2e200e2ULL,
    0x9b9b009b9b9b009bULL, 0x2626002626260026ULL, 0x3737003737370037ULL,
    0x3b3b003b3b3b003bULL, 0x9696009696960096ULL, 0x4b4b004b4b4b004bULL,
    0xbebe00bebebe00beULL, 0x2e2e002e2e2e002eULL, 0x7979007979790079ULL,
    0x8c8c008c8c8c008cULL, 0x6e6e006e6e6e006eULL, 0x8e8e008e8e8e008eULL,
    0xf5f500f5f5f500f5ULL, 0xb6b600b6b6b600b6ULL, 0xfdfd00fdfdfd00fdULL,
    0x5959005959590059ULL, 0x9898009898980098ULL, 0x6a6a006a6a6a006aULL,
    0x4646004646460046ULL, 0xbaba00bababa00baULL, 0x2525002525250025ULL,
    0x4242004242420042ULL, 0xa2a200a2a2a200a2ULL, 0xfafa00fafafa00faULL,
    0x0707000707070007ULL, 0x5555005555550055ULL, 0xeeee00eeeeee00eeULL,
    0x0a0a000a0a0a000aULL, 0x4949004949490049ULL, 0x6868006868680068ULL,
    0x3838003838380038ULL, 0xa4a400a4a4a400a4ULL, 0x2828002828280028ULL,
    0x7b7b007b7b7b007bULL, 0xc9c900c9c9c900c9ULL, 0xc1c100c1c1c100c1ULL,
    0xe3e300e3e3e300e3ULL, 0xf4f400f4f4f400f4ULL, 0xc7c700c7c7c700c7ULL,
    0x9e9e009e9e9e009eULL,
};

const u64 camellia_sp11101110[256] = {
    0x7070700070707000ULL, 0x8282820082828200ULL, 0x2c2c2c002c2c2c00ULL,
    0xececec00ececec00ULL, 0xb3b3b300b3b3b300ULL, 0x2727270027272700ULL,
    0xc0c0c000c0c0c000ULL, 0xe5e5e500e5e5e500ULL, 0xe4e4e400e4e4e400ULL,
    0x8585850085858500ULL, 0x5757570057575700ULL, 0x3535350035353500ULL,
    0xeaeaea00eaeaea00ULL, 0x0c0c0c000c0c0c00ULL, 0xaeaeae00aeaeae00ULL,
    0x4141410041414100ULL, 0x2323230023232300ULL, 0xefefef00efefef00ULL,
    0x6b6b6b006b6b6b00ULL, 0x9393930093939300ULL, 0x4545450045454500ULL,
    0x1919190019191900ULL, 0xa5a5a500a5a5a500ULL, 0x2121210021212100ULL,
    0xededed00ededed00ULL, 0x0e0e0e000e0e0e00ULL, 0x4f4f4f004f4f4f00ULL,
    0x4e4e4e004e4e4e00ULL, 0x1d1d1d001d1d1d00ULL, 0x6565650065656500ULL,
    0x9292920092929200ULL, 0xbdbdbd00bdbdbd00ULL, 0x8686860086868600ULL,
    0xb8b8b800b8b8b800ULL, 0xafafaf00afafaf00ULL, 0x8f8f8f008f8f8f00ULL,
    0x7c7c7c007c7c7c00ULL, 0xebebeb00ebebeb00ULL, 0x1f1f1f001f1f1f00ULL,
    0xcecece00cecece00ULL, 0x3e3e3e003e3e3e00ULL, 0x3030300030303000ULL,
    0xdcdcdc00dcdcdc00ULL, 0x5f5f5f005f5f5f00ULL, 0x5e5e5e005e5e5e00ULL,
    0xc5c5c500c5c5c500ULL, 0x0b0b0b000b0b0b00ULL, 0x1a1a1a001a1a1a00ULL,
    0xa6a6a600a6a6a600ULL, 0xe1e1e100e1e1e100ULL, 0x3939390039393900ULL,
    0xcacaca00cacaca00ULL, 0xd5d5d500d5d5d500ULL, 0x4747470047474700ULL,
    0x5d5d5d005d5d5d00ULL, 0x3d3d3d003d3d3d00ULL, 0xd9d9d900d9d9d900ULL,
    0x0101010001010100ULL, 0x5a5a5a005a5a5a00ULL, 0xd6d6d600d6d6d600ULL,
    0x5151510051515100ULL, 0x5656560056565600ULL, 0x6c6c6c006c6c6c00ULL,
    0x4d4d4d004d4d4d00ULL, 0x8b8b8b008b8b8b00ULL, 0x0d0d0d000d0d0d00ULL,
    0x9a9a9a009a9a9a00ULL, 0x6666660066666600ULL, 0xfbfbfb00fbfbfb00ULL,
    0xcccccc00cccccc00ULL, 0xb0b0b000b0b0b000ULL, 0x2d2d2d002d2d2d00ULL,
    0x7474740074747400ULL, 0x1212120012121200ULL, 0x2b2b2b002b2b2b00ULL,
    0x2020200020202000ULL, 0xf0f0f000f0f0f000ULL, 0xb1b1b100b1b1b100ULL,
    0x8484840084848400ULL, 0x9999990099999900ULL, 0xdfdfdf00dfdfdf00ULL,
    0x4c4c4c004c4c4c00ULL, 0xcbcbcb00cbcbcb00ULL, 0xc2c2c200c2c2c200ULL,
    0x3434340034343400ULL, 0x7e7e7e007e7e7e00ULL, 0x7676760076767600ULL,
    0x0505050005050500ULL, 0x6d6d6d006d6d6d00ULL, 0xb7b7b700b7b7b700ULL,
    0xa9a9a900a9a9a900ULL, 0x3131310031313100ULL, 0xd1d1d100d1d1d100ULL,
    0x1717170017171700ULL, 0x0404040004040400ULL, 0xd7d7d700d7d7d700ULL,
    0x1414140014141400ULL, 0x5858580058585800ULL, 0x3a3a3a003a3a3a00ULL,
    0x6161610061616100ULL, 0xdedede00dedede00ULL, 0x1b1b1b001b1b1b00ULL,
    0x1111110011111100ULL, 0x1c1c1c001c1c1c00ULL, 0x3232320032323200ULL,
    0x0f0f0f000f0f0f00ULL, 0x9c9c9c009c9c9c00ULL, 0x1616160016161600ULL,
    0x5353530053535300ULL, 0x1818180018181800ULL, 0xf2f2f200f2f2f200ULL,
    0x2222220022222200ULL, 0xfefefe00fefefe00ULL, 0x4444440044444400ULL,
    0xcfcfcf00cfcfcf00ULL, 0xb2b2b200b2b2b200ULL, 0xc3c3c300c3c3c300ULL,
    0xb5b5b500b5b5b500ULL, 0x7a7a7a007a7a7a00ULL, 0x9191910091919100ULL,
    0x2424240024242400ULL, 0x0808080008080800ULL, 0xe8e8e800e8e8e800ULL,
    0xa8a8a800a8a8a800ULL, 0x6060600060606000ULL, 0xfcfcfc00fcfcfc00ULL,
    0x6969690069696900ULL, 0x5050500050505000ULL, 0xaaaaaa00aaaaaa00ULL,
    0xd0d0d000d0d0d000ULL, 0xa0a0a000a0a0a000ULL, 0x7d7d7d007d7d7d00ULL,
    0xa1a1a100a1a1a100ULL, 0x8989890089898900ULL, 0x6262620062626200ULL,
    0x9797970097979700ULL, 0x5454540054545400ULL, 0x5b5b5b005b5b5b00ULL,
    0x1e1e1e001e1e1e00ULL, 0x9595950095959500ULL, 0xe0e0e000e0e0e000ULL,
    0xffffff00ffffff00ULL, 0x6464640064646400ULL, 0xd2d2d200d2d2d200ULL,
    0x1010100010101000ULL, 0xc4c4c400c4c4c400ULL, 0x0000000000000000ULL,
    0x4848480048484800ULL, 0xa3a3a300a3a3a300ULL, 0xf7f7f700f7f7f700ULL,
    0x7575750075757500ULL, 0xdbdbdb00dbdbdb00ULL, 0x8a8a8a008a8a8a00ULL,
    0x0303030003030300ULL, 0xe6e6e600e6e6e600ULL, 0xdadada00dadada00ULL,
    0x0909090009090900ULL, 0x3f3f3f003f3f3f00ULL, 0xdddddd00dddddd00ULL,
    0x9494940094949400ULL, 0x8787870087878700ULL, 0x5c5c5c005c5c5c00ULL,
    0x8383830083838300ULL, 0x0202020002020200ULL, 0xcdcdcd00cdcdcd00ULL,
    0x4a4a4a004a4a4a00ULL, 0x9090900090909000ULL, 0x3333330033333300ULL,
    0x7373730073737300ULL, 0x6767670067676700ULL, 0xf6f6f600f6f6f600ULL,
    0xf3f3f300f3f3f300ULL, 0x9d9d9d009d9d9d00ULL, 0x7f7f7f007f7f7f00ULL,
    0xbfbfbf00bfbfbf00ULL, 0xe2e2e200e2e2e200ULL, 0x5252520052525200ULL,
    0x9b9b9b009b9b9b00ULL, 0xd8d8d800d8d8d800ULL, 0x2626260026262600ULL,
    0xc8c8c800c8c8c800ULL, 0x3737370037373700ULL, 0xc6c6c600c6c6c600ULL,
    0x3b3b3b003b3b3b00ULL, 0x8181810081818100ULL, 0x9696960096969600ULL,
    0x6f6f6f006f6f6f00ULL, 0x4b4b4b004b4b4b00ULL, 0x1313130013131300ULL,
    0xbebebe00bebebe00ULL, 0x6363630063636300ULL, 0x2e2e2e002e2e2e00ULL,
    0xe9e9e900e9e9e900ULL, 0x7979790079797900ULL, 0xa7a7a700a7a7a700ULL,
    0x8c8c8c008c8c8c00ULL, 0x9f9f9f009f9f9f00ULL, 0x6e6e6e006e6e6e00ULL,
    0xbcbcbc00bcbcbc00ULL, 0x8e8e8e008e8e8e00ULL, 0x2929290029292900ULL,
    0xf5f5f500f5f5f500ULL, 0xf9f9f900f9f9f900ULL, 0xb6b6b600b6b6b600ULL,
    0x2f2f2f002f2f2f00ULL, 0xfdfdfd00fdfdfd00ULL, 0xb4b4b400b4b4b400ULL,
    0x5959590059595900ULL, 0x7878780078787800ULL, 0x9898980098989800ULL,
    0x0606060006060600ULL, 0x6a6a6a006a6a6a00ULL, 0xe7e7e700e7e7e700ULL,
    0x4646460046464600ULL, 0x7171710071717100ULL, 0xbababa00bababa00ULL,
    0xd4d4d400d4d4d400ULL, 0x2525250025252500ULL, 0xababab00ababab00ULL,
    0x4242420042424200ULL, 0x8888880088888800ULL, 0xa2a2a200a2a2a200ULL,
    0x8d8d8d008d8d8d00ULL, 0xfafafa00fafafa00ULL, 0x7272720072727200ULL,
    0x0707070007070700ULL, 0xb9b9b900b9b9b900ULL, 0x5555550055555500ULL,
    0xf8f8f800f8f8f800ULL, 0xeeeeee00eeeeee00ULL, 0xacacac00acacac00ULL,
    0x0a0a0a000a0a0a00ULL, 0x3636360036363600ULL, 0x4949490049494900ULL,
    0x2a2a2a002a2a2a00ULL, 0x6868680068686800ULL, 0x3c3c3c003c3c3c00ULL,
    0x3838380038383800ULL, 0xf1f1f100f1f1f100ULL, 0xa4a4a400a4a4a400ULL,
    0x4040400040404000ULL, 0x2828280028282800ULL, 0xd3d3d300d3d3d300ULL,
    0x7b7b7b007b7b7b00ULL, 0xbbbbbb00bbbbbb00ULL, 0xc9c9c900c9c9c900ULL,
    0x4343430043434300ULL, 0xc1c1c100c1c1c100ULL, 0x1515150015151500ULL,
    0xe3e3e300e3e3e300ULL, 0xadadad00adadad00ULL, 0xf4f4f400f4f4f400ULL,
    0x7777770077777700ULL, 0xc7c7c700c7c7c700ULL, 0x8080800080808000ULL,
    0x9e9e9e009e9e9e00ULL,
};
