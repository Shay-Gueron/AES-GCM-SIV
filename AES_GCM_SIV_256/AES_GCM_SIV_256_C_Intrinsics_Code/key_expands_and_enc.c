/*
###############################################################################
# AES-GCM-SIV developers and authors:                                         #
#                                                                             #
# Shay Gueron,    University of Haifa, Israel and                             #
#                 Intel Corporation, Israel Development Center, Haifa, Israel #
# Adam Langley,   Google                                                      #
# Yehuda Lindell, Bar Ilan University                                         #
###############################################################################
#                                                                             #
# References:                                                                 #
#                                                                             #
# [1] S. Gueron, Y. Lindell, GCM-SIV: Full Nonce Misuse-Resistant             #
# Authenticated Encryption at Under One Cycle per Byte,                       #
# 22nd ACM Conference on Computer and Communications Security,                #
# 22nd ACM CCS: pages 109-119, 2015.                                          #
# [2] S. Gueron, A. Langley, Y. Lindell, AES-GCM-SIV: Nonce Misuse-Resistant  #
# Authenticated Encryption.                                                   #
# https://tools.ietf.org/html/draft-gueron-gcmsiv-02#                         #
###############################################################################
#                                                                             #
###############################################################################
#                                                                             #
# Copyright (c) 2016, Shay Gueron                                             #
#                                                                             #
#                                                                             #
# Permission to use this code for AES-GCM-SIV is granted.                     #
#                                                                             #
# Redistribution and use in source and binary forms, with or without          #
# modification, are permitted provided that the following conditions are      #
# met:                                                                        #
#                                                                             #
# * Redistributions of source code must retain the above copyright notice,    #
#   this list of conditions and the following disclaimer.                     #
#                                                                             #
# * Redistributions in binary form must reproduce the above copyright         #
#   notice, this list of conditions and the following disclaimer in the       #
#   documentation and/or other materials provided with the distribution.      #
#                                                                             #
# * The names of the contributors may not be used to endorse or promote       #
# products derived from this software without specific prior written          #
# permission.                                                                 #
#                                                                             #
###############################################################################
#                                                                             #
###############################################################################
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY                  #
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE           #
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR          #
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR              #
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,       #
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,         #
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR          #
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF      #
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING        #
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS          #
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                #
###############################################################################
*/
#include <wmmintrin.h>
#include <stdint.h>

#if defined(__INTEL_COMPILER)
# include <ia32intrin.h> 
#elif defined(__GNUC__)
# include <emmintrin.h>
# include <smmintrin.h>
#endif


#if !defined (ALIGN16)
#if defined (__GNUC__)
#  define ALIGN16  __attribute__  ( (aligned (16)))
# else
#  define ALIGN16 __declspec (align (16))
# endif
#endif


#define KS_BLOCK(t, reg, reg2) {globAux=_mm_slli_epi64(reg, 32);\
								reg=_mm_xor_si128(globAux, reg);\
								globAux=_mm_shuffle_epi8(reg, con3);\
								reg=_mm_xor_si128(globAux, reg);\
								reg=_mm_xor_si128(reg2, reg);\
								}

#define KS_ENC_round(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(0, keyA, keyA_aux);\
	con=_mm_slli_epi32(con, 1);\
	block1=_mm_aesenc_si128(block1, keyA); \
	}

#define KS_ENC_round_last(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(0, keyA, keyA_aux);\
	block1=_mm_aesenclast_si128(block1, keyA); \
	}



//#pragma intrinsic( _mm_lddqu_si128 )

void AES256_KS_ENC_x1(const unsigned char* PT, unsigned char* CT, 
				   unsigned char* KS, unsigned char* key){
    register __m128i xmm1, xmm2, xmm3, xmm4, con3, xmm14, b1, mask, con1;
	int i=0;
	__m128i* Key_Schedule = (__m128i*)KS;
	mask = _mm_setr_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
	con1 = _mm_setr_epi32(1,1,1,1);
	con3 = _mm_setr_epi8(-1,-1,-1,-1,-1,-1,-1,-1,4,5,6,7,4,5,6,7);
	xmm4 = _mm_setzero_si128();
	xmm14 = _mm_setzero_si128();
	xmm1 = _mm_loadu_si128((__m128i*)key);
	xmm3 = _mm_loadu_si128(&(((__m128i*)key)[1]));
	_mm_storeu_si128(&Key_Schedule[0], xmm1);
	b1 = _mm_loadu_si128((__m128i*)PT);
	b1 = _mm_xor_si128(b1, xmm1);
	b1 = _mm_aesenc_si128(b1, xmm3);
	_mm_storeu_si128(&Key_Schedule[1], xmm3);
	for (i=0; i<6; i++)
	{
	    xmm2 = _mm_shuffle_epi8(xmm3, mask);
		xmm2 = _mm_aesenclast_si128(xmm2, con1);
		con1 = _mm_slli_epi32(con1, 1);
		xmm4 = _mm_slli_epi64 (xmm1, 32);
		xmm1 = _mm_xor_si128(xmm1, xmm4);
		xmm4 = _mm_shuffle_epi8(xmm1, con3);
		xmm1 = _mm_xor_si128(xmm1, xmm4);
		xmm1 = _mm_xor_si128(xmm1, xmm2);
		_mm_storeu_si128(&Key_Schedule[(i+1)*2], xmm1);
		b1 = _mm_aesenc_si128(b1, xmm1);
		
		xmm2 = _mm_shuffle_epi32(xmm1, 0xff);
		xmm2 = _mm_aesenclast_si128(xmm2, xmm14);
		xmm4 = _mm_slli_epi64(xmm3, 32);
		xmm3 = _mm_xor_si128(xmm4, xmm3);
		xmm4 = _mm_shuffle_epi8(xmm3, con3);
		xmm3 = _mm_xor_si128(xmm4, xmm3);
		xmm3 = _mm_xor_si128(xmm2, xmm3);
		_mm_storeu_si128(&Key_Schedule[(i+1)*2+1], xmm3);
		b1 = _mm_aesenc_si128(b1, xmm3);
		
	}
	xmm2 = _mm_shuffle_epi8(xmm3, mask);
	xmm2 = _mm_aesenclast_si128(xmm2, con1);
	xmm4 = _mm_slli_epi64 (xmm1, 32);
	xmm1 = _mm_xor_si128(xmm1, xmm4);
	xmm4 = _mm_shuffle_epi8(xmm1, con3);
	xmm1 = _mm_xor_si128(xmm1, xmm4);
	xmm1 = _mm_xor_si128(xmm1, xmm2);
	_mm_storeu_si128(&Key_Schedule[14], xmm1);
	b1 = _mm_aesenclast_si128(b1, xmm1);
	_mm_storeu_si128((__m128i*)CT, b1);	
}

void AES256_KS_ENC_x1_INIT_x6(const unsigned char* NONCE, unsigned char* CT, 
				   unsigned char* KS, unsigned char* key){
    register __m128i xmm1, xmm2, xmm3, xmm4, con3, xmm14, b1, mask, con1;
	int i=0;
	register __m128i one = _mm_set_epi32(0,0,0,1);
	register __m128i b2, b3, b4,b5,b6;
	__m128i* Key_Schedule = (__m128i*)KS;
	b1 = _mm_set_epi32(((int*)NONCE)[2], ((int*)NONCE)[1], ((int*)NONCE)[0], 0);
	b2 = _mm_add_epi32(b1, one);
	b3 = _mm_add_epi32(b2, one);
	b4 = _mm_add_epi32(b3, one);
	b5 = _mm_add_epi32(b4, one);
	b6 = _mm_add_epi32(b5, one);
	mask = _mm_setr_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
	con1 = _mm_setr_epi32(1,1,1,1);
	con3 = _mm_setr_epi8(-1,-1,-1,-1,-1,-1,-1,-1,4,5,6,7,4,5,6,7);
	xmm4 = _mm_setzero_si128();
	xmm14 = _mm_setzero_si128();
	xmm1 = _mm_loadu_si128((__m128i*)key);
	xmm3 = _mm_loadu_si128(&(((__m128i*)key)[1]));
	_mm_storeu_si128(&Key_Schedule[0], xmm1);
	b1 = _mm_xor_si128(b1, xmm1);
	b2 = _mm_xor_si128(b2, xmm1);
	b3 = _mm_xor_si128(b3, xmm1);
	b4 = _mm_xor_si128(b4, xmm1);
	b5 = _mm_xor_si128(b5, xmm1);
	b6 = _mm_xor_si128(b6, xmm1);
	b1 = _mm_aesenc_si128(b1, xmm3);
	b2 = _mm_aesenc_si128(b2, xmm3);
	b3 = _mm_aesenc_si128(b3, xmm3);
	b4 = _mm_aesenc_si128(b4, xmm3);
	b5 = _mm_aesenc_si128(b5, xmm3);
	b6 = _mm_aesenc_si128(b6, xmm3);
	_mm_storeu_si128(&Key_Schedule[1], xmm3);
	for (i=0; i<6; i++)
	{
	    xmm2 = _mm_shuffle_epi8(xmm3, mask);
		xmm2 = _mm_aesenclast_si128(xmm2, con1);
		con1 = _mm_slli_epi32(con1, 1);
		xmm4 = _mm_slli_epi64 (xmm1, 32);
		xmm1 = _mm_xor_si128(xmm1, xmm4);
		xmm4 = _mm_shuffle_epi8(xmm1, con3);
		xmm1 = _mm_xor_si128(xmm1, xmm4);
		xmm1 = _mm_xor_si128(xmm1, xmm2);
		_mm_storeu_si128(&Key_Schedule[(i+1)*2], xmm1);
		b1 = _mm_aesenc_si128(b1, xmm1);
		b2 = _mm_aesenc_si128(b2, xmm1);
		b3 = _mm_aesenc_si128(b3, xmm1);
		b4 = _mm_aesenc_si128(b4, xmm1);
		b5 = _mm_aesenc_si128(b5, xmm1);
		b6 = _mm_aesenc_si128(b6, xmm1);
		xmm2 = _mm_shuffle_epi32(xmm1, 0xff);
		xmm2 = _mm_aesenclast_si128(xmm2, xmm14);
		xmm4 = _mm_slli_epi64(xmm3, 32);
		xmm3 = _mm_xor_si128(xmm4, xmm3);
		xmm4 = _mm_shuffle_epi8(xmm3, con3);
		xmm3 = _mm_xor_si128(xmm4, xmm3);
		xmm3 = _mm_xor_si128(xmm2, xmm3);
		_mm_storeu_si128(&Key_Schedule[(i+1)*2+1], xmm3);
		b1 = _mm_aesenc_si128(b1, xmm3);
		b2 = _mm_aesenc_si128(b2, xmm3);
		b3 = _mm_aesenc_si128(b3, xmm3);
		b4 = _mm_aesenc_si128(b4, xmm3);
		b5 = _mm_aesenc_si128(b5, xmm3);
		b6 = _mm_aesenc_si128(b6, xmm3);
	}
	xmm2 = _mm_shuffle_epi8(xmm3, mask);
	xmm2 = _mm_aesenclast_si128(xmm2, con1);
	xmm4 = _mm_slli_epi64 (xmm1, 32);
	xmm1 = _mm_xor_si128(xmm1, xmm4);
	xmm4 = _mm_shuffle_epi8(xmm1, con3);
	xmm1 = _mm_xor_si128(xmm1, xmm4);
	xmm1 = _mm_xor_si128(xmm1, xmm2);
	_mm_storeu_si128(&Key_Schedule[14], xmm1);
	b1 = _mm_aesenclast_si128(b1, xmm1);
	b2 = _mm_aesenclast_si128(b2, xmm1);
	b3 = _mm_aesenclast_si128(b3, xmm1);
	b4 = _mm_aesenclast_si128(b4, xmm1);
	b5 = _mm_aesenclast_si128(b5, xmm1);
	b6 = _mm_aesenclast_si128(b6, xmm1);
	_mm_storeu_si128((__m128i*)(CT+0*16), b1);
	_mm_storeu_si128((__m128i*)(CT+1*16), b2);
	_mm_storeu_si128((__m128i*)(CT+2*16), b3);
	_mm_storeu_si128((__m128i*)(CT+3*16), b4);
	_mm_storeu_si128((__m128i*)(CT+4*16), b5);
	_mm_storeu_si128((__m128i*)(CT+5*16), b6);
}


void AES_256_ENC_x6(const unsigned char* NONCE, unsigned char* CT, 
				   unsigned char* KS){
    register __m128i xmm1, xmm3, b1;
	int i=0;
	register __m128i one = _mm_set_epi32(0,0,0,1);
	register __m128i b2, b3, b4,b5,b6;
	b1 = _mm_set_epi32(((int*)NONCE)[2], ((int*)NONCE)[1], ((int*)NONCE)[0], 0);
	b2 = _mm_add_epi32(b1, one);
	b3 = _mm_add_epi32(b2, one);
	b4 = _mm_add_epi32(b3, one);
	b5 = _mm_add_epi32(b4, one);
	b6 = _mm_add_epi32(b5, one);
	xmm1 = _mm_loadu_si128((__m128i*)KS);
	xmm3 = _mm_loadu_si128((__m128i*)(KS+16*1));
	b1 = _mm_xor_si128(b1, xmm1);
	b2 = _mm_xor_si128(b2, xmm1);
	b3 = _mm_xor_si128(b3, xmm1);
	b4 = _mm_xor_si128(b4, xmm1);
	b5 = _mm_xor_si128(b5, xmm1);
	b6 = _mm_xor_si128(b6, xmm1);
	b1 = _mm_aesenc_si128(b1, xmm3);
	b2 = _mm_aesenc_si128(b2, xmm3);
	b3 = _mm_aesenc_si128(b3, xmm3);
	b4 = _mm_aesenc_si128(b4, xmm3);
	b5 = _mm_aesenc_si128(b5, xmm3);
	b6 = _mm_aesenc_si128(b6, xmm3);
	for (i=1; i<=6; i++)
	{
		xmm1 = _mm_loadu_si128((__m128i*)(KS+2*16*i));
		xmm3 = _mm_loadu_si128((__m128i*)(KS+2*16*i+16));
		b1 = _mm_aesenc_si128(b1, xmm1);
		b2 = _mm_aesenc_si128(b2, xmm1);
		b3 = _mm_aesenc_si128(b3, xmm1);
		b4 = _mm_aesenc_si128(b4, xmm1);
		b5 = _mm_aesenc_si128(b5, xmm1);
		b6 = _mm_aesenc_si128(b6, xmm1);
		b1 = _mm_aesenc_si128(b1, xmm3);
		b2 = _mm_aesenc_si128(b2, xmm3);
		b3 = _mm_aesenc_si128(b3, xmm3);
		b4 = _mm_aesenc_si128(b4, xmm3);
		b5 = _mm_aesenc_si128(b5, xmm3);
		b6 = _mm_aesenc_si128(b6, xmm3);
	}
	xmm1 = _mm_loadu_si128((__m128i*)(KS+16*14));
	b1 = _mm_aesenclast_si128(b1, xmm1);
	b2 = _mm_aesenclast_si128(b2, xmm1);
	b3 = _mm_aesenclast_si128(b3, xmm1);
	b4 = _mm_aesenclast_si128(b4, xmm1);
	b5 = _mm_aesenclast_si128(b5, xmm1);
	b6 = _mm_aesenclast_si128(b6, xmm1);
	_mm_storeu_si128((__m128i*)(CT+0*16), b1);
	_mm_storeu_si128((__m128i*)(CT+1*16), b2);
	_mm_storeu_si128((__m128i*)(CT+2*16), b3);
	_mm_storeu_si128((__m128i*)(CT+3*16), b4);
	_mm_storeu_si128((__m128i*)(CT+4*16), b5);
	_mm_storeu_si128((__m128i*)(CT+5*16), b6);
}

void AES256_KS_no_mem_ENC_x2(const unsigned char* PT, unsigned char* CT, 
				   unsigned char* KS, unsigned char* key){
    register __m128i xmm3, xmm2, b1, xmm4, b2, xmm1, con1, xmm14, mask, con3;
	int i=0;
	
	mask = _mm_setr_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
	con1 = _mm_setr_epi32(1,1,1,1);
	con3 = _mm_setr_epi8(-1,-1,-1,-1,-1,-1,-1,-1,4,5,6,7,4,5,6,7);
	xmm4 = _mm_setzero_si128();
	xmm14 = _mm_setzero_si128();
	b1 = _mm_loadu_si128((__m128i*)PT);
	b2 = _mm_loadu_si128(&(((__m128i*)PT)[1]));
	xmm1 = _mm_loadu_si128((__m128i*)key);
	xmm3 = _mm_loadu_si128(&(((__m128i*)key)[1]));
	//_mm_storeu_si128(&Key_Schedule[0], xmm1);
	b1 = _mm_xor_si128(b1, xmm1);
	b2 = _mm_xor_si128(b2, xmm1);
	b1 = _mm_aesenc_si128(b1, xmm3);
	b2 = _mm_aesenc_si128(b2, xmm3);
	//_mm_storeu_si128(&Key_Schedule[1], xmm3);
	for (i=0; i<6; i++)
	{
	    xmm2 = _mm_shuffle_epi8(xmm3, mask);
		xmm2 = _mm_aesenclast_si128(xmm2, con1);
		con1 = _mm_slli_epi32(con1, 1);
		xmm4 = _mm_slli_epi64 (xmm1, 32);
		xmm1 = _mm_xor_si128(xmm1, xmm4);
		xmm4 = _mm_shuffle_epi8(xmm1, con3);
		xmm1 = _mm_xor_si128(xmm1, xmm4);
		xmm1 = _mm_xor_si128(xmm1, xmm2);
		//_mm_storeu_si128(&Key_Schedule[(i+1)*2], xmm1);
		b1 = _mm_aesenc_si128(b1, xmm1);
		b2 = _mm_aesenc_si128(b2, xmm1);
		xmm2 = _mm_shuffle_epi32(xmm1, 0xff);
		xmm2 = _mm_aesenclast_si128(xmm2, xmm14);
		xmm4 = _mm_slli_epi64(xmm3, 32);
		xmm3 = _mm_xor_si128(xmm4, xmm3);
		xmm4 = _mm_shuffle_epi8(xmm3, con3);
		xmm3 = _mm_xor_si128(xmm4, xmm3);
		xmm3 = _mm_xor_si128(xmm2, xmm3);
		//_mm_storeu_si128(&Key_Schedule[(i+1)*2+1], xmm3);
		b1 = _mm_aesenc_si128(b1, xmm3);
		b2 = _mm_aesenc_si128(b2, xmm3);
	}
	xmm2 = _mm_shuffle_epi8(xmm3, mask);
	xmm2 = _mm_aesenclast_si128(xmm2, con1);
	xmm4 = _mm_slli_epi64 (xmm1, 32);
	xmm1 = _mm_xor_si128(xmm1, xmm4);
	xmm4 = _mm_shuffle_epi8(xmm1, con3);
	xmm1 = _mm_xor_si128(xmm1, xmm4);
	xmm1 = _mm_xor_si128(xmm1, xmm2);
	//_mm_storeu_si128(&Key_Schedule[14], xmm1);
	b1 = _mm_aesenclast_si128(b1, xmm1);
	b2 = _mm_aesenclast_si128(b2, xmm1);
	_mm_storeu_si128((__m128i*)CT, b1);
	_mm_storeu_si128(&(((__m128i*)CT)[1]), b2);
}



void AES_256_KS (const unsigned char *key, unsigned char *ks) 
{ 
    __m128i xmm1, xmm2, xmm3, xmm14, xmm4;
    __m128i *Key_Schedule = (__m128i*)ks;
	__m128i con1, con3, mask;
	int i =0;
	mask = _mm_setr_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
	con1 = _mm_setr_epi32(1,1,1,1);
	con3 = _mm_setr_epi8(-1,-1,-1,-1,-1,-1,-1,-1,4,5,6,7,4,5,6,7);
	xmm4 = _mm_setzero_si128();
	xmm14 = _mm_setzero_si128();
	xmm1 = _mm_loadu_si128((__m128i*)key);
	xmm3 = _mm_loadu_si128(&(((__m128i*)key)[1]));
	_mm_storeu_si128(&Key_Schedule[0], xmm1);	
	_mm_storeu_si128(&Key_Schedule[1], xmm3);
	for (i=0; i<6; i++)
	{
	    xmm2 = _mm_shuffle_epi8(xmm3, mask);
		xmm2 = _mm_aesenclast_si128(xmm2, con1);
		con1 = _mm_slli_epi32(con1, 1);
		xmm4 = _mm_slli_epi64 (xmm1, 32);
		xmm1 = _mm_xor_si128(xmm1, xmm4);
		xmm4 = _mm_shuffle_epi8(xmm1, con3);
		xmm1 = _mm_xor_si128(xmm1, xmm4);
		xmm1 = _mm_xor_si128(xmm1, xmm2);
		_mm_storeu_si128(&Key_Schedule[(i+1)*2], xmm1);
		xmm2 = _mm_shuffle_epi32(xmm1, 0xff);
		xmm2 = _mm_aesenclast_si128(xmm2, xmm14);
		xmm4 = _mm_slli_epi64(xmm3, 32);
		xmm3 = _mm_xor_si128(xmm4, xmm3);
		xmm4 = _mm_shuffle_epi8(xmm3, con3);
		xmm3 = _mm_xor_si128(xmm4, xmm3);
		xmm3 = _mm_xor_si128(xmm2, xmm3);
		_mm_storeu_si128(&Key_Schedule[(i+1)*2+1], xmm3);
	}
	xmm2 = _mm_shuffle_epi8(xmm3, mask);
	xmm2 = _mm_aesenclast_si128(xmm2, con1);
	xmm4 = _mm_slli_epi64 (xmm1, 32);
	xmm1 = _mm_xor_si128(xmm1, xmm4);
	xmm4 = _mm_shuffle_epi8(xmm1, con3);
	xmm1 = _mm_xor_si128(xmm1, xmm4);
	xmm1 = _mm_xor_si128(xmm1, xmm2);
	_mm_storeu_si128(&Key_Schedule[14], xmm1);
}

void ECB_ENC_block(unsigned char* PT, unsigned char* CT, unsigned char* KS)
{
	int i;
	__m128i block = _mm_loadu_si128((__m128i*)PT);
	block = _mm_xor_si128(block , ((__m128i*)KS)[0]);
	for (i=1;i<14;i++)
	{
		block = _mm_aesenc_si128(block , ((__m128i*)KS)[i]);
	}
	block = _mm_aesenclast_si128(block , ((__m128i*)KS)[14]);
	_mm_storeu_si128((__m128i *)(CT), block);	
}
