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

#define KS_round(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(0, keyA, keyA_aux);\
	con=_mm_slli_epi32(con, 1);\
	}

#define KS_round_last(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(0, keyA, keyA_aux);\
	}

//#pragma intrinsic( _mm_lddqu_si128 )

void AES_KS_ENC_x1(const unsigned char* PT, unsigned char* CT, 
				   int bytes_length, unsigned char* KS,
				   unsigned char* first_key, int key_len){
	
    register __m128i keyA, con, mask, x2, keyA_aux, globAux;
	int i;
	int _con1[4]={1,1,1,1};
	int _con2[4]={0x1b,0x1b,0x1b,0x1b};
	int _mask[4]={0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d};
	int _con3[4]={0x0ffffffff, 0x0ffffffff, 0x07060504, 0x07060504};
	__m128i con3=_mm_loadu_si128((__m128i const*)_con3);
	
	for (i=0;i<bytes_length;i+=16){
		keyA = _mm_loadu_si128((__m128i const*)(first_key));	
		
		register __m128i block1 = _mm_loadu_si128((__m128i const*)(0*16+PT));	
		block1 = _mm_xor_si128(keyA, block1);
	
		con = _mm_loadu_si128((__m128i const*)_con1);	
		mask = _mm_loadu_si128((__m128i const*)_mask);	
		_mm_storeu_si128((__m128i *)(KS+0*16), keyA);
		KS_ENC_round(1)
		_mm_storeu_si128((__m128i *)(KS+1*16), keyA);
		KS_ENC_round(2)
		_mm_storeu_si128((__m128i *)(KS+2*16), keyA);
		KS_ENC_round(3)
		_mm_storeu_si128((__m128i *)(KS+3*16), keyA);
		KS_ENC_round(4)
		_mm_storeu_si128((__m128i *)(KS+4*16), keyA);
		KS_ENC_round(5)
		_mm_storeu_si128((__m128i *)(KS+5*16), keyA);
		KS_ENC_round(6)
		_mm_storeu_si128((__m128i *)(KS+6*16), keyA);
		KS_ENC_round(7)
		_mm_storeu_si128((__m128i *)(KS+7*16), keyA);
		KS_ENC_round(8)
		_mm_storeu_si128((__m128i *)(KS+8*16), keyA);

		con = _mm_loadu_si128((__m128i const*)_con2);			

		KS_ENC_round(9)
		_mm_storeu_si128((__m128i *)(KS+9*16), keyA);
		KS_ENC_round_last(10)
		_mm_storeu_si128((__m128i *)(KS+10*16), keyA);
		_mm_storeu_si128((__m128i *)(CT+0*16), block1);	
		
		first_key+=16;
		PT+=16;
		CT+=16;
	}	
}
void AES128_KS_ENC_x1_INIT_x4(const unsigned char* NONCE, unsigned char* CT, unsigned char* KS,
				   unsigned char* first_key){
	
    register __m128i keyA, con, mask, x2, keyA_aux, globAux;
	register __m128i one = _mm_set_epi32(0,0,0,1);
	register __m128i block2, block3, block4;
	int i;
	int _con1[4]={1,1,1,1};
	int _con2[4]={0x1b,0x1b,0x1b,0x1b};
	int _mask[4]={0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d};
	int _con3[4]={0x0ffffffff, 0x0ffffffff, 0x07060504, 0x07060504};
	__m128i con3=_mm_loadu_si128((__m128i const*)_con3);
	register __m128i block1 = _mm_set_epi32(((int*)NONCE)[2], ((int*)NONCE)[1], ((int*)NONCE)[0], 0);
	keyA = _mm_loadu_si128((__m128i const*)(first_key));	
	block2 = _mm_add_epi32(block1, one);
	block3 = _mm_add_epi32(block2, one);
	block4 = _mm_add_epi32(block3, one);
	block1 = _mm_xor_si128(keyA, block1);
	block2 = _mm_xor_si128(keyA, block2);
	block3 = _mm_xor_si128(keyA, block3);
	block4 = _mm_xor_si128(keyA, block4);
	con = _mm_loadu_si128((__m128i const*)_con1);	
	mask = _mm_loadu_si128((__m128i const*)_mask);	
	_mm_storeu_si128((__m128i *)(KS+0*16), keyA);
	KS_ENC_round(1)
	_mm_storeu_si128((__m128i *)(KS+1*16), keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	KS_ENC_round(2)
	_mm_storeu_si128((__m128i *)(KS+2*16), keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	KS_ENC_round(3)
	_mm_storeu_si128((__m128i *)(KS+3*16), keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	KS_ENC_round(4)
	_mm_storeu_si128((__m128i *)(KS+4*16), keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	KS_ENC_round(5)
	_mm_storeu_si128((__m128i *)(KS+5*16), keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	KS_ENC_round(6)
	_mm_storeu_si128((__m128i *)(KS+6*16), keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	KS_ENC_round(7)
	_mm_storeu_si128((__m128i *)(KS+7*16), keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	KS_ENC_round(8)
	_mm_storeu_si128((__m128i *)(KS+8*16), keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	con = _mm_loadu_si128((__m128i const*)_con2);			
	KS_ENC_round(9)
	_mm_storeu_si128((__m128i *)(KS+9*16), keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	KS_ENC_round_last(10)
	_mm_storeu_si128((__m128i *)(KS+10*16), keyA);
	block2 = _mm_aesenclast_si128(block2, keyA);
	block3 = _mm_aesenclast_si128(block3, keyA);
	block4 = _mm_aesenclast_si128(block4, keyA);
	_mm_storeu_si128((__m128i*)(CT+0*16), block1);	
	_mm_storeu_si128((__m128i*)(CT+1*16), block2);	
	_mm_storeu_si128((__m128i*)(CT+2*16), block3);	
	_mm_storeu_si128((__m128i*)(CT+3*16), block4);	
}

void AES_128_ENC_x4(const unsigned char* NONCE, unsigned char* CT, unsigned char* KS)
{
	
	register __m128i one = _mm_set_epi32(0,0,0,1);
	register __m128i keyA, block2, block3, block4;
	register __m128i block1 = _mm_set_epi32(((int*)NONCE)[2], ((int*)NONCE)[1], ((int*)NONCE)[0], 0);
	keyA = _mm_loadu_si128((__m128i const*)(KS));	
	block2 = _mm_add_epi32(block1, one);
	block3 = _mm_add_epi32(block2, one);
	block4 = _mm_add_epi32(block3, one);
	block1 = _mm_xor_si128(keyA, block1);
	block2 = _mm_xor_si128(keyA, block2);
	block3 = _mm_xor_si128(keyA, block3);
	block4 = _mm_xor_si128(keyA, block4);

	keyA = _mm_loadu_si128((__m128i *)(KS+1*16));
	block1 = _mm_aesenc_si128(block1, keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);

	keyA = _mm_loadu_si128((__m128i *)(KS+2*16));
	block1 = _mm_aesenc_si128(block1, keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);

	keyA = _mm_loadu_si128((__m128i *)(KS+3*16));
	block1 = _mm_aesenc_si128(block1, keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);

	keyA = _mm_loadu_si128((__m128i *)(KS+4*16));
	block1 = _mm_aesenc_si128(block1, keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);

	keyA = _mm_loadu_si128((__m128i *)(KS+5*16));
	block1 = _mm_aesenc_si128(block1, keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);

	keyA = _mm_loadu_si128((__m128i *)(KS+6*16));
	block1 = _mm_aesenc_si128(block1, keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	
	keyA = _mm_loadu_si128((__m128i *)(KS+7*16));
	block1 = _mm_aesenc_si128(block1, keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);

	keyA = _mm_loadu_si128((__m128i *)(KS+8*16));
	block1 = _mm_aesenc_si128(block1, keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);

	keyA = _mm_loadu_si128((__m128i *)(KS+9*16));
	block1 = _mm_aesenc_si128(block1, keyA);
	block2 = _mm_aesenc_si128(block2, keyA);
	block3 = _mm_aesenc_si128(block3, keyA);
	block4 = _mm_aesenc_si128(block4, keyA);
	
	keyA = _mm_loadu_si128((__m128i *)(KS+10*16));
	block1 = _mm_aesenclast_si128(block1, keyA);
	block2 = _mm_aesenclast_si128(block2, keyA);
	block3 = _mm_aesenclast_si128(block3, keyA);
	block4 = _mm_aesenclast_si128(block4, keyA);
	_mm_storeu_si128((__m128i*)(CT+0*16), block1);	
	_mm_storeu_si128((__m128i*)(CT+1*16), block2);	
	_mm_storeu_si128((__m128i*)(CT+2*16), block3);	
	_mm_storeu_si128((__m128i*)(CT+3*16), block4);	
}

void AES_KS_no_mem_ENC_x2(const unsigned char* PT, unsigned char* CT1, 
				   unsigned char* CT2, int bytes_length, unsigned char* KS,
				   unsigned char* first_key, int key_len){
    register __m128i keyA, con, mask, x2, keyA_aux, globAux;
	int i;
	int _con1[4]={1,1,1,1};
	int _con2[4]={0x1b,0x1b,0x1b,0x1b};
	int _mask[4]={0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d};
	int _con3[4]={0x0ffffffff, 0x0ffffffff, 0x07060504, 0x07060504};
	__m128i con3=_mm_loadu_si128((__m128i const*)_con3);
	
	for (i=0;i<bytes_length;i+=16){
		keyA = _mm_loadu_si128((__m128i const*)(first_key));	
		
		register __m128i block1 = _mm_loadu_si128((__m128i const*)(0*16+PT));	
		register __m128i block2 = _mm_loadu_si128((__m128i const*)(1*16+PT));	
		block1 = _mm_xor_si128(keyA, block1);
		block2 = _mm_xor_si128(keyA, block2);
	
		con = _mm_loadu_si128((__m128i const*)_con1);	
		mask = _mm_loadu_si128((__m128i const*)_mask);	
		
		KS_ENC_round(1)
		block2=_mm_aesenc_si128(block2, keyA);
		KS_ENC_round(2)
		block2=_mm_aesenc_si128(block2, keyA);
		KS_ENC_round(3)
		block2=_mm_aesenc_si128(block2, keyA);
		KS_ENC_round(4)
		block2=_mm_aesenc_si128(block2, keyA);
		KS_ENC_round(5)
		block2=_mm_aesenc_si128(block2, keyA);
		KS_ENC_round(6)
		block2=_mm_aesenc_si128(block2, keyA);
		KS_ENC_round(7)
		block2=_mm_aesenc_si128(block2, keyA);
		KS_ENC_round(8)
		block2=_mm_aesenc_si128(block2, keyA);

		con = _mm_loadu_si128((__m128i const*)_con2);			

		KS_ENC_round(9)
		block2=_mm_aesenc_si128(block2, keyA);
		KS_ENC_round_last(10)
		block2=_mm_aesenclast_si128(block2, keyA);
		_mm_storeu_si128((__m128i *)(CT1), block1);	
		_mm_storeu_si128((__m128i *)(CT2), block2);
		first_key+=16;
		PT+=16;
		CT1+=16;
		CT2+=16;
	}	
}

void ECB_ENC_block(unsigned char* PT, unsigned char* CT, unsigned char* KS)
{
	int i;
	__m128i block = _mm_loadu_si128((__m128i*)PT);
	block = _mm_xor_si128(block , ((__m128i*)KS)[0]);
	for (i=1;i<10;i++)
	{
		block = _mm_aesenc_si128(block , ((__m128i*)KS)[i]);
	}
	block = _mm_aesenclast_si128(block , ((__m128i*)KS)[10]);
	_mm_storeu_si128((__m128i *)(CT), block);	
}
__m128i AES_128_ASSIST (__m128i temp1, __m128i temp2)
{ 
    __m128i temp3;
	temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
	temp3 = _mm_slli_si128 (temp1, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp3 = _mm_slli_si128 (temp3, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp3 = _mm_slli_si128 (temp3, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp1 = _mm_xor_si128 (temp1, temp2);
	return temp1; 
}


void AES_KS(const unsigned char *key, unsigned char *KS)
{	
    register __m128i keyA, con, mask, x2, keyA_aux, globAux;
	int _con1[4]={1,1,1,1};
	int _con2[4]={0x1b,0x1b,0x1b,0x1b};
	int _mask[4]={0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d};
	int _con3[4]={0x0ffffffff, 0x0ffffffff, 0x07060504, 0x07060504};
	__m128i con3=_mm_loadu_si128((__m128i const*)_con3);
	keyA = _mm_loadu_si128((__m128i const*)(key));	
	con = _mm_loadu_si128((__m128i const*)_con1);	
	mask = _mm_loadu_si128((__m128i const*)_mask);	
	_mm_storeu_si128((__m128i *)(KS+0*16), keyA);
	KS_round(1)
	_mm_storeu_si128((__m128i *)(KS+1*16), keyA);
	KS_round(2)
	_mm_storeu_si128((__m128i *)(KS+2*16), keyA);
	KS_round(3)
	_mm_storeu_si128((__m128i *)(KS+3*16), keyA);
	KS_round(4)
	_mm_storeu_si128((__m128i *)(KS+4*16), keyA);
	KS_round(5)
	_mm_storeu_si128((__m128i *)(KS+5*16), keyA);
	KS_round(6)
	_mm_storeu_si128((__m128i *)(KS+6*16), keyA);
	KS_round(7)
	_mm_storeu_si128((__m128i *)(KS+7*16), keyA);
	KS_round(8)
	_mm_storeu_si128((__m128i *)(KS+8*16), keyA);
	con = _mm_loadu_si128((__m128i const*)_con2);			
	KS_round(9)
	_mm_storeu_si128((__m128i *)(KS+9*16), keyA);
	KS_round_last(10)
	_mm_storeu_si128((__m128i *)(KS+10*16), keyA);
}

