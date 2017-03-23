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
#include <stdlib.h>
#include <stdint.h>
#if !defined (ALIGN16)
#if defined (__GNUC__)
#  define ALIGN16  __attribute__  ( (aligned (16)))
# else
#  define ALIGN16 __declspec (align (16))
# endif
#endif
#if defined(__INTEL_COMPILER)
# include <ia32intrin.h> 
#elif defined(__GNUC__)
# include <emmintrin.h>
# include <smmintrin.h>
#endif

void ENC_MSG_x8(const unsigned char *PT,
                      unsigned char *CT,
                      const unsigned char *TAG,
                      const unsigned char *KS,
                      int length)
{
    __m128i or_mask, TWO,ctr_block, tmp, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, ONE;
    int i,j,remainder_loc;
	int has_semi = length%16;
    length/=16;
    ONE = _mm_setr_epi32(1,0,0,0);
	TWO = _mm_setr_epi32(2,0,0,0);
	ctr_block = _mm_setzero_si128();
	ctr_block = _mm_loadu_si128(((__m128i*)TAG));
	or_mask = _mm_setr_epi32(0,0,0,0x80000000);
	ctr_block = _mm_or_si128(ctr_block, or_mask);
	for (i=0; i< (length-length%8); i=i+8)
	{
		tmp = ctr_block;
		tmp1 = _mm_add_epi32(ctr_block, ONE);
		tmp2 = _mm_add_epi32(ctr_block, TWO);
		tmp3 = _mm_add_epi32(tmp2, ONE);
		tmp4 = _mm_add_epi32(tmp2, TWO);
		tmp5 = _mm_add_epi32(tmp4, ONE);
		tmp6 = _mm_add_epi32(tmp4, TWO);
		tmp7 = _mm_add_epi32(tmp6, ONE);
		ctr_block = _mm_add_epi32(tmp6, TWO);
		tmp = _mm_xor_si128(tmp, ((__m128i*)KS)[0]);
		tmp1 = _mm_xor_si128(tmp1, ((__m128i*)KS)[0]);
		tmp2 = _mm_xor_si128(tmp2, ((__m128i*)KS)[0]);
		tmp3 = _mm_xor_si128(tmp3, ((__m128i*)KS)[0]);
		tmp4 = _mm_xor_si128(tmp4, ((__m128i*)KS)[0]);
		tmp5 = _mm_xor_si128(tmp5, ((__m128i*)KS)[0]);
		tmp6 = _mm_xor_si128(tmp6, ((__m128i*)KS)[0]);
		tmp7 = _mm_xor_si128(tmp7, ((__m128i*)KS)[0]);
			for(j=1; j <10; j++) {
				tmp = _mm_aesenc_si128 (tmp, ((__m128i*)KS)[j]);
				tmp1 = _mm_aesenc_si128 (tmp1, ((__m128i*)KS)[j]);
				tmp2 = _mm_aesenc_si128 (tmp2, ((__m128i*)KS)[j]);
				tmp3 = _mm_aesenc_si128 (tmp3, ((__m128i*)KS)[j]);
				tmp4 = _mm_aesenc_si128 (tmp4, ((__m128i*)KS)[j]);
				tmp5 = _mm_aesenc_si128 (tmp5, ((__m128i*)KS)[j]);
				tmp6 = _mm_aesenc_si128 (tmp6, ((__m128i*)KS)[j]);
				tmp7 = _mm_aesenc_si128 (tmp7, ((__m128i*)KS)[j]);
				};
			tmp = _mm_aesenclast_si128 (tmp, ((__m128i*)KS)[j]);
			tmp1 = _mm_aesenclast_si128 (tmp1, ((__m128i*)KS)[j]);
			tmp2 = _mm_aesenclast_si128 (tmp2, ((__m128i*)KS)[j]);
			tmp3 = _mm_aesenclast_si128 (tmp3, ((__m128i*)KS)[j]);
			tmp4 = _mm_aesenclast_si128 (tmp4, ((__m128i*)KS)[j]);
			tmp5 = _mm_aesenclast_si128 (tmp5, ((__m128i*)KS)[j]);
			tmp6 = _mm_aesenclast_si128 (tmp6, ((__m128i*)KS)[j]);
			tmp7 = _mm_aesenclast_si128 (tmp7, ((__m128i*)KS)[j]);
			tmp = _mm_xor_si128(tmp,_mm_loadu_si128(&((__m128i*)PT)[i]));
			tmp1 = _mm_xor_si128(tmp1,_mm_loadu_si128(&((__m128i*)PT)[i+1]));
			tmp2 = _mm_xor_si128(tmp2,_mm_loadu_si128(&((__m128i*)PT)[i+2]));
			tmp3 = _mm_xor_si128(tmp3,_mm_loadu_si128(&((__m128i*)PT)[i+3]));
			tmp4 = _mm_xor_si128(tmp4,_mm_loadu_si128(&((__m128i*)PT)[i+4]));
			tmp5 = _mm_xor_si128(tmp5,_mm_loadu_si128(&((__m128i*)PT)[i+5]));
			tmp6 = _mm_xor_si128(tmp6,_mm_loadu_si128(&((__m128i*)PT)[i+6]));
			tmp7 = _mm_xor_si128(tmp7,_mm_loadu_si128(&((__m128i*)PT)[i+7]));
			_mm_storeu_si128(&((__m128i*)CT)[i],tmp);
			_mm_storeu_si128(&((__m128i*)CT)[i+1],tmp1);
			_mm_storeu_si128(&((__m128i*)CT)[i+2],tmp2);
			_mm_storeu_si128(&((__m128i*)CT)[i+3],tmp3);
			_mm_storeu_si128(&((__m128i*)CT)[i+4],tmp4);
			_mm_storeu_si128(&((__m128i*)CT)[i+5],tmp5);
			_mm_storeu_si128(&((__m128i*)CT)[i+6],tmp6);
			_mm_storeu_si128(&((__m128i*)CT)[i+7],tmp7);
		}
	// The remainder_loc is used to remember the location of our block handled 
	remainder_loc = length-length%8;
    for(i=0; i < (length%8); i++)
	{
		tmp = ctr_block;
        ctr_block = _mm_add_epi32(ctr_block, ONE);
        tmp = _mm_xor_si128(tmp, ((__m128i*)KS)[0]);

            for(j=1; j <10; j++) {
                tmp = _mm_aesenc_si128 (tmp, ((__m128i*)KS)[j]);
                };
            tmp = _mm_aesenclast_si128 (tmp, ((__m128i*)KS)[j]);
            tmp = _mm_xor_si128(tmp,_mm_loadu_si128(&((__m128i*)PT)[remainder_loc+i]));
            _mm_storeu_si128 (&((__m128i*)CT)[remainder_loc+i],tmp);
    }
	if (has_semi!=0)
	{
		uint8_t BLK[16] = {0};
		memcpy(BLK, PT+length*16, has_semi);
		tmp = ctr_block;
        ctr_block = _mm_add_epi32(ctr_block, ONE);
        tmp = _mm_xor_si128(tmp, ((__m128i*)KS)[0]);

            for(j=1; j <10; j++) {
                tmp = _mm_aesenc_si128 (tmp, ((__m128i*)KS)[j]);
                };
            tmp = _mm_aesenclast_si128 (tmp, ((__m128i*)KS)[j]);
            *(__m128i*)BLK = _mm_xor_si128(tmp,*(__m128i*)BLK);
			memset(BLK+has_semi, 0, 16-has_semi);
			memcpy(CT+length*16, BLK, has_semi);
    }
}
