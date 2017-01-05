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

#include <emmintrin.h>
#include <wmmintrin.h>
#include <tmmintrin.h>
#include <stdint.h>



#define SCHOOLBOOK_AAD(reg, htbl_reg){\
	TMP3 = _mm_clmulepi64_si128(reg, htbl_reg, 0x01);\
	TMP2 = _mm_xor_si128(TMP2, TMP3); \
	TMP3 = _mm_clmulepi64_si128(reg, htbl_reg, 0x00);\
	TMP0 = _mm_xor_si128(TMP0, TMP3); \
	TMP3 = _mm_clmulepi64_si128(reg, htbl_reg, 0x11);\
	TMP1 = _mm_xor_si128(TMP1, TMP3); \
	TMP3 = _mm_clmulepi64_si128(reg, htbl_reg, 0x10);\
	TMP2 = _mm_xor_si128(TMP2, TMP3); \
}

void INIT_Htable(uint8_t Htbl[16*8], uint8_t *H)
{
	int i;
	__m128i T, TMP0, TMP1, TMP2, TMP3, TMP4, POLY;
	POLY = _mm_setr_epi32(0x1,0,0,0xc2000000);
	T = _mm_loadu_si128(((__m128i*)H));
	TMP0 = T;
	_mm_storeu_si128(&((__m128i*)Htbl)[0], T);
	for (i=1; i<8; i++)
	{
		TMP1 = _mm_clmulepi64_si128(T, TMP0, 0x00);
		TMP4 = _mm_clmulepi64_si128(T, TMP0, 0x11);
		TMP2 = _mm_clmulepi64_si128(T, TMP0, 0x10);
		TMP3 = _mm_clmulepi64_si128(T, TMP0, 0x01);
		TMP2 = _mm_xor_si128(TMP2, TMP3);
		TMP3 = _mm_slli_si128(TMP2, 8);
		TMP2 = _mm_srli_si128(TMP2, 8);
		TMP1 = _mm_xor_si128(TMP3, TMP1);
		TMP4 = _mm_xor_si128(TMP4, TMP2);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP3, TMP2);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP3, TMP2);
		T = _mm_xor_si128(TMP4, TMP1);
		_mm_storeu_si128(&((__m128i*)Htbl)[i], T);
	}
}
void INIT_Htable_6(uint8_t Htbl[16*6], uint8_t *H)
{
	int i;
	__m128i T, TMP0, TMP1, TMP2, TMP3, TMP4, POLY;
	POLY = _mm_setr_epi32(0x1,0,0,0xc2000000);
	T = _mm_loadu_si128(((__m128i*)H));
	TMP0 = T;
	_mm_storeu_si128(&((__m128i*)Htbl)[0], T);
	for (i=1; i<6; i++)
	{
		TMP1 = _mm_clmulepi64_si128(T, TMP0, 0x00);
		TMP4 = _mm_clmulepi64_si128(T, TMP0, 0x11);
		TMP2 = _mm_clmulepi64_si128(T, TMP0, 0x10);
		TMP3 = _mm_clmulepi64_si128(T, TMP0, 0x01);
		TMP2 = _mm_xor_si128(TMP2, TMP3);
		TMP3 = _mm_slli_si128(TMP2, 8);
		TMP2 = _mm_srli_si128(TMP2, 8);
		TMP1 = _mm_xor_si128(TMP3, TMP1);
		TMP4 = _mm_xor_si128(TMP4, TMP2);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP3, TMP2);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP3, TMP2);
		T = _mm_xor_si128(TMP4, TMP1);
		_mm_storeu_si128(&((__m128i*)Htbl)[i], T);
	}
}
void Polyval_Horner(unsigned char* TAG,
					unsigned char* pH,
					unsigned char* inp,
					int length)
{
	__m128i TMP0, TMP1, TMP2, TMP3, TMP4, T, POLY, H;
	int i=0;
	if (length==0)
		return;
	int has_semi = length%16;
	uint8_t B[16]={0};
	length /=16;
	
	H = _mm_loadu_si128(((__m128i*)pH));
	T = _mm_loadu_si128(((__m128i*)TAG));
	POLY = _mm_setr_epi32(0x1,0,0,0xc2000000);
	for (i=0; i< length; i++)
	{
		T = _mm_xor_si128(T, _mm_loadu_si128(&((__m128i*)inp)[i]));
		TMP1 = _mm_clmulepi64_si128(T, H, 0x00);
		TMP4 = _mm_clmulepi64_si128(T, H, 0x11);
		TMP2 = _mm_clmulepi64_si128(T, H, 0x10);
		TMP3 = _mm_clmulepi64_si128(T, H, 0x01);
		TMP2 = _mm_xor_si128(TMP2, TMP3);
		TMP3 = _mm_slli_si128(TMP2, 8);
		TMP2 = _mm_srli_si128(TMP2, 8);
		TMP1 = _mm_xor_si128(TMP3, TMP1);
		TMP4 = _mm_xor_si128(TMP4, TMP2);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP3, TMP2);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP3, TMP2);
		T = _mm_xor_si128(TMP4, TMP1);
	}
	if (has_semi!=0)
	{
		memcpy(B, inp+length*16, has_semi);
		T = _mm_xor_si128(T, _mm_loadu_si128((__m128i*)B));
		TMP1 = _mm_clmulepi64_si128(T, H, 0x00);
		TMP4 = _mm_clmulepi64_si128(T, H, 0x11);
		TMP2 = _mm_clmulepi64_si128(T, H, 0x10);
		TMP3 = _mm_clmulepi64_si128(T, H, 0x01);
		TMP2 = _mm_xor_si128(TMP2, TMP3);
		TMP3 = _mm_slli_si128(TMP2, 8);
		TMP2 = _mm_srli_si128(TMP2, 8);
		TMP1 = _mm_xor_si128(TMP3, TMP1);
		TMP4 = _mm_xor_si128(TMP4, TMP2);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP3, TMP2);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP3, TMP2);
		T = _mm_xor_si128(TMP4, TMP1);
	}
	_mm_storeu_si128(((__m128i*)TAG), T);
}
void Polyval_Htable(unsigned char* Htbl,
                    unsigned char* inp,
					int length,
                    unsigned char* POLYVAL)
{
	int remainder =0;
	int rem_128 = (length%128) - length%16;
	int has_semi = length %16;
	unsigned char* fixed_inp = inp;
	int i;
	uint8_t B[16] ={0};
	__m128i data, TMP0, TMP1, TMP2, TMP3, TMP4, T, Xhi, POLY;
	if (length==0)
		return;
	Xhi = _mm_setzero_si128();
	POLY = _mm_setr_epi32(0x1,0,0,0xc2000000);
	T = _mm_loadu_si128(((__m128i*)POLYVAL));
	if ((length!=0) || (rem_128!=0)){
	if (rem_128!=0)
	{
		fixed_inp +=rem_128;
		
		remainder = rem_128/16;
		data = _mm_loadu_si128(((__m128i*)inp));
		data = _mm_xor_si128(T, data);
		TMP2 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[remainder-1], 0x01);
		TMP0 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[remainder-1], 0x00);
		TMP1 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[remainder-1], 0x11);
		TMP3 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[remainder-1], 0x10);
		TMP2 = _mm_xor_si128(TMP2, TMP3);
		for (i=1; i<(rem_128/16); i++)
		{
			data = _mm_loadu_si128(&((__m128i*)inp)[i]);
			TMP3 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[remainder-i-1], 0x00);
			TMP0 = _mm_xor_si128(TMP0, TMP3);
			TMP3 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[remainder-i-1], 0x11);
			TMP1 = _mm_xor_si128(TMP1, TMP3);
			TMP3 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[remainder-i-1], 0x01);
			TMP2 = _mm_xor_si128(TMP2, TMP3);
			TMP3 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[remainder-i-1], 0x10);
			TMP2 = _mm_xor_si128(TMP2, TMP3);    
			
		}
		TMP3 = _mm_srli_si128(TMP2, 8);
		TMP2 = _mm_slli_si128(TMP2, 8);
		Xhi = _mm_xor_si128(TMP3, TMP1);
		T = _mm_xor_si128(TMP0, TMP2);
		length -= rem_128;
	}
	length /=16;
	i=0;
	if (length!=0)
	{
		if (rem_128==0)
		{
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+7]);
			TMP2 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x01);
			TMP0 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x00);
			TMP1 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x11);
			TMP3 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x10);
			TMP2 = _mm_xor_si128(TMP2, TMP3);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+6]);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[1]);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+5]);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[2]);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+4]);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[3]);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+3]);
			TMP4 = _mm_clmulepi64_si128(T, POLY, 0x10);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[4]);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+2]);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[5]);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+1]);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[6]);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i]);
			data = _mm_xor_si128(T, data);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[7]);
			TMP3 = _mm_srli_si128(TMP2, 8);
			TMP2 = _mm_slli_si128(TMP2, 8);
			Xhi = _mm_xor_si128(TMP3, TMP1);
			T = _mm_xor_si128(TMP0, TMP2);
			i=8;
		}
		for (; i<length; i=i+8)
		{
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+7]);
			TMP2 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x01);
			TMP0 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x00);
			TMP1 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x11);
			TMP3 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x10);
			TMP2 = _mm_xor_si128(TMP2, TMP3);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+6]);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[1]);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+5]);
			TMP4 = _mm_clmulepi64_si128(T, POLY, 0x10);
			T =_mm_alignr_epi8(T, T, 8);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[2]);
			T = _mm_xor_si128(T, TMP4);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+4]);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[3]);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+3]);
			TMP4 = _mm_clmulepi64_si128(T, POLY, 0x10);
			T =_mm_alignr_epi8(T, T, 8);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[4]);
			T = _mm_xor_si128(T, TMP4);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+2]);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[5]);
			T = _mm_xor_si128(T, Xhi);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i+1]);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[6]);
			data = _mm_loadu_si128(&((__m128i*)fixed_inp)[i]);
			data = _mm_xor_si128(T, data);
			SCHOOLBOOK_AAD(data,((__m128i*)Htbl)[7]);
			TMP3 = _mm_srli_si128(TMP2, 8);
			TMP2 = _mm_slli_si128(TMP2, 8);
			Xhi = _mm_xor_si128(TMP3, TMP1);
			T = _mm_xor_si128(TMP0, TMP2);
		}
		TMP3 = _mm_clmulepi64_si128(T, POLY, 0x10);
		T =_mm_alignr_epi8(T, T, 8);
		T = _mm_xor_si128(TMP3, T);
		TMP3 = _mm_clmulepi64_si128(T, POLY, 0x10);
		T =_mm_alignr_epi8(T, T, 8);
		T = _mm_xor_si128(TMP3, T);
		T = _mm_xor_si128(Xhi, T);
	}
	else
	{ // length was <16 and there was several blocks on start - need to finialize reduction
		if (rem_128!=0)
		{
			TMP3 = _mm_clmulepi64_si128(T, POLY, 0x10);
			T =_mm_alignr_epi8(T, T, 8);
			T = _mm_xor_si128(TMP3, T);
			TMP3 = _mm_clmulepi64_si128(T, POLY, 0x10);
			T =_mm_alignr_epi8(T, T, 8);
			T = _mm_xor_si128(TMP3, T);
			T = _mm_xor_si128(Xhi, T);
		}
	}
	}
	if (has_semi!=0)
	{
		memcpy(B, (uint8_t*)(&((__m128i*)fixed_inp)[i]),has_semi);
		data = _mm_loadu_si128((__m128i*)B);
		data = _mm_xor_si128(T,data);
		TMP2 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x01);
		TMP0 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x00);
		TMP1 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x11);
		TMP3 = _mm_clmulepi64_si128(data, ((__m128i*)Htbl)[0], 0x10);
		TMP2 = _mm_xor_si128(TMP2, TMP3);
		TMP3 = _mm_srli_si128(TMP2, 8);
		TMP2 = _mm_slli_si128(TMP2, 8);
		Xhi = _mm_xor_si128(TMP3, TMP1);
		T = _mm_xor_si128(TMP0, TMP2);
		TMP3 = _mm_clmulepi64_si128(T, POLY, 0x10);
		T =_mm_alignr_epi8(T, T, 8);
		T = _mm_xor_si128(TMP3, T);
		TMP3 = _mm_clmulepi64_si128(T, POLY, 0x10);
		T =_mm_alignr_epi8(T, T, 8);
		T = _mm_xor_si128(TMP3, T);
		T = _mm_xor_si128(Xhi, T);
	}
	_mm_storeu_si128(((__m128i*)POLYVAL), T);
}
