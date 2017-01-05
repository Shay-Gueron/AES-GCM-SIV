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



#define SCHOOLBOOK(reg, htbl_reg){\
	TMP3 = _mm_clmulepi64_si128(reg, htbl_reg, 0x10);\
	TMP0 = _mm_xor_si128(TMP0, TMP3); \
	TMP3 = _mm_clmulepi64_si128(reg, htbl_reg, 0x11);\
	TMP1 = _mm_xor_si128(TMP1, TMP3); \
	TMP3 = _mm_clmulepi64_si128(reg, htbl_reg, 0x00);\
	TMP2 = _mm_xor_si128(TMP2, TMP3); \
	TMP3 = _mm_clmulepi64_si128(reg, htbl_reg, 0x01);\
	TMP0 = _mm_xor_si128(TMP0, TMP3); \
}
void Decrypt_Htable(unsigned char* CT,
                    unsigned char* PT,
                    unsigned char POLYVAL_dec[16],    
                    unsigned char pTAG[16],					
                    unsigned char Htbl[16*8],					
                    unsigned char* KS,                					
                    int byte_len,					
                    unsigned char secureBuffer[16*8])
{
    __m128i T, CTR, OR_MASK, ONE,TWO;
	__m128i register CTR1, CTR2,CTR3,CTR4,CTR5,sCTR1,sCTR2,sCTR3,sCTR4,sCTR5,sCTR6, CTR6, POLY, TMP0,TMP1, TMP2, TMP3,TMP4;
	int i;
	uint8_t B[16] = {0};
	int count = 0;
    T	= _mm_loadu_si128(((__m128i*)POLYVAL_dec));
	CTR = _mm_loadu_si128(((__m128i*)pTAG));
	OR_MASK = _mm_setr_epi32(0,0,0,0x80000000);
	POLY = _mm_setr_epi32(0x1,0,0,0xc2000000);
	ONE = _mm_setr_epi32(1,0,0,0);
	TWO = _mm_setr_epi32(2,0,0,0);
	CTR = _mm_or_si128(CTR, OR_MASK);
	
	if (byte_len >=96)
	{
	    CTR1 = CTR;
	    CTR2 = _mm_add_epi32(CTR, ONE);
	    CTR3 = _mm_add_epi32(CTR, TWO);
	    CTR4 = _mm_add_epi32(CTR3, ONE);
	    CTR5 = _mm_add_epi32(CTR3, TWO);
	    CTR6 = _mm_add_epi32(CTR5, ONE);
	    CTR = _mm_add_epi32(CTR5, TWO);
	    CTR1 = _mm_xor_si128(CTR1,((__m128i*)KS)[0]);
	    CTR2 = _mm_xor_si128(CTR2,((__m128i*)KS)[0]);
	    CTR3 = _mm_xor_si128(CTR3,((__m128i*)KS)[0]);
	    CTR4 = _mm_xor_si128(CTR4,((__m128i*)KS)[0]);
	    CTR5 = _mm_xor_si128(CTR5,((__m128i*)KS)[0]);
	    CTR6 = _mm_xor_si128(CTR6,((__m128i*)KS)[0]);
	    for (i=1; i<10;i++)
	    {
			CTR1 = _mm_aesenc_si128 (CTR1, ((__m128i*)KS)[i]); 
			CTR2 = _mm_aesenc_si128 (CTR2, ((__m128i*)KS)[i]); 
			CTR3 = _mm_aesenc_si128 (CTR3, ((__m128i*)KS)[i]); 
			CTR4 = _mm_aesenc_si128 (CTR4, ((__m128i*)KS)[i]); 
			CTR5 = _mm_aesenc_si128 (CTR5, ((__m128i*)KS)[i]); 
			CTR6 = _mm_aesenc_si128 (CTR6, ((__m128i*)KS)[i]);
		}
	    CTR1 = _mm_aesenclast_si128 (CTR1, ((__m128i*)KS)[i]);
	    CTR2 = _mm_aesenclast_si128 (CTR2, ((__m128i*)KS)[i]);
	    CTR3 = _mm_aesenclast_si128 (CTR3, ((__m128i*)KS)[i]);
	    CTR4 = _mm_aesenclast_si128 (CTR4, ((__m128i*)KS)[i]);
	    CTR5 = _mm_aesenclast_si128 (CTR5, ((__m128i*)KS)[i]);
	    CTR6 = _mm_aesenclast_si128 (CTR6, ((__m128i*)KS)[i]);
	    CTR1 = _mm_xor_si128(CTR1,((__m128i*)CT)[0]);
	    CTR2 = _mm_xor_si128(CTR2,((__m128i*)CT)[1]);
	    CTR3 = _mm_xor_si128(CTR3,((__m128i*)CT)[2]);
	    CTR4 = _mm_xor_si128(CTR4,((__m128i*)CT)[3]);
	    CTR5 = _mm_xor_si128(CTR5,((__m128i*)CT)[4]);
	    CTR6 = _mm_xor_si128(CTR6,((__m128i*)CT)[5]);
	    _mm_storeu_si128(&((__m128i*)PT)[0],CTR1);
	    _mm_storeu_si128(&((__m128i*)PT)[1],CTR2);
	    _mm_storeu_si128(&((__m128i*)PT)[2],CTR3);
	    _mm_storeu_si128(&((__m128i*)PT)[3],CTR4);
	    _mm_storeu_si128(&((__m128i*)PT)[4],CTR5);
	    _mm_storeu_si128(&((__m128i*)PT)[5],CTR6);
	    byte_len-=96;
		count+=6;
	    while (byte_len>=96)
	    {
	    	sCTR6 = CTR6;
	    	sCTR5 = CTR5;
	    	sCTR4 = CTR4;
	    	sCTR3 = CTR3;
	    	sCTR2 = CTR2;
	    	sCTR1 = CTR1;
	    	CTR1 = CTR;
	        CTR2 = _mm_add_epi32(CTR, ONE);
	        CTR3 = _mm_add_epi32(CTR, TWO);
	        CTR4 = _mm_add_epi32(CTR3, ONE);		
	        CTR5 = _mm_add_epi32(CTR3, TWO);		
	        CTR6 = _mm_add_epi32(CTR5, ONE);		
	        CTR = _mm_add_epi32(CTR5, TWO);	
	        CTR1 = _mm_xor_si128(CTR1,((__m128i*)KS)[0]);
	        CTR2 = _mm_xor_si128(CTR2,((__m128i*)KS)[0]);
	        CTR3 = _mm_xor_si128(CTR3,((__m128i*)KS)[0]);
	        CTR4 = _mm_xor_si128(CTR4,((__m128i*)KS)[0]);
	        CTR5 = _mm_xor_si128(CTR5,((__m128i*)KS)[0]);
	        CTR6 = _mm_xor_si128(CTR6,((__m128i*)KS)[0]);
            TMP3 = _mm_loadu_si128(((__m128i*)Htbl));
	    	TMP1 = _mm_clmulepi64_si128(sCTR6, TMP3, 0x11);
	    	TMP2 = _mm_clmulepi64_si128(sCTR6, TMP3, 0x00);
	    	TMP0 = _mm_clmulepi64_si128(sCTR6, TMP3, 0x01);
	    	TMP3 = _mm_clmulepi64_si128(sCTR6, TMP3, 0x10);
	    	TMP0 = _mm_xor_si128(TMP3,TMP0);
            CTR1 = _mm_aesenc_si128 (CTR1, ((__m128i*)KS)[1]); 
			CTR2 = _mm_aesenc_si128 (CTR2, ((__m128i*)KS)[1]); 
			CTR3 = _mm_aesenc_si128 (CTR3, ((__m128i*)KS)[1]); 
			CTR4 = _mm_aesenc_si128 (CTR4, ((__m128i*)KS)[1]); 
			CTR5 = _mm_aesenc_si128 (CTR5, ((__m128i*)KS)[1]); 
			CTR6 = _mm_aesenc_si128 (CTR6, ((__m128i*)KS)[1]); 
            SCHOOLBOOK(sCTR5, ((__m128i*)Htbl)[1]);
            CTR1 = _mm_aesenc_si128 (CTR1, ((__m128i*)KS)[2]); 
			CTR2 = _mm_aesenc_si128 (CTR2, ((__m128i*)KS)[2]); 
			CTR3 = _mm_aesenc_si128 (CTR3, ((__m128i*)KS)[2]); 
			CTR4 = _mm_aesenc_si128 (CTR4, ((__m128i*)KS)[2]); 
			CTR5 = _mm_aesenc_si128 (CTR5, ((__m128i*)KS)[2]); 
			CTR6 = _mm_aesenc_si128 (CTR6, ((__m128i*)KS)[2]); 
            SCHOOLBOOK(sCTR4, ((__m128i*)Htbl)[2]);
            CTR1 = _mm_aesenc_si128 (CTR1, ((__m128i*)KS)[3]); 
			CTR2 = _mm_aesenc_si128 (CTR2, ((__m128i*)KS)[3]); 
			CTR3 = _mm_aesenc_si128 (CTR3, ((__m128i*)KS)[3]); 
			CTR4 = _mm_aesenc_si128 (CTR4, ((__m128i*)KS)[3]); 
			CTR5 = _mm_aesenc_si128 (CTR5, ((__m128i*)KS)[3]); 
			CTR6 = _mm_aesenc_si128 (CTR6, ((__m128i*)KS)[3]);
            SCHOOLBOOK(sCTR3, ((__m128i*)Htbl)[3]);
	    	CTR1 = _mm_aesenc_si128 (CTR1, ((__m128i*)KS)[4]); 
			CTR2 = _mm_aesenc_si128 (CTR2, ((__m128i*)KS)[4]); 
			CTR3 = _mm_aesenc_si128 (CTR3, ((__m128i*)KS)[4]); 
			CTR4 = _mm_aesenc_si128 (CTR4, ((__m128i*)KS)[4]); 
			CTR5 = _mm_aesenc_si128 (CTR5, ((__m128i*)KS)[4]); 
			CTR6 = _mm_aesenc_si128 (CTR6, ((__m128i*)KS)[4]);
            SCHOOLBOOK(sCTR2, ((__m128i*)Htbl)[4]);
	    	CTR1 = _mm_aesenc_si128 (CTR1, ((__m128i*)KS)[5]); 
			CTR2 = _mm_aesenc_si128 (CTR2, ((__m128i*)KS)[5]); 
			CTR3 = _mm_aesenc_si128 (CTR3, ((__m128i*)KS)[5]); 
			CTR4 = _mm_aesenc_si128 (CTR4, ((__m128i*)KS)[5]); 
			CTR5 = _mm_aesenc_si128 (CTR5, ((__m128i*)KS)[5]); 
			CTR6 = _mm_aesenc_si128 (CTR6, ((__m128i*)KS)[5]);
	    	CTR1 = _mm_aesenc_si128 (CTR1, ((__m128i*)KS)[6]); 
			CTR2 = _mm_aesenc_si128 (CTR2, ((__m128i*)KS)[6]); 
			CTR3 = _mm_aesenc_si128 (CTR3, ((__m128i*)KS)[6]); 
			CTR4 = _mm_aesenc_si128 (CTR4, ((__m128i*)KS)[6]); 
			CTR5 = _mm_aesenc_si128 (CTR5, ((__m128i*)KS)[6]); 
			CTR6 = _mm_aesenc_si128 (CTR6, ((__m128i*)KS)[6]);
	    	CTR1 = _mm_aesenc_si128 (CTR1, ((__m128i*)KS)[7]); 
			CTR2 = _mm_aesenc_si128 (CTR2, ((__m128i*)KS)[7]); 
			CTR3 = _mm_aesenc_si128 (CTR3, ((__m128i*)KS)[7]); 
			CTR4 = _mm_aesenc_si128 (CTR4, ((__m128i*)KS)[7]); 
			CTR5 = _mm_aesenc_si128 (CTR5, ((__m128i*)KS)[7]); 
			CTR6 = _mm_aesenc_si128 (CTR6, ((__m128i*)KS)[7]);
	    	sCTR1 = _mm_xor_si128(T, sCTR1);
	    	TMP4 = _mm_loadu_si128(&((__m128i*)Htbl)[5]);
	    	TMP3 = _mm_clmulepi64_si128(sCTR1, TMP4,0x01);
	    	TMP0 = _mm_xor_si128(TMP3, TMP0);
	    	TMP3 = _mm_clmulepi64_si128(sCTR1, TMP4, 0x11);
	    	TMP1 = _mm_xor_si128(TMP3, TMP1);
	    	TMP3 = _mm_clmulepi64_si128(sCTR1, TMP4, 0x00);
	    	TMP2 = _mm_xor_si128(TMP3, TMP2);
	    	TMP3 = _mm_clmulepi64_si128(sCTR1, TMP4, 0x10);
	    	TMP0 = _mm_xor_si128(TMP3, TMP0);
	    	CTR1 = _mm_aesenc_si128 (CTR1, ((__m128i*)KS)[8]); 
			CTR2 = _mm_aesenc_si128 (CTR2, ((__m128i*)KS)[8]); 
			CTR3 = _mm_aesenc_si128 (CTR3, ((__m128i*)KS)[8]); 
			CTR4 = _mm_aesenc_si128 (CTR4, ((__m128i*)KS)[8]); 
			CTR5 = _mm_aesenc_si128 (CTR5, ((__m128i*)KS)[8]); 
			CTR6 = _mm_aesenc_si128 (CTR6, ((__m128i*)KS)[8]);
	    	TMP3 = _mm_srli_si128(TMP0, 8);
	    	TMP4 = _mm_xor_si128(TMP3, TMP1);
	    	TMP3 = _mm_slli_si128(TMP0, 8);
	    	T = _mm_xor_si128(TMP3, TMP2);
            CTR1 = _mm_aesenc_si128 (CTR1, ((__m128i*)KS)[9]); 
			CTR2 = _mm_aesenc_si128 (CTR2, ((__m128i*)KS)[9]); 
			CTR3 = _mm_aesenc_si128 (CTR3, ((__m128i*)KS)[9]); 
			CTR4 = _mm_aesenc_si128 (CTR4, ((__m128i*)KS)[9]); 
			CTR5 = _mm_aesenc_si128 (CTR5, ((__m128i*)KS)[9]); 
			CTR6 = _mm_aesenc_si128 (CTR6, ((__m128i*)KS)[9]);
            TMP1 =_mm_alignr_epi8(T, T, 8);
	    	T = _mm_clmulepi64_si128(T,  POLY, 0x10);
	    	T = _mm_xor_si128(TMP1, T);
	        CTR1 = _mm_aesenclast_si128 (CTR1, ((__m128i*)KS)[10]);
	        CTR2 = _mm_aesenclast_si128 (CTR2, ((__m128i*)KS)[10]);
	        CTR3 = _mm_aesenclast_si128 (CTR3, ((__m128i*)KS)[10]);
	        CTR4 = _mm_aesenclast_si128 (CTR4, ((__m128i*)KS)[10]);
	        CTR5 = _mm_aesenclast_si128 (CTR5, ((__m128i*)KS)[10]);
	        CTR6 = _mm_aesenclast_si128 (CTR6, ((__m128i*)KS)[10]);
	        CTR1 = _mm_xor_si128(CTR1,((__m128i*)CT)[count+0]);
	        CTR2 = _mm_xor_si128(CTR2,((__m128i*)CT)[count+1]);
	        CTR3 = _mm_xor_si128(CTR3,((__m128i*)CT)[count+2]);
	        CTR4 = _mm_xor_si128(CTR4,((__m128i*)CT)[count+3]);
	        CTR5 = _mm_xor_si128(CTR5,((__m128i*)CT)[count+4]);
	        CTR6 = _mm_xor_si128(CTR6,((__m128i*)CT)[count+5]);
	    	TMP1 =_mm_alignr_epi8(T, T, 8);
	    	T = _mm_clmulepi64_si128(T,  POLY, 0x10);
	    	T = _mm_xor_si128(TMP1, T);
	        _mm_storeu_si128(&((__m128i*)PT)[count+0],CTR1);
	        _mm_storeu_si128(&((__m128i*)PT)[count+1],CTR2);
	        _mm_storeu_si128(&((__m128i*)PT)[count+2],CTR3);
	        _mm_storeu_si128(&((__m128i*)PT)[count+3],CTR4);
	        _mm_storeu_si128(&((__m128i*)PT)[count+4],CTR5);
	        _mm_storeu_si128(&((__m128i*)PT)[count+5],CTR6);
	    	count+=6;
	    	T = _mm_xor_si128(TMP4, T);
	    	byte_len-=96;
	    }
		sCTR6 = CTR6;
	    sCTR5 = CTR5;
	   	sCTR4 = CTR4;
	    sCTR3 = CTR3;
	    sCTR2 = CTR2;
	    sCTR1 = CTR1;
	    TMP3 = _mm_loadu_si128(((__m128i*)Htbl));
		TMP0 = _mm_clmulepi64_si128(sCTR6, TMP3, 0x10);
	    TMP1 = _mm_clmulepi64_si128(sCTR6, TMP3, 0x11);
	    TMP2 = _mm_clmulepi64_si128(sCTR6, TMP3, 0x00);
	   	TMP3 = _mm_clmulepi64_si128(sCTR6, TMP3, 0x01);
		TMP0 = _mm_xor_si128(TMP3, TMP0);
		SCHOOLBOOK(sCTR5, ((__m128i*)Htbl)[1]);
		SCHOOLBOOK(sCTR4, ((__m128i*)Htbl)[2]);
		SCHOOLBOOK(sCTR3, ((__m128i*)Htbl)[3]);
		SCHOOLBOOK(sCTR2, ((__m128i*)Htbl)[4]);
	    sCTR1 = _mm_xor_si128(T, sCTR1);
	    TMP4 = _mm_loadu_si128(&((__m128i*)Htbl)[5]);
	    TMP3 = _mm_clmulepi64_si128(sCTR1, TMP4,0x11);
	    TMP1 = _mm_xor_si128(TMP3, TMP1);
	    TMP3 = _mm_clmulepi64_si128(sCTR1, TMP4, 0x00);
	    TMP2 = _mm_xor_si128(TMP3, TMP2);
	    TMP3 = _mm_clmulepi64_si128(sCTR1, TMP4, 0x10);
	    TMP0 = _mm_xor_si128(TMP3, TMP0);
	    TMP3 = _mm_clmulepi64_si128(sCTR1, TMP4, 0x01);
	    TMP0 = _mm_xor_si128(TMP3, TMP0);	
	    TMP3 = _mm_srli_si128(TMP0, 8);
	   	TMP4 = _mm_xor_si128(TMP3, TMP1);
	   	TMP3 = _mm_slli_si128(TMP0, 8);
	   	T = _mm_xor_si128(TMP3, TMP2);
        TMP1 =_mm_alignr_epi8(T, T, 8);
		T = _mm_clmulepi64_si128(T,  POLY, 0x10);
	    T = _mm_xor_si128(TMP1, T);
		TMP1 =_mm_alignr_epi8(T, T, 8);
		T = _mm_clmulepi64_si128(T,  POLY, 0x10);
	    T = _mm_xor_si128(TMP1, T);
		T = _mm_xor_si128(TMP4, T);
	}
	sCTR1 =  _mm_loadu_si128(((__m128i*)Htbl));
	while (byte_len>=16)
	{
	    CTR1 = CTR;
		CTR = _mm_add_epi32(CTR, ONE);
		CTR1 = _mm_xor_si128(CTR1, ((__m128i*)KS)[0]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[1]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[2]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[3]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[4]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[5]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[6]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[7]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[8]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[9]);
		CTR1 = _mm_aesenclast_si128(CTR1, ((__m128i*)KS)[10]);
		CTR1 = _mm_xor_si128(CTR1,((__m128i*)CT)[count]);
		_mm_storeu_si128(&((__m128i*)PT)[count++],CTR1);
		byte_len-=16;
		T = _mm_xor_si128(CTR1, T);
		TMP1 = _mm_clmulepi64_si128(T, sCTR1, 0x00);
		TMP4 = _mm_clmulepi64_si128(T, sCTR1, 0x11);
		TMP2 = _mm_clmulepi64_si128(T, sCTR1, 0x10);
		TMP3 = _mm_clmulepi64_si128(T, sCTR1, 0x01);
		TMP2 = _mm_xor_si128(TMP3, TMP2);
		TMP3 = _mm_slli_si128(TMP2, 8);
		TMP2 = _mm_srli_si128(TMP2, 8);
		TMP1 = _mm_xor_si128(TMP1, TMP3);
		TMP4 = _mm_xor_si128(TMP2, TMP4);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP2, TMP3);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP2, TMP3);
		T = _mm_xor_si128(TMP1, TMP4);
	}
	if (byte_len>0)
	{
		memcpy(B, (uint8_t*)(&((__m128i*)CT)[count]), byte_len);
		CTR1 = CTR;
		CTR = _mm_add_epi32(CTR, ONE);
		CTR1 = _mm_xor_si128(CTR1, ((__m128i*)KS)[0]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[1]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[2]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[3]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[4]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[5]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[6]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[7]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[8]);
		CTR1 = _mm_aesenc_si128(CTR1, ((__m128i*)KS)[9]);
		CTR1 = _mm_aesenclast_si128(CTR1, ((__m128i*)KS)[10]);
		CTR1 = _mm_xor_si128(CTR1,*((__m128i*)B));
		*(__m128i*)B = CTR1;
		memset(B+byte_len, 0, 16-byte_len);
		T = _mm_xor_si128(*(__m128i*)B, T);
		TMP1 = _mm_clmulepi64_si128(T, sCTR1, 0x00);
		TMP4 = _mm_clmulepi64_si128(T, sCTR1, 0x11);
		TMP2 = _mm_clmulepi64_si128(T, sCTR1, 0x10);
		TMP3 = _mm_clmulepi64_si128(T, sCTR1, 0x01);
		memcpy((uint8_t*)(&((__m128i*)PT)[count]), B, byte_len);
		TMP2 = _mm_xor_si128(TMP3, TMP2);
		TMP3 = _mm_slli_si128(TMP2, 8);
		TMP2 = _mm_srli_si128(TMP2, 8);
		TMP1 = _mm_xor_si128(TMP1, TMP3);
		TMP4 = _mm_xor_si128(TMP2, TMP4);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP2, TMP3);
		TMP2 = _mm_clmulepi64_si128(TMP1, POLY, 0x10);
		TMP3 = _mm_shuffle_epi32(TMP1, 78);
		TMP1 = _mm_xor_si128(TMP2, TMP3);
		T = _mm_xor_si128(TMP1, TMP4);
	}
	_mm_storeu_si128(((__m128i*)POLYVAL_dec), T);
}