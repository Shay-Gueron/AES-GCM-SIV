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
#include "aes_emulation.h"

int
emulated_aesenc_varset(void *dst,
	   uint8_t val,
	   uint32_t length)
{
	uint32_t i;

	for(i=0; i < length; i++)
		*((uint8_t *)dst + i) = val;
	return length;
}

int emulated_aesenc_substitute_bytes(
				 uint32_t *data)
{
	int i;
	uint8_t *ptr = (uint8_t *)data;
	for(i=0; i < NUM_OF_BYTES_IN_BLOCK; i++)
	{
		ptr[i] = emulated_aesenc_rijndael_sbox[ptr[i]];
	}
	return 1;
}

int emulated_aesenc_row_shifting(
			uint32_t *data)
{
	uint8_t byte_order[NUM_OF_BYTES_IN_BLOCK];
	byte_order[0]  = 0;
	byte_order[1]  = 5;
	byte_order[2]  = 10;
	byte_order[3]  = 15;
	byte_order[4]  = 4;
	byte_order[5]  = 9;
	byte_order[6]  = 14;
	byte_order[7]  = 3;
	byte_order[8]  = 8;
	byte_order[9]  = 13;
	byte_order[10] = 2;
	byte_order[11] = 7;
	byte_order[12] = 12;
	byte_order[13] = 1;
	byte_order[14] = 6;
	byte_order[15] = 11;

	int i;
	uint8_t *src = (uint8_t *)data;
	uint8_t dst[NUM_OF_BYTES_IN_BLOCK];
	emulated_aesenc_varset(dst, 0, NUM_OF_BYTES_IN_BLOCK);
	for(i=0; i < NUM_OF_BYTES_IN_BLOCK; i++)
		dst[i] = src[byte_order[i]];
	for(i=0; i < NUM_OF_BYTES_IN_BLOCK; i++)
		src[i] = dst[i];
	return 1;
}


void emulated_aesenc(_xmm _xmm1, _xmm _xmm2)
{
	uint32_t s0, s1, s2, s3;
	s0 = _xmm1[0];
	s1 = _xmm1[1];
	s2 = _xmm1[2];
	s3 = _xmm1[3];

	_xmm1[0] = emulated_aesenc_enc_table_0[s0 & 0xff] ^
		 emulated_aesenc_enc_table_1[(s1 >> 8) & 0xff] ^
		 emulated_aesenc_enc_table_2[(s2 >> 16) & 0xff] ^
		 emulated_aesenc_enc_table_3[(s3 >> 24) & 0xff];
	_xmm1[1] = emulated_aesenc_enc_table_0[s1 & 0xff] ^
		 emulated_aesenc_enc_table_1[(s2 >> 8) & 0xff] ^
		 emulated_aesenc_enc_table_2[(s3 >> 16) & 0xff] ^
		 emulated_aesenc_enc_table_3[(s0 >> 24) & 0xff];
	_xmm1[2] = emulated_aesenc_enc_table_0[s2 & 0xff] ^
		 emulated_aesenc_enc_table_1[(s3 >> 8) & 0xff] ^
		 emulated_aesenc_enc_table_2[(s0 >> 16) & 0xff] ^
		 emulated_aesenc_enc_table_3[(s1 >> 24) & 0xff] ;
	_xmm1[3] = emulated_aesenc_enc_table_0[s3 & 0xff] ^
		 emulated_aesenc_enc_table_1[(s0 >> 8) & 0xff] ^
		 emulated_aesenc_enc_table_2[(s1 >> 16) & 0xff] ^
		 emulated_aesenc_enc_table_3[(s2 >> 24) & 0xff];
	_xmm1[0] ^= _xmm2[0];
	_xmm1[1] ^= _xmm2[1];
	_xmm1[2] ^= _xmm2[2];
	_xmm1[3] ^= _xmm2[3];
	return;
}


void emulated_aesenclast(_xmm _xmm1, _xmm _xmm2)
{
	emulated_aesenc_row_shifting((uint32_t*)&_xmm1[0]);
	emulated_aesenc_substitute_bytes((uint32_t*)&_xmm1[0]);
	_xmm1[0] ^= _xmm2[0];
	_xmm1[1] ^= _xmm2[1];
	_xmm1[2] ^= _xmm2[2];
	_xmm1[3] ^= _xmm2[3];
	return;
}
