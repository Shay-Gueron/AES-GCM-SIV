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
#include <stdint.h>
// #include <smmintrin.h>
// #include <wmmintrin.h>
#include  <stdio.h>

#include "clmul_emulator.h"

//Extracts the the value of the <index>th bith of arr
uint8_t extreactBit(uint64_t arr, uint8_t index)
{
	if ((arr & (((uint64_t)1)<<index)) != 0) return 1;
	return 0;
}

//Does carryless multiplication src1*src2
//Stores the result in destination
void mul(uint64_t src1, uint64_t src2, uint64_t* dst)
//void mul(uint64_t src1, uint64_t src2, __m128i* destination)
{
	//Initialization
	uint8_t i;
	//uint64_t* dst = (uint64_t*)destination;
	dst[0] = 0;
	dst[1] = 0;
	
	for(i=0; i<64; i++)
	{
		if(extreactBit(src2,i) == 1) dst[1]^=src1;
		
		//Shift the result
		dst[0]>>=1;
		if(extreactBit(dst[1],0) == 1) dst[0]^=(((uint64_t)1)<<63);
		dst[1]>>=1;
	}
}

//Non destructive clmul emulation
void vclmul_emulator(uint64_t* src1, uint64_t* src2, uint64_t* destination, uint8_t imm)
//void vclmul_emulator(__m128i source1, __m128i source2, __m128i* destination, uint8_t imm)
{
	// uint64_t* src1 = (uint64_t*)&source1;
	// uint64_t* src2 = (uint64_t*)&source2;
	
	switch(imm)
	{
		case 0x00:	mul(src1[0],src2[0],destination); break;
		case 0x01:	mul(src1[1],src2[0],destination); break;
		case 0x10:	mul(src1[0],src2[1],destination); break;
		case 0x11:	mul(src1[1],src2[1],destination); break;
	}
}


#ifdef TEST_CLMUL_EMUL
void printdata(uint64_t* s1, uint64_t* s2, uint64_t* res, uint8_t imm)
{
	printf("The result is %.16x | %.16x\n", res[1], res[0]);
}

int main()
{
	__m128i _src1;
	__m128i _src2;
	__m128i _dest1;
	__m128i _dest2;
	
	uint64_t* src1 = (uint64_t*)&_src1;
	uint64_t* src2 = (uint64_t*)&_src2;
	uint64_t* dst1 = (uint64_t*)&_dest1;
	uint64_t* dst2 = (uint64_t*)&_dest2;
	
	src1[0] = 0x00000000ada5f29b;
	src1[1] = 0;
	src2[0] = 0x000000002d978a49;
	src2[1] = 0;
	#define IMM 0x00
	
	printf("Testing CLMUL emulator:\n");
	vclmul_emulator(_src1,_src2,&_dest1,IMM);
	_dest2 = _mm_clmulepi64_si128(_src1,_src2,IMM);
	
	printf("Emulated:\n");
	printdata(src1,src2,dst1,IMM);
	printf("Reference:\n");
	printdata(src1,src2,dst2,IMM);
	
	return 0;
	#undef IMM
}
#endif