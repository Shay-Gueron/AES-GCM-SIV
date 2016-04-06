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
#ifndef GCM_SIV_H
#define GCM_SIV_H


#if !defined (ALIGN64)
#if defined (__GNUC__)
#  define ALIGN64  __attribute__  ( (aligned (64)))
# else
#  define ALIGN64 __declspec (align (64))
# endif
#endif


typedef struct KEY_SCHEDULE
	{
		ALIGN64 unsigned char KEY[16*15];
		unsigned int nr;
	} ROUND_KEYS;
	
	
void Polyval_Horner(unsigned char T[16],  			// input/output 
					 unsigned char* H,				// H
					 unsigned char* BUF,			// Buffer
					 unsigned int blocks);			// LEn2
					 
void ENC_MSG_x4(unsigned char* PT, 
				  unsigned char* CT, 				//Output
				  unsigned char* TAG, 
				  unsigned char* KS,
				  int byte_len);
				  
void ENC_MSG_x8(unsigned char* PT, 
				  unsigned char* CT, 				//Output
				  unsigned char* TAG, 
				  unsigned char* KS,
				  int byte_len);
				  
void INIT_Htable(uint8_t Htbl[16*8], uint8_t *H);
void Polyval_Htable(uint8_t Htbl[16*8], uint8_t *MSG, uint64_t LEN, uint8_t T[16]);

void Decrypt_Horner(unsigned char* CT, 				//input
				 unsigned char* DT,					//output
				 unsigned char POLYVAL_dec[16], 	//input/output
				 unsigned char TAG[16],
				 unsigned char H[16],
				 unsigned char* KS, 				//Key Schedule for decryption
				 int byte_len);		
				 
void Decrypt_Htable(unsigned char* CT, 				//input
				 unsigned char* PT,					//output
				 unsigned char POLYVAL_dec[16], 	//input/output
				 unsigned char TAG[16],
				 unsigned char Htable[16*8],
				 unsigned char* KS, 				//Key Schedule for decryption
				 int byte_len,
				 unsigned char secureBuffer[16*8]);			
	
	
void print16_BE(uint8_t *in);
void print16_LE(uint8_t *in);
void print_buffer_LE(uint8_t *in, int length);
void print_buffer_BE(uint8_t *in, int length);
void print_counters_from_TAG_BE(uint8_t *in, int num_of_counters);
void print_counters_from_TAG_LE(uint8_t *in, int num_of_counters);
void print_lengths(int init_AAD_byte_len, 
				  int init_AAD_bit_len, 
				  int init_MSG_byte_len, 
				  int init_MSG_bit_len, 
				  int padded_AAD_byte_len,
				  int padded_MSG_byte_len, 
				  int L1, int L2);
				  
void print_buffers_BE(int init_AAD_byte_len, 
					int padded_AAD_byte_len, 
					int init_MSG_byte_len, 
					int total_blocks,
					unsigned char* SINGLE_KEY,
					unsigned char* K,
					unsigned char* H,
					unsigned char* IV,
					unsigned char* BIG_BUF); 	
					
void print_buffers_LE(int init_AAD_byte_len, 
					int padded_AAD_byte_len, 
					int init_MSG_byte_len, 
					int total_blocks,
					unsigned char* SINGLE_KEY,
					unsigned char* K,
					unsigned char* H,
					unsigned char* IV,
					unsigned char* BIG_BUF); 
					
void print_res_buffers_BE(int init_AAD_byte_len, int init_MSG_byte_len,
							unsigned char* H,
							unsigned char* K,
							unsigned char* T,
							unsigned char* TxorIV,
							unsigned char* TxorIV_masked,
							unsigned char* TAG,
							unsigned char* BIG_BUF,
							unsigned char* CT); 	
							
void print_res_buffers_LE(int init_AAD_byte_len, int init_MSG_byte_len,
							unsigned char* H,
							unsigned char* K,
							unsigned char* T,
							unsigned char* TxorIV,
							unsigned char* TxorIV_masked,
							unsigned char* TAG,
							unsigned char* BIG_BUF,
							unsigned char* CT); 	
					
void init_lengths(int init_AAD_byte_len, 
				int init_MSG_byte_len, 
				int* init_AAD_bit_len, 
				int* init_MSG_bit_len,
				int* padded_AAD_byte_len,
				int* padded_MSG_byte_len,
				int* total_blocks,
				int* L1, int* L2);
				
void init_buffers(int total_blocks, int init_MSG_bit_len, int init_AAD_bit_len, 
				unsigned char* BIG_BUF, 
				unsigned char* LENBLK,
				unsigned char* SINGLE_KEY, 
				unsigned char* K, 
				unsigned char* H, 
				unsigned char* IV, 
				unsigned char* AND_MASK);




#endif
