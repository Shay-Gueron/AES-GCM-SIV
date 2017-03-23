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
	
typedef struct GCM_SIV_CONTEXT
{
	ROUND_KEYS KS;
	uint8_t Htbl[16*8];
	ALIGN64 uint8_t secureBuffer[16*16];
	#ifdef DETAILS
	uint8_t details_info[16*56]; // first 20*16 for enc , last 20*16 for dec
	#endif
}AES_GCM_SIV_CONTEXT;


void AES_GCM_SIV_Encrypt (AES_GCM_SIV_CONTEXT* ctx, uint8_t* CT, uint8_t* TAG, const uint8_t* AAD, const uint8_t* PT, size_t L1, size_t L2, const uint8_t* IV, const uint8_t* KEY);

int AES_GCM_SIV_Decrypt (AES_GCM_SIV_CONTEXT* ctx, uint8_t* DT, uint8_t* TAG, const uint8_t* AAD, const uint8_t* CT, size_t L1, size_t L2, const uint8_t* IV, const uint8_t* KEY);

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
/*
	This function key expansion (128bit) first key - and encrypt 4 blocks in the following way:
	CT[0] = AES_128(first_key, NONCE[95:0] || 0)
	CT[1] = AES_128(first_key, NONCE[95:0] || 1)
	CT[2] = AES_128(first_key, NONCE[95:0] || 2)
	CT[3] = AES_128(first_key, NONCE[95:0] || 3)
*/
void AES128_KS_ENC_x1_INIT_x4(const unsigned char* NONCE, unsigned char* CT, unsigned char* KS,
				   unsigned char* first_key);				 
	
void print16_BE(uint8_t *in);
void print16_LE(uint8_t *in);
void print_buffer_LE(uint8_t *in, int length);
void print_buffer_BE(uint8_t *in, int length);
void print_counters_from_TAG_BE(uint8_t *in, int num_of_counters);
void print_counters_from_TAG_LE(uint8_t *in, int num_of_counters);
void print_lengths(int init_AAD_byte_len, 
                  int init_MSG_byte_len);
				  
void print_buffers_BE(int init_AAD_byte_len, 
                    int init_MSG_byte_len, 
                    unsigned char*K,
                    unsigned char*H,
                    unsigned char*IV,
                    unsigned char*AAD,
					unsigned char*PT,
					unsigned char*LENBLK) ;	
					

void print_buffers_LE(int init_AAD_byte_len, 
                    int init_MSG_byte_len, 
                    unsigned char*K,
                    unsigned char*H,
                    unsigned char*IV,
                    unsigned char*AAD,
					unsigned char*PT,
					unsigned char*LENBLK) ;
					
void print_res_buffers_BE(int init_AAD_byte_len, int init_MSG_byte_len,
                            unsigned char* H,
                            unsigned char* K,
                            unsigned char* T,
							unsigned char* TxorIV,
							unsigned char* TxorIV_MSB_Zeroed,
                            unsigned char* TAG,
                            unsigned char* AAD,
                            unsigned char* CT); 	
							
void print_res_buffers_LE(int init_AAD_byte_len, int init_MSG_byte_len,
                            unsigned char* H,
                            unsigned char* K,
                            unsigned char* T,
							unsigned char* TxorIV,
							unsigned char* TxorIV_MSB_Zeroed,
                            unsigned char* TAG,
                            unsigned char* AAD,
                            unsigned char* CT);

				
void init_buffers(unsigned char* AAD, int init_AAD_byte_len, unsigned char* PT, unsigned char* CT, unsigned char* DT, int init_MSG_byte_len,
			unsigned char* K, unsigned char* IV, unsigned char* LENBLK);


void AES_KS(unsigned char* key, unsigned char* KS);
void AES_KS_ENC_x1(unsigned char* PT, unsigned char* CT, int len, unsigned char *KS, unsigned char* key);
void INIT_Htable_6(unsigned char* Htbl, unsigned char* H);
void ECB_ENC_block(unsigned char* PT, unsigned char* CT, unsigned char* KS);
void Clear_SIV_CTX(AES_GCM_SIV_CONTEXT* ctx);
#endif
