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
#include <stdio.h>
#include <wmmintrin.h>
#include <string.h>
#include "measurements.h"
#include "GCM_SIV.h"
/*
void AES256_KS_ENC_x1(const unsigned char PT[16],	
						unsigned char CT[16],			
						AES_KEY *KS,					
						const unsigned char *userKey);
						
void AES128_KS_ENC_x2(const unsigned char PT[32],	
						unsigned char CT[32],			
						AES_KEY *KS,					
						const unsigned char *userKey);*/
#define LENGTH (16)


//****************************************************************************				   
int main(int argc, char *argv[])
{
	int L1=0, L2=0;
	int init_AAD_bit_len=0;
	int init_MSG_bit_len=0;
	int init_AAD_byte_len=0;
	int init_MSG_byte_len=0;
	int padded_MSG_byte_len=0;
    int padded_AAD_byte_len=0;	
	int total_blocks=0; 
	int i=0;
	int enc_dec_flag=0;
	unsigned char *BIG_BUF = NULL;
	unsigned char *CT = NULL;
	unsigned char *DT = NULL;
	unsigned char *secureBuffer = NULL;
	
	ROUND_KEYS KS;
	ROUND_KEYS KS_pseudo;	//Used in SINGLE_KEY mode for K1 and K2 derivation
	ROUND_KEYS KS_dec;
	
	uint8_t K[32]={0};
	uint8_t H[16]={0};
	uint8_t SINGLE_KEY[32]={0};
	uint8_t IV[16]={0};
	uint8_t TAG[16]={0};  
	uint8_t T[16]={0};  
	uint8_t TxorIV[16]={0};  
	uint8_t TxorIV_masked[16]={0};
	uint8_t POLYVAL_dec[16]={0};		//POLYVAL calculation during decryption
	uint8_t TAG_dec[16]={0};  			//TAG calculated for authentication
	uint8_t Htbl[16*8]={0};
	uint8_t LENBLK[16]={0};
	uint8_t ZERO[16]={0};
	uint8_t AND_MASK[16]={0};
	uint8_t H_and_K[48]={0};
	uint8_t ENC_KEY[32] = {0};
	//Get Input
	if(argc == 1 || argc == 2) {
      init_AAD_byte_len = 0;
	  init_MSG_byte_len = LENGTH;
    }
	else if (argc == 3) {
      init_AAD_byte_len = atoi(argv[1]);
	  init_MSG_byte_len = atoi(argv[2]);
	}
		
	init_lengths(init_AAD_byte_len, 
				init_MSG_byte_len, 
				&init_AAD_bit_len, 
				&init_MSG_bit_len, 
				&padded_AAD_byte_len,
				&padded_MSG_byte_len,
				&total_blocks,
				&L1, &L2);
	
	//Allocate and init buffers
	BIG_BUF = (uint8_t*)_mm_malloc(total_blocks*16, 64);		//buffer for L1+L2+1 blocks
	CT      = (uint8_t*)_mm_malloc(padded_MSG_byte_len, 64);	//in the end if (padded_MSG_byte_len > init_MSG_byte_len) need to chop
	DT      = (uint8_t*)_mm_malloc(padded_MSG_byte_len, 64);	//buffer for decrypted text
	secureBuffer = (uint8_t*)_mm_malloc(16*16, 64);	
	
	init_buffers(total_blocks, init_MSG_bit_len, init_AAD_bit_len, 
				BIG_BUF,
				LENBLK,
				SINGLE_KEY, 
				K, H, IV, 
				AND_MASK);
	
#ifdef DETAILS	
	print_lengths(init_AAD_byte_len, 
				  init_AAD_bit_len, 
				  init_MSG_byte_len, 
				  init_MSG_bit_len, 
				  padded_AAD_byte_len,
				  padded_MSG_byte_len, 
				  L1, L2);
	
	#ifndef LITTLE_ENDIAN_			  
	print_buffers_BE(init_AAD_byte_len, 
					padded_AAD_byte_len, 
					init_MSG_byte_len, 
					total_blocks,
					SINGLE_KEY,
					K,H,IV,
					BIG_BUF); 
	#else
	print_buffers_LE(init_AAD_byte_len, 
					padded_AAD_byte_len, 
					init_MSG_byte_len, 
					total_blocks,
					SINGLE_KEY,
					K,H,IV,
					BIG_BUF); 
	#endif
					
#endif	


		INIT_Htable(Htbl, H);
	
//*********************************** START - ENCRYPT **********************************************	
#ifdef COUNT
	//ENCRYPT
	#ifndef DEC
	MEASURE({
	#endif
#endif


	
	if (total_blocks <= 8) { //HORNER
	
		Polyval_Horner(T, H, BIG_BUF, total_blocks);                                            //T = POLYVAL(padded_AADAAD||padded_MSG||LENBLK)
		*((__m128i*)TxorIV) = _mm_xor_si128(*((__m128i*)IV), *((__m128i*)T));                   //TxorIV
		*((__m128i*)TxorIV_masked) = _mm_and_si128(*((__m128i*)AND_MASK), *((__m128i*)TxorIV));	//TxorIV_masked = [0]TxorIV[120..0]  (MS bit is cleared)
		AES256_KS_ENC_x1(IV, ENC_KEY+16 , (unsigned char *)&KS, K);    		//ENC_KEY = AES_K (IV)
		ECB_ENC_block(ENC_KEY+16, ENC_KEY, (unsigned char *)&KS);
		AES256_KS_ENC_x1(TxorIV_masked, TAG,(unsigned char *)&KS, ENC_KEY);                     //TAG = AES_ENC_KEY (TxorIV_masked)
		ENC_MSG_x4(BIG_BUF+L1*16, CT, TAG, (unsigned char *)&KS, padded_MSG_byte_len);			//CT = AES_K (CTRBLCK) xor MSG		
	
	}
	else { //Htable
		
		#ifdef WITH_INIT
		INIT_Htable(Htbl, H);
		#endif
		Polyval_Htable(Htbl, BIG_BUF, total_blocks*16, T);										//T = POLYVAL(padded_AADAAD||padded_MSG||LENBLK)
		*((__m128i*)TxorIV) = _mm_xor_si128(*((__m128i*)IV), *((__m128i*)T));					//TxorIV
		*((__m128i*)TxorIV_masked) = _mm_and_si128(*((__m128i*)AND_MASK), *((__m128i*)TxorIV));	//TxorIV_masked = [0]TxorIV[120..0]  (MS bit is cleared)
		//AES_KS_ENC_x1(TxorIV_masked, TAG, 16, (unsigned char *)&KS, K);							//TAG = AES_K (TxorIV_masked)
		AES256_KS_ENC_x1(IV, ENC_KEY+16 , (unsigned char *)&KS, K);    		//ENC_KEY = AES_K (IV)
		ECB_ENC_block(ENC_KEY+16, ENC_KEY, (unsigned char *)&KS);                               //ENC_KEY = AES_K (IV)
		AES256_KS_ENC_x1(TxorIV_masked, TAG, (unsigned char *)&KS, ENC_KEY);                                //TAG = AES_ENC_KEY (TxorIV_masked)
		ENC_MSG_x8(BIG_BUF+L1*16, CT, TAG, (unsigned char *)&KS, padded_MSG_byte_len);			//CT = AES_K (CTRBLCK) xor MSG		
	}
	
	
#ifdef COUNT
	#ifndef DEC
	});
	#endif
#endif

//*********************************** END - ENCRYPT **********************************************	
	
		
#ifdef DETAILS
	#ifndef LITTLE_ENDIAN_
	print_res_buffers_BE(init_AAD_byte_len, init_MSG_byte_len,
						H, K, T, TxorIV, TxorIV_masked,	TAG, BIG_BUF, CT); 	
	printf("Encryption_Key =                ");print_buffer_BE(ENC_KEY,32);
	
	#else
	print_res_buffers_LE(init_AAD_byte_len, init_MSG_byte_len,
						H, K, T, TxorIV, TxorIV_masked,	TAG, BIG_BUF, CT);
	printf("Encryption_Key =                ");print_buffer_LE(ENC_KEY,32);
	
	#endif
#endif


	
	INIT_Htable_6(Htbl, H);
	
	
//*********************************** START - DECRYPT **********************************************	
	
#ifdef COUNT			
	//DECRYPT
	#ifdef DEC
	MEASURE({
	#endif
#endif


	
	#ifdef WITH_INIT

	INIT_Htable_6(Htbl, H);
	#endif
	AES256_KS_ENC_x1(IV, ENC_KEY+16 , (unsigned char *)&KS, K);    		//ENC_KEY = AES_K (IV)
	ECB_ENC_block(ENC_KEY+16, ENC_KEY, (unsigned char *)&KS);	
	AES_256_KS(ENC_KEY, (unsigned char *)&KS_dec);
	
	
	Polyval_Horner(POLYVAL_dec, H, BIG_BUF, L1);													//POLYVAL(padded_AAD)
	Decrypt_Htable(CT, DT, POLYVAL_dec, TAG, Htbl, (unsigned char *)&KS_dec, padded_MSG_byte_len, secureBuffer);
	Polyval_Horner(POLYVAL_dec, H, LENBLK, 1);														//POLYVAL(padded_AAD||padded_MSG||LENBLK)
	//Calculate TAG_dec
	*((__m128i*)POLYVAL_dec) = _mm_xor_si128(*((__m128i*)IV), *((__m128i*)POLYVAL_dec));			//POLYVAL xor IV
	*((__m128i*)POLYVAL_dec) = _mm_and_si128(*((__m128i*)AND_MASK), *((__m128i*)POLYVAL_dec));		//MSbit cleared
	ECB_ENC_block(POLYVAL_dec, TAG_dec, (unsigned char *)&KS_dec);									//TAG_dec = AES_K (POLYVAL_masked)

	
#ifdef COUNT	
	#ifdef DEC
	});
	#endif
#endif
//*********************************** END - DECRYPT **********************************************	

#ifdef DEC
// upon tag mismatch, the output is a copy of the input ciphertext (and a mismatch indicator)
	if (memcmp(TAG, TAG_dec, 16) != 0)
	{
		for (i=0; i<padded_MSG_byte_len; i++)
		{
			DT[i] = CT[i];
		}
	}
#ifdef ADD_INFO
#ifdef DETAILS	

	printf("\nPerforming Decryption and\nAuthentication:\n\n");
	#ifndef LITTLE_ENDIAN_
	printf("Decrypted MSG =                 "); print_buffer_BE(DT, init_MSG_byte_len);
	printf("\nTAG' =                          "); print16_BE(TAG_dec);
	#ifdef ADD_INFO
	if (memcmp(TAG, TAG_dec, 16) == 0) {
		printf("\nTAG comparison PASSED!!!\n");
	}
	else {
		printf("\nTAG comparison FAILED!!!\n");
	}
	#endif
	#else
	printf("Decrypted MSG =                 "); print_buffer_LE(DT, init_MSG_byte_len);
	printf("\nTAG' =                          "); print16_LE(TAG_dec);
	#ifdef ADD_INFO
	if (memcmp(TAG, TAG_dec, 16) == 0) {
		printf("\nTAG comparison PASSED!!!\n");
	}
	else {
		printf("\nTAG comparison FAILED!!!\n");
	}
	#endif
	#endif
#endif	
#endif	
#endif

#ifdef DETAILS
		    printf("\n***************************\n");
		      printf("         APPENDIX          \n");
		      printf("***************************\n");
		printf("KEY_SCHEDULE (Encryption_Key)   ");
		#ifndef LITTLE_ENDIAN_
		#ifdef DEC
		print_buffer_BE((unsigned char *)&KS_dec, 16*15);
		#else
		print_buffer_BE((unsigned char *)&KS, 16*15);
		#endif
		#ifdef ADD_INFO
		#ifdef DEC
		if (total_blocks > 6) {
			printf("\nHTABLE for aggregated POLYVAL \nH^j * x^(-128(j-1)) mod Q       ");
			print_buffer_BE(Htbl, 16*6);
		}
		#else
		if (total_blocks > 8) {
			printf("\nHTABLE for aggregated POLYVAL \nH^j * x^(-128(j-1)) mod Q       ");
			print_buffer_BE(Htbl, 16*8);
		}
		#endif
		#endif
		printf("\nCTRBLKS (with MSbit set to 1)\n");
		print_counters_from_TAG_BE(TAG, padded_MSG_byte_len/16);
		#else
		#ifdef DEC
		print_buffer_LE((unsigned char *)&KS_dec, 16*15);
		#else
		print_buffer_LE((unsigned char *)&KS, 16*15);
		#endif
		if (total_blocks > 8) {
		printf("\nHTABLE for aggregated POLYVAL \nH^j * x^(-128(j-1)) mod Q       ");
		print_buffer_LE(Htbl, 16*8);
		}
		printf("\nCTRBLKS (with MSbit set to 1)        ");
		print_counters_from_TAG_LE(TAG, padded_MSG_byte_len/16);
		#endif
		
 #endif
 #ifdef RDTSC
 #ifdef COUNT
		#ifdef DETAILS
		printf("\n\n****************************************************\n");
		printf("*************** PERFORMANCE ************************\n");
		printf("Best result for %d bytes (padded AAD + padded MSG): \n", (L1+L2)*16);
		printf("Cycles: %.0f\n", RDTSC_total_clk);
		printf("Cycles/Byte: %.2f\n", RDTSC_total_clk/((L1+L2)*16));
		#else
		//printf("%.0f\n", RDTSC_total_clk);
		printf("Cycles = %.0f  C/B = %.2f\n", RDTSC_total_clk, RDTSC_total_clk/((L1+L2)*16));
		#endif
 #endif
#endif

	_mm_free(BIG_BUF);
	_mm_free(CT);
	_mm_free(DT);
	_mm_free(secureBuffer);
}



//**********************************************************************
//Functions
void print16_BE(uint8_t *in) {
	int i;
	for(i=0; i<16; i++)
	{
		printf("%02x", in[i]);
	}
	printf("\n");
}	

void print16_LE(uint8_t *in)
{
	int i;
	for (i=15; i>=0; i--)
	{
		printf("%02x", in[i]);
	}
	printf("\n");
}

void print_buffer_LE(uint8_t *in, int length)
{
   int i;
   if (length == 0) {
		printf("\n");
		return;
	}
   for(i=0; i<length/16; i++)
   {
	  if (i!=0) printf("                                ");
      print16_LE(&in[i*16]);
   }

   if(i*16<length)
   {
      int last=i*16;
	  if (length > 16) printf("                                ");
	  for (i=last+16;i>length;i--)
	  {
	    printf("  ");
	  }
      for(i=length-1; i>=last; i--)
      {
         printf("%02x", in[i]);
      }
   printf("\n");
   }
}

void print_buffer_BE(uint8_t *in, int length)
{
   int i;
   if (length == 0) {
		printf("\n");
		return;
	}
   for(i=0; i<length/16; i++)
   {
      if (i!=0) printf("                                ");
	  print16_BE(&in[i*16]);
   }

   if(i*16<length)
   {
      if (length > 16) printf("                                ");
      for(i=i*16; i<length; i++)
      {
         printf("%02x", in[i]);
      }
   printf("\n");
   }
}

void print_counters_from_TAG_BE(uint8_t *in, int num_of_counters)
{
   int i,j;
   uint32_t count=0;
   in[15] |= 0x80;
   if (num_of_counters == 0) {
		printf("\n");
		return;
	}
   printf("\n");
   ((uint8_t*)&count)[0] = in[0];
   ((uint8_t*)&count)[1] = in[1];
   ((uint8_t*)&count)[2] = in[2];
   ((uint8_t*)&count)[3] = in[3];
   for(i=0; i<num_of_counters; i++)
   {
	  printf("                                ");
	  if (count<256)
		printf("%02x000000",((uint8_t*)&count)[0]);
	  else
		if (count<(1<<16))
		{
			printf("%02x%02x0000",((uint8_t*)&count)[0],((uint8_t*)&count)[1]);
		}
	    else
	      if (count<(1<<24))
		    printf("%02x%02x%02x00",((uint8_t*)&count)[0], ((uint8_t*)&count)[1], ((uint8_t*)&count)[2]);
		  else
		    printf("%02x%02x%02x%02x",((uint8_t*)&count)[0], ((uint8_t*)&count)[1], ((uint8_t*)&count)[2], ((uint8_t*)&count)[3]);
	  for(j=4; j<16; j++) {
		printf("%02x", in[j]);
	  }
	printf("\n");
	count++;
   }
}

void print_counters_from_TAG_LE(uint8_t *in, int num_of_counters)
{
   int i,j;
   uint32_t count=0;
   in[15] |= 0x80;
   if (num_of_counters == 0) {
		printf("\n");
		return;
	}
   printf("\n");
   ((uint8_t*)&count)[0] = in[0];
   ((uint8_t*)&count)[1] = in[1];
   ((uint8_t*)&count)[2] = in[2];
   ((uint8_t*)&count)[3] = in[3];
   for(i=0; i<num_of_counters; i++)
   {
	  printf("                                ");

	  for(j=15; j>=4; j--) {
		printf("%02x", in[j]);
	  }
      if (count<256)
		  printf("000000%02x",count++);
	  else
		  if (count<(1<<16))
			printf("0000%04x",count++);
	      else
	        if (count<(1<<24))
		      printf("00%06x",count++);
		    else
		      printf("%08x",count++);
	printf("\n");
	  
   }
}

void doXOR(uint8_t *out, uint8_t *a, uint8_t *b, int bytes) {
	int i;
	for(i=0; i<bytes; i++) {
		out[i] = a[i] ^ b[i];
	}
}

void init_lengths(int init_AAD_byte_len, int init_MSG_byte_len, int* init_AAD_bit_len, int* init_MSG_bit_len, 
				int* padded_AAD_byte_len, int* padded_MSG_byte_len, int* total_blocks, int* L1, int* L2)
{
	*init_AAD_bit_len = init_AAD_byte_len * 8;
	*init_MSG_bit_len = init_MSG_byte_len * 8;
	*L1 = init_AAD_byte_len/16;
	*L2 = init_MSG_byte_len/16;
	if ((init_AAD_byte_len % 16) != 0) (*L1)++;
	if ((init_MSG_byte_len % 16) != 0) (*L2)++;
	*padded_AAD_byte_len = (*L1) * 16;
	*padded_MSG_byte_len = (*L2) * 16;
	*total_blocks = *L1+*L2+1;
}

void init_buffers(int total_blocks, int init_MSG_bit_len, int init_AAD_bit_len, 
				unsigned char* BIG_BUF, 
				unsigned char* LENBLK,
				unsigned char* SINGLE_KEY, 
				unsigned char* K, 
				unsigned char* H, 
				unsigned char* IV, 

				unsigned char* AND_MASK) 
{
	int i, j;
	for(i=0; i<16; i++) {
		SINGLE_KEY[i] = 0;
		SINGLE_KEY[i+16] = 0;
		K[i] 	= 0;
		K[i+16] = 0;
		H[i] 	= 0;
		IV[i] 	= 0;
		AND_MASK[i] = 255;
	}
	SINGLE_KEY[0] = 3;
	K[0]=1;
	H[0]=3;
	IV[0]=3;
	AND_MASK[15] = 127;		//AND_MASK= 011111..11

	
	//Init BIG_BUFFER: [00..1][00..2]...[len-block]
	for(i=0; i< total_blocks*16; i++) {
		BIG_BUF[i] = 0;
	}
	//INIT LENBLK
	((uint64_t*)LENBLK)[1]=init_MSG_bit_len;
	((uint64_t*)LENBLK)[0]=init_AAD_bit_len;
	
	((uint64_t*)BIG_BUF)[2*total_blocks-2]=init_AAD_bit_len;
	((uint64_t*)BIG_BUF)[2*total_blocks-1]=init_MSG_bit_len;
	
	//INIT the rest
	for(j=1, i=0; i < (total_blocks-1)*16; i++) {
		if (i % 16 == 0) {
			BIG_BUF[i] = j++;
		}
	}
	//HERE the buffer looks like:  [00..1][00..2]...[len-block]			
				
}

void print_lengths(int init_AAD_byte_len, 
				  int init_AAD_bit_len, 
				  int init_MSG_byte_len, 
				  int init_MSG_bit_len, 
				  int padded_AAD_byte_len,
				  int padded_MSG_byte_len, 
				  int L1, int L2)
{

	printf("\n\n--------------------- TWO_KEYS     (AAD = %d, MSG = %d)---------\n\n", init_AAD_byte_len, init_MSG_byte_len);
	printf("AAD_byte_len = %d\n", init_AAD_byte_len);
	printf("AAD_bit_len  = %d\n", init_AAD_bit_len);
	printf("MSG_byte_len = %d\n", init_MSG_byte_len);
	printf("MSG_bit_len  = %d\n", init_MSG_bit_len);
	printf("padded_AAD_byte_len = %d\n", padded_AAD_byte_len);
	printf("padded_MSG_byte_len = %d\n", padded_MSG_byte_len);
	printf("L1 blocks AAD(padded)  = %d\n", L1);
	printf("L2 blocks MSG(padded)  = %d\n", L2);
}

void print_buffers_BE(int init_AAD_byte_len, 
					int padded_AAD_byte_len, 
					int init_MSG_byte_len, 
					int total_blocks,
					unsigned char*SINGLE_KEY,
					unsigned char*K,
					unsigned char*H,
					unsigned char*IV,
					unsigned char*BIG_BUF) 
{
	
	printf("                                            BYTES ORDER         \n");
	#ifndef LITTLE_ENDIAN_
	printf("                                LSB--------------------------MSB\n");
	printf("                                00010203040506070809101112131415\n");
	#else	
	printf("                                MSB--------------------------LSB\n");
	printf("                                15141312111009080706050403020100\n");
	#endif
	printf("                                --------------------------------\n");

	

		printf("K1 = H =                        "); print16_BE(H);
		printf("K2 = K =                        "); print_buffer_BE(K,32);

		printf("NONCE =                         "); print16_BE(IV);
	  printf("AAD =                           ");print_buffer_BE(BIG_BUF, init_AAD_byte_len);
		printf("MSG =                           ");print_buffer_BE(BIG_BUF+padded_AAD_byte_len, init_MSG_byte_len);
	  printf("PADDED_AAD_and_MSG =            ");print_buffer_BE(BIG_BUF, (total_blocks-1)*16);
	  printf("LENBLK =                        "); print_buffer_BE(BIG_BUF+(total_blocks-1)*16, 16);
		

		printf("\nComputing POLYVAL on a\nbuffer of %d blocks + LENBLK.\n", total_blocks-1);


}

void print_buffers_LE(int init_AAD_byte_len, 
					int padded_AAD_byte_len, 
					int init_MSG_byte_len, 
					int total_blocks,
					unsigned char*SINGLE_KEY,
					unsigned char*K,
					unsigned char*H,
					unsigned char*IV,
					unsigned char*BIG_BUF) 
{

	printf("                                            BYTES ORDER         \n");
	printf("                                MSB--------------------------LSB\n");
	printf("                                15141312111009080706050403020100\n");
	printf("                                --------------------------------\n");

		printf("K1 = H =                        "); print16_LE(H);
		printf("K2 = K =                        "); print_buffer_LE(K,32);

		printf("NONCE =                         "); print16_LE(IV);
	    printf("AAD =                           ");print_buffer_LE(BIG_BUF, init_AAD_byte_len);
		printf("MSG =                           ");print_buffer_LE(BIG_BUF+padded_AAD_byte_len, init_MSG_byte_len);
	    printf("PADDED_AAD_and_MSG =            ");print_buffer_LE(BIG_BUF, (total_blocks-1)*16);
	    printf("LENBLK =                        "); print_buffer_LE(BIG_BUF+(total_blocks-1)*16, 16);
		

		printf("\nComputing POLYVAL on a\nbuffer of %d blocks + LENBLK.\n", total_blocks-1);


}

void print_res_buffers_BE(int init_AAD_byte_len, int init_MSG_byte_len,
							unsigned char* H,
							unsigned char* K,
							unsigned char* T,
							unsigned char* TxorIV,
							unsigned char* TxorIV_masked,
							unsigned char* TAG,
							unsigned char* BIG_BUF,
							unsigned char* CT)
{

	
	printf("POLYVAL =                       "); print_buffer_BE(T,16);
	printf("POLYVAL_xor_NONCE  =            "); print_buffer_BE(TxorIV,16);
	printf("with MSBit cleared =            "); print16_BE(TxorIV_masked);
	printf("TAG =                           "); print16_BE(TAG);
	printf("AAD =                           ");print_buffer_BE(BIG_BUF, init_AAD_byte_len);
	printf("CT  =                           "); print_buffer_BE(CT, init_MSG_byte_len);
}							
							
void print_res_buffers_LE(int init_AAD_byte_len, int init_MSG_byte_len,
							unsigned char* H,
							unsigned char* K,
							unsigned char* T,
							unsigned char* TxorIV,
							unsigned char* TxorIV_masked,
							unsigned char* TAG,
							unsigned char* BIG_BUF,
							unsigned char* CT)
{

	
	printf("POLYVAL =                       "); print_buffer_LE(T,16);
	printf("POLYVAL_xor_NONCE  =            "); print_buffer_LE(TxorIV,16);
	printf("with MSBit cleared =            "); print16_LE(TxorIV_masked);
	printf("TAG =                           "); print16_LE(TAG);
	printf("AAD =                           ");print_buffer_LE(BIG_BUF, init_AAD_byte_len);
	printf("CT  =                           "); print_buffer_LE(CT, init_MSG_byte_len);
}							







