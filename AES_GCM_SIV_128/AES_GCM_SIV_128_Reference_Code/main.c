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
#include <stdlib.h>
#include <stdio.h>

#if !defined (ALIGN16)
#if defined (__GNUC__)
#  define ALIGN16  __attribute__  ( (aligned (16)))
# else
#  define ALIGN16 __declspec (align (16))
# endif
#endif

#ifndef ALEN
#define ALEN 0
#endif
#ifndef MLEN
#define MLEN 256
#endif


#define SUCCESS 1
#define SINGLE_KEY 0
#define TWO_KEYS 1


void print16(uint8_t *in);
void print_buffer(uint8_t *in, int length);
void rand_vec(uint8_t *in, int length);
void init_buffers(uint8_t* PLAINTEXT, uint8_t* AAD, uint8_t* K1, uint8_t* N, uint64_t aad_len, 
				  uint64_t in_len, uint64_t aad_pad, uint64_t msg_pad);
void print_buffers(uint8_t* PLAINTEXT, uint8_t* AAD, uint8_t* K1, uint8_t* N, uint64_t aad_len, 
                   uint64_t in_len, uint64_t aad_pad, uint64_t msg_pad, int flag);


				
void SIV_GCM_ENC_2_Keys(uint8_t* CT, 				// Output
						uint8_t TAG[16], 			// Output
						uint8_t K1[16], 
						uint8_t K2[16],
						uint8_t N[16],
						uint8_t* AAD, 
						uint8_t* MSG, 
						uint64_t AAD_len, 
						uint64_t MSG_len);
				
int SIV_GCM_DEC_2_Keys(uint8_t* MSG, 				// Output
						uint8_t TAG[16], 			
						uint8_t K1[16], 
						uint8_t K2[16],
						uint8_t N[16],
						uint8_t* AAD, 
						uint8_t* CT, 
						uint64_t AAD_len, 
						uint64_t CT_len);



						
int main(int argc, char *argv[])
{   
 	uint8_t *PLAINTEXT = NULL;
    uint8_t *AAD = NULL;
    uint8_t *CIPHERTEXT = NULL;
    uint8_t *decrypted_CT = NULL;
	
	uint8_t TAG[16] = {0};
	uint8_t K1[16] = {0};
	uint8_t N[16] = {0};
	int i = 0;
	int res = 0;
	uint64_t aad_len, in_len;
	uint64_t msg_pad = 0;
	uint64_t aad_pad = 0;
    
	//Get Input
	if(argc == 1 || argc == 2) {
      aad_len = ALEN;
	  in_len  = MLEN;
    }
	else if (argc >= 3) {
      aad_len = atoi(argv[1]);
	  in_len  = atoi(argv[2]);
	}
	
	if ((aad_len % 16) != 0) {
		aad_pad = 16 - (aad_len % 16);
	}
	if ((in_len % 16) != 0) {
		msg_pad = 16 - (in_len % 16);
	}
		
	PLAINTEXT = 	 (uint8_t*)malloc(in_len + msg_pad);
    CIPHERTEXT = 	 (uint8_t*)malloc(in_len + msg_pad);
    decrypted_CT = 	 (uint8_t*)malloc(in_len + msg_pad);
    AAD =  			 (uint8_t*)malloc(aad_len + aad_pad);
	for (i=0; i<(in_len+msg_pad); i++)
	{
		CIPHERTEXT[i] = 0;
		decrypted_CT[i] = 0;
	}	
#ifdef DETAILS	
	init_buffers(PLAINTEXT, AAD, K1, N, aad_len, in_len, aad_pad, msg_pad);
	printf("*****************************");
	printf("\nPerforming SIV_GCM - Two Keys:");
	printf("\n*****************************\n\n");
	printf("AAD_len = %d bytes\n", aad_len);
	printf("MSG_len = %d bytes\n", in_len);
	print_buffers(PLAINTEXT, AAD, K1, N, aad_len, in_len, aad_pad, msg_pad, TWO_KEYS);
#else
	int count;
	for (i=0; i<(aad_len+aad_pad); i++)
		AAD[i] = 0;
	for (count = 0; count < 40; count ++) {
		printf("Random test number %d:\n", count+1);
		rand_vec(PLAINTEXT, in_len);
		rand_vec(K1, 16);
		rand_vec(&N[4], 12);
#endif
	
//Check SIV_GCM 2 keys	
	GCM_SIV_ENC_2_Keys(CIPHERTEXT, TAG, K1, N, AAD, PLAINTEXT, aad_len, in_len);
	res = GCM_SIV_DEC_2_Keys(decrypted_CT, TAG, K1, N, AAD, CIPHERTEXT, aad_len, in_len);
	
#ifdef DETAILS	
	printf("\nAAD =                           "); print_buffer(AAD, aad_len);
	printf("\nCIPHERTEXT =                    "); print_buffer(CIPHERTEXT, in_len);
	printf("\nDecrypted MSG =                 "); print_buffer(decrypted_CT, in_len);
#endif
	
	if (res == SUCCESS && (memcmp(PLAINTEXT, decrypted_CT, in_len) == 0)) {
		printf("SIV_GCM_2_KEYS Passed\n");
	}
	else {
		printf("SIV_GCM_2_KEYS Failed\n");
	}
 
	free(PLAINTEXT);
    free(CIPHERTEXT);
    free(decrypted_CT);
    free(AAD);
 
}

//**************************************************************************************
void rand_vec(uint8_t *in, int length)
{
   int i;
   for(i=0; i<length; i++)
   {
	   in[i] = i+1;//rand()%256;
   }
}

void print16(uint8_t *in) {
	int i;
	for(i=0; i<16; i++)
	{
		#ifdef LE
		printf("%02x", in[15-i]);
		#else
		printf("%02x", in[i]);
		#endif
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
      print16(&in[i*16]);
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
      print16(&in[i*16]);
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

void print_buffer(uint8_t *in, int length)
{
   #ifdef LE
   print_buffer_LE(in, length);
   #else
   print_buffer_BE(in ,length);
   #endif
}


void init_buffers(uint8_t* PLAINTEXT, uint8_t* AAD, uint8_t* K1, uint8_t* N, 
				  uint64_t aad_len, uint64_t in_len, uint64_t aad_pad, uint64_t msg_pad)
{
	int i, j;
	for(i=0; i<16; i++) {
		K1[i] = 0;
		N[i] 	= 0;
	}
	K1[0]=1;
	N[0]=3;
	
	//Init AAD [00..1][00..2]...[000 aad_len]
	for(j=1, i=0; i < aad_len + aad_pad; i++) {
		AAD[i] = 0;
		if (i % 16 == 0) {
			AAD[i] = j++;
		}
	}

	//Init PT [00..aad_len+1][00..aad_len+2]...[000 aad_len+in_len]
	for(i=0; i < in_len + msg_pad; i++) {
		PLAINTEXT[i] = 0;
		if (i % 16 == 0) {
			PLAINTEXT[i] = j++;
		}
	}
	
}

void print_buffers(uint8_t* PLAINTEXT, uint8_t* AAD, uint8_t* K1, uint8_t* N, 
					uint64_t aad_len, uint64_t in_len, uint64_t aad_pad, uint64_t msg_pad, int flag)
{
	printf("                                            BYTES ORDER         \n");
	#ifndef LE
	printf("                                LSB--------------------------MSB\n");
	printf("                                00010203040506070809101112131415\n");
	#else
	printf("                                MSB--------------------------LSB\n");
	printf("                                15141312111009080706050403020100\n");
	#endif
	printf("                                --------------------------------\n\n");
	
	if (flag == SINGLE_KEY) {
		printf("SINGLE_KEY=                     "); print16(K1);
	}
	else {
		printf("K1 = K =                        "); print16(K1);
	}
	
	printf("NONCE =                         "); print_buffer(N,12);
	printf("\nAAD =                           "); print_buffer(AAD, aad_len);
	printf("\nMSG =                           "); print_buffer(PLAINTEXT, in_len);
	printf("\nPADDED_AAD =                    "); print_buffer(AAD, aad_len + aad_pad);
	printf("\nPADDED_MSG =                    "); print_buffer(PLAINTEXT, in_len + msg_pad);
}

















