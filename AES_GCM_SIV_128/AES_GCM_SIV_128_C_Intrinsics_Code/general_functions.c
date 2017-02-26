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


#define LENGTH (16)
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


void init_buffers(unsigned char* AAD, int init_AAD_byte_len, unsigned char* PT, unsigned char* CT, unsigned char* DT, int init_MSG_byte_len,
			unsigned char* K, unsigned char* IV, unsigned char* LENBLK)
{
	int i=0, j=0;
    for(i=0; i<16; i++) {
        K[i]    = 0;
        IV[i]   = 0;
    }
	K[0]=1;
    IV[0]=3;
	for(i=0; i< init_AAD_byte_len; i++) {
        AAD[i] = 0;
    }
	for(i=0; i< init_MSG_byte_len; i++) {
        CT[i] = 0;
		PT[i] = 0;
		DT[i] = 0;
    }
	for(j=1, i=0; i < init_AAD_byte_len; i++) {
        if (i % 16 == 0) {
            AAD[i] = j++;
        }
    }
	for(i=0; i < init_MSG_byte_len; i++) {
        if (i % 16 == 0) {
            PT[i] = j++;
        }
    }
	((uint64_t*)LENBLK)[1]=init_MSG_byte_len*8;
    ((uint64_t*)LENBLK)[0]=init_AAD_byte_len*8;
}


void print_lengths(int init_AAD_byte_len, 
                  int init_MSG_byte_len)
{

    printf("\n\n-----------------      (AAD = %d, MSG = %d)        --------------\n\n", init_AAD_byte_len, init_MSG_byte_len);
    printf("AAD_byte_len = %d\n", init_AAD_byte_len);
    printf("MSG_byte_len = %d\n", init_MSG_byte_len);
}

void print_buffers_BE(int init_AAD_byte_len, 
                    int init_MSG_byte_len, 
                    unsigned char*K,
                    unsigned char*H,
                    unsigned char*IV,
                    unsigned char*AAD,
					unsigned char*PT,
					unsigned char*LENBLK) 
{
    int A_blocks = ((init_AAD_byte_len % 16) == 0 ) ? init_AAD_byte_len/16 : (init_AAD_byte_len/16) +1;
	int M_blocks = ((init_MSG_byte_len % 16) == 0 ) ? init_MSG_byte_len/16 : (init_MSG_byte_len/16) +1;
    printf("                                            BYTES ORDER         \n");
    #ifndef LITTLE_ENDIAN_
    printf("                                LSB--------------------------MSB\n");
    printf("                                00010203040506070809101112131415\n");
    #else   
    printf("                                MSB--------------------------LSB\n");
    printf("                                15141312111009080706050403020100\n");
    #endif
    printf("                                --------------------------------\n");
    printf("K =                             "); print16_BE(K);
    printf("NONCE =                         "); print_buffer_BE(IV,12);
	printf("Record_Hash_Key =               "); print16_BE(H);
    printf("AAD =                           ");print_buffer_BE(AAD, init_AAD_byte_len);
    printf("MSG =                           ");print_buffer_BE(PT, init_MSG_byte_len);
    printf("LENBLK =                        "); print_buffer_BE(LENBLK, 16);

    printf("\nComputing POLYVAL on a\nbuffer of %d blocks + LENBLK.\n", A_blocks+M_blocks);

    
}

void print_buffers_LE(int init_AAD_byte_len, 
                    int init_MSG_byte_len, 
                    unsigned char*K,
                    unsigned char*H,
                    unsigned char*IV,
                    unsigned char*AAD,
					unsigned char*PT,
					unsigned char*LENBLK) 
{
	int A_blocks = ((init_AAD_byte_len % 16) == 0 ) ? init_AAD_byte_len/16 : (init_AAD_byte_len/16) +1;
	int M_blocks = ((init_MSG_byte_len % 16) == 0 ) ? init_MSG_byte_len/16 : (init_MSG_byte_len/16) +1;
    printf("                                            BYTES ORDER         \n");
    printf("                                MSB--------------------------LSB\n");
    printf("                                15141312111009080706050403020100\n");
    printf("                                --------------------------------\n");
    printf("K =                             "); print16_LE(K);
    printf("NONCE =                         "); print_buffer_LE(IV,12);
	printf("Record_Hash_Key =               "); print16_LE(H);
    printf("AAD =                           ");print_buffer_LE(AAD, init_AAD_byte_len);
    printf("MSG =                           ");print_buffer_LE(PT, init_MSG_byte_len);
    printf("LENBLK =                        "); print_buffer_LE(LENBLK, 16);
    printf("\nComputing POLYVAL on a\nbuffer of %d blocks + LENBLK.\n", A_blocks+M_blocks);

}

void print_res_buffers_BE(int init_AAD_byte_len, int init_MSG_byte_len,
                            unsigned char* H,
                            unsigned char* K,
                            unsigned char* T,
							unsigned char* TxorIV,
							unsigned char* TxorIV_MSB_Zeroed,
                            unsigned char* TAG,
                            unsigned char* AAD,
                            unsigned char* CT)
{
    
    printf("POLYVAL                         "); print_buffer_BE(T,16);
	printf("POLYVAL xor NONCE(N)            "); print_buffer_BE(TxorIV,16);
	printf("POLYVAL xor N & MSBit cleared   "); print_buffer_BE(TxorIV_MSB_Zeroed,16);
    printf("TAG =                           "); print16_BE(TAG);
    printf("AAD =                           ");print_buffer_BE(AAD, init_AAD_byte_len);
    printf("CT  =                           "); print_buffer_BE(CT, init_MSG_byte_len);
}                           
                            
void print_res_buffers_LE(int init_AAD_byte_len, int init_MSG_byte_len,
                            unsigned char* H,
                            unsigned char* K,
                            unsigned char* T,
							unsigned char* TxorIV,
							unsigned char* TxorIV_MSB_Zeroed,
                            unsigned char* TAG,
                            unsigned char* AAD,
                            unsigned char* CT)
{

    
    printf("POLYVAL                         "); print_buffer_LE(T,16);
	printf("POLYVAL xor NONCE(N)            "); print_buffer_LE(TxorIV,16);
	printf("POLYVAL xor N & MSBit cleared   "); print_buffer_LE(TxorIV_MSB_Zeroed,16);
    printf("TAG =                           "); print16_LE(TAG);
    printf("AAD =                           ");print_buffer_LE(AAD, init_AAD_byte_len);
    printf("CT  =                           "); print_buffer_LE(CT, init_MSG_byte_len);
}                           

