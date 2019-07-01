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
//#define XOR_WITH_NONCE

//****************************************************************************                 
int main(int argc, char *argv[])
{
  //int L1=0, L2=0;
    //int init_AAD_bit_len=0;
    //int init_MSG_bit_len=0;
    int init_AAD_byte_len=0; // L1
    int init_MSG_byte_len=0; //L2
    //int padded_MSG_byte_len=0;
    //int padded_AAD_byte_len=0;  
    int total_blocks=0; 
    //int i=0;
    //int enc_dec_flag=0;
	  unsigned char *AAD = NULL;
    unsigned char *PT = NULL;
    unsigned char *CT = NULL;
    unsigned char *DT = NULL;
    int result =0;
    uint8_t K[32]={0};
    uint8_t IV[16]={0};
    uint8_t TAG[16]={0};

	AES_GCM_SIV_CONTEXT ctx;
    // variables for printing
    uint8_t LENBLK[16]={0};
#ifdef DETAILS
    uint8_t* Record_Hash_Key = (ctx.details_info+20*16);
	uint8_t* Record_Enc_Key = ctx.details_info+21*16;
	//uint8_t* Record_Hash_Key_DEC = ctx.details_info+43*16;
	//uint8_t* Record_Enc_Key_DEC = ctx.details_info+44*16;
	uint8_t* T = ctx.details_info+16*16;
	//uint8_t* T_DEC = ctx.details_info+39*16;
#ifdef DEC
	uint8_t* TAG_D = ctx.details_info+42*16;
#endif /* DEC */
#endif /* DETAILS */
    //Get Input
    if(argc == 1 || argc == 2) {
      init_AAD_byte_len = 0;
      init_MSG_byte_len = LENGTH;
    }
    else if (argc == 3) {
      init_AAD_byte_len = atoi(argv[1]);
      init_MSG_byte_len = atoi(argv[2]);
    }
    
    
    //Allocate and init buffers
	AAD= (uint8_t*)_mm_malloc(init_AAD_byte_len, 64);        //buffer for L1 bytes
    PT = (uint8_t*)_mm_malloc(init_MSG_byte_len, 64);        //buffer for L2 bytes
    CT      = (uint8_t*)_mm_malloc(init_MSG_byte_len, 64);    //buffer for L2 bytes
    DT      = (uint8_t*)_mm_malloc(init_MSG_byte_len, 64);    //buffer for decrypted text
    init_buffers(AAD, init_AAD_byte_len, PT, CT, DT, init_MSG_byte_len, K, IV, LENBLK);
	total_blocks = ((init_AAD_byte_len/16)*16+(init_MSG_byte_len/16)*16+16)/16;
	AES_GCM_SIV_Init(&ctx, K);
    
//*********************************** START - ENCRYPT **********************************************    
#ifdef COUNT
    //ENCRYPT
#ifndef DEC
    MEASURE({
#endif /* DEC */
#endif /* COUNT */
	AES_GCM_SIV_Encrypt(&ctx, CT, TAG, AAD, PT, init_AAD_byte_len, init_MSG_byte_len, IV, K);
#ifdef COUNT
    #ifndef DEC
    });
#endif /* DEC */
#endif /* COUNT */

//*********************************** END - ENCRYPT **********************************************  

#ifdef DETAILS
    print_lengths(init_AAD_byte_len,
                  init_MSG_byte_len);

#ifndef LITTLE_ENDIAN_            
    print_buffers_BE(init_AAD_byte_len, 
                    init_MSG_byte_len, 
                    K,Record_Hash_Key,IV,
                    AAD, PT, LENBLK);
    print_res_buffers_BE(init_AAD_byte_len, init_MSG_byte_len,
                         Record_Hash_Key, K, T, T+16, T+32, TAG, AAD, CT);  
    printf("Encryption_Key=                 ");print_buffer_BE(Record_Enc_Key, 32);
#else
    print_buffers_LE(init_AAD_byte_len, 
                    init_MSG_byte_len, 
                    K,Record_Hash_Key,IV,
                    AAD, PT, LENBLK); 
    print_res_buffers_LE(init_AAD_byte_len, init_MSG_byte_len,
                        Record_Hash_Key, K, T, T+16, T+32, TAG, AAD, CT);
    printf("Encryption_Key=                 ");print_buffer_LE(Record_Enc_Key, 32);
#endif /* LITTLE_ENDIAN_ */
#endif /* DETAILS */

	AES_GCM_SIV_Init(&ctx, K);



//*********************************** START - DECRYPT **********************************************    
#ifdef COUNT
    //DECRYPT
#ifdef DEC
    MEASURE({
#endif /* DEC */
#endif /* COUNT */
	result = AES_GCM_SIV_Decrypt(&ctx, DT, TAG, AAD, CT, init_AAD_byte_len, init_MSG_byte_len, IV, K);

#ifdef COUNT
#ifdef DEC
    });
#endif /* DEC */
#endif /* COUNT */
//*********************************** END - DECRYPT **********************************************  
	Clear_SIV_CTX(&ctx);

#ifdef DEC
// upon tag mismatch, the output is a copy of the input ciphertext (and a mismatch indicator)

#ifdef DETAILS
    printf("\nPerforming Decryption and\nAuthentication:\n\n");
#ifndef LITTLE_ENDIAN_
    printf("Decrypted MSG =                 "); print_buffer_BE(DT, init_MSG_byte_len);
    printf("\nTAG' =                          "); print16_BE(TAG_D);
#ifdef ADD_INFO
    if (result == 0) {
        printf("\nTAG comparison PASSED!!!\n");
    }
    else {
        printf("\nTAG comparison FAILED!!!\n");
    }
#endif /* ADD_INFO */
#else /* LITTLE_ENDIAN_ */
    printf("Decrypted MSG =                 "); print_buffer_LE(DT, init_MSG_byte_len);
    printf("\nTAG' =                          "); print16_LE(TAG_D);
#ifdef ADD_INFO
    if (result == 0) {
        printf("\nTAG comparison PASSED!!!\n");
    }
    else {
        printf("\nTAG comparison FAILED!!!\n");
    }
#endif /* AAD_INFO */
#endif /* LITTLE_ENDIAN_ */
#endif /* DETAILS */
#endif /* DEC */

#ifdef DETAILS
            printf("\n***************************\n");
              printf("         APPENDIX          \n");
              printf("***************************\n");
        printf("KEY_SCHEDULE (Encryption_Key)   ");
#ifndef LITTLE_ENDIAN_
#ifndef DEC
        print_buffer_BE((unsigned char *)(ctx.details_info), 16*15);
#else /* DEC */
		print_buffer_BE((unsigned char *)(ctx.details_info+23*16), 16*15);
#endif /* DEC */
#ifdef ADD_INFO
#ifdef DEC
        if (total_blocks > 6) {
            printf("\nHTABLE for aggregated POLYVAL \nH^j * x^(-128(j-1)) mod Q       ");
            print_buffer_BE((ctx.details_info+46*16), 16*6);
        }
#else /* DEC */
        if (total_blocks > 8) {
            printf("\nHTABLE for aggregated POLYVAL \nH^j * x^(-128(j-1)) mod Q       ");
            print_buffer_BE((ctx.details_info+46*16), 16*8);
        }
#endif /* DEC */
#endif /* ADD_INFO */
        printf("\nCTRBLKS (with MSbit set to 1)\n");
        print_counters_from_TAG_BE(TAG, init_MSG_byte_len/16 + ((init_MSG_byte_len%16 ==0) ? 0 : 1));
#else /* LITTLE_ENDIAN_ */
#ifndef DEC
        print_buffer_LE((unsigned char *)(ctx.details_info), 16*15);
#else /* DEC */
		print_buffer_LE((unsigned char *)(ctx.details_info+23*16), 16*15);
#endif /* DEC */
        if (total_blocks > 8) {
        printf("\nHTABLE for aggregated POLYVAL \nH^j * x^(-128(j-1)) mod Q       ");
        print_buffer_LE((ctx.details_info+46*16), 16*8);
        }
        printf("\nCTRBLKS (with MSbit set to 1)        ");
        print_counters_from_TAG_LE(TAG, init_MSG_byte_len/16 + ((init_MSG_byte_len%16 ==0) ? 0 : 1));
#endif /* LITTLE_ENDIAN_ */

#endif /* DETAILS */

 #ifdef RDTSC
 #ifdef COUNT
#ifdef DETAILS
        printf("\n\n****************************************************\n");
        printf("*************** PERFORMANCE ************************\n");
        printf("Best result for %d bytes (padded AAD + padded MSG): \n", init_MSG_byte_len+init_AAD_byte_len);
        printf("Cycles: %.0f\n", RDTSC_total_clk);
        printf("Cycles/Byte: %.2f\n", RDTSC_total_clk/(init_MSG_byte_len+init_AAD_byte_len));
#else /* DETAILS */
        //printf("%.0f\n", RDTSC_total_clk);
        printf("Cycles = %.0f  C/B = %.2f\n", RDTSC_total_clk, RDTSC_total_clk/(init_MSG_byte_len+init_AAD_byte_len));
#endif /* DETAILS */
#endif /* COUNT */
#endif /* RDTSC */
	_mm_free(AAD);
    _mm_free(PT);
    _mm_free(CT);
    _mm_free(DT);
}



