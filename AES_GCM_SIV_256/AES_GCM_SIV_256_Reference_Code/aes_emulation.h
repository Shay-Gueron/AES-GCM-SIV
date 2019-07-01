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
#ifndef AES_CORE_H_CMAC
#define AES_CORE_H_CMAC

#define NUM_OF_BYTES_IN_BLOCK 16

#include <stddef.h>
#include <inttypes.h>
#include <string.h>

typedef uint32_t _xmm[4];

typedef uint32_t aes128_key_schedule[44];
typedef uint32_t aes192_key_schedule[52];
typedef uint32_t aes256_key_schedule[60];


extern uint32_t emulated_aesenc_enc_table_0[256];
extern uint32_t emulated_aesenc_enc_table_1[256];
extern uint32_t emulated_aesenc_enc_table_2[256];
extern uint32_t emulated_aesenc_enc_table_3[256];
extern uint32_t emulated_aesenc_dec_table_0[256];
extern uint32_t emulated_aesenc_dec_table_1[256];
extern uint32_t emulated_aesenc_dec_table_2[256];
extern uint32_t emulated_aesenc_dec_table_3[256];
extern uint8_t  emulated_aesenc_rijndael_sbox[256];

void emulated_aesenc(_xmm _xmm1, _xmm _xmm2);
void emulated_aesenclast(_xmm _xmm1, _xmm _xmm2);

int emulated_aesenc_row_shifting(uint32_t *out);
int emulated_aesenc_substitute_bytes(uint32_t *out);

#endif
