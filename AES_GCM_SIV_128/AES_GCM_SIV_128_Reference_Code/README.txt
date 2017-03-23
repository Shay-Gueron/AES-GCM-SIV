###############################################################################
# AES-GCM-SIV developers and authors:                                         #
#                                                                             #
# Shay Gueron,    University of Haifa, Israel and                             #
#                 Intel Corporation, Israel Development Center, Haifa, Israel #
# Adam Langley,   Google.                                                     #
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
# All rights reserved.                                                        #
#                                                                             #
# Permission to use this code is granted only for the purpose of evaluating   #
# AES-GCM-SIV.                                                                #
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

GENERAL_PURPOSE_SIV

To compile, use the makefile in 2 ways:
1. make DEF=-DDETAILS      - The executable will print outputs for 
                             according to provided parameters
2. make	                   - The executable will run 40 random tests

The compilation line is:
gcc -DDETAILS main.c SIV_GCM_c.c clmul_emulator.c aes_emulation.c aes_emulation_tables.c -o GCM_SIV_GENERAL

The parameters are: GCM_SIV_GENERAL A B
A - AAD length in bytes
B - MSG length in bytes

in SIV_GCM_c.c are implemented: 
1. POLYVAL, 
4. GCM_SIV_ENC_Keys
5. GCM_SIV_DEC_Keys



The output example:
*****************************
Performing SIV_GCM - Two Keys:
*****************************

AAD_len = 12 bytes
MSG_len = 34 bytes
                                            BYTES ORDER         
                                LSB--------------------------MSB
                                00010203040506070809101112131415
                                --------------------------------

K1 = H =                        03000000000000000000000000000000
K2 = K =                        01000000000000000000000000000000
NONCE =                         03000000000000000000000000000000

AAD =                           010000000000000000000000

MSG =                           02000000000000000000000000000000
                                03000000000000000000000000000000
                                0400

PADDED_AAD =                    01000000000000000000000000000000

PADDED_MSG =                    02000000000000000000000000000000
                                03000000000000000000000000000000
                                04000000000000000000000000000000

LENBLK =                        10010000000000006000000000000000

POLYVAL =                       6d02000000000040d900c04c63ad9807

POLYVAL_xor_NONCE =             6e02000000000040d900c04c63ad9807

with_MSbit_cleared =            6e02000000000040d900c04c63ad9807

TAG =                           7b01c2703733cd550145d99f1e36a3b0

CTRBLK =                        010000003733cd550145d99f1e36a3b0

TAG' =                          7b01c2703733cd550145d99f1e36a3b0

AAD =                           010000000000000000000000

CIPHERTEXT =                    b1d7eecccbc79d7327faf971603a7cf3
                                53569936ac2a97a7e9ef93997acb0ab8
                                06ae

Decrypted MSG =                 02000000000000000000000000000000
                                03000000000000000000000000000000
                                0400
SIV_GCM_2_KEYS Passed
