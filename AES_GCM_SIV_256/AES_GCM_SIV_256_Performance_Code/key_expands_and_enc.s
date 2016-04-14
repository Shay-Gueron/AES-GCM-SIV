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

.align   16
mask:
.long    0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d
con1:
.long    1,1,1,1
con2:
.long    0x1b,0x1b,0x1b,0x1b
con3:
.byte -1,-1,-1,-1,-1,-1,-1,-1,4,5,6,7,4,5,6,7

#########################################################
#Regular Key Expansion no assist

.align    64
.globl AES_256_KS
AES_256_KS:
# parameter 1: %rdi
# parameter 2: %rsi

   movl   $14, 240(%rsi)

   vmovdqu (%rdi), %xmm1
   vmovdqu 16(%rdi), %xmm3
   vmovdqu %xmm1, (%rsi)
   vmovdqu %xmm3, 16(%rsi)
   vmovdqa (con1), %xmm0
   vmovdqa (mask), %xmm15
   vpxor %xmm14, %xmm14, %xmm14
   mov $6, %rax
LOOP_256_AVX:
    add $32, %rsi
    dec %rax
    vpshufb %xmm15, %xmm3, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld $1, %xmm0, %xmm0
    vpsllq $32, %xmm1, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpshufb (con3), %xmm1,  %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vmovdqu %xmm1, (%rsi)
    vpshufd $0xff, %xmm1, %xmm2
    vaesenclast %xmm14, %xmm2, %xmm2
    vpsllq $32, %xmm3, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpshufb (con3), %xmm3,  %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpxor %xmm2, %xmm3, %xmm3
    vmovdqu %xmm3, 16(%rsi)
    jne LOOP_256_AVX
    vpshufb %xmm15, %xmm3, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpsllq $32, %xmm1, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpshufb (con3), %xmm1,  %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vmovdqu %xmm1, 32(%rsi)
    ret

#########################################################
# Expand and encrypt one block

.macro ROUND_double i j
    vpshufb %xmm15, %xmm3, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld $1, %xmm0, %xmm0
    vpslldq $4, %xmm1, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vaesenc %xmm1, BLOCK1, BLOCK1
    vmovdqu %xmm1, \i*16(KS)

    vpshufd $0xff, %xmm1, %xmm2
    vaesenclast %xmm14, %xmm2, %xmm2
    vpslldq $4, %xmm3, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpxor %xmm2, %xmm3, %xmm3
    vaesenc %xmm3, BLOCK1, BLOCK1
    vmovdqu %xmm3, \j*16(KS)
.endm
.macro ROUND_last i
    vpshufb %xmm15, %xmm3, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslldq $4, %xmm1, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vaesenclast %xmm1, BLOCK1, BLOCK1
    vmovdqu %xmm1, \i*16(KS)
.endm

.set PT, %rdi
.set CT, %rsi
.set KS, %rdx
.set KEYp, %rcx

.set CON_MASK, %xmm0
.set MASK_256, %xmm15
.set KEY_1, %xmm1
.set KEY_2, %xmm3
.set BLOCK1, %xmm8
.set AUX_REG, %xmm14

#********************************************************
#   void AES256_KS_ENC_x1(const unsigned char PT[16],   *
#                       unsigned char CT[16],           *
#                       AES_KEY *KS,                    *
#                       const unsigned char *userKey);  *
#********************************************************

.globl AES256_KS_ENC_x1
AES256_KS_ENC_x1:

# parameter 1: %rdi         Pointer to PT1
# parameter 2: %rsi         Pointer to CT1
# parameter 3: %rdx         Pointer to KS
# parameter 4: %rcx         Pointer to initial key

    movl         $14, 240(KS)                    #key.rounds = 12
    vmovdqu      (con1), CON_MASK                #CON_MASK  = 1,1,1,1
    vmovdqu      (mask), MASK_256            #MASK_256
    vmovdqu      (PT), BLOCK1
    vmovdqu      (KEYp),   KEY_1                 # KEY_1 || KEY_2 [0..7] = user key
    vmovdqu      16(KEYp), KEY_2
    vpxor        KEY_1, BLOCK1, BLOCK1
    vaesenc      KEY_2, BLOCK1, BLOCK1
    vmovdqu      KEY_1, (KS)                     # First round key
    vmovdqu      KEY_2, 16(KS)
    vpxor        AUX_REG, AUX_REG, AUX_REG
    ROUND_double 2 3
    ROUND_double 4 5
    ROUND_double 6 7
    ROUND_double 8 9
    ROUND_double 10 11
    ROUND_double 12 13
    ROUND_last   14
    vmovdqu      BLOCK1, (CT)
    ret
#########################################################
# Expand without storing and encrypt two blocks
.macro ROUND_double_x2 i j
    vpshufb %xmm15, %xmm3, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld $1, %xmm0, %xmm0
    vpslldq $4, %xmm1, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vaesenc %xmm1, BLOCK1, BLOCK1
    vaesenc %xmm1, BLOCK2, BLOCK2
    ##  vmovdqu %xmm1, \i*16(KS)

    vpshufd $0xff, %xmm1, %xmm2
    vaesenclast %xmm14, %xmm2, %xmm2
    vpslldq $4, %xmm3, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpxor %xmm2, %xmm3, %xmm3
    vaesenc %xmm3, BLOCK1, BLOCK1
    vaesenc %xmm3, BLOCK2, BLOCK2
     ## vmovdqu %xmm3, \j*16(KS)
.endm

.macro ROUND_last_x2 i
    vpshufb %xmm15, %xmm3, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslldq $4, %xmm1, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vaesenclast %xmm1, BLOCK1, BLOCK1
    vaesenclast %xmm1, BLOCK2, BLOCK2
    ##vmovdqu %xmm1, \i*16(KS)
.endm

.set BLOCK2, %xmm9

#********************************************************
#   void AES256_KS_no_mem_ENC_x2(const unsigned char PT[32],    *
#                       unsigned char CT[32],           *
#                       AES_KEY *KS,                    *
#                       const unsigned char *userKey);  *
#********************************************************

.globl AES256_KS_no_mem_ENC_x2
AES256_KS_no_mem_ENC_x2:

# parameter 1: %rdi         Pointer to PT1
# parameter 2: %rsi         Pointer to CT1
# parameter 3: %rdx         Pointer to KS
# parameter 4: %rcx         Pointer to initial key

    #movl        $14, 240(KS)                    #key.rounds = 12
    vmovdqu      (con1), CON_MASK                #CON_MASK  = 1,1,1,1
    vmovdqu      (mask), MASK_256            #MASK_256
    vmovdqu      (PT), BLOCK1
    vmovdqu      16(PT), BLOCK2
    vmovdqu      (KEYp),   KEY_1                 # KEY_1 || KEY_2 [0..7] = user key
    vmovdqu      16(KEYp), KEY_2
    vpxor        KEY_1, BLOCK1, BLOCK1
    vpxor        KEY_1, BLOCK2, BLOCK2
    vaesenc      KEY_2, BLOCK1, BLOCK1
    vaesenc      KEY_2, BLOCK2, BLOCK2
  # vmovdqu     KEY_1, (KS)                     # First round key
  # vmovdqu     KEY_2, 16(KS)
    vpxor        AUX_REG, AUX_REG, AUX_REG
 
    ROUND_double_x2 2 3
    ROUND_double_x2 4 5
    ROUND_double_x2 6 7
    ROUND_double_x2 8 9
    ROUND_double_x2 10 11
    ROUND_double_x2 12 13
    ROUND_last_x2    14
 
    vmovdqu      BLOCK1, (CT)
    vmovdqu      BLOCK2, 16(CT)
    ret
##########################################################
# encrypt one block only
.align  16
.globl ECB_ENC_block
ECB_ENC_block:
.set KSp, %rdx
.set STATE_1, %xmm1
#parameter 1: PT            %rdi    (pointer to 128 bit)
#parameter 2: CT            %rsi    (pointer to 128 bit)
#parameter 3: ks            %rdx    (pointer to ks)
    push    %rbp                                # store rbp
    mov     %rsp, %rbp
    vmovdqu (%rdi), STATE_1
    vpxor       (KSp), STATE_1, STATE_1
    vaesenc 1*16(KSp), STATE_1, STATE_1
    vaesenc 2*16(KSp), STATE_1, STATE_1
    vaesenc 3*16(KSp), STATE_1, STATE_1
    vaesenc 4*16(KSp), STATE_1, STATE_1
    vaesenc 5*16(KSp), STATE_1, STATE_1
    vaesenc 6*16(KSp), STATE_1, STATE_1
    vaesenc 7*16(KSp), STATE_1, STATE_1
    vaesenc 8*16(KSp), STATE_1, STATE_1
    vaesenc 9*16(KSp), STATE_1, STATE_1
    vaesenc 10*16(KSp), STATE_1, STATE_1
    vaesenc 11*16(KSp), STATE_1, STATE_1
    vaesenc 12*16(KSp), STATE_1, STATE_1
    vaesenc 13*16(KSp), STATE_1, STATE_1
    vaesenclast 14*16(KSp), STATE_1, STATE_1    # STATE_1 == IV
    vmovdqa STATE_1, (%rsi)
    mov %rbp, %rsp
    pop %rbp
    ret
########################################################
# Expand without storing and encrypt three blocks

.macro ROUND_double_x3 i j
    vpshufb %xmm15, %xmm3, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld $1, %xmm0, %xmm0
    vpslldq $4, %xmm1, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vaesenc %xmm1, BLOCK1, BLOCK1
    vaesenc %xmm1, BLOCK2, BLOCK2
    vaesenc %xmm1, BLOCK3, BLOCK3
    vpshufd $0xff, %xmm1, %xmm2
    vaesenclast %xmm14, %xmm2, %xmm2
    vpslldq $4, %xmm3, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpxor %xmm2, %xmm3, %xmm3
    vaesenc %xmm3, BLOCK1, BLOCK1
    vaesenc %xmm3, BLOCK2, BLOCK2
    vaesenc %xmm3, BLOCK3, BLOCK3

.endm

.macro ROUND_last_x3 i
    vpshufb %xmm15, %xmm3, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslldq $4, %xmm1, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vaesenclast %xmm1, BLOCK1, BLOCK1
    vaesenclast %xmm1, BLOCK2, BLOCK2
    vaesenclast %xmm1, BLOCK3, BLOCK3

.endm

.set BLOCK3, %xmm10

#*********************************************************
#void AES256_KS_no_mem_ENC_x3(const unsigned char PT[48],*
#                       unsigned char CT[16],            *
#                       unsigned char CT1[32],           *
#                       const unsigned char *userKey);   *
#*********************************************************

.globl AES256_KS_no_mem_ENC_x3
AES256_KS_no_mem_ENC_x3:

# parameter 1: %rdi         Pointer to PT
# parameter 2: %rsi         Pointer to CT1[16]
# parameter 2: %rdx         Pointer to CT2[16]
# parameter 4: %rcx         Pointer to initial key

   vmovdqu      (con1), CON_MASK                #CON_MASK  = 1,1,1,1
   vmovdqu      (mask), MASK_256            #MASK_256
   vmovdqu      (%rdi), BLOCK1
   vmovdqu      16(%rdi), BLOCK2
   vmovdqu      32(%rdi), BLOCK3
   vmovdqu      (%rcx),   KEY_1                 # KEY_1 || KEY_2 [0..7] = user key
   vmovdqu      16(%rcx), KEY_2
   vpxor        KEY_1, BLOCK1, BLOCK1
   vpxor        KEY_1, BLOCK2, BLOCK2
   vpxor        KEY_1, BLOCK3, BLOCK3
   vaesenc      KEY_2, BLOCK1, BLOCK1
   vaesenc      KEY_2, BLOCK2, BLOCK2
   vaesenc      KEY_2, BLOCK3, BLOCK3
   vpxor        AUX_REG, AUX_REG, AUX_REG


   ROUND_double_x3 2 3
   ROUND_double_x3 4 5
   ROUND_double_x3 6 7
   ROUND_double_x3 8 9
   ROUND_double_x3 10 11
   ROUND_double_x3 12 13
   ROUND_last_x3    14

   vmovdqu      BLOCK1, (%rsi)
   vmovdqu      BLOCK2, 0(%rdx)
   vmovdqu      BLOCK3, 16(%rdx)
   ret
