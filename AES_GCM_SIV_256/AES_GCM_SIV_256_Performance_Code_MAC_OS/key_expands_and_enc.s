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

#.align   16
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

#.align    64
.globl _AES256_KS
_AES256_KS:
# parameter 1: %rdi
# parameter 2: %rsi

    pushq %rdi
    pushq %rsi
    vmovdqu (%rdi), %xmm1
    vmovdqu 16(%rdi), %xmm3
    vmovdqu %xmm1, (%rsi)
    vmovdqu %xmm3, 16(%rsi)
    vmovdqu con1(%rip), %xmm0
    vmovdqu mask(%rip), %xmm15
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
    vpshufb con3(%rip), %xmm1,  %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vmovdqu %xmm1, (%rsi)
    vpshufd $0xff, %xmm1, %xmm2
    vaesenclast %xmm14, %xmm2, %xmm2
    vpsllq $32, %xmm3, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpshufb con3(%rip), %xmm3,  %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpxor %xmm2, %xmm3, %xmm3
    vmovdqu %xmm3, 16(%rsi)
    jne LOOP_256_AVX
    vpshufb %xmm15, %xmm3, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpsllq $32, %xmm1, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpshufb con3(%rip), %xmm1,  %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vmovdqu %xmm1, 32(%rsi)
    popq %rsi
    popq %rdi
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
    vaesenc %xmm1, %xmm8, %xmm8
    vmovdqu %xmm1, \i*16(%rdx)

    vpshufd $0xff, %xmm1, %xmm2
    vaesenclast %xmm14, %xmm2, %xmm2
    vpslldq $4, %xmm3, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpxor %xmm2, %xmm3, %xmm3
    vaesenc %xmm3, %xmm8, %xmm8
    vmovdqu %xmm3, \j*16(%rdx)
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
    vaesenclast %xmm1, %xmm8, %xmm8
    vmovdqu %xmm1, \i*16(%rdx)
.endm

#.set PT, %rdi
#.set CT, %rsi
#.set KS, %rdx
#.set KEYp, %rcx
#
#.set CON_MASK, %xmm0
#.set MASK_256, %xmm15
#.set KEY_1, %xmm1
#.set KEY_2, %xmm3
#.set BLOCK1, %xmm8
#.set AUX_REG, %xmm14

#********************************************************
#   void AES256_KS_ENC_x1(const unsigned char PT[16],   *
#                       unsigned char CT[16],           *
#                       AES_KEY *KS,                    *
#                       const unsigned char *userKey);  *
#********************************************************

.globl _AES256_KS_ENC_x1
_AES256_KS_ENC_x1:

# parameter 1: %rdi         Pointer to PT1
# parameter 2: %rsi         Pointer to CT1
# parameter 3: %rdx         Pointer to KS
# parameter 4: %rcx         Pointer to initial key

    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq   %r9
    vmovdqu      con1(%rip), %xmm0                #CON_MASK  = 1,1,1,1
    vmovdqu      mask(%rip), %xmm15            #MASK_256
    vmovdqu      (%rdi), %xmm8
    vmovdqu      (%rcx),   %xmm1                 # KEY_1 || KEY_2 [0..7] = user key
    vmovdqu      16(%rcx), %xmm3
    vpxor        %xmm1, %xmm8, %xmm8
    vaesenc      %xmm3, %xmm8, %xmm8
    vmovdqu      %xmm1, (%rdx)                     # First round key
    vmovdqu      %xmm3, 16(%rdx)
    vpxor        %xmm14, %xmm14, %xmm14
    ROUND_double 2, 3
    ROUND_double 4, 5
    ROUND_double 6, 7
    ROUND_double 8, 9
    ROUND_double 10, 11
    ROUND_double 12, 13
    ROUND_last   14
    vmovdqu      %xmm8, (%rsi)
    popq  %r9
    popq  %r8
    popq  %rcx
    popq  %rdx
    popq  %rsi
    popq  %rdi
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
    vaesenc %xmm1, %xmm8, %xmm8
    vaesenc %xmm1, %xmm9, %xmm9

    vpshufd $0xff, %xmm1, %xmm2
    vaesenclast %xmm14, %xmm2, %xmm2
    vpslldq $4, %xmm3, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpxor %xmm2, %xmm3, %xmm3
    vaesenc %xmm3, %xmm8, %xmm8
    vaesenc %xmm3, %xmm9, %xmm9
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
    vaesenclast %xmm1, %xmm8, %xmm8
    vaesenclast %xmm1, %xmm9, %xmm9
.endm

#.set BLOCK2, %xmm9

#********************************************************
#   void AES256_KS_no_mem_ENC_x2(const unsigned char PT[32],    *
#                       unsigned char CT[32],           *
#                       AES_KEY *KS,                    *
#                       const unsigned char *userKey);  *
#********************************************************

.globl _AES256_KS_no_mem_ENC_x2
_AES256_KS_no_mem_ENC_x2:

# parameter 1: %rdi         Pointer to PT1
# parameter 2: %rsi         Pointer to CT1
# parameter 3: %rdx         Pointer to KS
# parameter 4: %rcx         Pointer to initial key

    #movl        $14, 240(%rdx)                    #key.rounds = 12
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    vmovdqu      con1(%rip), %xmm0                #CON_MASK  = 1,1,1,1
    vmovdqu      mask(%rip), %xmm15            #MASK_256
    vmovdqu      (%rdi), %xmm8
    vmovdqu      16(%rdi), %xmm9
    vmovdqu      (%rcx),   %xmm1                 # KEY_1 || KEY_2 [0..7] = user key
    vmovdqu      16(%rcx), %xmm3
    vpxor        %xmm1, %xmm8, %xmm8
    vpxor        %xmm1, %xmm9, %xmm9
    vaesenc      %xmm3, %xmm8, %xmm8
    vaesenc      %xmm3, %xmm9, %xmm9
  # vmovdqu     %xmm1, (%rdx)                     # First round key
  # vmovdqu     %xmm3, 16(%rdx)
    vpxor        %xmm14, %xmm14, %xmm14
 
    ROUND_double_x2 2, 3
    ROUND_double_x2 4, 5
    ROUND_double_x2 6, 7
    ROUND_double_x2 8, 9
    ROUND_double_x2 10, 11
    ROUND_double_x2 12, 13
    ROUND_last_x2    14
 
    vmovdqu      %xmm8, (%rsi)
    vmovdqu      %xmm9, 16(%rsi)
    popq  %r9
    popq  %r8
    popq  %rcx
    popq  %rdx
    popq  %rsi
    popq  %rdi
    ret
##########################################################
# encrypt one block only
#.align  16
.globl _ECB_ENC_block
_ECB_ENC_block:
#.set KSp, %rdx
#.set STATE_1, %xmm1
#parameter 1: PT            %rdi    (pointer to 128 bit)
#parameter 2: CT            %rsi    (pointer to 128 bit)
#parameter 3: ks            %rdx    (pointer to ks)
    pushq   %rdx
    pushq   %rdi
    pushq   %rsi
    pushq   %rbp                                # store rbp
    mov     %rsp, %rbp
    vmovdqu (%rdi), %xmm1
    vpxor       (%rdx), %xmm1, %xmm1
    vaesenc 1*16(%rdx), %xmm1, %xmm1
    vaesenc 2*16(%rdx), %xmm1, %xmm1
    vaesenc 3*16(%rdx), %xmm1, %xmm1
    vaesenc 4*16(%rdx), %xmm1, %xmm1
    vaesenc 5*16(%rdx), %xmm1, %xmm1
    vaesenc 6*16(%rdx), %xmm1, %xmm1
    vaesenc 7*16(%rdx), %xmm1, %xmm1
    vaesenc 8*16(%rdx), %xmm1, %xmm1
    vaesenc 9*16(%rdx), %xmm1, %xmm1
    vaesenc 10*16(%rdx), %xmm1, %xmm1
    vaesenc 11*16(%rdx), %xmm1, %xmm1
    vaesenc 12*16(%rdx), %xmm1, %xmm1
    vaesenc 13*16(%rdx), %xmm1, %xmm1
    vaesenclast 14*16(%rdx), %xmm1, %xmm1    # STATE_1 == IV
    vmovdqa %xmm1, (%rsi)
    mov %rbp, %rsp
    popq    %rbp
    popq    %rsi
    popq    %rdi
    popq    %rdx
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
    vaesenc %xmm1, %xmm8, %xmm8
    vaesenc %xmm1, %xmm9, %xmm9
    vaesenc %xmm1, %xmm10, %xmm10
    vpshufd $0xff, %xmm1, %xmm2
    vaesenclast %xmm14, %xmm2, %xmm2
    vpslldq $4, %xmm3, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpslldq $4, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpxor %xmm2, %xmm3, %xmm3
    vaesenc %xmm3, %xmm8, %xmm8
    vaesenc %xmm3, %xmm9, %xmm9
    vaesenc %xmm3, %xmm10, %xmm10

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
    vaesenclast %xmm1, %xmm8, %xmm8
    vaesenclast %xmm1, %xmm9, %xmm9
    vaesenclast %xmm1, %xmm10, %xmm10

.endm

#.set BLOCK3, %xmm10

#*********************************************************
#void AES256_KS_no_mem_ENC_x3(const unsigned char PT[48],*
#                       unsigned char CT[16],            *
#                       unsigned char CT1[32],           *
#                       const unsigned char *userKey);   *
#*********************************************************

.globl _AES256_KS_no_mem_ENC_x3
_AES256_KS_no_mem_ENC_x3:

# parameter 1: %rdi         Pointer to PT
# parameter 2: %rsi         Pointer to CT1[16]
# parameter 2: %rdx         Pointer to CT2[16]
# parameter 4: %rcx         Pointer to initial key

   vmovdqu      con1(%rip), %xmm0                #CON_MASK  = 1,1,1,1
   vmovdqu      mask(%rip), %xmm15            #MASK_256
   vmovdqu      (%rdi), %xmm8
   vmovdqu      16(%rdi), %xmm9
   vmovdqu      32(%rdi), %xmm10
   vmovdqu      (%rcx),   %xmm1                 # KEY_1 || KEY_2 [0..7] = user key
   vmovdqu      16(%rcx), %xmm3
   vpxor        %xmm1, %xmm8, %xmm8
   vpxor        %xmm1, %xmm9, %xmm9
   vpxor        %xmm1, %xmm10, %xmm10
   vaesenc      %xmm3, %xmm8, %xmm8
   vaesenc      %xmm3, %xmm9, %xmm9
   vaesenc      %xmm3, %xmm10, %xmm10
   vpxor        %xmm14, %xmm14, %xmm14


   ROUND_double_x3 2 3
   ROUND_double_x3 4 5
   ROUND_double_x3 6 7
   ROUND_double_x3 8 9
   ROUND_double_x3 10 11
   ROUND_double_x3 12 13
   ROUND_last_x3    14

   vmovdqu      %xmm8, (%rsi)
   vmovdqu      %xmm9, 0(%rdx)
   vmovdqu      %xmm10, 16(%rdx)
   ret
