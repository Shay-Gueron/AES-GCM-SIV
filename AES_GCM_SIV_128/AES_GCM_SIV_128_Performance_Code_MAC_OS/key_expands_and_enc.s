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

.globl _AES_KS
_AES_KS:
# parameter 1: %rdi
# parameter 2: %rsi
   #movl      $10, 240(%rsi)
   pushq %rdi
   pushq %rsi
   vmovdqu    (%rdi), %xmm1                             # xmm1 = user key
   vmovdqu    %xmm1, (%rsi)                             # rsi points to output

   vmovdqu con1(%rip), %xmm0
   vmovdqu mask(%rip), %xmm15

   mov $8, %rax
LOOP1_AVX:        
    add $16, %rsi                                     # rsi points for next key
    dec %rax        
    vpshufb %xmm15, %xmm1, %xmm2                      # xmm2 = shuffled user key
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld $1, %xmm0, %xmm0
    vpslldq $4, %xmm1, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vmovdqu %xmm1, (%rsi)   
    jne LOOP1_AVX

    vmovdqu con2(%rip), %xmm0
    
    vpshufb %xmm15, %xmm1, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld $1, %xmm0, %xmm0
    vpslldq $4, %xmm1, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vmovdqu %xmm1, 16(%rsi)
    
    vpshufb %xmm15, %xmm1, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslldq $4, %xmm1, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq $4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vmovdqu %xmm1, 32(%rsi)
    popq %rsi
    popq %rdi
    ret        
   
#########################################################
# Expand and encrypt one block

#.set BLOCK1, %xmm4
#.set AUXREG, %xmm3
#.set KS1_REGA, %xmm1
#.set KS1_REGB, %xmm2
#
#.set DUMP_KEYS, 1

.macro KS_BLOCK reg reg2 auxReg
    vpsllq $32, \reg, \auxReg         #!!saving mov instruction to xmm3
    vpxor \auxReg, \reg, \reg
    vpshufb con3(%rip), \reg,  \auxReg
    vpxor \auxReg, \reg, \reg
    vpxor \reg2, \reg, \reg
.endm

.macro ROUND i
    vpshufb %xmm15, %xmm1, %xmm2      #!!saving mov instruction to xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld $1, %xmm0, %xmm0
    KS_BLOCK %xmm1,%xmm2,%xmm3
    vaesenc  %xmm1, %xmm4, %xmm4
    vmovdqa %xmm1, \i*16(%rcx)   
.endm        

.macro ROUNDLAST i
    vpshufb %xmm15, %xmm1, %xmm2      #!!saving mov instruction to xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    KS_BLOCK %xmm1,%xmm2, %xmm3
    vaesenclast  %xmm1, %xmm4, %xmm4
    vmovdqa %xmm1, \i*16(%rcx)   
.endm        

.globl _AES_KS_ENC_x1
_AES_KS_ENC_x1:
# parameter 1: %rdi                         Pointer to PT
# parameter 2: %rsi                         Pointer to CT
# parameter 3: %rdx                         buffer len
# parameter 4: %rcx                         Pointer to keys
# parameter 5: %r8                          Pointer to initial key
# parameter 5: %r9d                         key length (unused for now)

  # movl      $10, 240(%rcx)                    # key.rounds = 10
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq   %r9
    vmovdqu    (%r8), %xmm1                  # xmm1 = first 16 bytes of random key
    vmovdqu  0*16(%rdi), %xmm4
    vmovdqa    %xmm1, (%rcx)                 # KEY[0] = first 16 bytes of random key
    
    vpxor    %xmm1, %xmm4, %xmm4
    
    vmovdqu con1(%rip), %xmm0                    #xmm0  = 1,1,1,1
    vmovdqu mask(%rip), %xmm15                   #xmm15 = mask
    
    ROUND 1
    ROUND 2
    ROUND 3
    ROUND 4
    ROUND 5
    ROUND 6
    ROUND 7
    ROUND 8
    
    vmovdqu con2(%rip), %xmm0
    
    ROUND 9
    ROUNDLAST 10
   
    vmovdqu     %xmm4, 0*16(%rsi)
    popq  %r9
    popq  %r8
    popq  %rcx
    popq  %rdx
    popq  %rsi
    popq  %rdi
    ret        

#########################################################
# Expand without storing and encrypt two blocks

#.set AUXREG, %xmm3
#.set KS1_REGA, %xmm1
#.set KS1_REGB, %xmm2
#
#.set BLOCK1, %xmm4
#.set BLOCK2, %xmm5

#.set DUMP_KEYS, 1

.macro KS_BLOCK_b reg reg2 auxReg
    vpsllq $32, \reg, \auxReg         #!!saving mov instruction to xmm3
    vpxor \auxReg, \reg, \reg
    vpshufb con3(%rip), \reg,  \auxReg
    vpxor \auxReg, \reg, \reg
    vpxor \reg2, \reg, \reg
.endm

.macro ROUND_B i
    vpshufb %xmm15, %xmm1, %xmm2      #!!saving mov instruction to xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    KS_BLOCK_b %xmm1,%xmm2,%xmm3
    
    vpslld $1, %xmm0, %xmm0
    
    vaesenc  %xmm1, %xmm4, %xmm4
    vaesenc  %xmm1, %xmm5, %xmm5
#.ifdef DUMP_KEYS
#      vmovdqa %xmm1, \i*16(%rcx)   
#.endif      
.endm        

.macro ROUNDLAST_B i
    vpshufb %xmm15, %xmm1, %xmm2      #!!saving mov instruction to xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    
    KS_BLOCK_b %xmm1,%xmm2,%xmm3

    vaesenclast  %xmm1, %xmm4, %xmm4
    vaesenclast  %xmm1, %xmm5, %xmm5
#.ifdef DUMP_KEYS      
#      vmovdqa %xmm1, \i*16(%rcx)   
#.endif      
.endm        

.globl _AES_KS_no_mem_ENC_x2
_AES_KS_no_mem_ENC_x2:
# parameter 1: %rdi                         Pointer to PT
# parameter 2: %rsi                         Pointer to CT1
# parameter 3: %rdx                         Pointer to CT2
# parameter 4: %rcx                         Pointer to keys
# parameter 5: %r8                          Pointer to initial key
# parameter 5: %r9d                         key length (unused for now)

    #movl      $10, 240(%rcx)                    # key.rounds = 10
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    vmovdqu    (%r8), %xmm1                  # xmm1 = first 16 bytes of random key
    vmovdqu  0*16(%rdi), %xmm4
    vmovdqu  1*16(%rdi), %xmm5
   
#.ifdef DUMP_KEYS   
#   vmovdqa    %xmm1, (%rcx)                    # KEY[0] = first 16 bytes of random key
#.endif   
   
    vpxor    %xmm1, %xmm4, %xmm4
    vpxor    %xmm1, %xmm5, %xmm5
    
    vmovdqu con1(%rip), %xmm0                    #xmm0  = 1,1,1,1
    vmovdqu mask(%rip), %xmm15                   #xmm15 = mask
    
    ROUND_B 1
    ROUND_B 2
    ROUND_B 3
    ROUND_B 4
    ROUND_B 5
    ROUND_B 6
    ROUND_B 7
    ROUND_B 8
    vmovdqu con2(%rip), %xmm0
    ROUND_B 9
    ROUNDLAST_B 10
    vmovdqu     %xmm4, 0*16(%rsi)
    vmovdqu     %xmm5, 0*16(%rdx)
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
    vaesenclast 10*16(%rdx), %xmm1, %xmm1   # STATE_1 == IV
    vmovdqu %xmm1, (%rsi)
    mov %rbp, %rsp
    popq    %rbp
    popq    %rsi
    popq    %rdi
    popq    %rdx
    ret

#.align 16
.Lbswap_mask:
.byte 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
shuff_mask:
.quad 0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
poly:
.quad 0x1, 0xc200000000000000 
