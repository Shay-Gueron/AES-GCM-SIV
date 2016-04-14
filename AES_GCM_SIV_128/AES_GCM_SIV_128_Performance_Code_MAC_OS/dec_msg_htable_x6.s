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

.align  16
CTR_MASK:
.long    0x00000000,0xffffffff,0xffffffff,0xffffffff
OR_MASK:
.long    0x00000000,0x00000000,0x00000000,0x80000000
ONE:
.quad   1,0
TWO:
.quad   2,0
poly:
.quad 0x1, 0xc200000000000000 


###############################################################################
#.set T,%xmm0
#.set TMP0,%xmm1
#.set TMP1,%xmm2
#.set TMP2,%xmm3
#.set TMP3,%xmm4
#.set TMP4,%xmm5
#.set TMP5,%xmm6
#.set CTR1,%xmm7
#.set CTR2,%xmm8
#.set CTR3,%xmm9
#.set CTR4,%xmm10
#.set CTR5,%xmm11
#.set CTR6,%xmm12
#
#.set CTR,%xmm15
#
#.set HTABLE_ROUNDS,%xmm13
#.set S_BUF_ROUNDS, %xmm14
#
#
#
#.set CT,%rdi
#.set PT,%rsi
#.set POL, %rdx
#.set TAG, %rcx
#.set Htbl, %r8
#.set KS, %r9
#.set LEN,%r10
#.set secureBuffer, %rax

###############################################################################
# void Decrypt_Htable(unsigned char* CT,                //input
#                   unsigned char* PT,                  //output
#                   unsigned char POLYVAL_dec[16],      //input/output
#                   unsigned char TAG[16],
#                   unsigned char Htable[16*8],
#                   unsigned char* KS,                  //Key Schedule for decryption
#                   int byte_len,
#                   unsigned char secureBuffer[16*8]);      

#.type Decrypt_Htable,@function
.globl _Decrypt_Htable
#.align 16
_Decrypt_Htable:
# parameter 1: %rdi     %rdi             # input
# parameter 2: %rsi     %rsi             # output
# parameter 3: %rdx     %rdx             # input/output
# parameter 4: %rcx     %rcx             # %rcx
# parameter 5: %r8      %r8      # H
# parameter 6: %r9      %r9          # %r9
# parameter 7: %rsp+8   %r10             # %r10
# parameter 8: %rsp+16  %rax # %rax

.macro ROUND i
    vmovdqu  \i*16(%r9), %xmm4
    vaesenc  %xmm4, %xmm7, %xmm7
    vaesenc  %xmm4, %xmm8, %xmm8
    vaesenc  %xmm4, %xmm9, %xmm9
    vaesenc  %xmm4, %xmm10, %xmm10
    vaesenc  %xmm4, %xmm11, %xmm11
    vaesenc  %xmm4, %xmm12, %xmm12
  
.endm

.macro LASTROUND i
    vmovdqu  \i*16(%r9), %xmm4
    vaesenclast  %xmm4, %xmm7, %xmm7
    vaesenclast  %xmm4, %xmm8, %xmm8
    vaesenclast  %xmm4, %xmm9, %xmm9
    vaesenclast  %xmm4, %xmm10, %xmm10
    vaesenclast  %xmm4, %xmm11, %xmm11
    vaesenclast  %xmm4, %xmm12, %xmm12
  
.endm

.macro SCHOOLBOOK i
    vmovdqu  \i*16-32(%rax), %xmm6
    vmovdqu  \i*16-32(%r8), %xmm13
  
    vpclmulqdq  $0x10, %xmm13, %xmm6, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpclmulqdq  $0x11, %xmm13, %xmm6, %xmm4
    vpxor %xmm4, %xmm2, %xmm2
    vpclmulqdq  $0x00, %xmm13, %xmm6, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpclmulqdq  $0x01, %xmm13, %xmm6, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
.endm
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r13
    pushq %rax
    
    
    movq    8+9*8(%rsp), %r10
    movq $0xffffffff, %r13
    andq    %r13, %r10
    test    %r10, %r10
    jnz   .Lbegin
    jmp .LDone

.Lbegin:

    vzeroupper

    mov      16+9*8(%rsp), %rax
    vmovdqu  (%rdx), %xmm0

    leaq 32(%rax), %rax
    leaq 32(%r8), %r8
    
    #make %xmm15BLKs from %rcx
    vmovdqu     (%rcx), %xmm15
    vpand       CTR_MASK(%rip), %xmm15, %xmm15      #%xmm15 = %rcx[127...32][00..00]
    vpor        OR_MASK(%rip), %xmm15, %xmm15           #%xmm15 = [1]%rcx[126...32][00..00]
    
    
    #If less then 6 blocks, make singles
    cmp      $96, %r10
    jb       .LDataSingles

    
    #Decrypt the first six blocks
    sub   $96, %r10
    vmovdqa  %xmm15, %xmm7
    vpaddq   ONE(%rip), %xmm7, %xmm8
    vpaddq   TWO(%rip), %xmm7, %xmm9
    vpaddq   ONE(%rip), %xmm9, %xmm10
    vpaddq   TWO(%rip), %xmm9, %xmm11
    vpaddq   ONE(%rip), %xmm11, %xmm12
    vpaddq   TWO(%rip), %xmm11, %xmm15

    
    vpxor  (%r9), %xmm7, %xmm7
    vpxor  (%r9), %xmm8, %xmm8
    vpxor  (%r9), %xmm9, %xmm9
    vpxor  (%r9), %xmm10, %xmm10
    vpxor  (%r9), %xmm11, %xmm11
    vpxor  (%r9), %xmm12, %xmm12
   
    ROUND 1
    ROUND 2
    ROUND 3
    ROUND 4
    ROUND 5
    ROUND 6
    ROUND 7
    ROUND 8
    ROUND 9
    LASTROUND 10
    
    #Xor with %rdi
    vpxor  0*16(%rdi), %xmm7, %xmm7
    vpxor  1*16(%rdi), %xmm8, %xmm8
    vpxor  2*16(%rdi), %xmm9, %xmm9
    vpxor  3*16(%rdi), %xmm10, %xmm10
    vpxor  4*16(%rdi), %xmm11, %xmm11
    vpxor  5*16(%rdi), %xmm12, %xmm12
    
    vmovdqu  %xmm7, 0*16(%rsi)
    vmovdqu  %xmm8, 1*16(%rsi)
    vmovdqu  %xmm9, 2*16(%rsi)
    vmovdqu  %xmm10, 3*16(%rsi)
    vmovdqu  %xmm11, 4*16(%rsi)
    vmovdqu  %xmm12, 5*16(%rsi)
   
    add   $96, %rdi
    add   $96, %rsi
    jmp   .LDataOctets

# Decrypt 6 blocks each time while hashing previous 6 blocks
#.align 64
.LDataOctets:

    cmp      $96, %r10
    jb       .LEndOctets
    sub      $96, %r10

    vmovdqu  %xmm12, %xmm6
    vmovdqu  %xmm11, 1*16-32(%rax)
    vmovdqu  %xmm10, 2*16-32(%rax)
    vmovdqu  %xmm9, 3*16-32(%rax)
    vmovdqu  %xmm8, 4*16-32(%rax)
    vmovdqu  %xmm7, 5*16-32(%rax)
        
    vmovdqa  %xmm15, %xmm7
    vpaddq   ONE(%rip), %xmm7, %xmm8
    vpaddq   TWO(%rip), %xmm7, %xmm9
    vpaddq   ONE(%rip), %xmm9, %xmm10
    vpaddq   TWO(%rip), %xmm9, %xmm11
    vpaddq   ONE(%rip), %xmm11, %xmm12
    vpaddq   TWO(%rip), %xmm11, %xmm15

    vmovdqu (%r9), %xmm4
    vpxor  %xmm4, %xmm7, %xmm7
    vpxor  %xmm4, %xmm8, %xmm8
    vpxor  %xmm4, %xmm9, %xmm9
    vpxor  %xmm4, %xmm10, %xmm10
    vpxor  %xmm4, %xmm11, %xmm11
    vpxor  %xmm4, %xmm12, %xmm12
    
    vmovdqu     0*16-32(%r8), %xmm4
    vpclmulqdq  $0x11, %xmm4, %xmm6, %xmm2
    vpclmulqdq  $0x00, %xmm4, %xmm6, %xmm3 
    vpclmulqdq  $0x01, %xmm4, %xmm6, %xmm1
    vpclmulqdq  $0x10, %xmm4, %xmm6, %xmm4
    vpxor       %xmm4, %xmm1, %xmm1

    ROUND 1
    SCHOOLBOOK 1

    ROUND 2
    SCHOOLBOOK 2

    ROUND 3
    SCHOOLBOOK 3

    ROUND 4
    SCHOOLBOOK 4

    ROUND 5
    #SCHOOLBOOK 5

    ROUND 6
    #SCHOOLBOOK 6

    ROUND 7

    vmovdqu  5*16-32(%rax), %xmm6
    vpxor %xmm0, %xmm6, %xmm6
    vmovdqu  5*16-32(%r8), %xmm5

    vpclmulqdq  $0x01, %xmm5, %xmm6, %xmm4
    vpxor %xmm4, %xmm1, %xmm1
    vpclmulqdq  $0x11, %xmm5, %xmm6, %xmm4
    vpxor %xmm4, %xmm2, %xmm2
    vpclmulqdq  $0x00, %xmm5, %xmm6, %xmm4
    vpxor %xmm4, %xmm3, %xmm3
    vpclmulqdq  $0x10, %xmm5, %xmm6, %xmm4
    vpxor %xmm4, %xmm1, %xmm1

    ROUND 8      

    vpsrldq  $8, %xmm1, %xmm4
    vpxor    %xmm4, %xmm2, %xmm5
    vpslldq  $8, %xmm1, %xmm4
    vpxor    %xmm4, %xmm3, %xmm0

    vmovdqa poly(%rip), %xmm3

    ROUND 9

    vmovdqu  10*16(%r9), %xmm6
    
    vpalignr    $8, %xmm0, %xmm0, %xmm2
    vpclmulqdq  $0x10, %xmm3, %xmm0, %xmm0
    vpxor       %xmm0, %xmm2, %xmm0

    vpxor  0*16(%rdi), %xmm6, %xmm4
    vaesenclast  %xmm4, %xmm7, %xmm7
    vpxor  1*16(%rdi), %xmm6, %xmm4
    vaesenclast  %xmm4, %xmm8, %xmm8
    vpxor  2*16(%rdi), %xmm6, %xmm4
    vaesenclast  %xmm4, %xmm9, %xmm9
    vpxor  3*16(%rdi), %xmm6, %xmm4
    vaesenclast  %xmm4, %xmm10, %xmm10
    vpxor  4*16(%rdi), %xmm6, %xmm4
    vaesenclast  %xmm4, %xmm11, %xmm11
    vpxor  5*16(%rdi), %xmm6, %xmm4
    vaesenclast  %xmm4, %xmm12, %xmm12
    
    vpalignr    $8, %xmm0, %xmm0, %xmm2
    vpclmulqdq  $0x10, %xmm3, %xmm0, %xmm0
    vpxor       %xmm0, %xmm2, %xmm0

    vmovdqu  %xmm7, 0*16(%rsi)
    vmovdqu  %xmm8, 1*16(%rsi)
    vmovdqu  %xmm9, 2*16(%rsi)
    vmovdqu  %xmm10, 3*16(%rsi)
    vmovdqu  %xmm11, 4*16(%rsi)
    vmovdqu  %xmm12, 5*16(%rsi)
    
    vpxor %xmm5, %xmm0, %xmm0

    lea 96(%rdi), %rdi
    lea 96(%rsi), %rsi
    jmp  .LDataOctets

.LEndOctets:

    vmovdqu  %xmm12, %xmm6
    vmovdqu  %xmm11, 1*16-32(%rax)
    vmovdqu  %xmm10, 2*16-32(%rax)
    vmovdqu  %xmm9, 3*16-32(%rax)
    vmovdqu  %xmm8, 4*16-32(%rax)
    vmovdqu  %xmm7, 5*16-32(%rax)

    vmovdqu     0*16-32(%r8), %xmm4
    vpclmulqdq  $0x10, %xmm4, %xmm6, %xmm1
    vpclmulqdq  $0x11, %xmm4, %xmm6, %xmm2
    vpclmulqdq  $0x00, %xmm4, %xmm6, %xmm3
    vpclmulqdq  $0x01, %xmm4, %xmm6, %xmm4
    vpxor       %xmm4, %xmm1, %xmm1

    SCHOOLBOOK 1
    SCHOOLBOOK 2
    SCHOOLBOOK 3      
    SCHOOLBOOK 4
    

    vmovdqu     5*16-32(%rax), %xmm6
    vpxor       %xmm0, %xmm6, %xmm6
    vmovdqu     5*16-32(%r8), %xmm5            
    vpclmulqdq  $0x11, %xmm5, %xmm6, %xmm4
    vpxor       %xmm4, %xmm2, %xmm2
    vpclmulqdq  $0x00, %xmm5, %xmm6, %xmm4
    vpxor       %xmm4, %xmm3, %xmm3       
    vpclmulqdq  $0x10, %xmm5, %xmm6, %xmm4
    vpxor       %xmm4, %xmm1, %xmm1  
    vpclmulqdq  $0x01, %xmm5, %xmm6, %xmm4
    vpxor       %xmm4, %xmm1, %xmm1

    vpsrldq     $8, %xmm1, %xmm4
    vpxor       %xmm4, %xmm2, %xmm5
    vpslldq     $8, %xmm1, %xmm4
    vpxor       %xmm4, %xmm3, %xmm0

    vmovdqa     poly(%rip), %xmm3

    vpalignr    $8, %xmm0, %xmm0, %xmm2
    vpclmulqdq  $0x10, %xmm3, %xmm0, %xmm0
    vpxor       %xmm0, %xmm2, %xmm0

    vpalignr    $8, %xmm0, %xmm0, %xmm2
    vpclmulqdq  $0x10, %xmm3, %xmm0, %xmm0
    vpxor       %xmm0, %xmm2, %xmm0

    vpxor       %xmm5, %xmm0, %xmm0

#Here we encrypt any remaining whole block
.LDataSingles:
    
    cmp   $16, %r10
    jb    DATA_END
    sub   $16, %r10

    vmovdqa %xmm15, %xmm2
    vpaddd  ONE(%rip), %xmm15, %xmm15

    vpxor    0*16(%r9), %xmm2, %xmm2
    vaesenc  1*16(%r9), %xmm2, %xmm2
    vaesenc  2*16(%r9), %xmm2, %xmm2
    vaesenc  3*16(%r9), %xmm2, %xmm2
    vaesenc  4*16(%r9), %xmm2, %xmm2
    vaesenc  5*16(%r9), %xmm2, %xmm2
    vaesenc  6*16(%r9), %xmm2, %xmm2
    vaesenc  7*16(%r9), %xmm2, %xmm2
    vaesenc  8*16(%r9), %xmm2, %xmm2
    vaesenc  9*16(%r9), %xmm2, %xmm2
    vaesenclast  10*16(%r9), %xmm2, %xmm2

    vpxor    (%rdi), %xmm2, %xmm2
    vmovdqu  %xmm2, (%rsi)
    addq     $16, %rdi
    addq     $16, %rsi

    vpxor    %xmm2, %xmm0, %xmm0
    vmovdqu  -32(%r8), %xmm1
    call     GFMUL_

    jmp   .LDataSingles

DATA_END:
    vmovdqu  %xmm0, (%rdx)
.LDone:
    popq %rax
    popq %r13
    popq %r10
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    ret

    
#.size Decrypt_Htable, .-Decrypt_Htable

#########################
# a = T
# b = %xmm1 - remains unchanged
# res = T
# uses also %xmm2,%xmm3,%xmm4,%xmm5
# __m128i GFMUL_(__m128i A, __m128i B);
#.type GFMUL_,@function
.globl GFMUL_
GFMUL_:  
    vpclmulqdq  $0x00, %xmm1, %xmm0, %xmm2
    vpclmulqdq  $0x11, %xmm1, %xmm0, %xmm5
    vpclmulqdq  $0x10, %xmm1, %xmm0, %xmm3
    vpclmulqdq  $0x01, %xmm1, %xmm0, %xmm4
    vpxor       %xmm4, %xmm3, %xmm3
    vpslldq     $8, %xmm3, %xmm4
    vpsrldq     $8, %xmm3, %xmm3
    vpxor       %xmm4, %xmm2, %xmm2
    vpxor       %xmm3, %xmm5, %xmm5

    vpclmulqdq  $0x10, poly(%rip), %xmm2, %xmm3
    vpshufd     $78, %xmm2, %xmm4
    vpxor       %xmm4, %xmm3, %xmm2
        
    vpclmulqdq  $0x10, poly(%rip), %xmm2, %xmm3
    vpshufd     $78, %xmm2, %xmm4
    vpxor       %xmm4, %xmm3, %xmm2

    vpxor       %xmm5, %xmm2, %xmm0
    ret
#.size GFMUL_, .-GFMUL_














    
