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

#.align  16
ONE:
.quad 1,0
TWO:
.quad 2,0
.Lbswap_mask:
.byte 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
shuff_mask:
.quad 0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
poly:
.quad 0x1, 0xc200000000000000 


################################################################################
# Generates the H table
# void INIT_Htable(uint8_t Htbl[16*8], uint8_t *H);
#.type INIT_Htable,@function
.globl _INIT_Htable
#.align 16
_INIT_Htable:
   
#.set  Htbl, %rdi
#.set  H, %rsi


#.set %xmm0,%xmm0
#.set TMP0,%xmm1


    vmovdqu  (%rsi), %xmm0
    vmovdqu   %xmm0, %xmm1
    vmovdqu   %xmm0, (%rdi)     # H 
    call  GFMUL
    vmovdqu  %xmm0, 16(%rdi)    # H^2 
    call  GFMUL
    vmovdqu  %xmm0, 32(%rdi)    # H^3
    call  GFMUL
    vmovdqu  %xmm0, 48(%rdi)    # H^4 
    call  GFMUL
    vmovdqu  %xmm0, 64(%rdi)    # H^5
    call  GFMUL
    vmovdqu  %xmm0, 80(%rdi)    # H^6 
    call  GFMUL
    vmovdqu  %xmm0, 96(%rdi)    # H^7 
    call  GFMUL
    vmovdqu  %xmm0, 112(%rdi)   # H^8  
    ret
#.size INIT_Htable, .-INIT_Htable


################################################################################
# Generates the H table
# void INIT_Htable_6(uint8_t Htbl[16*6], uint8_t *H);
#.type INIT_Htable_6,@function
.globl _INIT_Htable_6
#.align 16
_INIT_Htable_6:
   
#.set  Htbl, %rdi
#.set  H, %rsi


#.set T,%xmm0
#.set TMP0,%xmm1


    vmovdqu  (%rsi), %xmm0
    vmovdqu   %xmm0, %xmm1
    vmovdqu   %xmm0, (%rdi)     # H 
    call  GFMUL
    vmovdqu  %xmm0, 16(%rdi)    # H^2 
    call  GFMUL
    vmovdqu  %xmm0, 32(%rdi)    # H^3
    call  GFMUL
    vmovdqu  %xmm0, 48(%rdi)    # H^4 
    call  GFMUL
    vmovdqu  %xmm0, 64(%rdi)    # H^5
    call  GFMUL
    vmovdqu  %xmm0, 80(%rdi)    # H^6 
    ret
#.size INIT_Htable_6, .-INIT_Htable_6

################################################################################
# void Polyval_Htable(uint8_t Htbl[16*8], uint8_t *MSG, uint64_t LEN, uint8_t *T);

#.set DATA, %xmm0
#.set T, %xmm1
#.set TMP0, %xmm3
#.set TMP1, %xmm4
#.set TMP2, %xmm5
#.set TMP3, %xmm6
#.set TMP4, %xmm7
#.set Xhi, %xmm9
#.set IV, %xmm10
#.set Htbl, %rdi
#.set inp, %rsi
#.set len, %rdx
#.set Tp, %rcx


#.set hlp0, %r11

.macro SCHOOLBOOK_AAD i
    vpclmulqdq  $0x01, 16*\i(%rdi), %xmm0, %xmm6
    vpxor          %xmm6, %xmm5, %xmm5
    vpclmulqdq  $0x00, 16*\i(%rdi), %xmm0, %xmm6
    vpxor          %xmm6, %xmm3, %xmm3
    vpclmulqdq  $0x11, 16*\i(%rdi), %xmm0, %xmm6
    vpxor          %xmm6, %xmm4, %xmm4
    vpclmulqdq  $0x10, 16*\i(%rdi), %xmm0, %xmm6
    vpxor          %xmm6, %xmm5, %xmm5
.endm

.globl  _Polyval_Htable
#.type  Polyval_Htable,@function
#.align 16
_Polyval_Htable:

# parameter 1: %rdi     Htable  - pointer to Htable
# parameter 2: %rsi     INp     - pointer to %rsiut
# parameter 3: %rdx     LEN     - %rdxgth of BUFFER in bytes 
# parameter 4: %rcx     T       - pointer to POLYVAL output

    test  %rdx, %rdx
    jnz   .LbeginAAD
    ret

.LbeginAAD:

    vzeroupper
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r11
    
    vpxor    %xmm9, %xmm9, %xmm9
    vmovdqu (%rcx),%xmm1

# we hash 8 block each iteration, if the total amount of blocks is not a multiple of 8, we hash the first n%8 blocks first
    mov    %rdx, %r11
    and    $~-128, %r11

    jz        .Lmod_loop

    sub    %r11, %rdx
    sub    $16, %r11

    #hash first prefix block
    vmovdqu (%rsi), %xmm0
    vpxor    %xmm1, %xmm0, %xmm0

    vpclmulqdq  $0x01, (%rdi, %r11), %xmm0, %xmm5
    vpclmulqdq  $0x00, (%rdi, %r11), %xmm0, %xmm3
    vpclmulqdq  $0x11, (%rdi, %r11), %xmm0, %xmm4
    vpclmulqdq  $0x10, (%rdi, %r11), %xmm0, %xmm6
    vpxor       %xmm6, %xmm5, %xmm5

    lea 16(%rsi), %rsi
    test    %r11, %r11
    jnz .Lpre_loop
    jmp .Lred1

    #hash remaining prefix bocks (up to 7 total prefix blocks)
#.align 64
.Lpre_loop:

    sub $16, %r11

    vmovdqu     (%rsi),%xmm0           # next data block

    vpclmulqdq  $0x00, (%rdi,%r11), %xmm0, %xmm6
    vpxor       %xmm6, %xmm3, %xmm3
    vpclmulqdq  $0x11, (%rdi,%r11), %xmm0, %xmm6
    vpxor       %xmm6, %xmm4, %xmm4
    vpclmulqdq  $0x01, (%rdi,%r11), %xmm0, %xmm6
    vpxor       %xmm6, %xmm5, %xmm5
    vpclmulqdq  $0x10, (%rdi,%r11), %xmm0, %xmm6
    vpxor       %xmm6, %xmm5, %xmm5

    test    %r11, %r11

    lea 16(%rsi), %rsi

    jnz .Lpre_loop
    
.Lred1:
    vpsrldq     $8, %xmm5, %xmm6
    vpslldq     $8, %xmm5, %xmm5

    vpxor          %xmm6, %xmm4, %xmm9
    vpxor          %xmm5, %xmm3, %xmm1
    
#.align 64
.Lmod_loop:
    sub $0x80, %rdx
    jb  .Ldone

    vmovdqu     16*7(%rsi),%xmm0        # Ii

    vpclmulqdq  $0x01, (%rdi), %xmm0, %xmm5
    vpclmulqdq  $0x00, (%rdi), %xmm0, %xmm3
    vpclmulqdq  $0x11, (%rdi), %xmm0, %xmm4
    vpclmulqdq  $0x10, (%rdi), %xmm0, %xmm6
    vpxor       %xmm6, %xmm5, %xmm5
    #########################################################
    vmovdqu     16*6(%rsi),%xmm0
    SCHOOLBOOK_AAD 1
    #########################################################
    vmovdqu     16*5(%rsi),%xmm0

    vpclmulqdq  $0x10, poly(%rip), %xmm1, %xmm7         #reduction stage 1a
    vpalignr       $8, %xmm1, %xmm1, %xmm1

    SCHOOLBOOK_AAD 2

    vpxor          %xmm7, %xmm1, %xmm1                 #reduction stage 1b
    #########################################################
    vmovdqu     16*4(%rsi),%xmm0

    SCHOOLBOOK_AAD 3
    #########################################################
    vmovdqu     16*3(%rsi),%xmm0

    vpclmulqdq  $0x10, poly(%rip), %xmm1, %xmm7         #reduction stage 2a
    vpalignr       $8, %xmm1, %xmm1, %xmm1

    SCHOOLBOOK_AAD 4

    vpxor          %xmm7, %xmm1, %xmm1                 #reduction stage 2b
    #########################################################
    vmovdqu     16*2(%rsi),%xmm0

    SCHOOLBOOK_AAD 5

    vpxor          %xmm9, %xmm1, %xmm1                  #reduction finalize
    #########################################################
    vmovdqu     16*1(%rsi),%xmm0

    SCHOOLBOOK_AAD 6
    #########################################################
    vmovdqu     16*0(%rsi),%xmm0
    vpxor          %xmm1,%xmm0,%xmm0

    SCHOOLBOOK_AAD 7
    #########################################################
    vpsrldq $8, %xmm5, %xmm6
    vpslldq $8, %xmm5, %xmm5

    vpxor       %xmm6, %xmm4, %xmm9
    vpxor       %xmm5, %xmm3, %xmm1

    lea 16*8(%rsi), %rsi
    jmp .Lmod_loop
    #########################################################

.Ldone:
    vpclmulqdq  $0x10, poly(%rip), %xmm1, %xmm6
    vpalignr    $8, %xmm1, %xmm1, %xmm1
    vpxor       %xmm6, %xmm1, %xmm1

    vpclmulqdq  $0x10, poly(%rip), %xmm1, %xmm6
    vpalignr    $8, %xmm1, %xmm1, %xmm1
    vpxor       %xmm6, %xmm1, %xmm1
    vpxor       %xmm9, %xmm1, %xmm1

.Lsave:
   
    vmovdqu     %xmm1,(%rcx)
    vzeroupper
    popq %r11
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    ret
#.size  Polyval_Htable,.-Polyval_Htable

#
#.set T,%xmm0
#.set TMP0,%xmm1
#.set TMP1,%xmm2
#.set TMP2,%xmm3
#.set TMP3,%xmm4
#.set TMP4,%xmm5

#########################
# a = T
# b = %xmm1 - remains unchanged
# res = T
# uses also %xmm2,%xmm3,%xmm4,%xmm5
# __m128i GFMUL(__m128i A, __m128i B);
#.type GFMUL,@function
.globl GFMUL
GFMUL:  
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
#.size GFMUL, .-GFMUL

