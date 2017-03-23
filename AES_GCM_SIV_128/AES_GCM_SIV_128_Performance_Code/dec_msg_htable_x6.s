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
OR_MASK:
.long    0x00000000,0x00000000,0x00000000,0x80000000
ONE:
.quad   1,0
TWO:
.quad   2,0
poly:
.quad 0x1, 0xc200000000000000 
CONST_Vector:
.long 0,0,0,0, 0x80000000,0,0,0, 0x80000000,0x80000000,0,0, 0x80000000,0x80000000,0x80000000,0
AND_VEC:
.long 0,0,0,0, 0x000000ff,0,0,0, 0x0000ffff,0,0,0, 0x00ffffff,0,0,0, 0xffffffff,0,0,0
.long 0xffffffff,0x000000ff,0,0, 0xffffffff,0x0000ffff,0,0, 0xffffffff,0x00ffffff,0,0, 0xffffffff,0xffffffff,0,0
.long 0xffffffff,0xffffffff, 0x000000ff,0, 0xffffffff,0xffffffff,0x0000ffff,0, 0xffffffff,0xffffffff,0x00ffffff,0, 0xffffffff,0xffffffff,0xffffffff,0
.long 0xffffffff,0xffffffff,0xffffffff,0x000000ff, 0xffffffff,0xffffffff,0xffffffff, 0x0000ffff, 0xffffffff,0xffffffff,0xffffffff,0x00ffffff, 0xffffffff,0xffffffff,0xffffffff,0xffffffff
###############################################################################
.set T,%xmm0
.set TMP0,%xmm1
.set TMP1,%xmm2
.set TMP2,%xmm3
.set TMP3,%xmm4
.set TMP4,%xmm5
.set TMP5,%xmm6
.set CTR1,%xmm7
.set CTR2,%xmm8
.set CTR3,%xmm9
.set CTR4,%xmm10
.set CTR5,%xmm11
.set CTR6,%xmm12

.set CTR,%xmm15

.set HTABLE_ROUNDS,%xmm13
.set S_BUF_ROUNDS, %xmm14



.set CT,%rdi
.set PT,%rsi
.set POL, %rdx
.set TAG, %rcx
.set Htbl, %r8
.set KS, %r9
.set LEN,%r10
.set secureBuffer, %rax

###############################################################################
# void Decrypt_Htable(unsigned char* CT,                //input
#                   unsigned char* PT,                  //output
#                   unsigned char POLYVAL_dec[16],      //input/output
#                   unsigned char TAG[16],
#                   unsigned char Htable[16*8],
#                   unsigned char* KS,                  //Key Schedule for decryption
#                   int byte_len,
#                   unsigned char secureBuffer[16*8]);      

.type Decrypt_Htable,@function
.globl Decrypt_Htable
.align 16
Decrypt_Htable:
# parameter 1: %rdi     CT           # input
# parameter 2: %rsi     PT           # output
# parameter 3: %rdx     POL          # input/output
# parameter 4: %rcx     TAG          # TAG
# parameter 5: %r8      Htbl         # H
# parameter 6: %r9      KS           # KS
# parameter 7: %rsp+8   LEN          # LEN
# parameter 8: %rsp+16  secureBuffer # secureBuffer

.macro ROUND i
    vmovdqu  \i*16(KS), TMP3
    vaesenc  TMP3, CTR1, CTR1
    vaesenc  TMP3, CTR2, CTR2
    vaesenc  TMP3, CTR3, CTR3
    vaesenc  TMP3, CTR4, CTR4
    vaesenc  TMP3, CTR5, CTR5
    vaesenc  TMP3, CTR6, CTR6
  
.endm

.macro LASTROUND i
    vmovdqu  \i*16(KS), TMP3
    vaesenclast  TMP3, CTR1, CTR1
    vaesenclast  TMP3, CTR2, CTR2
    vaesenclast  TMP3, CTR3, CTR3
    vaesenclast  TMP3, CTR4, CTR4
    vaesenclast  TMP3, CTR5, CTR5
    vaesenclast  TMP3, CTR6, CTR6
  
.endm

.macro SCHOOLBOOK i
    vmovdqu  \i*16-32(secureBuffer), TMP5
    vmovdqu  \i*16-32(Htbl), HTABLE_ROUNDS
   
    vpclmulqdq  $0x10, HTABLE_ROUNDS, TMP5, TMP3
    vpxor TMP3, TMP0, TMP0
    vpclmulqdq  $0x11, HTABLE_ROUNDS, TMP5, TMP3
    vpxor TMP3, TMP1, TMP1
    vpclmulqdq  $0x00, HTABLE_ROUNDS, TMP5, TMP3
    vpxor TMP3, TMP2, TMP2
    vpclmulqdq  $0x01, HTABLE_ROUNDS, TMP5, TMP3
    vpxor TMP3, TMP0, TMP0
.endm
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %r10
	pushq %r11
	pushq %r12
    pushq %r13
	pushq %r14
	pushq %r15
    pushq %rax
    
    
    movq    8+13*8(%rsp), LEN
    movq $0xffffffff, %r13
    andq    %r13, LEN
	
    
	vzeroall
    mov      16+13*8(%rsp), secureBuffer
	subq $16, %rsp
    vmovdqu  (POL), T

    leaq 32(secureBuffer), secureBuffer
    leaq 32(Htbl), Htbl
	testq    LEN, LEN
    jnz   .Lbegin
    jmp .LDone

.Lbegin:

    
    
    #make CTRBLKs from TAG
    vmovdqu     (TAG), CTR
    vpor        OR_MASK(%rip), CTR, CTR         #CTR = [1]TAG[126...32][00..00]
    
    
    #If less then 6 blocks, make singles
    cmp      $96, LEN
    jb       .LDataSingles

    
    #Decrypt the first six blocks
    sub   $96, LEN
    vmovdqa  CTR, CTR1
    vpaddd   ONE(%rip), CTR1, CTR2
    vpaddd   TWO(%rip), CTR1, CTR3
    vpaddd   ONE(%rip), CTR3, CTR4
    vpaddd   TWO(%rip), CTR3, CTR5
    vpaddd   ONE(%rip), CTR5, CTR6
    vpaddd   TWO(%rip), CTR5, CTR

    
    vpxor  (KS), CTR1, CTR1
    vpxor  (KS), CTR2, CTR2
    vpxor  (KS), CTR3, CTR3
    vpxor  (KS), CTR4, CTR4
    vpxor  (KS), CTR5, CTR5
    vpxor  (KS), CTR6, CTR6
   
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
    
    #Xor with CT
    vpxor  0*16(CT), CTR1, CTR1
    vpxor  1*16(CT), CTR2, CTR2
    vpxor  2*16(CT), CTR3, CTR3
    vpxor  3*16(CT), CTR4, CTR4
    vpxor  4*16(CT), CTR5, CTR5
    vpxor  5*16(CT), CTR6, CTR6
    
    vmovdqu  CTR1, 0*16(PT)
    vmovdqu  CTR2, 1*16(PT)
    vmovdqu  CTR3, 2*16(PT)
    vmovdqu  CTR4, 3*16(PT)
    vmovdqu  CTR5, 4*16(PT)
    vmovdqu  CTR6, 5*16(PT)
   
    add   $96, CT
    add   $96, PT
    jmp   .LDataOctets

# Decrypt 6 blocks each time while hashing previous 6 blocks
.align 64
.LDataOctets:

    cmp      $96, LEN
    jb       .LEndOctets
    sub      $96, LEN

    vmovdqu  CTR6, TMP5
    vmovdqu  CTR5, 1*16-32(secureBuffer)
    vmovdqu  CTR4, 2*16-32(secureBuffer)
    vmovdqu  CTR3, 3*16-32(secureBuffer)
    vmovdqu  CTR2, 4*16-32(secureBuffer)
    vmovdqu  CTR1, 5*16-32(secureBuffer)
        
    vmovdqa  CTR, CTR1
    vpaddd   ONE(%rip), CTR1, CTR2
    vpaddd   TWO(%rip), CTR1, CTR3
    vpaddd   ONE(%rip), CTR3, CTR4
    vpaddd   TWO(%rip), CTR3, CTR5
    vpaddd   ONE(%rip), CTR5, CTR6
    vpaddd   TWO(%rip), CTR5, CTR

    vmovdqu (KS), TMP3
    vpxor  TMP3, CTR1, CTR1
    vpxor  TMP3, CTR2, CTR2
    vpxor  TMP3, CTR3, CTR3
    vpxor  TMP3, CTR4, CTR4
    vpxor  TMP3, CTR5, CTR5
    vpxor  TMP3, CTR6, CTR6
    
    vmovdqu     0*16-32(Htbl), TMP3
    vpclmulqdq  $0x11, TMP3, TMP5, TMP1
    vpclmulqdq  $0x00, TMP3, TMP5, TMP2 
    vpclmulqdq  $0x01, TMP3, TMP5, TMP0
    vpclmulqdq  $0x10, TMP3, TMP5, TMP3
    vpxor       TMP3, TMP0, TMP0

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
    
    vmovdqu  5*16-32(secureBuffer), TMP5
    vpxor T, TMP5, TMP5
    vmovdqu  5*16-32(Htbl), TMP4
    
    vpclmulqdq  $0x01, TMP4, TMP5, TMP3
    vpxor TMP3, TMP0, TMP0
    vpclmulqdq  $0x11, TMP4, TMP5, TMP3
    vpxor TMP3, TMP1, TMP1
    vpclmulqdq  $0x00, TMP4, TMP5, TMP3
    vpxor TMP3, TMP2, TMP2
    vpclmulqdq  $0x10, TMP4, TMP5, TMP3
    vpxor TMP3, TMP0, TMP0
    
    ROUND 8      
    
    vpsrldq  $8, TMP0, TMP3
    vpxor    TMP3, TMP1, TMP4
    vpslldq  $8, TMP0, TMP3
    vpxor    TMP3, TMP2, T
    
    vmovdqa poly(%rip), TMP2
    
    ROUND 9
    
    vmovdqu  10*16(KS), TMP5
    
    vpalignr    $8, T, T, TMP1
    vpclmulqdq  $0x10, TMP2, T, T
    vpxor       T, TMP1, T
    
    vpxor  0*16(CT), TMP5, TMP3
    vaesenclast  TMP3, CTR1, CTR1
    vpxor  1*16(CT), TMP5, TMP3
    vaesenclast  TMP3, CTR2, CTR2
    vpxor  2*16(CT), TMP5, TMP3
    vaesenclast  TMP3, CTR3, CTR3
    vpxor  3*16(CT), TMP5, TMP3
    vaesenclast  TMP3, CTR4, CTR4
    vpxor  4*16(CT), TMP5, TMP3
    vaesenclast  TMP3, CTR5, CTR5
    vpxor  5*16(CT), TMP5, TMP3
    vaesenclast  TMP3, CTR6, CTR6
    
    vpalignr    $8, T, T, TMP1
    vpclmulqdq  $0x10, TMP2, T, T
    vpxor       T, TMP1, T

    vmovdqu  CTR1, 0*16(PT)
    vmovdqu  CTR2, 1*16(PT)
    vmovdqu  CTR3, 2*16(PT)
    vmovdqu  CTR4, 3*16(PT)
    vmovdqu  CTR5, 4*16(PT)
    vmovdqu  CTR6, 5*16(PT)
    
    vpxor TMP4, T, T

    lea 96(CT), CT
    lea 96(PT), PT
    jmp  .LDataOctets

.LEndOctets:

    vmovdqu  CTR6, TMP5
    vmovdqu  CTR5, 1*16-32(secureBuffer)
    vmovdqu  CTR4, 2*16-32(secureBuffer)
    vmovdqu  CTR3, 3*16-32(secureBuffer)
    vmovdqu  CTR2, 4*16-32(secureBuffer)
    vmovdqu  CTR1, 5*16-32(secureBuffer)

    vmovdqu     0*16-32(Htbl), TMP3
    vpclmulqdq  $0x10, TMP3, TMP5, TMP0
    vpclmulqdq  $0x11, TMP3, TMP5, TMP1
    vpclmulqdq  $0x00, TMP3, TMP5, TMP2
    vpclmulqdq  $0x01, TMP3, TMP5, TMP3
    vpxor       TMP3, TMP0, TMP0

    SCHOOLBOOK 1
    SCHOOLBOOK 2
    SCHOOLBOOK 3      
    SCHOOLBOOK 4
    

    vmovdqu     5*16-32(secureBuffer), TMP5
    vpxor       T, TMP5, TMP5
    vmovdqu     5*16-32(Htbl), TMP4            
    vpclmulqdq  $0x11, TMP4, TMP5, TMP3
    vpxor       TMP3, TMP1, TMP1
    vpclmulqdq  $0x00, TMP4, TMP5, TMP3
    vpxor       TMP3, TMP2, TMP2       
    vpclmulqdq  $0x10, TMP4, TMP5, TMP3
    vpxor       TMP3, TMP0, TMP0  
    vpclmulqdq  $0x01, TMP4, TMP5, TMP3
    vpxor       TMP3, TMP0, TMP0

    vpsrldq     $8, TMP0, TMP3
    vpxor       TMP3, TMP1, TMP4
    vpslldq     $8, TMP0, TMP3
    vpxor       TMP3, TMP2, T

    vmovdqa     poly(%rip), TMP2

    vpalignr    $8, T, T, TMP1
    vpclmulqdq  $0x10, TMP2, T, T
    vpxor       T, TMP1, T

    vpalignr    $8, T, T, TMP1
    vpclmulqdq  $0x10, TMP2, T, T
    vpxor       T, TMP1, T

    vpxor       TMP4, T, T

#Here we encrypt any remaining whole block
.LDataSingles:
    
    #if there are no whole blocks
    cmp   $16, LEN
    jb    DATA_END
    sub   $16, LEN

    vmovdqa CTR, TMP1
    vpaddd  ONE(%rip), CTR, CTR

    vpxor    0*16(KS), TMP1, TMP1
    vaesenc  1*16(KS), TMP1, TMP1
    vaesenc  2*16(KS), TMP1, TMP1
    vaesenc  3*16(KS), TMP1, TMP1
    vaesenc  4*16(KS), TMP1, TMP1
    vaesenc  5*16(KS), TMP1, TMP1
    vaesenc  6*16(KS), TMP1, TMP1
    vaesenc  7*16(KS), TMP1, TMP1
    vaesenc  8*16(KS), TMP1, TMP1
    vaesenc  9*16(KS), TMP1, TMP1
    vaesenclast  10*16(KS), TMP1, TMP1

    vpxor    (CT), TMP1, TMP1
    vmovdqu  TMP1, (PT)
    addq     $16, CT
    addq     $16, PT

    vpxor    TMP1, T, T
    vmovdqu  -32(Htbl), TMP0
    call     GFMUL_

    jmp   .LDataSingles

DATA_END:
	cmp $0, LEN
	jbe .LSave
	movq $0, (%rsp)
	movq $0, 8(%rsp)
	vmovdqa CTR, TMP1
    vpaddd  ONE(%rip), CTR, CTR
	movq LEN, %r11
    vpxor    0*16(KS), TMP1, TMP1
    vaesenc  1*16(KS), TMP1, TMP1
#	shrq $2, %r11
#	movq %r11, %r12
    vaesenc  2*16(KS), TMP1, TMP1
    vaesenc  3*16(KS), TMP1, TMP1
    vaesenc  4*16(KS), TMP1, TMP1

	leaq CONST_Vector(%rip), %r13
    vaesenc  5*16(KS), TMP1, TMP1
    vaesenc  6*16(KS), TMP1, TMP1
	movq LEN, %r14

    vaesenc  7*16(KS), TMP1, TMP1
	shlq $4, %r14
	leaq AND_VEC(%rip), %r15
	addq %r14, %r15
	vmovdqu (%r15), TMP4
    vaesenc  8*16(KS), TMP1, TMP1
    vaesenc  9*16(KS), TMP1, TMP1
	movq %rsp, %r14
	cmp $8, LEN
    vaesenclast  10*16(KS), TMP1, TMP1
	vpand TMP4, TMP1, TMP1
	jb .bytes_read_dec_loop
	movq (CT), %r12
	movq %r12, (%rsp)
	addq $8, CT
	addq $8, %r14
	subq $8, LEN
.bytes_read_dec_loop:
	cmp $0, LEN
	je .done_read_dec
	dec LEN
	movb (CT), %al
	movb %al, (%r14)
	inc %r14
	inc CT
	jmp .bytes_read_dec_loop
.done_read_dec:
	#TMP3 - PT BLOCK
	vpxor (%rsp), TMP1 , TMP3
	vmovdqu TMP3, (%rsp)
	movq %rsp, %r14
	cmp $8, %r11
	jb .bytes_write_dec
	movq (%rsp), %r12
	movq %r12, (PT)
	addq $8, PT
	subq $8, %r11
	addq $8, %r14
.bytes_write_dec:
	cmp $0, %r11
	je .done_write_dec
	dec %r11
	movb (%r14), %al
	movb %al, (PT)
	inc PT
	inc %r14
	jmp .bytes_write_dec
.done_write_dec:
	cmp $0, LEN
	je .DONE_PT
	movq $0, (%rsp)
	movq $0, 8(%rsp)
.DONE_PT:
	vpand TMP4, TMP3, TMP3
	vpxor    TMP3, T, T
    vmovdqu  -32(Htbl), TMP0
    call     GFMUL_	
	jmp .LSave
.LSave:
	vmovdqu  T, (POL)
.LDone:
	addq $16, %rsp
    popq %rax
    popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    ret
    
.size Decrypt_Htable, .-Decrypt_Htable

#########################
# a = T
# b = TMP0 - remains unchanged
# res = T
# uses also TMP1,TMP2,TMP3,TMP4
# __m128i GFMUL_(__m128i A, __m128i B);
.type GFMUL_,@function
.globl GFMUL_
GFMUL_:  
    vpclmulqdq  $0x00, TMP0, T, TMP1
    vpclmulqdq  $0x11, TMP0, T, TMP4
    vpclmulqdq  $0x10, TMP0, T, TMP2
    vpclmulqdq  $0x01, TMP0, T, TMP3
    vpxor       TMP3, TMP2, TMP2
    vpslldq     $8, TMP2, TMP3
    vpsrldq     $8, TMP2, TMP2
    vpxor       TMP3, TMP1, TMP1
    vpxor       TMP2, TMP4, TMP4

    vpclmulqdq  $0x10, poly(%rip), TMP1, TMP2
    vpshufd     $78, TMP1, TMP3
    vpxor       TMP3, TMP2, TMP1
        
    vpclmulqdq  $0x10, poly(%rip), TMP1, TMP2
    vpshufd     $78, TMP1, TMP3
    vpxor       TMP3, TMP2, TMP1

    vpxor       TMP4, TMP1, T
    ret
.size GFMUL_, .-GFMUL_














    
