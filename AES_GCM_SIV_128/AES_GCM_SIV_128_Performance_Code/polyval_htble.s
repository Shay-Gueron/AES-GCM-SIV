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
.type INIT_Htable,@function
.globl INIT_Htable
.align 16
INIT_Htable:
   
.set  Htbl, %rdi
.set  H, %rsi


.set T,%xmm0
.set TMP0,%xmm1

    vmovdqu  (H), T
    vmovdqu   T, TMP0
    vmovdqu   T, (Htbl)     # H 
    call  GFMUL
    vmovdqu  T, 16(Htbl)    # H^2 
    call  GFMUL
    vmovdqu  T, 32(Htbl)    # H^3
    call  GFMUL
    vmovdqu  T, 48(Htbl)    # H^4 
    call  GFMUL
    vmovdqu  T, 64(Htbl)    # H^5
    call  GFMUL
    vmovdqu  T, 80(Htbl)    # H^6 
    call  GFMUL
    vmovdqu  T, 96(Htbl)    # H^7 
    call  GFMUL
    vmovdqu  T, 112(Htbl)   # H^8  
    ret
.size INIT_Htable, .-INIT_Htable


################################################################################
# Generates the H table
# void INIT_Htable_6(uint8_t Htbl[16*6], uint8_t *H);
.type INIT_Htable_6,@function
.globl INIT_Htable_6
.align 16
INIT_Htable_6:
   
.set  Htbl, %rdi
.set  H, %rsi


.set T,%xmm0
.set TMP0,%xmm1


    vmovdqu  (H), T
    vmovdqu   T, TMP0
    vmovdqu   T, (Htbl)     # H 
    call  GFMUL
    vmovdqu  T, 16(Htbl)    # H^2 
    call  GFMUL
    vmovdqu  T, 32(Htbl)    # H^3
    call  GFMUL
    vmovdqu  T, 48(Htbl)    # H^4 
    call  GFMUL
    vmovdqu  T, 64(Htbl)    # H^5
    call  GFMUL
    vmovdqu  T, 80(Htbl)    # H^6 
    ret
.size INIT_Htable_6, .-INIT_Htable_6

################################################################################
# void Polyval_Htable(uint8_t Htbl[16*8], uint8_t *MSG, uint64_t LEN, uint8_t *T);


.set DATA, %xmm0
.set T, %xmm1
.set TMP0, %xmm3
.set TMP1, %xmm4
.set TMP2, %xmm5
.set TMP3, %xmm6
.set TMP4, %xmm7
.set Xhi, %xmm9
.set IV, %xmm10
.set Htbl, %rdi
.set inp, %rsi
.set len, %rdx
.set Tp, %rcx


.set hlp0, %r11

.macro SCHOOLBOOK_AAD i
    vpclmulqdq  $0x01, 16*\i(Htbl), DATA, TMP3
    vpxor          TMP3, TMP2, TMP2
    vpclmulqdq  $0x00, 16*\i(Htbl), DATA, TMP3
    vpxor          TMP3, TMP0, TMP0
    vpclmulqdq  $0x11, 16*\i(Htbl), DATA, TMP3
    vpxor          TMP3, TMP1, TMP1
    vpclmulqdq  $0x10, 16*\i(Htbl), DATA, TMP3
    vpxor          TMP3, TMP2, TMP2
.endm


########################################################################################################################
# void Polyval_Htable(uint8_t Htbl[16*8], uint8_t *AAD, uint64_t AAD_LEN, uint8_t *T);

.set Htbl, %rdi
.set inp, %rsi
.set len, %rdx
.set Tp, %rcx
.set gtmp0, %r10
.set gtmp1, %r12
.set gtmp2, %r14
.set gtmp3, %r15
.set buffer, %r8

.globl  Polyval_Htable
.type   Polyval_Htable,@function
.align  16
Polyval_Htable:

# parameter 1: %rdi     Htable  - pointer to Htable
# parameter 2: %rsi     INp     - pointer to input
# parameter 3: %rdx     LEN     - length of BUFFER in bytes 
# parameter 4: %rcx     T       - pointer to POLYVAL output

    test  len, len
    jnz   .LbeginAAD_
    ret

.LbeginAAD_:

    vzeroall
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
	subq $16, %rsp
	movq %rsp, buffer
	movq $0, 0(buffer)
	movq $0, 8(buffer)
    vpxor    Xhi, Xhi, Xhi
    vmovdqu (Tp),T

# we hash 8 block each iteration, if the total amount of blocks is not a multiple of 8, we hash the first n%8 blocks first
    movq    len, hlp0
    andq    $~-128, hlp0
	movq	len, %r9
	andq    $-16, hlp0
	andq	$~-16, %r9
	
	subq $0x80, len
	jb .LRemainder_part
	movq $112, %r10
    vmovdqu (inp), DATA
    vpxor    T, DATA, DATA
	
    vpclmulqdq  $0x01, (Htbl, %r10), DATA, TMP2
    vpclmulqdq  $0x00, (Htbl, %r10), DATA, TMP0
    vpclmulqdq  $0x11, (Htbl, %r10), DATA, TMP1
    vpclmulqdq  $0x10, (Htbl, %r10), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2

    lea 16(inp), inp

    #hash remaining prefix bocks (up to 7 total prefix blocks)
.align 64
.Lpre_hash_htable:

    subq $16, %r10

    vmovdqu     (inp),DATA           # next data block

    vpclmulqdq  $0x00, (Htbl,%r10), DATA, TMP3
    vpxor       TMP3, TMP0, TMP0
    vpclmulqdq  $0x11, (Htbl,%r10), DATA, TMP3
    vpxor       TMP3, TMP1, TMP1
    vpclmulqdq  $0x01, (Htbl,%r10), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    vpclmulqdq  $0x10, (Htbl,%r10), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2

    test    %r10, %r10

    leaq 16(inp), inp

    jnz .Lpre_hash_htable
    
.Lred_pre_hash_htable:
    vpsrldq     $8, TMP2, TMP3
    vpslldq     $8, TMP2, TMP2

    vpxor          TMP3, TMP1, Xhi
    vpxor          TMP2, TMP0, T
	subq $0x80, len
	jb .LPre_Remainder_part
.Lmod_loop_:
    
    jb  .LPre_Remainder_part

    vmovdqu     16*7(inp),DATA      # Ii

    vpclmulqdq  $0x01, (Htbl), DATA, TMP2
    vpclmulqdq  $0x00, (Htbl), DATA, TMP0
    vpclmulqdq  $0x11, (Htbl), DATA, TMP1
    vpclmulqdq  $0x10, (Htbl), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    #########################################################
    vmovdqu     16*6(inp),DATA
    SCHOOLBOOK_AAD 1
    #########################################################
    vmovdqu     16*5(inp),DATA

    vpclmulqdq  $0x10, poly(%rip), T, TMP4         #reduction stage 1a
    vpalignr       $8, T, T, T

    SCHOOLBOOK_AAD 2

    vpxor          TMP4, T, T                 #reduction stage 1b
    #########################################################
    vmovdqu     16*4(inp),DATA

    SCHOOLBOOK_AAD 3
    #########################################################
    vmovdqu     16*3(inp),DATA

    vpclmulqdq  $0x10, poly(%rip), T, TMP4         #reduction stage 2a
    vpalignr       $8, T, T, T

    SCHOOLBOOK_AAD 4

    vpxor          TMP4, T, T                 #reduction stage 2b
    #########################################################
    vmovdqu     16*2(inp),DATA

    SCHOOLBOOK_AAD 5

    vpxor          Xhi, T, T                  #reduction finalize
    #########################################################
    vmovdqu     16*1(inp),DATA

    SCHOOLBOOK_AAD 6
    #########################################################
    vmovdqu     16*0(inp),DATA
    vpxor          T,DATA,DATA

    SCHOOLBOOK_AAD 7
    #########################################################
    vpsrldq $8, TMP2, TMP3
    vpslldq $8, TMP2, TMP2

    vpxor       TMP3, TMP1, Xhi
    vpxor       TMP2, TMP0, T

    lea 16*8(inp), inp
	subq $0x80, len
    jmp .Lmod_loop_
.LPre_Remainder_part:
    vpclmulqdq  $0x10, poly(%rip), T, TMP4
	vpalignr       $8, T, T, T
	vpxor          TMP4, T, T 
	vpxor TMP0, TMP0, TMP0
	vpxor TMP1, TMP1, TMP1
	vpclmulqdq  $0x10, poly(%rip), T, TMP4         #reduction stage 2a
    vpalignr       $8, T, T, T
	vpxor          TMP4, T, T 
	vpxor TMP2, TMP2, TMP2
	vpxor TMP3, TMP3, TMP3
	vpxor          Xhi, T, T
	cmp $-0x80, len
	je .Lsave_
	addq $0x80, len
	jmp .LRemainder_check
.LRemainder_part:
	addq $0x80, len
	cmp $0, len
	je .Ldone_
.LRemainder_check:
	cmp $0, %r9
	jne .LRemainder_with_semi_block
	#remainder has no semi blocks
	vmovdqu (inp), DATA
    vpxor    T, DATA, DATA
	subq $16, hlp0
    vpclmulqdq  $0x00, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP0, TMP0
    vpclmulqdq  $0x11, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP1, TMP1
    vpclmulqdq  $0x01, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    vpclmulqdq  $0x10, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    leaq 16(inp), inp
    cmp $0, hlp0
	je .Lred1_
.align 64
.Lpre_loop_:
    
	subq $16, hlp0
    vmovdqu     (inp),DATA           # next data block

    vpclmulqdq  $0x00, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP0, TMP0
    vpclmulqdq  $0x11, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP1, TMP1
    vpclmulqdq  $0x01, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    vpclmulqdq  $0x10, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    leaq 16(inp), inp 
	cmpq    $0, hlp0
    jne .Lpre_loop_
	jmp .Lred1_
.LRemainder_with_semi_block:
	addq $16, Htbl
	cmp $0, hlp0
	je .Lsemi_block_first 
	vmovdqu (inp), DATA
    vpxor    T, DATA, DATA
	subq $16, hlp0
    vpclmulqdq  $0x00, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP0, TMP0
    vpclmulqdq  $0x11, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP1, TMP1
    vpclmulqdq  $0x01, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    vpclmulqdq  $0x10, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
	
    leaq 16(inp), inp
    cmp $0, hlp0
	je .Lsemiblock
.align 64
.Lpre_loop_semi_block:
    
	subq $16, hlp0
    vmovdqu     (inp),DATA           # next data block

    vpclmulqdq  $0x00, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP0, TMP0
    vpclmulqdq  $0x11, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP1, TMP1
    vpclmulqdq  $0x01, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    vpclmulqdq  $0x10, (Htbl,hlp0), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    leaq 16(inp), inp
	cmpq    $0, hlp0

   
    jne .Lpre_loop_semi_block	
.Lsemiblock:
	
	subq $16, Htbl
	movq %r9, gtmp0
	movq buffer, gtmp1
	cmp $8, %r9
	jb .bytes_read_loop
	movq (inp), gtmp2
	movq gtmp2, (gtmp1)
	addq $8, inp
	addq $8, gtmp1
	subq $8, %r9
.bytes_read_loop:
	cmp $0, %r9
	je .done_read
	dec %r9
	movb (inp), %al
	movb %al, (gtmp1)
	inc gtmp1
	inc inp
	jmp .bytes_read_loop
.done_read:
	vmovdqu (buffer), DATA
	vpclmulqdq  $0x00, (Htbl), DATA, TMP3
    vpxor       TMP3, TMP0, TMP0
    vpclmulqdq  $0x11, (Htbl), DATA, TMP3
    vpxor       TMP3, TMP1, TMP1
    vpclmulqdq  $0x01, (Htbl), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    vpclmulqdq  $0x10, (Htbl), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
	jmp .Lred1_

	
.Lsemi_block_first:
	subq $16, Htbl
	subq hlp0, len
	movq %r9, gtmp0
	movq buffer, gtmp1
	cmp $8, %r9
	jb .bytes_read_loop1
	movq (inp), gtmp2
	movq gtmp2, (gtmp1)
	addq $8, inp
	addq $8, gtmp1
	subq $8, %r9
.bytes_read_loop1:
	cmp $0, %r9
	je .done_read1
	dec %r9
	movb (inp), %al
	movb %al, (gtmp1)
	inc gtmp1
	inc inp
	jmp .bytes_read_loop1
.done_read1:
	vmovdqu (buffer), DATA
	vpxor T, DATA, DATA
	vpclmulqdq  $0x00, (Htbl), DATA, TMP3
    vpxor       TMP3, TMP0, TMP0
    vpclmulqdq  $0x11, (Htbl), DATA, TMP3
    vpxor       TMP3, TMP1, TMP1
    vpclmulqdq  $0x01, (Htbl), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2
    vpclmulqdq  $0x10, (Htbl), DATA, TMP3
    vpxor       TMP3, TMP2, TMP2	
	
	########################################################
.Lred1_:
    vpsrldq     $8, TMP2, TMP3
    vpslldq     $8, TMP2, TMP2

    vpxor          TMP3, TMP1, Xhi
    vpxor          TMP2, TMP0, T
    

    

.Ldone_:
    vpclmulqdq  $0x10, poly(%rip), T, TMP3
    vpalignr    $8, T, T, T
    vpxor       TMP3, T, T

    vpclmulqdq  $0x10, poly(%rip), T, TMP3
    vpalignr    $8, T, T, T
    vpxor       TMP3, T, T
    vpxor       Xhi, T, T	
.Lsave_:
   
    vmovdqu     T,(Tp)
    vzeroall
  
	addq $16, %rsp
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
.size   Polyval_Htable,.-Polyval_Htable


.set T,%xmm0
.set TMP0,%xmm1
.set TMP1,%xmm2
.set TMP2,%xmm3
.set TMP3,%xmm4
.set TMP4,%xmm5

#########################
# a = T
# b = TMP0 - remains unchanged
# res = T
# uses also TMP1,TMP2,TMP3,TMP4
# __m128i GFMUL(__m128i A, __m128i B);
.type GFMUL,@function
.globl GFMUL
GFMUL:  
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
.size GFMUL, .-GFMUL

