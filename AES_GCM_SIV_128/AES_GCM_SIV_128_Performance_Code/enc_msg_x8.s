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
one:
.quad   1,0
two:
.quad   2,0
three:
.quad   3,0
four:
.quad   4,0
five:
.quad   5,0
six:
.quad   6,0
seven:
.quad   7,0
eight:
.quad   8,0

  

.set STATE1, %xmm1
.set STATE2, %xmm2
.set STATE3, %xmm3
.set STATE4, %xmm4
.set STATE5, %xmm5
.set STATE6, %xmm6
.set STATE7, %xmm7
.set STATE8, %xmm8

.set CTR1, %xmm0
.set CTR2, %xmm9
.set CTR3, %xmm10
.set CTR4, %xmm11
.set CTR5, %xmm12
.set CTR6, %xmm13
.set CTR7, %xmm14
.set SCHED, %xmm15

.set TMP1, %xmm1
.set TMP2, %xmm2


.set KS, %rcx
.set LEN, %r8
.set PT, %rdi
.set CT, %rsi
.set TAG, %rdx
.set gTMP, %r11
.macro AES_ROUND i
    vmovdqu  \i*16(KS), SCHED
    vaesenc  SCHED, STATE1, STATE1
    vaesenc  SCHED, STATE2, STATE2
    vaesenc  SCHED, STATE3, STATE3
    vaesenc  SCHED, STATE4, STATE4
    vaesenc  SCHED, STATE5, STATE5
    vaesenc  SCHED, STATE6, STATE6
    vaesenc  SCHED, STATE7, STATE7
    vaesenc  SCHED, STATE8, STATE8
.endm

.macro AES_LASTROUND i
    vmovdqu  \i*16(KS), SCHED
    vaesenclast  SCHED, STATE1, STATE1
    vaesenclast  SCHED, STATE2, STATE2
    vaesenclast  SCHED, STATE3, STATE3
    vaesenclast  SCHED, STATE4, STATE4
    vaesenclast  SCHED, STATE5, STATE5
    vaesenclast  SCHED, STATE6, STATE6
    vaesenclast  SCHED, STATE7, STATE7
    vaesenclast  SCHED, STATE8, STATE8
.endm

#####################################################################
# void ENC_MSG_x8(unsigned char* PT, 
#                 unsigned char* CT, 
#                 unsigned char* TAG, 
#                 unsigned char* KS,
#                 int byte_len);
.globl ENC_MSG_x8
ENC_MSG_x8:

# parameter 1: %rdi     #PT
# parameter 2: %rsi     #CT
# parameter 3: %rdx     #TAG        [127 126 ... 0]  IV=[127...32]
# parameter 4: %rcx     #KS
# parameter 5: %r8      #LEN MSG_length in bytes

    test  LEN, LEN
    jnz   .Lbegin
    ret
.Lbegin:    
    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %r8
    pushq   %r10
	pushq  %r11
	pushq  %r12
	pushq  %r13
	pushq %rax
	pushq   %rbp
    movq    %rsp, %rbp
    #Place in stack
    subq    $128, %rsp #changed from 16 to 32 in order to save buffer for remaining bytes.
    andq    $-64, %rsp
    xorq   	  gTMP, gTMP
    movq      LEN, %r10
    shrq      $4, LEN                           #LEN = num of blocks
    shlq      $60, %r10
    je        NO_PARTS
	shrq	  $60, %r10
    movq      %r10, gTMP
NO_PARTS:   
    movq      LEN, %r10
    shlq      $61, %r10
    shrq      $61, %r10
    
    #make IV from TAG
    vmovdqu     (TAG), TMP1
    vpor OR_MASK(%rip), TMP1, TMP1              #TMP1= IV = [1]TAG[126...32][00..00]
    
    #store counter8 in the stack
    vpaddd      seven(%rip), TMP1, CTR1         
    vmovdqu     CTR1,        (%rsp)             #CTR8 = TAG[127...32][00..07]
    vpaddd      one(%rip),   TMP1, CTR2         #CTR2 = TAG[127...32][00..01]
    vpaddd      two(%rip), TMP1, CTR3           #CTR3 = TAG[127...32][00..02]
    vpaddd      three(%rip),  TMP1, CTR4            #CTR4 = TAG[127...32][00..03] 
    vpaddd      four(%rip),  TMP1, CTR5         #CTR5 = TAG[127...32][00..04] 
    vpaddd      five(%rip),   TMP1, CTR6            #CTR6 = TAG[127...32][00..05] 
    vpaddd      six(%rip), TMP1, CTR7           #CTR7 = TAG[127...32][00..06]
    vmovdqa     TMP1, CTR1          #CTR1 = TAG[127...32][00..00]            
        
    shrq    $3, LEN
    je      REMAINDER
                            
    subq    $128, CT
    subq    $128, PT

LOOP:
 
    addq    $128, CT   
    addq    $128, PT 
    
    vmovdqa CTR1, STATE1
    vmovdqa CTR2, STATE2
    vmovdqa CTR3, STATE3
    vmovdqa CTR4, STATE4
    vmovdqa CTR5, STATE5
    vmovdqa CTR6, STATE6
    vmovdqa CTR7, STATE7
    #move from stack
    vmovdqu (%rsp), STATE8
    
    vpxor    (KS), STATE1, STATE1
    vpxor    (KS), STATE2, STATE2
    vpxor    (KS), STATE3, STATE3
    vpxor    (KS), STATE4, STATE4
    vpxor    (KS), STATE5, STATE5
    vpxor    (KS), STATE6, STATE6
    vpxor    (KS), STATE7, STATE7
    vpxor    (KS), STATE8, STATE8
    
    
    AES_ROUND 1
    vmovdqu     (%rsp), CTR7                    #deal with CTR8
    vpaddd      eight(%rip), CTR7, CTR7
    vmovdqu     CTR7, (%rsp)
    AES_ROUND 2
    vpsubd      one(%rip), CTR7, CTR7           #CTR7
    AES_ROUND 3
    vpaddd      eight(%rip),  CTR1, CTR1        #CTR1
    AES_ROUND 4
    vpaddd      eight(%rip),  CTR2, CTR2        #CTR2
    AES_ROUND 5
    vpaddd      eight(%rip),  CTR3, CTR3        #CTR3
    AES_ROUND 6   
    vpaddd      eight(%rip),  CTR4, CTR4        #CTR4
    AES_ROUND 7
    vpaddd      eight(%rip),  CTR5, CTR5        #CTR5
    AES_ROUND 8
    vpaddd      eight(%rip),  CTR6, CTR6        #CTR6
    AES_ROUND 9
    AES_LASTROUND 10
    
   
    #Xor with Plaintext
    vpxor   0*16(PT), STATE1, STATE1
    vpxor   1*16(PT), STATE2, STATE2
    vpxor   2*16(PT), STATE3, STATE3
    vpxor   3*16(PT), STATE4, STATE4
    vpxor   4*16(PT), STATE5, STATE5
    vpxor   5*16(PT), STATE6, STATE6
    vpxor   6*16(PT), STATE7, STATE7
    vpxor   7*16(PT), STATE8, STATE8
   

    dec LEN

    vmovdqu STATE1, 0*16(CT)
    vmovdqu STATE2, 1*16(CT)
    vmovdqu STATE3, 2*16(CT)
    vmovdqu STATE4, 3*16(CT)
    vmovdqu STATE5, 4*16(CT)
    vmovdqu STATE6, 5*16(CT)
    vmovdqu STATE7, 6*16(CT)
    vmovdqu STATE8, 7*16(CT)
 
    jne LOOP
    
    #vmovdqu (%rsp), CTR1
    #vpsubq     seven(%rip),  CTR1, CTR1
    
    addq    $128,CT
    addq    $128,PT
   
REMAINDER:
   cmpq      $0, %r10
   je   END_FULL_BLOCKS

LOOP2:
    
    #enc each block separately
    #CTR1 is the highest counter (even if no LOOP done)
    vmovdqa     CTR1, STATE1
    vpaddd      one(%rip),  CTR1, CTR1                  #inc counter
    
    vpxor         (KS), STATE1, STATE1
    vaesenc     16(KS), STATE1, STATE1
    vaesenc    32(KS) , STATE1, STATE1
    vaesenc    48(KS) , STATE1, STATE1
    vaesenc    64(KS) , STATE1, STATE1
    vaesenc    80(KS) , STATE1, STATE1
    vaesenc    96(KS) , STATE1, STATE1
    vaesenc    112(KS), STATE1, STATE1
    vaesenc    128(KS), STATE1, STATE1
    vaesenc    144(KS), STATE1, STATE1
    vaesenclast  160(KS), STATE1, STATE1
    
    
    #Xor with Plaintext
    vpxor   (PT), STATE1, STATE1
    
    vmovdqu STATE1, (CT)
    
    addq    $16, PT
    addq    $16, CT   
     
    
    decq      %r10
    jne       LOOP2
END_FULL_BLOCKS:
    cmp $0, gTMP
	je END
	subq $16, %rsp
	movq %rsp, %r13
	movq $0, (%rsp)
	movq $0, 8(%rsp)
	movq gTMP, %r8
	vpxor (KS), CTR1, STATE1
	vaesenc     16(KS), STATE1, STATE1
	vaesenc    32(KS) , STATE1, STATE1
	vaesenc    48(KS) , STATE1, STATE1
	vaesenc    64(KS) , STATE1, STATE1
    vaesenc    80(KS) , STATE1, STATE1
	vaesenc    96(KS) , STATE1, STATE1
    vaesenc    112(KS), STATE1, STATE1
	vaesenc    128(KS), STATE1, STATE1
	vaesenc    144(KS), STATE1, STATE1
    vaesenclast  160(KS), STATE1, STATE1
	cmp $8, gTMP
	jb .bytes_read_loop
	movq (PT), %r10
	movq %r10, (%r13)
	addq $8, PT
	addq $8, %r13
	subq $8, gTMP
.bytes_read_loop:
	cmp $0, gTMP
	je .done_read
	dec gTMP
	movb (PT), %al
	movb %al, (%r13)
	inc %r13
	inc PT
	jmp .bytes_read_loop
.done_read:
	vpxor (%rsp), STATE1, STATE1
	vmovdqu STATE1, (%rsp)
	movq %rsp, %r13
	cmp $8, %r8
	jb .bytes_write_loop
	movq (%r13), %r10
	movq %r10, (CT)
	addq $8, CT
	subq $8, %r8
	addq $8, %r13
.bytes_write_loop:
	cmp $0, %r8
	je .done_write
	dec %r8
	movb (%r13), %al
	movb %al, (CT)
	inc CT
	inc %r13
	jmp .bytes_write_loop
.done_write:
	addq $16, %rsp
END:
	addq $128, %rsp
	movq    %rbp, %rsp
    popq    %rbp
	popq    %rax
	popq   %r13
	popq   %r12
	popq   %r11
    popq   %r10
    popq   %r8
    popq   %rcx
    popq   %rdx
    popq   %rsi
    popq   %rdi
       
    ret
