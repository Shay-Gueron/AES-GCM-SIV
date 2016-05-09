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
OR_MASK:
.long    0x00000000,0x00000000,0x00000000,0x80000000
one:
.quad	1,0
two:
.quad	2,0
three:
.quad	3,0
four:
.quad	4,0
five:
.quad	5,0
six:
.quad	6,0
seven:
.quad	7,0
eight:
.quad	8,0

  

#.set STATE1, %xmm1
#.set STATE2, %xmm2
#.set STATE3, %xmm3
#.set STATE4, %xmm4
#.set STATE5, %xmm5
#.set STATE6, %xmm6
#.set STATE7, %xmm7
#.set STATE8, %xmm8

#.set CTR1, %xmm0
#.set CTR2, %xmm9
#.set CTR3, %xmm10
#.set CTR4, %xmm11
#.set CTR5, %xmm12
#.set CTR6, %xmm13
#.set CTR7, %xmm14
#.set SCHED, %xmm15

#.set TMP1, %xmm1
#.set TMP2, %xmm2
#

#.set KS, %rcx
#.set LEN, %r8
#.set PT, %rdi
#.set CT, %rsi
#.set TAG, %rdx

.macro AES_ROUND i
   vmovdqu  \i*16(%rcx), %xmm15
   vaesenc  %xmm15, %xmm1, %xmm1
   vaesenc  %xmm15, %xmm2, %xmm2
   vaesenc  %xmm15, %xmm3, %xmm3
   vaesenc  %xmm15, %xmm4, %xmm4
   vaesenc  %xmm15, %xmm5, %xmm5
   vaesenc  %xmm15, %xmm6, %xmm6
   vaesenc  %xmm15, %xmm7, %xmm7
   vaesenc  %xmm15, %xmm8, %xmm8
.endm

.macro AES_LASTROUND i
   vmovdqu  \i*16(%rcx), %xmm15
   vaesenclast  %xmm15, %xmm1, %xmm1
   vaesenclast  %xmm15, %xmm2, %xmm2
   vaesenclast  %xmm15, %xmm3, %xmm3
   vaesenclast  %xmm15, %xmm4, %xmm4
   vaesenclast  %xmm15, %xmm5, %xmm5
   vaesenclast  %xmm15, %xmm6, %xmm6
   vaesenclast  %xmm15, %xmm7, %xmm7
   vaesenclast  %xmm15, %xmm8, %xmm8
.endm

#####################################################################
# void ENC_MSG_x8(unsigned char* PT, 
#				  unsigned char* CT, 
#				  unsigned char* TAG, 
#				  unsigned char* KS,
#				  int byte_len);
.globl _ENC_MSG_x8
_ENC_MSG_x8:

# parameter 1: %rdi     #PT
# parameter 2: %rsi     #CT
# parameter 3: %rdx     #TAG		[127 126 ... 0]  IV=[127...32]
# parameter 4: %rcx     #KS
# parameter 5: %r8      #LEN MSG_length in bytes

	test  %r8 , %r8 
    jnz   .Lbegin
    ret
	
.Lbegin:
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rdi
	pushq   %rsi
	pushq   %rdx
	pushq   %rcx
	pushq   %r8
	pushq   %r10
	#Place in stack
 	subq    $16, %rsp
    andq    $-64, %rsp
	
	movq      %r8 , %r10
    shrq      $4, %r8 							#LEN = num of blocks
    shlq      $60, %r10
    je        NO_PARTS
    addq      $1, %r8 
NO_PARTS:	
	movq      %r8 , %r10
    shlq      $61, %r10
    shrq      $61, %r10
	
	#make IV from TAG
	vmovdqu		(%rdx), %xmm1
	vpor OR_MASK(%rip), %xmm1, %xmm1				#TMP1= IV = [1]TAG[126...32][00..00]
    
	#store counter8 in the stack
	vpaddd 		seven(%rip), %xmm1, %xmm0			
	vmovdqu 	%xmm0, 		 (%rsp)				#CTR8 = TAG[127...32][00..07]
	vpaddd 		one(%rip),   %xmm1, %xmm9			#CTR2 = TAG[127...32][00..01]
	vpaddd 		two(%rip), %xmm1, %xmm10			#CTR3 = TAG[127...32][00..02]
	vpaddd 		three(%rip),  %xmm1, %xmm11			#CTR4 = TAG[127...32][00..03] 
	vpaddd 		four(%rip),	 %xmm1, %xmm12			#CTR5 = TAG[127...32][00..04] 
	vpaddd 		five(%rip),   %xmm1, %xmm13			#CTR6 = TAG[127...32][00..05] 
	vpaddd 		six(%rip), %xmm1, %xmm14			#CTR7 = TAG[127...32][00..06]
	vmovdqa 	%xmm1, %xmm0			#CTR1 = TAG[127...32][00..00]			 
	    
	shrq    $3, %r8 
    je      REMAINDER
   							
	subq    $128, %rsi
    subq    $128, %rdi

LOOP:
 
    addq    $128, %rsi   
    addq    $128, %rdi 
	
    vmovdqa %xmm0, %xmm1
	vmovdqa %xmm9, %xmm2
	vmovdqa %xmm10, %xmm3
	vmovdqa %xmm11, %xmm4
	vmovdqa %xmm12, %xmm5
	vmovdqa %xmm13, %xmm6
	vmovdqa %xmm14, %xmm7
	#move from stack
	vmovdqu (%rsp), %xmm8
	
	vpxor    (%rcx), %xmm1, %xmm1
	vpxor    (%rcx), %xmm2, %xmm2
	vpxor    (%rcx), %xmm3, %xmm3
	vpxor    (%rcx), %xmm4, %xmm4
	vpxor    (%rcx), %xmm5, %xmm5
	vpxor    (%rcx), %xmm6, %xmm6
	vpxor    (%rcx), %xmm7, %xmm7
	vpxor    (%rcx), %xmm8, %xmm8
    
	
	AES_ROUND 1
	vmovdqu 	(%rsp), %xmm14					#deal with CTR8
	vpaddd		eight(%rip), %xmm14, %xmm14
	vmovdqu 	%xmm14, (%rsp)
    AES_ROUND 2
    vpsubd		one(%rip), %xmm14, %xmm14			#CTR7
	AES_ROUND 3
	vpaddd 		eight(%rip),  %xmm0, %xmm0		#CTR1
    AES_ROUND 4
	vpaddd 		eight(%rip),  %xmm9, %xmm9		#CTR2
	AES_ROUND 5
    vpaddd 		eight(%rip),  %xmm10, %xmm10		#CTR3
    AES_ROUND 6   
	vpaddd 		eight(%rip),  %xmm11, %xmm11		#CTR4
    AES_ROUND 7
	vpaddd 		eight(%rip),  %xmm12, %xmm12		#CTR5
    AES_ROUND 8
	vpaddd 		eight(%rip),  %xmm13, %xmm13		#CTR6
    AES_ROUND 9
	AES_LASTROUND 10
	
   
	#Xor with Plaintext
    vpxor   0*16(%rdi), %xmm1, %xmm1
    vpxor   1*16(%rdi), %xmm2, %xmm2
    vpxor   2*16(%rdi), %xmm3, %xmm3
    vpxor   3*16(%rdi), %xmm4, %xmm4
	vpxor   4*16(%rdi), %xmm5, %xmm5
    vpxor   5*16(%rdi), %xmm6, %xmm6
    vpxor   6*16(%rdi), %xmm7, %xmm7
    vpxor   7*16(%rdi), %xmm8, %xmm8
   

    dec %r8 

    vmovdqu %xmm1, 0*16(%rsi)
    vmovdqu %xmm2, 1*16(%rsi)
    vmovdqu %xmm3, 2*16(%rsi)
    vmovdqu %xmm4, 3*16(%rsi)
	vmovdqu %xmm5, 4*16(%rsi)
    vmovdqu %xmm6, 5*16(%rsi)
    vmovdqu %xmm7, 6*16(%rsi)
    vmovdqu %xmm8, 7*16(%rsi)
 
    jne LOOP
	
	#vmovdqu (%rsp), %xmm9
	#vpsubq 	seven(%rip),  %xmm9, %xmm9
	
	addq    $128,%rsi
    addq    $128,%rdi
   
REMAINDER:
   cmpq      $0, %r10
   je   END
   
LOOP2:
	
	#enc each block separately
	#CTR1 is the highest counter (even if no LOOP done)
	vmovdqa 	%xmm0, %xmm1
	vpaddd 		one(%rip),  %xmm9, %xmm9					#inc counter
	
	vpxor         (%rcx), %xmm1, %xmm1
	vaesenc     16(%rcx), %xmm1, %xmm1
	vaesenc    32(%rcx) , %xmm1, %xmm1
    vaesenc    48(%rcx) , %xmm1, %xmm1
    vaesenc    64(%rcx) , %xmm1, %xmm1
    vaesenc    80(%rcx) , %xmm1, %xmm1
    vaesenc    96(%rcx) , %xmm1, %xmm1
    vaesenc    112(%rcx), %xmm1, %xmm1
    vaesenc    128(%rcx), %xmm1, %xmm1
    vaesenc    144(%rcx), %xmm1, %xmm1
    vaesenclast  160(%rcx), %xmm1, %xmm1
	
	
	#Xor with Plaintext
    vpxor   (%rdi), %xmm1, %xmm1
	
	vmovdqu %xmm1, (%rsi)
	
	addq    $16, %rdi
	addq    $16, %rsi   
     
	
	decq      %r10
    jne       LOOP2
	
END:
	popq   %r10
	popq   %r8
    popq   %rcx
	popq   %rdx
	popq   %rsi
	popq   %rdi
    movq    %rbp, %rsp
    popq    %rbp    
    ret
