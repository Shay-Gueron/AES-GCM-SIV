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
.quad	1,0
two:
.quad	2,0
three:
.quad	3,0
four:
.quad	4,0


.macro AES_ROUND i
    vmovdqu  \i*16(KS), TMP
    vaesenc  TMP, STATE1, STATE1
    vaesenc  TMP, STATE2, STATE2
    vaesenc  TMP, STATE3, STATE3
    vaesenc  TMP, STATE4, STATE4

.endm

.macro AES_LASTROUND i
    vmovdqu  \i*16(KS), TMP
    vaesenclast  TMP, STATE1, STATE1
    vaesenclast  TMP, STATE2, STATE2
    vaesenclast  TMP, STATE3, STATE3
    vaesenclast  TMP, STATE4, STATE4
.endm

.set CTR1, %xmm0
.set CTR2, %xmm1
.set CTR3, %xmm2
.set CTR4, %xmm3
.set ADDER, %xmm4

.set STATE1, %xmm5
.set STATE2, %xmm6
.set STATE3, %xmm7
.set STATE4, %xmm8

.set TMP, %xmm12
.set TMP2, %xmm13
.set TMP3, %xmm14
.set IV, %xmm15

.set PT, %rdi
.set CT, %rsi
.set TAG, %rdx
.set KS, %rcx
.set LEN, %r8
.set gTMP, %r11


#####################################################################
# void ENC_MSG_x4(unsigned char* PT, 
#				  unsigned char* CT, 
#				  unsigned char* TAG, 
#				  unsigned char* KS,
#				  int byte_len);
.globl ENC_MSG_x4
ENC_MSG_x4:

# parameter 1: %rdi     #PT
# parameter 2: %rsi     #CT
# parameter 3: %rdx     #TAG		[127 126 ... 0]  IV=[127...32]
# parameter 4: %rcx     #KS
# parameter 5: %r8      #LEN MSG_length in bytes

    test  LEN, LEN
    jnz   .Lbegin
    ret
	
.Lbegin:	   
    pushq  %rdi
	pushq  %rsi
	pushq  %rdx
	pushq  %rcx
	pushq  %r8	  
    pushq  %r10
	pushq  %r11
	pushq  %r12
	pushq  %r13
	pushq %rax
	xorq   	  gTMP, gTMP
	movq      LEN, %r10
    shrq      $4, LEN							#LEN = num of blocks
    shlq      $60, %r10
    je        NO_PARTS
	shrq	  $60, %r10
    movq      %r10, gTMP
NO_PARTS:	
	movq      LEN, %r10
    shlq      $62, %r10
    shrq      $62, %r10
	
	
   	#make IV from TAG
	vmovdqu		(TAG), IV
	vpor   		 OR_MASK(%rip), IV, IV			#IV	  = [1]TAG[126...32][00..00]
	
	vmovdqu		four(%rip), ADDER				#Register to increment counters
	vmovdqa     IV, CTR1			            #CTR1 = TAG[1][127...32][00..00]
	vpaddd 		one(%rip)  ,   IV, CTR2			#CTR2 = TAG[1][127...32][00..01]
	vpaddd 		two(%rip)  , IV, CTR3			#CTR3 = TAG[1][127...32][00..02]
	vpaddd 		three(%rip),  IV, CTR4		    #CTR4 = TAG[1][127...32][00..03] 
    
	
	    
	shrq    $2, LEN
    je      REMAINDER
   							
	subq    $64, CT
    subq    $64, PT

LOOP:
 
    addq    $64, CT   
    addq    $64, PT 

    vmovdqa CTR1, STATE1
	vmovdqa CTR2, STATE2
	vmovdqa CTR3, STATE3
	vmovdqa CTR4, STATE4
    
	vpxor    (KS), STATE1, STATE1
	vpxor    (KS), STATE2, STATE2
	vpxor    (KS), STATE3, STATE3
	vpxor    (KS), STATE4, STATE4
    
    AES_ROUND 1
	vpaddd 		ADDER,  CTR1, CTR1
    AES_ROUND 2
	vpaddd 		ADDER,  CTR2, CTR2
    AES_ROUND 3
	vpaddd 		ADDER,  CTR3, CTR3
    AES_ROUND 4
	vpaddd 		ADDER,  CTR4, CTR4
    
	AES_ROUND 5    
    AES_ROUND 6    
    AES_ROUND 7
    AES_ROUND 8
    AES_ROUND 9
	AES_LASTROUND 10
	
    #Xor with Plaintext
    vpxor   0*16(PT), STATE1, STATE1
    vpxor   1*16(PT), STATE2, STATE2
    vpxor   2*16(PT), STATE3, STATE3
    vpxor   3*16(PT), STATE4, STATE4
   
    dec LEN

    vmovdqu STATE1, 0*16(CT)
    vmovdqu STATE2, 1*16(CT)
    vmovdqu STATE3, 2*16(CT)
    vmovdqu STATE4, 3*16(CT)
 
    jne LOOP
	
	addq    $64,CT
    addq    $64,PT
   
REMAINDER:
   cmpq      $0, %r10
   je   END_BLOCK
   
LOOP2:
	
	#enc each block separately
	#CTR1 is the highest counter (even if no LOOP done)
	
	vmovdqa 	CTR1, STATE1
	vpaddd 		one(%rip),  CTR1, CTR1					#inc counter
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
	
END_BLOCK:
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
	popq %rax
	popq %r13
	popq %r12
	popq %r11
	popq %r10
	popq %r8
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi
    ret

