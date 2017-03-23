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

#####################
#Used by _GFMUL		#
.set RES, %xmm0		#
.set H, %xmm1		#
.set TMP1, %xmm2	#
.set TMP2, %xmm3	#
.set TMP3, %xmm4	#
.set TMP4, %xmm5	#
#################################################################
# RES = _GFMUL(RES, H)
# a = RES
# b = H - remains unchanged
# res = RES
# uses also TMP1,TMP2,TMP3,TMP4
# __m128i _GFMUL(__m128i A, __m128i B);
.type _GFMUL,@function
.globl _GFMUL
_GFMUL:
    vpclmulqdq  $0x00, H, RES, TMP1
    vpclmulqdq  $0x11, H, RES, TMP4
    vpclmulqdq  $0x10, H, RES, TMP2
    vpclmulqdq  $0x01, H, RES, TMP3
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

    vpxor       TMP4, TMP1, RES
    ret
.size _GFMUL, .-_GFMUL




.set T, %rdi
.set Hp, %rsi
.set INp, %rdx
.set L, %rcx

.set LOC, %r10
.set LEN, %eax

#void   Polyval_Horner(unsigned char T[16],  		// output
#					    const unsigned char* H,	// H
#						unsigned char* BUF,		// Buffer
#						unsigned int blocks);		// LEn2


.globl Polyval_Horner
Polyval_Horner:

# parameter 1: %rdi		T	 	- pointers to POLYVAL output
# parameter 2: %rsi		Hp 	 	- pointer to H (user key)
# parameter 3: %rdx		INp 	- pointer to input
# parameter 4: %rcx		L 	 	- total number of blocks in input BUFFER


	test  L, L
    jnz   .LbeginPoly
    ret

.LbeginPoly:
	#We will start with L _GFMULS for POLYVAL(BIG_BUFFER)
	#RES = _GFMUL(RES, H)

	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r12
	pushq %r13
	pushq %rax
	xor 		%r10, %r10
	movq L, %r8
	vmovdqu  	(Hp), H
	vmovdqu		(T), RES
	cmp $16, %r8
	jb .Lrem
.Lloop:

	vpxor 		(INp,LOC), RES, RES			#RES = RES + Xi
	call _GFMUL								#RES = RES * H


	add 	$16, LOC
	subq $16, %r8
	cmp		$16, %r8
	jae   .Lloop
.Lrem:
	cmp $0, %r8
	je .polyend
	subq $16, %rsp
	movq $0, (%rsp)
	movq $0, 8(%rsp)
	movq %rsp, L
	cmp $8, %r8
	jb .bytes_read_l
	movq (INp, LOC), %r9
	movq %r9, (L)
	addq $8, LOC
	addq $8, L
	subq $8, %r8
.bytes_read_l:
	cmp $0, %r8
	je .done_read_l
	dec %r8
	movb (INp, LOC), %al
	movb %al, (L)
	inc L
	inc LOC
	jmp .bytes_read_l
.done_read_l:
	vpxor (%rsp), RES, RES
	call _GFMUL
	#calculation of T is over here. RES=T
	addq $16, %rsp
.polyend:
	vmovdqu RES, (%rdi)
	popq %rax
	popq %r13
	popq %r12
	popq %r10
	popq %r9
	popq %r8
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi
ret

.size Polyval_Horner, .-Polyval_Horner

.set T, %rdi
.set Hp, %rsi
.set aadINp, %rdx
.set aadLen, %rcx
.set msgINp, %r8
.set msgLen, %r9
.set LOC, %r10
.set aadLoc, %r11
.set msgLoc, %r12
.set TMP, %r13
.set pLENBLK, %r14
.set TMP1, %rsi
.set buffer, %r15
.globl Polyval_Horner_AAD_MSG_LENBLK
Polyval_Horner_AAD_MSG_LENBLK:
# parameter 1: %rdi		T	 	- pointers to POLYVAL output
# parameter 2: %rsi		Hp 	 	- pointer to H (user key)
# parameter 3: %rdx		aadINp 	- pointer to AAD input
# parameter 4: %rcx		aadLen 	 	- aad Length
# parameter 5: %r8		msgINp 	 	- pointer to MSG input
# parameter 6: %r9		msgLen 	 	- msg Length
# parameter 7: 8(%rsp)  lenBlk      - lenBLK



.Lbegin:
	#We will start with L _GFMULS for POLYVAL(BIG_BUFFER)
	#RES = _GFMUL(RES, H)

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
	movq 12*8+8(%rsp), pLENBLK
	subq $16, %rsp
	movq %rsp, buffer
	movq $0, 0(buffer)
	movq $0, 8(buffer)
	xorq 		%r10, %r10
	movq 		aadLen, aadLoc
	movq			msgLen, msgLoc
	#shr 		$4, aadLoc						#L contains number of bytes to proceed
	shlq			$60, aadLen
	shrq			$60, aadLen
	vmovdqu  	(Hp), H
	vmovdqu		(T), RES
	cmp $16, aadLoc
	jb .LaadRemainder
	subq $16, aadLoc

.Lloop1:

	vpxor 		(aadINp,LOC), RES, RES			#RES = RES + Xi
	call _GFMUL								#RES = RES * H


	add 	$16, LOC
	cmp		LOC, aadLoc
	jae   .Lloop1
.LaadRemainder:

	cmp $0, aadLen
	je .MsgPart

	#handle rem aad
	movq buffer, TMP
	cmp $8, aadLen
	jb .bytes_read_aad_loop
	movq (aadINp, LOC), TMP1
	movq TMP1, (TMP)
	addq $8, LOC
	addq $8, TMP
	subq $8,aadLen
.bytes_read_aad_loop:
	cmp $0, aadLen
	je .aadDone
	dec aadLen
	movb (aadINp, LOC), %al
	movb %al, (TMP)
	inc LOC
	inc TMP
	jmp .bytes_read_aad_loop
.aadDone:	
	vmovdqu (buffer), %xmm10
	vpxor %xmm10, RES, RES
	call _GFMUL
	movq $0, (buffer)
	movq $0, 8(buffer)
.MsgPart:
	xorq LOC, LOC
	cmp $16, msgLoc
	jb .LMsgRemaining
	subq $16, msgLoc
.MsgLoop:
	vpxor (msgINp, LOC), RES, RES
	call _GFMUL								#RES = RES * H
	add 	$16, LOC
	cmp		LOC, msgLoc
	jae   .MsgLoop
.LMsgRemaining:
	shlq			$60, msgLen
	shrq			$60, msgLen
	cmp $0, msgLen
	je .LenBlkPart

	# handle rem msg
	movq $0, (buffer)
	movq $0, 8(buffer)
	movq buffer, TMP
	cmp $8, msgLen
	jb .bytes_read_msg_loop
	movq (msgINp, LOC), TMP1
	movq TMP1, (TMP)
	addq $8, LOC
	addq $8, TMP
	subq $8,msgLen
.bytes_read_msg_loop:
	cmp $0, msgLen
	je .msgDone
	dec msgLen
	movb (msgINp, LOC), %al
	movb %al, (TMP)
	inc LOC
	inc TMP
	jmp .bytes_read_msg_loop
.msgDone:	
	vmovdqu (buffer), %xmm10
	vpxor %xmm10, RES, RES
	call _GFMUL
	movq $0, (buffer)
	movq $0, 8(buffer)
	

.LenBlkPart:

	#calculation of T is over here. RES=T
	vpxor (pLENBLK), RES, RES
	call _GFMUL
	vmovdqu RES, (%rdi)
.END:
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
.size Polyval_Horner_AAD_MSG_LENBLK, .-Polyval_Horner_AAD_MSG_LENBLK
