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


.align   16
mask:
.long    0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d
con1:
.long    1,1,1,1
con2:
.long    0x1b,0x1b,0x1b,0x1b
con3:
.byte -1,-1,-1,-1,-1,-1,-1,-1,4,5,6,7,4,5,6,7
one:
.long 1,0,0,0
and_mask:
.long 0,0xffffffff, 0xffffffff, 0xffffffff

.align 16
.Lbswap_mask:
.byte 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
shuff_mask:
.quad 0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
poly:
.quad 0x1, 0xc200000000000000 


#########################################################
#Regular Key Expansion no assist        

.globl AES_KS
AES_KS:
# parameter 1: %rdi
# parameter 2: %rsi
    #movl      $10, 240(%rsi)
    pushq %rdi
    pushq %rsi
	pushq %rax
    vmovdqu    (%rdi), %xmm1                             # xmm1 = user key
    vmovdqu    %xmm1, (%rsi)                             # rsi points to output
    
    vmovdqu (con1), %xmm0
    vmovdqu (mask), %xmm15
    
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
    vmovdqu (con2), %xmm0
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
	popq %rax
    popq %rsi
    popq %rdi
    ret        
   
#########################################################
# Expand and encrypt one block

.set BLOCK1, %xmm4
.set AUXREG, %xmm3
.set KS1_REGA, %xmm1
.set KS1_REGB, %xmm2

.set DUMP_KEYS, 1

.macro KS_BLOCK reg reg2 auxReg
    vpsllq $32, \reg, \auxReg         #!!saving mov instruction to xmm3
    vpxor \auxReg, \reg, \reg
    vpshufb (con3), \reg,  \auxReg
    vpxor \auxReg, \reg, \reg
    vpxor \reg2, \reg, \reg
.endm

.macro round i j
    vpshufb %xmm15, %xmm1, %xmm2      #!!saving mov instruction to xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld $1, %xmm0, %xmm0
    KS_BLOCK KS1_REGA KS1_REGB AUXREG
    vaesenc  %xmm1, BLOCK1, BLOCK1
    vmovdqa %xmm1, \i*16(\j)   

.endm        

.macro roundlast i j
    vpshufb %xmm15, %xmm1, %xmm2      #!!saving mov instruction to xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    KS_BLOCK KS1_REGA KS1_REGB AUXREG
    vaesenclast  %xmm1, BLOCK1, BLOCK1
    vmovdqa %xmm1, \i*16(\j)   
.endm        

.globl AES_KS_ENC_x1
AES_KS_ENC_x1:
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
    vmovdqu  0*16(%rdi), BLOCK1

    vmovdqa    %xmm1, (%rcx)                 # KEY[0] = first 16 bytes of random key
    vpxor    %xmm1, BLOCK1, BLOCK1
    
    vmovdqa (con1), %xmm0                    #xmm0  = 1,1,1,1
    vmovdqa (mask), %xmm15                   #xmm15 = mask
    
    ROUND 1, %rcx
    ROUND 2, %rcx
    ROUND 3, %rcx
    ROUND 4, %rcx
    ROUND 5, %rcx
    ROUND 6, %rcx
    ROUND 7, %rcx
    ROUND 8, %rcx
   
    vmovdqa (con2), %xmm0
    
    ROUND 9, %rcx
    ROUNDLAST 10, %rcx
    
    vmovdqu     BLOCK1, 0*16(%rsi)
    popq  %r9
    popq  %r8
    popq  %rcx
    popq  %rdx
    popq  %rsi
    popq  %rdi
    ret        
#########################################################
#void AES128_KS_ENC_x1_INIT_x4(const unsigned char* NONCE, unsigned char* CT, unsigned char* KS,
#				   unsigned char* first_key);	
.set BLOCK2, %xmm10
.set BLOCK3, %xmm11
.set BLOCK4, %xmm12
.set ONE, %xmm13
.globl AES128_KS_ENC_x1_INIT_x4
AES128_KS_ENC_x1_INIT_x4:
# parameter 1: %rdi                         Pointer to NONCE
# parameter 2: %rsi                         Pointer to CT
# parameter 4: %rdx                         Pointer to keys
# parameter 5: %rcx                          Pointer to initial key


    movl      $10, 240(%rcx)                    # key.rounds = 10
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    vmovdqu    (%rcx), %xmm1                  # xmm1 = first 16 bytes of random key
    vmovdqu  0*16(%rdi), BLOCK1
	vmovdqu and_mask(%rip), BLOCK4
	vmovdqu  one(%rip), ONE
	vpshufd $0x90, BLOCK1, BLOCK1
	vpand BLOCK4, BLOCK1, BLOCK1
	vpaddd ONE, BLOCK1, BLOCK2
	vpaddd ONE, BLOCK2, BLOCK3
	vpaddd ONE, BLOCK3, BLOCK4
	
    vmovdqa    %xmm1, (%rcx)                 # KEY[0] = first 16 bytes of random key
    vpxor    %xmm1, BLOCK1, BLOCK1
	vpxor    %xmm1, BLOCK2, BLOCK2
	vpxor    %xmm1, BLOCK3, BLOCK3
	vpxor    %xmm1, BLOCK4, BLOCK4
    
	vmovdqa (con1), %xmm0                    #xmm0  = 1,1,1,1
	vmovdqa (mask), %xmm15                   #xmm15 = mask
   
	ROUND 1, %rdx
	vaesenc %xmm1, BLOCK2, BLOCK2
	vaesenc %xmm1, BLOCK3, BLOCK3
	vaesenc %xmm1, BLOCK4, BLOCK4
	ROUND 2, %rdx
	vaesenc %xmm1, BLOCK2, BLOCK2
	vaesenc %xmm1, BLOCK3, BLOCK3
	vaesenc %xmm1, BLOCK4, BLOCK4
	ROUND 3, %rdx
	vaesenc %xmm1, BLOCK2, BLOCK2
	vaesenc %xmm1, BLOCK3, BLOCK3
	vaesenc %xmm1, BLOCK4, BLOCK4
	ROUND 4, %rdx
	vaesenc %xmm1, BLOCK2, BLOCK2
	vaesenc %xmm1, BLOCK3, BLOCK3
	vaesenc %xmm1, BLOCK4, BLOCK4
	ROUND 5, %rdx
	vaesenc %xmm1, BLOCK2, BLOCK2
	vaesenc %xmm1, BLOCK3, BLOCK3
	vaesenc %xmm1, BLOCK4, BLOCK4
	ROUND 6, %rdx
	vaesenc %xmm1, BLOCK2, BLOCK2
	vaesenc %xmm1, BLOCK3, BLOCK3
	vaesenc %xmm1, BLOCK4, BLOCK4
	ROUND 7, %rdx
	vaesenc %xmm1, BLOCK2, BLOCK2
	vaesenc %xmm1, BLOCK3, BLOCK3
	vaesenc %xmm1, BLOCK4, BLOCK4
	ROUND 8, %rdx
	vaesenc %xmm1, BLOCK2, BLOCK2
	vaesenc %xmm1, BLOCK3, BLOCK3
	vaesenc %xmm1, BLOCK4, BLOCK4
	vmovdqa (con2), %xmm0
  
	ROUND 9, %rdx
	vaesenc %xmm1, BLOCK2, BLOCK2
	vaesenc %xmm1, BLOCK3, BLOCK3
	vaesenc %xmm1, BLOCK4, BLOCK4
	ROUNDLAST 10, %rdx
	vaesenclast %xmm1, BLOCK2, BLOCK2
	vaesenclast %xmm1, BLOCK3, BLOCK3
	vaesenclast %xmm1, BLOCK4, BLOCK4
	vmovdqu     BLOCK1, 0*16(%rsi)
	vmovdqu     BLOCK2, 1*16(%rsi)
	vmovdqu     BLOCK3, 2*16(%rsi)
	vmovdqu     BLOCK4, 3*16(%rsi)
	
	vpxor %xmm1, %xmm1, %xmm1
    popq  %rcx
    popq  %rdx
    popq  %rsi
    popq  %rdi
    ret        

#########################################################

.macro ENC_ROUNDx4 i j
	vmovdqu \i*16(%rdx), \j
	vaesenc    \j, BLOCK1, BLOCK1
	vaesenc    \j, BLOCK2, BLOCK2
	vaesenc    \j, BLOCK3, BLOCK3
	vaesenc    \j, BLOCK4, BLOCK4
.endm
.macro ENC_ROUNDLASTx4 i j
	vmovdqu \i*16(%rdx), \j
	vaesenclast    \j, BLOCK1, BLOCK1
	vaesenclast    \j, BLOCK2, BLOCK2
	vaesenclast    \j, BLOCK3, BLOCK3
	vaesenclast    \j, BLOCK4, BLOCK4
.endm
#########################################################
#void AES_128_ENC_x4(const unsigned char* NONCE, unsigned char* CT, unsigned char* KS);	
.set BLOCK2, %xmm10
.set BLOCK3, %xmm11
.set BLOCK4, %xmm12
.set ONE, %xmm13
.globl AES_128_ENC_x4
AES_128_ENC_x4:
# parameter 1: %rdi                         Pointer to NONCE
# parameter 2: %rsi                         Pointer to CT
# parameter 4: %rdx                         Pointer to keys

    pushq %rdi
    pushq %rsi
    pushq %rdx
	
    vmovdqu    (%rdx), %xmm1                  # xmm1 = first 16 bytes of random key
    vmovdqu  0*16(%rdi), BLOCK1
	vmovdqu and_mask(%rip), BLOCK4
	vmovdqu  one(%rip), ONE
	vpshufd $0x90, BLOCK1, BLOCK1
	vpand BLOCK4, BLOCK1, BLOCK1
	vpaddd ONE, BLOCK1, BLOCK2
	vpaddd ONE, BLOCK2, BLOCK3
	vpaddd ONE, BLOCK3, BLOCK4
	
    vpxor    %xmm1, BLOCK1, BLOCK1
	vpxor    %xmm1, BLOCK2, BLOCK2
	vpxor    %xmm1, BLOCK3, BLOCK3
	vpxor    %xmm1, BLOCK4, BLOCK4
 
    ENC_ROUNDx4 1, %xmm1
	ENC_ROUNDx4 2, %xmm2
	ENC_ROUNDx4 3, %xmm1
	ENC_ROUNDx4 4, %xmm2
	ENC_ROUNDx4 5, %xmm1
	ENC_ROUNDx4 6, %xmm2
	ENC_ROUNDx4 7, %xmm1
	ENC_ROUNDx4 8, %xmm2
	ENC_ROUNDx4 9, %xmm1
	ENC_ROUNDLASTx4 10, %xmm2
	
	vmovdqu     BLOCK1, 0*16(%rsi)
	vmovdqu     BLOCK2, 1*16(%rsi)
	vmovdqu     BLOCK3, 2*16(%rsi)
	vmovdqu     BLOCK4, 3*16(%rsi)
	
	vpxor %xmm1, %xmm1, %xmm1
	vpxor %xmm2, %xmm2, %xmm2
    popq  %rdx
    popq  %rsi
    popq  %rdi
    ret        

#########################################################
# Expand without storing and encrypt two blocks

.set AUXREG, %xmm3
.set KS1_REGA, %xmm1
.set KS1_REGB, %xmm2

.set BLOCK1, %xmm4
.set BLOCK2, %xmm5



.macro KS_BLOCK_b reg reg2 auxReg
    vpsllq $32, \reg, \auxReg         #!!saving mov instruction to xmm3
    vpxor \auxReg, \reg, \reg
    vpshufb (con3), \reg,  \auxReg
    vpxor \auxReg, \reg, \reg
    vpxor \reg2, \reg, \reg
.endm

.macro round_b i
    vpshufb %xmm15, KS1_REGA, KS1_REGB        #!!saving mov instruction to xmm2
    vaesenclast %xmm0, KS1_REGB, KS1_REGB
    KS_BLOCK_b KS1_REGA KS1_REGB AUXREG

    vpslld $1, %xmm0, %xmm0
    
    vaesenc  KS1_REGA, BLOCK1, BLOCK1
    vaesenc  KS1_REGA, BLOCK2, BLOCK2
.endm  

.macro roundlast_b i
    vpshufb %xmm15, KS1_REGA, KS1_REGB        #!!saving mov instruction to xmm2
    vaesenclast %xmm0, KS1_REGB, KS1_REGB
    
    KS_BLOCK_b KS1_REGA KS1_REGB AUXREG
    
    vaesenclast  KS1_REGA, BLOCK1, BLOCK1
    vaesenclast  KS1_REGA, BLOCK2, BLOCK2     
.endm        

.globl AES_KS_no_mem_ENC_x2
AES_KS_no_mem_ENC_x2:
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
    vmovdqu  0*16(%rdi), BLOCK1
    vmovdqu  1*16(%rdi), BLOCK2
   
   
    vpxor    KS1_REGA, BLOCK1, BLOCK1
    vpxor    KS1_REGA, BLOCK2, BLOCK2
    
    vmovdqa (con1), %xmm0                    #xmm0  = 1,1,1,1
    vmovdqa (mask), %xmm15                   #xmm15 = mask
    
    ROUND_B 1
    ROUND_B 2
    ROUND_B 3
    ROUND_B 4
    ROUND_B 5
    ROUND_B 6
    ROUND_B 7
    ROUND_B 8
    
    vmovdqa (con2), %xmm0
    
    ROUND_B 9
    ROUNDLAST_B 10
    
    vmovdqu     BLOCK1, 0*16(%rsi)
    vmovdqu     BLOCK2, 0*16(%rdx)
    popq  %r9
    popq  %r8
    popq  %rcx
    popq  %rdx
    popq  %rsi
    popq  %rdi
    ret        

##########################################################
# encrypt one block only

.align  16

.globl ECB_ENC_block
ECB_ENC_block:

.set KSp, %rdx
.set STATE_1, %xmm1

#parameter 1: PT            %rdi    (pointer to 128 bit)
#parameter 2: CT            %rsi    (pointer to 128 bit)
#parameter 3: ks            %rdx    (pointer to ks)

    pushq   %rdx
    pushq   %rdi
    pushq   %rsi
    pushq   %rbp                                # store rbp
    mov     %rsp, %rbp
    
    
    vmovdqu (%rdi), STATE_1

        
    vpxor       (KSp), STATE_1, STATE_1
    vaesenc 1*16(KSp), STATE_1, STATE_1
    vaesenc 2*16(KSp), STATE_1, STATE_1
    vaesenc 3*16(KSp), STATE_1, STATE_1
    vaesenc 4*16(KSp), STATE_1, STATE_1
    vaesenc 5*16(KSp), STATE_1, STATE_1
    vaesenc 6*16(KSp), STATE_1, STATE_1
    vaesenc 7*16(KSp), STATE_1, STATE_1
    vaesenc 8*16(KSp), STATE_1, STATE_1
    vaesenc 9*16(KSp), STATE_1, STATE_1
    vaesenclast 10*16(KSp), STATE_1, STATE_1    # STATE_1 == IV

    vmovdqa STATE_1, (%rsi)


    mov %rbp, %rsp
    popq    %rbp
    popq    %rsi
    popq    %rdi
    popq    %rdx
    ret

    


##########################################################
# encrypt one block only

.align  16

.globl Finalize_Tag
Finalize_Tag:

.set KSp, %rdx
.set STATE_1, %xmm1

#parameter 1: PT            %rdi    (pointer to 128 bit)
#parameter 2: CT            %rsi    (pointer to 128 bit)
#parameter 3: ks            %rdx    (pointer to ks)
#parameter 3: ks            %rcx    (pointer to tag)

    pushq   %rdx
    pushq   %rdi
    pushq   %rsi
    pushq   %rbp                                # store rbp
	pushq   %r8
	pushq   %r9
	pushq   %r10
	pushq   %r11
    movq     %rsp, %rbp
    subq $16, %rsp
    movq $0, %rax
	movq $1, %r8
    vmovdqu (%rdi), STATE_1

    movq (%rcx), %r10
	movq 8(%rcx), %r11
    vpxor       (KSp), STATE_1, STATE_1
    vaesenc 1*16(KSp), STATE_1, STATE_1
    vaesenc 2*16(KSp), STATE_1, STATE_1
    vaesenc 3*16(KSp), STATE_1, STATE_1
    vaesenc 4*16(KSp), STATE_1, STATE_1
    vaesenc 5*16(KSp), STATE_1, STATE_1
    vaesenc 6*16(KSp), STATE_1, STATE_1
    vaesenc 7*16(KSp), STATE_1, STATE_1
    vaesenc 8*16(KSp), STATE_1, STATE_1
    vaesenc 9*16(KSp), STATE_1, STATE_1
    vaesenclast 10*16(KSp), STATE_1, STATE_1    # STATE_1 == IV

    vmovdqa STATE_1, (%rsi)
	vmovdqu STATE_1, (%rsp)
	
	xorq (%rsp), %r10
	xorq 8(%rsp), %r11
	orq %r10, %r11
	cmp $0, %r11
	cmovneq %r8, %rax
	addq $16, %rsp
    movq %rbp, %rsp
	popq    %r11
	popq    %r10
	popq    %r9
	popq    %r8
    popq    %rbp
    popq    %rsi
    popq    %rdi
    popq    %rdx
    ret





