#GCC = /usr/intel/pkgs/gcc/5.2.0/bin/gcc -mpclmul -O3 -maes  -mavx -w
# Above not needed - this has been successfully tested with GCC-9.1
GCC = gcc
#GCC = clang
ICC = icc

FLAGS  = -mpclmul -O3 -maes  -mavx -w
FLAGS += -DRDTSC -march=native -Werror -Wall

# Detect whether we're on Mac
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Darwin)
  ifeq ($(GCC), gcc)
    # On Mac at least some GCC (like Macports) require native Assembler from Xcode
    # But Clang - native or Macports - does not need that.
    FLAGS += -Wa,-q
  endif
endif

DEF ?= -DDETAILS -DLITTLE_ENDIAN_ -DADD_INFO
#DEF +== -DCOUNT

default: all

all:  ALL

ALL:  GHASH 
	
GHASH:
	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS -DDEC  GCM_SIV.c main.c general_functions.c polyval.c enc_msg_x4.c enc_msg_x8.c dec_msg_htable_x6.c key_expands_and_enc.c -o GCM_SIV_DEC
	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS        GCM_SIV.c main.c general_functions.c polyval.c enc_msg_x4.c enc_msg_x8.c dec_msg_htable_x6.c key_expands_and_enc.c -o GCM_SIV_ENC

clean:
	rm -f GCM_SIV_DEC
	rm -f GCM_SIV_ENC
