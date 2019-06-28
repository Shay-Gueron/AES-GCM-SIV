#GCC = /usr/intel/pkgs/gcc/5.2.0/bin/gcc -mpclmul -O3 -maes  -mavx -w
# Above not needed - this has been successfully tested with GCC-9.1
GCC = gcc -mpclmul -O3 -maes  -mavx -w
ICC = icc

# Detect whether we're on Mac
UNAME_S := $(shell uname -s)
FLAGS = -DRDTSC -march=native -Werror -Wall
ifeq ($(UNAME_S), Darwin)
  # On Mac at least some GCC (like Macports) require native Assembler from Xcode
  FLAGS += -Wa,-q
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
