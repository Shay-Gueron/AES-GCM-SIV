#GCC = /usr/intel/pkgs/gcc/5.2.0/bin/gcc -mpclmul -O3 -maes  -mavx -w
#GCC = gcc -mpclmul -O3 -maes  -mavx -w
GCC = clang
ICC = icc
FLAGS = -DRDTSC -march=native -Werror -Wall
#FLAGS+= -Wa,-q
DEF  = -DDETAILS -DLITTLE_ENDIAN_
DEF += -DADD_INFO
#DEF +== -DCOUNT

default: all

all:  ALL

ALL:  GHASH 
	
GHASH:

	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS -DDEC  GCM_SIV.c main.c general_functions.c polyval.c enc_msg_x4.c enc_msg_x8.c dec_msg_htable_x6.c key_expands_and_enc.c -o GCM_SIV_DEC
	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS        GCM_SIV.c main.c general_functions.c polyval.c enc_msg_x4.c enc_msg_x8.c dec_msg_htable_x6.c key_expands_and_enc.c  -o GCM_SIV_ENC

clean:
	rm -f GCM_SIV_DEC
	rm -f GCM_SIV_ENC
