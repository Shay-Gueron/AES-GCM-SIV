GCC = /usr/intel/pkgs/gcc/5.2.0/bin/gcc -mpclmul -maes  -mavx -O3 -w
ICC = icc
FLAGS = -DRDTSC
DEF= -DDETAILS -DADD_INFO
#DEF= -DCOUNT
FLAGS+= -Wa,-q

ALL:  GHASH 
	
GHASH:

	$(GCC) $(FLAGS) $(DEF) -DDEC  GCM_SIV.c general_functions.c main.c polyval.c enc_msg_x4.c enc_msg_x8.c dec_msg_htable_x6.c key_expands_and_enc.c  -o GCM_SIV_DEC
	$(GCC) $(FLAGS) $(DEF)        GCM_SIV.c general_functions.c main.c polyval.c enc_msg_x4.c enc_msg_x8.c dec_msg_htable_x6.c key_expands_and_enc.c  -o GCM_SIV_ENC


clean:
	rm -f GCM_SIV_DEC
	rm -f GCM_SIV_ENC
