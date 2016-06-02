GCC = gcc -mpclmul -maes  -mavx -O3 -w
ICC = icc
FLAGS = -DRDTSC
DEF= -DDETAILS -DADD_INFO
#DEF= -DCOUNT
FLAGS+= -Wa,-q

ALL:  GHASH 
	
GHASH:

	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS -DDEC  GCM_SIV_main.c polyval.c enc_msg_x4.c enc_msg_x8.c dec_msg_htable_x6.c key_expands_and_enc.c -o GCM_SIV_DEC
	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS        GCM_SIV_main.c polyval.c enc_msg_x4.c enc_msg_x8.c dec_msg_htable_x6.c key_expands_and_enc.c -o GCM_SIV_ENC


clean:
	rm -f GCM_SIV_DEC
	rm -f GCM_SIV_ENC
