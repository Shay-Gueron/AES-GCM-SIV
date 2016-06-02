GCC = gcc -mpclmul -O3 -maes  -mavx -w
ICC = icc
FLAGS = -DRDTSC
#DEF= -DDETAILS -DADD_INFO
DEF= -DCOUNT
# The following line should be added for Macports-installed GCC
#FLAGS+= -Wa,-q

ALL:  GHASH 
	
GHASH:

	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS -DDEC  GCM_SIV_main.c polyval_horner.s polyval_htble.s enc_msg_x4.s enc_msg_x8.s dec_msg_htable_x6.s key_expands_and_enc.s  -o GCM_SIV_DEC
	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS        GCM_SIV_main.c polyval_horner.s polyval_htble.s enc_msg_x4.s enc_msg_x8.s dec_msg_htable_x6.s key_expands_and_enc.s  -o GCM_SIV_ENC


clean:
	rm -f GCM_SIV_DEC
	rm -f GCM_SIV_ENC
