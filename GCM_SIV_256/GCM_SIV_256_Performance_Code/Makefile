GCC = gcc -mpclmul -O3 -msse4 -maes  -mavx2
ICC = icc
FLAGS = -DRDTSC
DEF= -DDETAILS -DLITTLE_ENDIAN_
#DEF= -DCOUNT


ALL:  GHASH 
	
GHASH:

	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS -DDEC  GCM_SIV_main.c polyval_horner.s polyval_htble.s enc_msg_x4.s enc_msg_x8.s dec_msg_htable_x6.s key_expands_and_enc.s  -o GCM_SIV_DEC
	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS        GCM_SIV_main.c polyval_horner.s polyval_htble.s enc_msg_x4.s enc_msg_x8.s dec_msg_htable_x6.s key_expands_and_enc.s  -o GCM_SIV_ENC

	


clean:
	rm GCM_SIV_DEC
	rm GCM_SIV_ENC
