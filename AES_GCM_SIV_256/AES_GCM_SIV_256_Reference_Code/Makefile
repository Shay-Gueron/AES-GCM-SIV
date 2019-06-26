GCC = gcc
ICC = icc
FLAGS =  -march=native -Ofast -Os -Werror
BINUTILS = 
DEF=-DDETAILS 

ALL:  SIV_GCM 
	
SIV_GCM:

	$(GCC) $(FLAGS) $(DEF) main.c GCM_SIV_c.c clmul_emulator.c aes_emulation.c aes_emulation_tables.c -o GCM_SIV_GENERAL_V02_BE
	$(GCC) $(FLAGS) $(DEF) main.c GCM_SIV_c.c clmul_emulator.c aes_emulation.c aes_emulation_tables.c -DLE -o GCM_SIV_GENERAL_V02_LE
clean:
	rm -f GCM_SIV_GENERAL_V02_BE
	rm -f GCM_SIV_GENERAL_V02_LE
