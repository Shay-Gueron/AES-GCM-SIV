#GCC = gcc -mpclmul -O3 -maes  -mavx -w
GCC    = gcc -O3 -maes -mpclmul -mavx -w
ICC    = icc
FLAGS  = -DRDTSC -DLITTLE_ENDIAN_
#DEF    = -DDETAILS -DADD_INFO 
DEF    = -DCOUNT
#FLAGS += -Wa,-q

ifeq ($(OS),Windows_NT)
    CCFLAGS += -D WIN32
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        CCFLAGS += -DLINUX
    endif
    ifeq ($(UNAME_S),Darwin)
        #CCFLAGS += -DOSX -march=native
        GCC    = clang $(CCFLAGS) -O3 -march=native
    endif
    #UNAME_P := $(shell uname -p)
    #ifeq ($(UNAME_P),x86_64)
    #    CCFLAGS += -DAMD64
    #endif
    #ifneq ($(filter %86,$(UNAME_P)),)
    #    CCFLAGS += -DIA32
    #endif
    #ifneq ($(filter arm%,$(UNAME_P)),)
    #    CCFLAGS += -DARM
    #endif
endif

ALL:  GHASH 
	
GHASH:

	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS -DDEC  main.c GCM_SIV.c general_functions.c polyval_horner.s polyval_htble.s enc_msg_x4.s enc_msg_x8.s dec_msg_htable_x6.s key_expands_and_enc.s  -o GCM_SIV_DEC
	$(GCC) $(FLAGS) $(DEF) -DTWO_KEYS        main.c GCM_SIV.c general_functions.c polyval_horner.s polyval_htble.s enc_msg_x4.s enc_msg_x8.s dec_msg_htable_x6.s key_expands_and_enc.s  -o GCM_SIV_ENC

	


clean:
	rm -f GCM_SIV_DEC
	rm -f GCM_SIV_ENC
