AES GCM SIV

In the following package 4 different packages included:

1. AES GCM SIV Package - ASM code - performance code - this versions was tested on linux based systems.
2. AES GENEREL PURPOSE GCM SIV - C code - works on any computer.
3. AES GCM SIV Package MAC OS- ASM code - performance code - version enabled for MAC OS using xcode, llvm and gcc.
   The tested machine is using Apple LLVM Version 7.3.0 (clang-703.0.29) with target x86_64-apple-darwin15.3.0.
4. AES GCM SIV C Intrinsics Code - C code - version with about the similar performance to the performance code - more portability version.

Both of the codes were validated and both supply same output. 
The Performance code has more details on output.

Each package contains EXEC Files to run, sample output file,
result of measurements (Performance package).

Each exec file has 2 inputs <AAD_LEN> <MSG LEN> and same input "constants" 
as sample - so it will be easy to verify and check with each other.

Please read each README for further details.
Please use gcc with version 5.2+ (can be modified on the makefile)
The versions were tested with GCC 5.2.0.

Results on performance code (using Performance code version on Fixed frequency):
                Decryption	
              	HSW [C/B]   BDW [C/B]    SKL [C/B]
AAD=0 MSG=1024	1.98        1.43        1.17
AAD=0 MSG=2048	1.54        1.06        0.88
AAD=0 MSG=4096	1.39        0.91        0.76
AAD=0 MSG=8192	1.28        0.82        0.69
AAD=0 MSG=16384	1.24        0.78        0.66


                Encryption	
                HSW [C/B]   BDW [C/B]   SKL [C/B]
AAD=0 MSG=1024	1.82        1.44        1.37
AAD=0 MSG=2048	1.53        1.16        1.14
AAD=0 MSG=4096	1.39        1.03        1.04
AAD=0 MSG=8192	1.32        0.96        0.98
AAD=0 MSG=16384	1.29        0.93        0.96
