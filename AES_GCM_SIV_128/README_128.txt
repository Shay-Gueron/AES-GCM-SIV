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
AAD=0 MSG=1024	1.88        1.36        1.15
AAD=0 MSG=2048	1.50        1.03        0.86
AAD=0 MSG=4096	1.38        0.89        0.75
AAD=0 MSG=8192	1.29        0.81        0.69
AAD=0 MSG=16384	1.26        0.78        0.66


                Encryption	
                HSW [C/B]   BDW [C/B]   SKL [C/B]
AAD=0 MSG=1024	1.78        1.46        1.36
AAD=0 MSG=2048	1.50        1.18        1.14
AAD=0 MSG=4096	1.37        1.03        1.03
AAD=0 MSG=8192	1.31        0.96        0.98
AAD=0 MSG=16384	1.27        0.93        0.95
