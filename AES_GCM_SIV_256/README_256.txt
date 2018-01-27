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

This implementation of AES-GCM-SIV supports message length of up to  2^31 - 1 bytes, and AAD length of up to 2^31 - 1 bytes.

It is possible to modify this implementation to support larger input (message and AAD) sizes up to the maximum allowed sizes (e.g., message of 2^36 – 1 byes) that are allowed by the specification document.

Such changes need to be done carefully, because supporting very long input could degrade the performance due to the limited cache and memory sizes supported by the OS.

Please read each README for further details.
Please use gcc with version 5.2+ (can be modified on the makefile)
The versions were tested with GCC 5.2.0.

Results on performance code (using Performance code version on Fixed frequency):
                Decryption	
              	HSW [C/B]   BDW [C/B]    SKL [C/B]
AAD=0 MSG=1024	2.38        1.85        1.48
AAD=0 MSG=2048	1.84        1.41        1.16
AAD=0 MSG=4096	1.65        1.22        1.03
AAD=0 MSG=8192	1.53        1.11        0.95
AAD=0 MSG=16384	1.47        1.07        0.92


                Encryption	
                HSW [C/B]   BDW [C/B]   SKL [C/B]
AAD=0 MSG=1024	2.15        1.75        1.69
AAD=0 MSG=2048	1.83        1.44        1.43
AAD=0 MSG=4096	1.67        1.29        1.31
AAD=0 MSG=8192	1.59        1.22        1.24
AAD=0 MSG=16384	1.56        1.19        1.21
