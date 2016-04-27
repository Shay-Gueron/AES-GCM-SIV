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

Results on performance code (using Performance code version on Fixed frequency):
                2 KEY DEC	
              	HSW [C/B]   BDW [C/B]    SKL [C/B]
AAD=0 MSG=1024	1.74        1.34        1.07
AAD=0 MSG=2048	1.52        1.14        0.96
AAD=0 MSG=4096	1.49        1.09        0.93
AAD=0 MSG=8192	1.44        1.04        0.90
AAD=0 MSG=16384	1.44        1.03        0.89


                2 KEY ENC	
                HSW [C/B]   BDW [C/B]   SKL [C/B]
AAD=0 MSG=1024	1.85        1.50        1.43
AAD=0 MSG=2048	1.68        1.33        1.30
AAD=0 MSG=4096	1.59        1.24        1.24
AAD=0 MSG=8192	1.55        1.19        1.21
AAD=0 MSG=16384	1.53        1.17        1.20
